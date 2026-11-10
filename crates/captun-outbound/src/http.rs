//! HTTP CONNECT proxy client, over plain TCP or TLS (an "HTTPS proxy"). TCP
//! only: HTTP proxies have no way to relay UDP, which config validation makes
//! the user handle explicitly.

use std::{io, sync::Arc};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use captun_core::{EgressId, TargetAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{BoxStream, Credentials, HANDSHAKE_TIMEOUT, Outbound, PrefixedStream, UdpSession, timed_out, tls};

const MAX_RESPONSE_HEAD: usize = 16 * 1024;

#[derive(Debug)]
pub struct HttpConnect {
    id: EgressId,
    server: TargetAddr,
    auth: Option<Credentials>,
    tls: bool,
    /// Replaces the bundled certificate authorities (tests only).
    tls_config: Option<Arc<rustls::ClientConfig>>,
    dialer: Arc<dyn Outbound>,
}

impl HttpConnect {
    pub fn new(id: EgressId, server: TargetAddr, auth: Option<Credentials>, dialer: Arc<dyn Outbound>) -> Self {
        Self { id, server, auth, tls: false, tls_config: None, dialer }
    }

    /// Talks to the proxy over TLS (an HTTPS proxy).
    pub fn with_tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }

    fn request(&self, target: &TargetAddr) -> String {
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(creds) = &self.auth {
            let token = STANDARD.encode(format!("{}:{}", creds.username, creds.password.expose()));
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        req.push_str("\r\n");
        req
    }
}

#[async_trait]
impl Outbound for HttpConnect {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let stream = self.dialer.connect_tcp(&self.server).await?;
        let (stream, leftover) = timeout(HANDSHAKE_TIMEOUT, async {
            let mut stream =
                if self.tls { tls::wrap(stream, &self.server, self.tls_config.clone()).await? } else { stream };
            stream.write_all(self.request(target).as_bytes()).await?;
            let leftover = read_response_head(&mut stream, target).await?;
            Ok::<_, io::Error>((stream, leftover))
        })
        .await
        .map_err(|_| timed_out("HTTP CONNECT"))??;

        if leftover.is_empty() {
            Ok(stream)
        } else {
            Ok(Box::new(PrefixedStream::new(leftover, stream)))
        }
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("egress {} is an HTTP proxy and cannot carry UDP", self.id)))
    }
}

/// Reads the proxy's response head and returns any bytes that arrived after it.
async fn read_response_head(stream: &mut BoxStream, target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP proxy closed the connection during CONNECT"));
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let code = response.code.unwrap_or(0);
                return match code {
                    200..=299 => Ok(buf.split_off(head_len)),
                    407 => Err(io::Error::new(io::ErrorKind::PermissionDenied, "HTTP proxy authentication failed (407)")),
                    _ => Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("HTTP proxy refused CONNECT to {target}: {code} {}", response.reason.unwrap_or("")),
                    )),
                };
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_RESPONSE_HEAD => continue,
            Ok(httparse::Status::Partial) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP proxy response head too large"));
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad HTTP proxy response: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use captun_core::{EgressId, TargetAddr};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::Direct;

    /// An HTTPS proxy for "localhost" that answers CONNECT with 200 and then
    /// echoes, plus a client config that trusts only its certificate.
    async fn https_proxy() -> (SocketAddr, Arc<rustls::ClientConfig>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if tls.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    assert!(head.starts_with(b"CONNECT example.com:80 HTTP/1.1"));
                    tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                    let mut buf = [0u8; 64];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, Arc::new(client))
    }

    fn proxy(server: TargetAddr) -> HttpConnect {
        let id = EgressId::from("https");
        HttpConnect::new(id.clone(), server, None, Arc::new(Direct::new(id, None))).with_tls(true)
    }

    #[tokio::test]
    async fn https_proxy_tunnels_over_verified_tls() {
        let (addr, trusted) = https_proxy().await;
        let mut proxy = proxy(TargetAddr::Domain("localhost".into(), addr.port()));
        proxy.tls_config = Some(trusted);
        let mut stream = proxy.connect_tcp(&"example.com:80".parse().unwrap()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
    }

    #[tokio::test]
    async fn https_proxy_rejects_an_untrusted_certificate() {
        let (addr, _) = https_proxy().await;
        // The bundled public authorities do not trust a self-signed certificate.
        let proxy = proxy(TargetAddr::Domain("localhost".into(), addr.port()));
        let err = proxy.connect_tcp(&"example.com:80".parse().unwrap()).await.err().unwrap();
        assert!(err.to_string().contains("TLS to the proxy"), "{err}");
    }
}
