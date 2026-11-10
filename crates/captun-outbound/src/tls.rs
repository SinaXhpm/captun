//! TLS to a proxy server (HTTPS proxies), verified against the public
//! certificate authorities bundled with Captun.

use std::{
    io,
    sync::{Arc, OnceLock},
};

use captun_core::TargetAddr;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_rustls::TlsConnector;

use crate::BoxStream;

/// The client side for TLS over HTTP/1.1: proxies' CONNECT, and downloads.
pub(crate) fn client_config() -> io::Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // An explicit provider: another crate in the binary may enable a
            // second one, which would make the process-default builder panic.
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            // CONNECT is an HTTP/1.1 method, and downloads speak nothing newer.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(config))
        })
        .clone()
        .map_err(io::Error::other)
}

/// Wraps an open connection to `server` in TLS, checking its certificate
/// against the server's name (or IP address).
pub(crate) async fn wrap(
    stream: BoxStream,
    server: &TargetAddr,
    config: Option<Arc<ClientConfig>>,
) -> io::Result<BoxStream> {
    let name = ServerName::try_from(server.host())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a valid TLS server name", server.host())))?;
    let config = match config {
        Some(config) => config,
        None => client_config()?,
    };
    let tls = TlsConnector::from(config).connect(name, stream).await.map_err(|e| {
        io::Error::new(e.kind(), format!("TLS to the proxy {server} failed: {e}"))
    })?;
    Ok(Box::new(tls))
}
