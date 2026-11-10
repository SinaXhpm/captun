//! End-to-end tests against in-process mock servers: a TCP/UDP echo target, a
//! minimal SOCKS5 server (CONNECT + UDP ASSOCIATE) and an HTTP CONNECT proxy.
#![allow(clippy::unwrap_used)]

use std::{io, net::SocketAddr, sync::Arc};

use captun_core::{EgressId, Secret, TargetAddr};
use captun_outbound::{Credentials, Direct, HttpConnect, Outbound, Socks5};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
};

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn read_target<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<SocketAddr> {
    let atyp = s.read_u8().await?;
    assert_eq!(atyp, 1, "mock server only handles IPv4 targets");
    let mut ip = [0u8; 4];
    s.read_exact(&mut ip).await?;
    let port = s.read_u16().await?;
    Ok(SocketAddr::from((ip, port)))
}

async fn socks5_server(auth: Option<(&'static str, &'static str)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(socks5_session(s, auth));
        }
    });
    addr
}

async fn socks5_session(mut s: TcpStream, auth: Option<(&str, &str)>) -> io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).await?;

    if let Some((user, pass)) = auth {
        if !methods.contains(&2) {
            s.write_all(&[5, 0xff]).await?;
            return Ok(());
        }
        s.write_all(&[5, 2]).await?;
        let _ver = s.read_u8().await?;
        let mut u = vec![0u8; usize::from(s.read_u8().await?)];
        s.read_exact(&mut u).await?;
        let mut p = vec![0u8; usize::from(s.read_u8().await?)];
        s.read_exact(&mut p).await?;
        let ok = u == user.as_bytes() && p == pass.as_bytes();
        s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok {
            return Ok(());
        }
    } else {
        s.write_all(&[5, 0]).await?;
    }

    let mut req = [0u8; 3];
    s.read_exact(&mut req).await?;
    let target = read_target(&mut s).await?;
    match req[1] {
        1 => {
            let mut upstream = TcpStream::connect(target).await?;
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            copy_bidirectional(&mut s, &mut upstream).await?;
        }
        3 => {
            let relay = UdpSocket::bind("127.0.0.1:0").await?;
            let port = relay.local_addr()?.port().to_be_bytes();
            // Answer 0.0.0.0 to exercise the "use the server address" path.
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]]).await?;
            let upstream = UdpSocket::bind("127.0.0.1:0").await?;
            let mut buf = [0u8; 2048];
            let mut reply = [0u8; 2048];
            let (n, client) = relay.recv_from(&mut buf).await?;
            assert_eq!(buf[3], 1);
            let dest = SocketAddr::from(([buf[4], buf[5], buf[6], buf[7]], u16::from_be_bytes([buf[8], buf[9]])));
            upstream.send_to(&buf[10..n], dest).await?;
            let (m, from) = upstream.recv_from(&mut reply).await?;
            let SocketAddr::V4(from) = from else { unreachable!() };
            let mut packet = vec![0, 0, 0, 1];
            packet.extend_from_slice(&from.ip().octets());
            packet.extend_from_slice(&from.port().to_be_bytes());
            packet.extend_from_slice(&reply[..m]);
            relay.send_to(&packet, client).await?;
            // Hold the association open until the client hangs up.
            let _ = s.read(&mut buf).await;
        }
        _ => s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
    }
    Ok(())
}

async fn http_proxy(auth: Option<&'static str>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(http_session(s, auth));
        }
    });
    addr
}

async fn http_session(mut s: TcpStream, auth: Option<&str>) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).await?;
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf).unwrap();
    let target = head.split_whitespace().nth(1).unwrap().to_owned();
    if let Some(expected) = auth
        && !head.contains(&format!("Proxy-Authorization: Basic {expected}"))
    {
        s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await?;
        return Ok(());
    }
    let mut upstream = TcpStream::connect(target).await?;
    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    copy_bidirectional(&mut s, &mut upstream).await?;
    Ok(())
}

async fn assert_echo<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    stream.write_all(b"ping through the hub").await.unwrap();
    let mut buf = [0u8; 20];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping through the hub");
}

fn direct() -> Arc<dyn Outbound> {
    Arc::new(Direct::new(EgressId::new("direct"), None))
}

fn creds(user: &str, pass: &str) -> Option<Credentials> {
    Some(Credentials { username: user.into(), password: Secret::new(pass) })
}

#[tokio::test]
async fn direct_tcp_and_udp() {
    let echo = TargetAddr::Ip(tcp_echo().await);
    assert_echo(direct().connect_tcp(&echo).await.unwrap()).await;

    let target = TargetAddr::Ip(udp_echo().await);
    let session = direct().udp_session().await.unwrap();
    session.send_to(b"dgram", &target).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = session.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"dgram");
    assert_eq!(from, target);
}

#[tokio::test]
async fn direct_resolves_domains() {
    let port = tcp_echo().await.port();
    let stream = direct().connect_tcp(&TargetAddr::Domain("localhost".into(), port)).await;
    // `localhost` may resolve to ::1 first; Direct must fall through to 127.0.0.1.
    assert_echo(stream.unwrap()).await;
}

#[tokio::test]
async fn socks5_connect_with_and_without_auth() {
    let echo = TargetAddr::Ip(tcp_echo().await);

    let open = Socks5::new("s".into(), TargetAddr::Ip(socks5_server(None).await), None, direct());
    assert_echo(open.connect_tcp(&echo).await.unwrap()).await;

    let server = TargetAddr::Ip(socks5_server(Some(("alice", "s3cret"))).await);
    let authed = Socks5::new("s".into(), server.clone(), creds("alice", "s3cret"), direct());
    assert_echo(authed.connect_tcp(&echo).await.unwrap()).await;

    let wrong = Socks5::new("s".into(), server.clone(), creds("alice", "nope"), direct());
    let err = wrong.connect_tcp(&echo).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    let anonymous = Socks5::new("s".into(), server, None, direct());
    let err = anonymous.connect_tcp(&echo).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn socks5_udp_associate() {
    let target = TargetAddr::Ip(udp_echo().await);
    let proxy = Socks5::new("s".into(), TargetAddr::Ip(socks5_server(None).await), None, direct());
    let session = proxy.udp_session().await.unwrap();
    session.send_to(b"over socks udp", &target).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = session.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"over socks udp");
    assert_eq!(from, target);
}

#[tokio::test]
async fn http_connect_and_auth() {
    let echo = TargetAddr::Ip(tcp_echo().await);

    let open = HttpConnect::new("h".into(), TargetAddr::Ip(http_proxy(None).await), None, direct());
    assert_echo(open.connect_tcp(&echo).await.unwrap()).await;

    // "bob:pw" in base64.
    let server = TargetAddr::Ip(http_proxy(Some("Ym9iOnB3")).await);
    let authed = HttpConnect::new("h".into(), server.clone(), creds("bob", "pw"), direct());
    assert_echo(authed.connect_tcp(&echo).await.unwrap()).await;

    let anonymous = HttpConnect::new("h".into(), server, None, direct());
    assert_eq!(anonymous.connect_tcp(&echo).await.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(anonymous.udp_session().await.err().unwrap().kind(), io::ErrorKind::Unsupported);
}

#[tokio::test]
async fn socks5_chained_through_http() {
    let echo = TargetAddr::Ip(tcp_echo().await);
    let http: Arc<dyn Outbound> =
        Arc::new(HttpConnect::new("h".into(), TargetAddr::Ip(http_proxy(None).await), None, direct()));
    let chained = Socks5::new("s".into(), TargetAddr::Ip(socks5_server(None).await), None, http);
    assert_echo(chained.connect_tcp(&echo).await.unwrap()).await;
}
