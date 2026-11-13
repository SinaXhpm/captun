//! End to end against the real Xray program, entirely on loopback: an Xray
//! VLESS server, the sidecar as its client, and TCP/UDP echo targets reached
//! through the sidecar's SOCKS5 inbound exactly as the data plane reaches it.
//!
//! Needs the program: set CAPTUN_TEST_XRAY to its path, or run
//! `node scripts/fetch-xray.mjs` so it sits in target/debug. Skipped otherwise.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use captun_core::{EgressConfig, EgressId, EgressKind, TargetAddr};
use captun_outbound::{Direct, Outbound, Socks5};
use captun_xray::{Sidecar, SidecarState};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    process::Command,
    time::sleep,
};

const UUID: &str = "5f2b2a1c-8f36-4d8e-9a4a-0c3a2b1d4e5f";

fn program() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CAPTUN_TEST_XRAY") {
        return Some(PathBuf::from(path));
    }
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    // tests run from target/debug/deps
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join(name);
    path.is_file().then_some(path)
}

/// Run as root (CI containers, WSL), the sidecar drops Xray to `nobody`,
/// who cannot reach a program under /root; a copy in a world-readable
/// folder stands in for an installed one.
#[cfg(unix)]
fn reachable_copy(program: PathBuf) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("captun-xray-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let copy = dir.join("xray");
    std::fs::copy(&program, &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    copy
}

/// On Windows the sidecar marks the program to run at low integrity, which
/// takes WRITE_OWNER on the file: a copy in the user's own temp folder lets
/// this test run Xray as the service does.
#[cfg(not(unix))]
fn reachable_copy(program: PathBuf) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("captun-xray-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let copy = dir.join("xray.exe");
    std::fs::copy(&program, &copy).unwrap();
    copy
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// An Xray VLESS server on loopback that sends everything straight out.
async fn vless_server(program: &PathBuf, port: u16) -> tokio::process::Child {
    let config = serde_json::json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
            "streamSettings": { "network": "tcp", "security": "none" }
        }],
        // Xray blocks private targets for remote users by default; the echo
        // targets are on loopback, so allow exactly that.
        "outbounds": [{ "protocol": "freedom", "settings": { "finalRules": [{ "action": "allow", "network": "tcp,udp", "ip": ["127.0.0.0/8"] }] } }]
    });
    let mut child = Command::new(program)
        .args(["run", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(config.to_string().as_bytes()).await.unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(10);
    while tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(Instant::now() < deadline, "the test VLESS server did not start");
        sleep(Duration::from_millis(100)).await;
    }
    child
}

#[tokio::test]
async fn vless_link_carries_tcp_and_udp_through_the_sidecar() {
    let Some(program) = program() else {
        eprintln!("skipped: no Xray program (set CAPTUN_TEST_XRAY or run scripts/fetch-xray.mjs)");
        return;
    };

    let tcp_echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_target = tcp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp_echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..n], from).await;
        }
    });

    let server_port = free_port();
    let _server = vless_server(&program, server_port).await;

    let changes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = changes.clone();
    let sidecar = Sidecar::start(Some(reachable_copy(program)), None, move || {
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    let id = EgressId::from("vpn");
    sidecar.apply(&[EgressConfig {
        id: id.clone(),
        name: None,
        kind: EgressKind::Xray {
            // A private address, so Xray allows VLESS without TLS for the test.
            link: Some(format!("vless://{UUID}@127.0.0.1:{server_port}?type=tcp&security=none#test").as_str().into()),
            config_file: None,
        },
        udp: Default::default(),
        enabled: true,
    }]);

    let deadline = Instant::now() + Duration::from_secs(15);
    let endpoint = loop {
        match sidecar.endpoint(&id) {
            Ok(endpoint) => break endpoint,
            Err(why) => {
                assert!(Instant::now() < deadline, "sidecar never came up: {why} ({:?})", sidecar.status());
                sleep(Duration::from_millis(100)).await;
            }
        }
    };
    assert_eq!(sidecar.status().state, SidecarState::Running);
    assert!(sidecar.status().version.is_some_and(|v| v.contains('.')));
    assert!(changes.load(std::sync::atomic::Ordering::SeqCst) > 0, "the owner was told about the new endpoint");

    let proxy = Socks5::new(id.clone(), TargetAddr::Ip(endpoint.addr), endpoint.auth.clone(), Arc::new(Direct::new(id.clone(), None)));

    let mut stream = proxy.connect_tcp(&TargetAddr::Ip(tcp_target)).await.unwrap();
    stream.write_all(b"hello through vless").await.unwrap();
    let mut back = [0u8; 19];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"hello through vless");

    let udp = proxy.udp_session().await.unwrap();
    let mut buf = [0u8; 64];
    let mut answered = None;
    // UDP may need a retry while the association settles.
    for _ in 0..10 {
        udp.send_to(b"datagram", &TargetAddr::Ip(udp_target)).await.unwrap();
        if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut buf)).await {
            answered = Some((buf[..n].to_vec(), from));
            break;
        }
    }
    let (payload, from) = answered.expect("no UDP answer through the sidecar");
    assert_eq!(payload, b"datagram");
    assert_eq!(from.port(), udp_target.port());

    // Wrong credentials are refused: the inbound is not an open proxy.
    let stranger = Socks5::new(id.clone(), TargetAddr::Ip(endpoint.addr), None, Arc::new(Direct::new(id.clone(), None)));
    assert!(stranger.connect_tcp(&TargetAddr::Ip(tcp_target)).await.is_err());

    // Removing the outbound stops the child and withdraws the endpoint.
    sidecar.apply(&[]);
    let deadline = Instant::now() + Duration::from_secs(10);
    while sidecar.status().state != SidecarState::Idle {
        assert!(Instant::now() < deadline);
        sleep(Duration::from_millis(50)).await;
    }
    assert!(sidecar.endpoint(&id).is_err());
}
