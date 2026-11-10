//! UDP and TCP listeners on one address, both with hard concurrency caps so a
//! flood from a hotspot device degrades DNS rather than exhausting the host.
//! UDP's caps are the handler's ([`DnsHandler::admit`]): they hold for all
//! devices together and for each one, and the engine's path shares them.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};

use crate::{DnsHandler, Transport, message::HEADER_LEN};

/// Each connection answers one query at a time.
const MAX_TCP_CONNECTIONS: usize = 256;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Queries are tiny; anything bigger than this is not a DNS query.
const MAX_QUERY: usize = 4096;

/// Running DNS server. Dropping it stops both listeners.
#[derive(Debug)]
pub struct DnsServerHandle {
    local_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl DnsServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DnsServerHandle {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Serves UDP and TCP on `listen`. With port 0 both share the port the OS
/// picked for UDP; when another program holds that port for TCP, a few other
/// ports are tried.
pub async fn serve(listen: SocketAddr, handler: Arc<DnsHandler>) -> io::Result<DnsServerHandle> {
    const TRIES_ON_ANY_PORT: usize = 8;
    let tries = if listen.port() == 0 { TRIES_ON_ANY_PORT } else { 1 };
    let mut attempt = 1;
    let (udp, tcp, local_addr) = loop {
        let udp = UdpSocket::bind(listen).await?;
        let local_addr = udp.local_addr()?;
        match TcpListener::bind(local_addr).await {
            Ok(tcp) => break (Arc::new(udp), tcp, local_addr),
            Err(e) if attempt >= tries || e.kind() != io::ErrorKind::AddrInUse => return Err(e),
            Err(_) => attempt += 1,
        }
    };
    let tasks = vec![tokio::spawn(udp_loop(udp, handler.clone())), tokio::spawn(tcp_loop(tcp, handler))];
    Ok(DnsServerHandle { local_addr, tasks })
}

async fn udp_loop(socket: Arc<UdpSocket>, handler: Arc<DnsHandler>) {
    let mut buf = vec![0u8; MAX_QUERY];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            // Windows reports an earlier ICMP port-unreachable as a
            // ConnectionReset on the next receive; it says nothing about us.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                tracing::warn!("DNS UDP receive failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let client = peer.ip().to_canonical();
        // Too many queries being answered, from all devices or from this one:
        // dropped, and the device asks again.
        let Some(admitted) = handler.admit(client) else { continue };
        let query = buf[..n].to_vec();
        let (socket, handler) = (socket.clone(), handler.clone());
        tokio::spawn(async move {
            let _admitted = admitted;
            if let Some(response) = handler.handle(&query, client, Transport::Udp).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn tcp_loop(listener: TcpListener, handler: Arc<DnsHandler>) {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!("DNS TCP accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else { continue };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tcp_session(stream, peer, handler).await;
        });
    }
}

/// RFC 7766: length-prefixed messages, several per connection, answered in
/// order, closed after an idle period.
async fn tcp_session(mut stream: TcpStream, peer: SocketAddr, handler: Arc<DnsHandler>) {
    let client = peer.ip().to_canonical();
    loop {
        let Ok(Ok(len)) = timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await else { return };
        let len = usize::from(len);
        if !(HEADER_LEN..=MAX_QUERY).contains(&len) {
            return;
        }
        let mut query = vec![0u8; len];
        if !matches!(timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut query)).await, Ok(Ok(_))) {
            return;
        }
        let Some(response) = handler.handle(&query, client, Transport::Tcp).await else { return };
        let Ok(response_len) = u16::try_from(response.len()) else { return };
        let mut frame = Vec::with_capacity(2 + response.len());
        frame.extend_from_slice(&response_len.to_be_bytes());
        frame.extend_from_slice(&response);
        if !matches!(timeout(TCP_IDLE_TIMEOUT, stream.write_all(&frame)).await, Ok(Ok(()))) {
            return;
        }
    }
}
