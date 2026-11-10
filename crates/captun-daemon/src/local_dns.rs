//! The hub's own DNS as an outbound, so the routing engine can carry a
//! device's DNS flow to it like any other flow. Devices send their queries to
//! the hotspot address; where another DNS server holds that address (Windows'
//! Internet Connection Sharing), the engine takes the queries first and hands
//! them here. Each answer is resolved through the device's own egress.

use std::{io, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use captun_core::{EgressId, TargetAddr};
use captun_dns::{DnsHandler, Transport};
use captun_outbound::{BoxStream, Outbound, UdpSession};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{Mutex, mpsc},
};

/// DNS over TCP carries messages of up to 64 KiB.
const TCP_BUFFER: usize = 64 * 1024;
/// Answers waiting to be read back by the engine.
const ANSWERS: usize = 64;

/// Answers the DNS of one device (`client`) with the hub's DNS.
#[derive(Debug)]
pub(crate) struct LocalDns {
    id: EgressId,
    handler: Arc<DnsHandler>,
    client: IpAddr,
}

impl LocalDns {
    pub(crate) fn new(handler: Arc<DnsHandler>, client: IpAddr) -> Self {
        Self { id: EgressId::new("captun-dns"), handler, client }
    }
}

#[async_trait]
impl Outbound for LocalDns {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        let (ours, theirs) = tokio::io::duplex(TCP_BUFFER);
        tokio::spawn(answer_tcp(ours, self.handler.clone(), self.client));
        Ok(Box::new(theirs))
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        let (answers, waiting) = mpsc::channel(ANSWERS);
        Ok(Box::new(DnsSession { handler: self.handler.clone(), client: self.client, answers, waiting: Mutex::new(waiting) }))
    }
}

/// DNS over TCP: every message is preceded by its length in two bytes.
async fn answer_tcp(mut stream: DuplexStream, handler: Arc<DnsHandler>, client: IpAddr) {
    loop {
        let mut len = [0u8; 2];
        if stream.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let Some(answer) = handler.handle(&query, client, Transport::Tcp).await else { continue };
        let Ok(answer_len) = u16::try_from(answer.len()) else { continue };
        if stream.write_all(&answer_len.to_be_bytes()).await.is_err() || stream.write_all(&answer).await.is_err() {
            return;
        }
    }
}

/// DNS over UDP: each query is answered on its own, in whatever order the
/// answers come. Queries share the limits of the hub's own DNS server
/// ([`DnsHandler::admit`]): one past them is dropped and the device asks again.
#[derive(Debug)]
struct DnsSession {
    handler: Arc<DnsHandler>,
    client: IpAddr,
    answers: mpsc::Sender<(Vec<u8>, TargetAddr)>,
    waiting: Mutex<mpsc::Receiver<(Vec<u8>, TargetAddr)>>,
}

#[async_trait]
impl UdpSession for DnsSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        // Let in before a task is made for it, so a device flooding queries
        // costs no more than the limits allow.
        let Some(admitted) = self.handler.admit(self.client) else { return Ok(()) };
        let (handler, client, answers) = (self.handler.clone(), self.client, self.answers.clone());
        let (query, from) = (payload.to_vec(), target.clone());
        tokio::spawn(async move {
            // The query counts until its answer is handed back.
            let _admitted = admitted;
            if let Some(answer) = handler.handle(&query, client, Transport::Udp).await {
                let _ = answers.send((answer, from)).await;
            }
        });
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let (answer, from) = self.waiting.lock().await.recv().await.ok_or(io::ErrorKind::BrokenPipe)?;
        let n = answer.len().min(buf.len());
        buf[..n].copy_from_slice(&answer[..n]);
        Ok((n, from))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use captun_core::config::{DnsConfig, DnsOverride};
    use captun_dns::{DnsRoute, DnsRouter, DnsSettings};

    use super::*;

    struct NoRoute;

    impl DnsRouter for NoRoute {
        fn route(&self, _client: IpAddr, _name: &str) -> Option<DnsRoute> {
            None
        }
    }

    /// A handler that knows one name, so nothing leaves this computer.
    fn handler() -> Arc<DnsHandler> {
        let config = DnsConfig {
            overrides: vec![DnsOverride {
                domain: "printer.home".parse().unwrap(),
                addrs: vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))],
            }],
            ..DnsConfig::default()
        };
        Arc::new(DnsHandler::new(DnsSettings::from_config(&config).unwrap(), Arc::new(NoRoute), None))
    }

    /// An A query for `printer.home`, with id 0x4242.
    fn query() -> Vec<u8> {
        let mut q = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["printer", "home"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    fn answers_with_the_override(answer: &[u8]) -> bool {
        answer.starts_with(&[0x42, 0x42]) && answer.windows(4).any(|w| w == [10, 1, 2, 3])
    }

    #[tokio::test]
    async fn udp_queries_get_the_hubs_answers() {
        let dns = LocalDns::new(handler(), "192.168.137.80".parse().unwrap());
        let session = dns.udp_session().await.unwrap();
        let gateway: TargetAddr = "192.168.137.1:53".parse().unwrap();
        session.send_to(&query(), &gateway).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = session.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, gateway, "answers come from where the query went");
        assert!(answers_with_the_override(&buf[..n]));
    }

    /// How many more queries `client` may have answered at once now.
    fn places_left(handler: &DnsHandler, client: IpAddr) -> usize {
        std::iter::from_fn(|| handler.admit(client)).collect::<Vec<_>>().len()
    }

    // The test runtime runs one task at a time, so a query's task has not
    // started until the test waits for something.
    #[tokio::test]
    async fn a_udp_query_counts_until_its_answer_is_handed_back() {
        let handler = handler();
        let client: IpAddr = "192.168.137.80".parse().unwrap();
        let all = places_left(&handler, client);
        assert!(all > 1);
        let session = LocalDns::new(handler.clone(), client).udp_session().await.unwrap();
        let gateway: TargetAddr = "192.168.137.1:53".parse().unwrap();
        session.send_to(&query(), &gateway).await.unwrap();
        assert_eq!(places_left(&handler, client), all - 1, "taken from the moment it is sent");
        let mut buf = [0u8; 512];
        let (n, _) = session.recv_from(&mut buf).await.unwrap();
        assert!(answers_with_the_override(&buf[..n]));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while places_left(&handler, client) != all {
            assert!(tokio::time::Instant::now() < deadline, "the place was never given back");
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_udp_query_past_the_limit_is_dropped_and_asked_again() {
        let handler = handler();
        let (client, other): (IpAddr, IpAddr) = ("192.168.137.80".parse().unwrap(), "192.168.137.81".parse().unwrap());
        let gateway: TargetAddr = "192.168.137.1:53".parse().unwrap();
        let session = LocalDns::new(handler.clone(), client).udp_session().await.unwrap();
        let mut buf = [0u8; 512];

        // The device has as many queries being answered as it may.
        let held: Vec<_> = std::iter::from_fn(|| handler.admit(client)).collect();
        session.send_to(&query(), &gateway).await.unwrap();
        let wait = std::time::Duration::from_millis(300);
        assert!(tokio::time::timeout(wait, session.recv_from(&mut buf)).await.is_err(), "dropped, not answered");

        // Another device is not held up by it.
        let theirs = LocalDns::new(handler.clone(), other).udp_session().await.unwrap();
        theirs.send_to(&query(), &gateway).await.unwrap();
        let (n, _) = theirs.recv_from(&mut buf).await.unwrap();
        assert!(answers_with_the_override(&buf[..n]));

        // Once its earlier ones are answered, its next try is.
        drop(held);
        session.send_to(&query(), &gateway).await.unwrap();
        let (n, _) = session.recv_from(&mut buf).await.unwrap();
        assert!(answers_with_the_override(&buf[..n]));
    }

    #[tokio::test]
    async fn tcp_queries_get_the_hubs_answers() {
        let dns = LocalDns::new(handler(), "192.168.137.80".parse().unwrap());
        let mut stream = dns.connect_tcp(&"192.168.137.1:53".parse().unwrap()).await.unwrap();
        let q = query();
        stream.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        stream.write_all(&q).await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut answer).await.unwrap();
        assert!(answers_with_the_override(&answer));
    }
}
