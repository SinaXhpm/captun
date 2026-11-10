//! Windows packet capture for routing hotspot devices through Captun.
//!
//! Windows forwards a hotspot device's traffic and translates it itself
//! (Internet Connection Sharing), and it has no source-based routing, so no
//! route can send one device's traffic anywhere else. WinDivert, a signed
//! packet-capture driver, can: it takes the device's packets out of the
//! forwarding path before ICS translates them and hands them to the routing
//! engine, which puts its replies back on the hotspot interface.
//!
//! Packets are taken at the forward layer, where Windows shows traffic it
//! routes for others, and at the local inbound layer as a fallback; DNS
//! queries to this computer's own address arrive there too. Replies are
//! injected at the forward layer (they are, after all, forwarded packets to the
//! device), falling back to the outbound path if Windows refuses that. Answers
//! from this computer's own address go out the outbound path, as sent packets.
//!
//! ICS's NAT driver takes the devices' packets as well, beside the capture,
//! and injects translated copies of its own: left alone, they leak the
//! devices' traffic past the engine and bring back the real servers' answers,
//! which reset the engine's connections. While a network is captured, those
//! injected copies are dropped ahead of everything else.
//!
//! Packets cross the driver in batches, so a busy network costs a driver call
//! per batch rather than per packet. Each handle's thread takes up to 255
//! packets a call and hands them straight on to the engine, whose queue holds
//! 4096: when the engine falls that far behind, new packets are dropped (and
//! counted, beside the packets captured). While
//! the thread itself is busy, or not running, the driver holds up to 16,384 of
//! a capture handle's packets (32 MiB) for it. Writing a reply only queues it,
//! so the engine never waits on the driver: one thread sends whatever has
//! gathered, up to 255 a call for each handle. A reply that finds 4096 already
//! waiting is dropped, as on a congested link, and the engine's TCP sends it
//! again.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    thread::JoinHandle,
};

use ipnet::{IpNet, Ipv4Net};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
use tracing::{debug, info, warn};

use crate::capture::{CaptureConfig, CaptureError, divert_filter};

/// Captured packets waiting for the engine. When it falls this far behind,
/// new packets are dropped, as on a congested link.
const QUEUE: usize = 4096;
/// Replies waiting for the thread that sends them. When it falls this far
/// behind, new replies are dropped the same way.
const REPLY_QUEUE: usize = 4096;
/// Packets one driver call takes or sends: WinDivert's limit.
const BATCH: usize = ffi::BATCH_MAX;
/// Room for the packets of one receive call. The driver locks all of it in
/// memory for every call, however few packets come, so it holds 64 packets of
/// the largest size the devices' links carry (1500 bytes on Wi-Fi and
/// Ethernet) rather than 255: a full batch of small ones, such as the
/// acknowledgements a downloading device sends. It also holds the largest
/// packet the driver takes, so a batch's first packet always fits; a later one
/// that does not fit waits for the next call.
const RECV_BUFFER: usize = 64 * 1500;
const _: () = assert!(RECV_BUFFER >= ffi::MTU_MAX);
/// Captured packets the driver may hold for a capture handle, and their bytes:
/// WinDivert's largest queue (4096 packets and 4 MiB by default), so a burst
/// that comes while the handle's thread is busy, or not running, waits for it
/// instead of being lost. The thread never waits for the engine: when the
/// engine falls behind, what does not fit in [`QUEUE`] is still dropped.
/// Packets still expire after the driver's default two seconds.
const DRIVER_QUEUE_LENGTH: u64 = 16_384;
const DRIVER_QUEUE_SIZE: u64 = 32 << 20;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One network being captured, and the interface its devices are reached on.
#[derive(Clone, Debug)]
struct Route {
    id: u64,
    subnet: Ipv4Net,
    /// This computer's address on the network.
    gateway: Ipv4Addr,
    /// The adapter the devices are on; 0 until known. Windows gives the
    /// hotspot adapter its address a few seconds after the access point comes
    /// up, so it is learned from the devices' own packets as well.
    if_index: Arc<AtomicU32>,
}

struct Shared {
    api: Arc<ffi::Api>,
    routes: Mutex<Vec<Route>>,
    next_id: AtomicU64,
    inbound: mpsc::Sender<Vec<u8>>,
    captured: AtomicU64,
    /// Captured packets dropped because the engine's queue was full.
    dropped: AtomicU64,
    /// Set once the driver has refused a larger queue, so that is said once.
    queue_refused: AtomicBool,
}

/// Puts batches of replies on the network: a WinDivert handle, or a stand-in
/// in tests.
trait Outlet {
    /// Fixes each packet's checksums, as injected packets need, and marks in
    /// its address the ones fixed, so the driver does not redo them.
    fn fix_checksums(&self, batch: &mut Batch);
    /// Injects the batch as each packet's address describes. An empty batch
    /// is not sent.
    fn send(&self, batch: &Batch) -> io::Result<()>;
}

impl Outlet for ffi::Handle {
    fn fix_checksums(&self, batch: &mut Batch) {
        batch.fix_checksums(self.api());
    }

    fn send(&self, batch: &Batch) -> io::Result<()> {
        self.send_batch(&batch.data, &batch.addrs)
    }
}

/// Sends the engine's replies to the devices: owned by the one thread that
/// does, with the handles they go out through.
struct Injector<O> {
    forward_send: O,
    network_send: O,
    /// Set once Windows refuses forward-layer injection, so later replies go
    /// straight to the fallback.
    use_network_send: bool,
    out: Outgoing,
}

impl<O: Outlet> Injector<O> {
    /// Sends the replies queued in `queue`, a batch at a time, to the
    /// captured networks in `routes`, until the device that queues them is
    /// dropped.
    fn run(mut self, routes: &Mutex<Vec<Route>>, queue: &std::sync::mpsc::Receiver<Vec<u8>>) {
        let mut replies = Vec::with_capacity(BATCH);
        // Waits for a reply, then takes whatever else is waiting, up to a batch.
        while let Ok(first) = queue.recv() {
            replies.push(first);
            replies.extend(queue.try_iter().take(BATCH - 1));
            self.inject(&replies, routes);
            replies.clear();
        }
        debug!("reply thread ends: the engine is gone");
    }

    /// Sends one batch of replies to the devices they are for, found in
    /// `routes`: one driver call for those forwarded and one for those sent.
    fn inject(&mut self, replies: &[Vec<u8>], routes: &Mutex<Vec<Route>>) {
        let out = &mut self.out;
        out.clear();
        {
            let routes = lock(routes);
            for reply in replies {
                out.add(reply, &routes, !self.use_network_send);
            }
        }
        self.forward_send.fix_checksums(&mut out.forward);
        self.network_send.fix_checksums(&mut out.network);
        if let Err(e) = self.forward_send.send(&out.forward) {
            info!("forward-layer injection refused ({e}); replying through the outbound path instead");
            self.use_network_send = true;
            // All of them again: the driver does not say which went out.
            out.forward.set_layer(ffi::LAYER_NETWORK);
            send(&self.network_send, &out.forward);
        }
        send(&self.network_send, &out.network);
    }
}

/// Sends a batch through the network layer's handle. Replies that cannot be
/// delivered are lost like any other packet; the engine's TCP retransmits.
fn send(outlet: &impl Outlet, batch: &Batch) {
    if let Err(e) = outlet.send(batch) {
        debug!(replies = batch.len(), "replies not delivered: {e}");
    }
}

/// One batch of replies, packed for the handle that sends each.
#[derive(Default)]
struct Outgoing {
    /// Forwarded to the devices' adapter, as the internet's answers are.
    forward: Batch,
    /// Sent from this computer: its own answers, replies on a network whose
    /// adapter is not known yet, and every reply once forwarding is refused.
    network: Batch,
}

impl Outgoing {
    fn clear(&mut self) {
        self.forward.clear();
        self.network.clear();
    }

    /// Packs one reply from the engine for the handle that sends it, found by
    /// the captured network its destination is on; `forward` is false once
    /// Windows has refused forward-layer injection. A reply that is not a
    /// whole IPv4 packet, or is for no captured network, is dropped.
    fn add(&mut self, reply: &[u8], routes: &[Route], forward: bool) {
        // The driver finds each packet of a batch by the length its header
        // gives, so exactly that much goes in.
        let Some(reply) = ip_packet_len(reply).map(|len| &reply[..len]) else { return };
        let Some(dst) = ipv4_destination(reply) else { return };
        let Some(route) = routes.iter().find(|r| r.subnet.contains(&dst)) else {
            debug!(%dst, "no captured network for this reply; dropped");
            return;
        };
        let if_index = route.if_index.load(Ordering::Relaxed);
        // Answers from this computer's own address (DNS) are sent, not
        // forwarded: Windows does not forward packets from its own address.
        // So is everything until the adapter is known, which forwarding needs;
        // a sent packet's adapter is picked by Windows from its destination.
        let own = ipv4_source(reply) == Some(route.gateway);
        if forward && !own && if_index != 0 {
            self.forward.push(reply, ffi::Address::outbound(ffi::LAYER_NETWORK_FORWARD, if_index));
        } else {
            self.network.push(reply, ffi::Address::outbound(ffi::LAYER_NETWORK, if_index));
        }
    }
}

/// Packets for one handle, back to back as WinDivertSendEx takes them, with an
/// address for each.
#[derive(Default)]
struct Batch {
    data: Vec<u8>,
    /// Where each packet ends in `data`.
    ends: Vec<usize>,
    addrs: Vec<ffi::Address>,
}

impl Batch {
    fn push(&mut self, packet: &[u8], addr: ffi::Address) {
        self.data.extend_from_slice(packet);
        self.ends.push(self.data.len());
        self.addrs.push(addr);
    }

    fn len(&self) -> usize {
        self.addrs.len()
    }

    fn clear(&mut self) {
        self.data.clear();
        self.ends.clear();
        self.addrs.clear();
    }

    /// Fixes each packet's checksums, as injected packets need, and marks in
    /// its address the ones fixed, so the driver does not redo them.
    fn fix_checksums(&mut self, api: &ffi::Api) {
        let mut start = 0;
        for (&end, addr) in self.ends.iter().zip(&mut self.addrs) {
            api.fix_checksums(&mut self.data[start..end], addr);
            start = end;
        }
    }

    /// Moves every packet to `layer`, for a handle there to send.
    fn set_layer(&mut self, layer: i32) {
        for addr in &mut self.addrs {
            addr.set_layer(layer);
        }
    }
}

fn ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    (packet.len() >= 20 && packet[0] >> 4 == 4).then(|| Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]))
}

fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    (packet.len() >= 20 && packet[0] >> 4 == 4).then(|| Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}

/// The length the IP packet at the start of `data` gives itself (IPv4's total
/// length, or IPv6's payload length plus its 40-byte header), if that length
/// is sane and `data` holds all of it.
fn ip_packet_len(data: &[u8]) -> Option<usize> {
    let len = match data.first()? >> 4 {
        4 if data.len() >= 20 => {
            let header = usize::from(data[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([data[2], data[3]]));
            (header >= 20 && total >= header).then_some(total)?
        }
        6 if data.len() >= 40 => 40 + usize::from(u16::from_be_bytes([data[4], data[5]])),
        _ => return None,
    };
    (len <= data.len()).then_some(len)
}

/// The packets of a batch from the driver: back to back, each as long as its
/// own header says. Ends early at one whose length does not fit, since nothing
/// after it can be found.
fn packets(mut batch: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (packet, rest) = batch.split_at(ip_packet_len(batch)?);
        batch = rest;
        Some(packet)
    })
}

/// Room for one batch from the driver: the packets back to back, and an
/// address for each.
struct Inbox {
    data: Vec<u8>,
    addrs: Vec<ffi::Address>,
}

impl Inbox {
    fn new() -> Self {
        Self { data: vec![0; RECV_BUFFER], addrs: vec![ffi::Address::zeroed(); BATCH] }
    }

    /// Blocks for the next packets `handle` captures, then gives each with its
    /// address.
    fn recv(&mut self, handle: &ffi::Handle) -> io::Result<impl Iterator<Item = (&[u8], &ffi::Address)>> {
        let (len, count) = handle.recv_batch(&mut self.data, &mut self.addrs)?;
        Ok(packets(&self.data[..len]).zip(&self.addrs[..count]))
    }
}

/// The engine's side: captured packets to read, replies to write.
pub struct DivertDevice {
    rx: mpsc::Receiver<Vec<u8>>,
    /// Replies for the thread that sends them. Dropping it ends that thread.
    replies: std::sync::mpsc::SyncSender<Vec<u8>>,
    /// Replies dropped because that thread had fallen behind.
    dropped: u64,
}

impl std::fmt::Debug for DivertDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DivertDevice").finish_non_exhaustive()
    }
}

impl AsyncRead for DivertDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let n = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DivertDevice {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        // Only queued, so the engine never waits on the driver. A reply that
        // finds the queue full, or cannot be delivered, is dropped like a lost
        // packet; the engine's TCP retransmits.
        match self.replies.try_send(packet.to_vec()) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.dropped += 1;
                if self.dropped.is_power_of_two() {
                    info!(dropped = self.dropped, "replies to the devices dropped: the packet driver is falling behind");
                }
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the thread that sends replies has stopped")));
            }
        }
        Poll::Ready(Ok(packet.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Adds networks to the capture.
pub struct DivertSteerer {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for DivertSteerer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DivertSteerer").field("captured", &self.captured_packets()).finish_non_exhaustive()
    }
}

/// Why WinDivert was not loaded.
#[derive(Debug)]
enum LoadError {
    /// Programs other than Windows and the administrators can change its
    /// files, so loading them could run their code with the service's rights.
    Untrusted(crate::trust::UntrustedFile),
    Failed(io::Error),
}

/// What the capture says when it refuses WinDivert's files.
const UNTRUSTED_CAPTURE: &str = "Devices are not going through Captun because other programs on this computer can \
                                 change Captun's files. Reinstall Captun for all users.";

/// Loads WinDivert from the service's own folder. A release build first makes
/// sure that only Windows and the administrators can change the DLL and the
/// driver, and the folders they are in; a debug build runs from `target\`,
/// which its user can change.
fn load_api() -> Result<Arc<ffi::Api>, LoadError> {
    let started_in = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        .ok_or_else(|| LoadError::Failed(io::Error::other("cannot find the service's folder")))?;
    let dir = windivert_folder(&started_in, !cfg!(debug_assertions))?;
    ffi::Api::load(&dir).map(Arc::new).map_err(LoadError::Failed)
}

/// The folder to load WinDivert from: the real path of `started_in`, the
/// folder the service was started from, after (when `check`) WinDivert's
/// files there passed the trust check. `started_in` may be reached through a
/// link its maker can point elsewhere at any moment, between a check and the
/// load; the real path, checked level by level, is one nobody else can
/// change once it passes, so the files checked are the files loaded.
fn windivert_folder(started_in: &std::path::Path, check: bool) -> Result<std::path::PathBuf, LoadError> {
    let dir = crate::trust::real_path(started_in).map_err(|e| {
        LoadError::Failed(io::Error::other(format!("cannot find the service's folder {}: {e}", started_in.display())))
    })?;
    if check {
        for file in ["WinDivert.dll", "WinDivert64.sys"] {
            match crate::trust::check_program_file(&dir.join(file)) {
                // Said by `Api::load`, in its own words.
                Ok(()) | Err(crate::trust::UntrustedFile::Missing { .. }) => {}
                Err(why) => return Err(LoadError::Untrusted(why)),
            }
        }
    }
    Ok(dir)
}

/// Loads WinDivert from the service's own folder, opens the handles that put
/// replies back on the network and starts the thread that sends them. Needs
/// administrator rights.
pub fn open() -> Result<(DivertDevice, DivertSteerer), CaptureError> {
    let api = load_api().map_err(|e| match e {
        LoadError::Untrusted(why) => CaptureError::Driver(format!("{UNTRUSTED_CAPTURE} ({why})")),
        LoadError::Failed(e) => CaptureError::Driver(e.to_string()),
    })?;
    // "false" matches nothing: these handles only inject.
    let forward_send = ffi::Handle::open(&api, "false", ffi::LAYER_NETWORK_FORWARD, ffi::FLAG_SEND_ONLY)
        .map_err(|e| CaptureError::Driver(e.to_string()))?;
    let network_send = ffi::Handle::open(&api, "false", ffi::LAYER_NETWORK, ffi::FLAG_SEND_ONLY)
        .map_err(|e| CaptureError::Driver(e.to_string()))?;
    let (inbound, rx) = mpsc::channel(QUEUE);
    let shared = Arc::new(Shared {
        api,
        routes: Mutex::new(Vec::new()),
        next_id: AtomicU64::new(1),
        inbound,
        captured: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        queue_refused: AtomicBool::new(false),
    });
    let steerer = DivertSteerer { shared: shared.clone() };
    let (replies, queue) = std::sync::mpsc::sync_channel(REPLY_QUEUE);
    let injector = Injector { forward_send, network_send, use_network_send: false, out: Outgoing::default() };
    std::thread::Builder::new()
        .name("captun-inject".into())
        .spawn(move || injector.run(&shared.routes, &queue))
        .map_err(|e| CaptureError::Driver(format!("cannot start the thread that sends replies: {e}")))?;
    info!("packet capture (WinDivert) ready");
    Ok((DivertDevice { rx, replies, dropped: 0 }, steerer))
}

impl DivertSteerer {
    /// Starts taking the packets of `config`'s devices out of Windows'
    /// forwarding and into the engine. The network's adapter is looked for
    /// in `adapters`, a list read beforehand: reading them here could hold
    /// the caller, who holds the engine's lock, for seconds.
    pub fn steer(&self, config: &CaptureConfig, adapters: &[crate::iface::Interface]) -> Result<NetworkCapture, CaptureError> {
        let IpNet::V4(subnet) = config.subnet else {
            return Err(CaptureError::Steering("IPv6 device networks are not supported on Windows yet".into()));
        };
        let IpAddr::V4(gateway) = config.gateway else {
            return Err(CaptureError::Steering("the network's gateway must be an IPv4 address".into()));
        };
        // Known now if Windows had finished setting the adapter up when the
        // list was read; otherwise the first packet a device sends tells.
        let known = adapters.iter().find(|i| i.has_addr(&config.gateway)).map_or(0, |i| i.index);
        let if_index = Arc::new(AtomicU32::new(known));

        let filter = divert_filter(subnet, config.dns.then_some(gateway));
        let open = |filter: &str, layer| {
            ffi::Handle::open(&self.shared.api, filter, layer, ffi::FLAG_RECV_ONLY)
                .map(Arc::new)
                .map_err(|e| CaptureError::Driver(e.to_string()))
        };
        let handles = vec![
            open(&filter, ffi::LAYER_NETWORK_FORWARD)?,
            open(&format!("inbound and {filter}"), ffi::LAYER_NETWORK)?,
        ];
        for handle in &handles {
            self.raise_queue(handle);
        }

        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        lock(&self.shared.routes).push(Route { id, subnet, gateway, if_index: if_index.clone() });
        let threads = handles
            .iter()
            .enumerate()
            .map(|(i, handle)| {
                let (handle, shared) = (handle.clone(), self.shared.clone());
                // Packets arriving at the local inbound layer carry the adapter
                // they came in on; forward-layer ones carry the way out instead.
                let learn = (i == 1).then(|| if_index.clone());
                std::thread::Builder::new()
                    .name("captun-capture".into())
                    .spawn(move || receive(&handle, &shared, learn.as_deref()))
                    .map_err(|e| CaptureError::Driver(format!("cannot start a capture thread: {e}")))
            })
            .collect::<Result<Vec<_>, _>>();
        // Built first so a failure below still gives the network back.
        let mut capture = NetworkCapture { shared: self.shared.clone(), id, handles, threads: Vec::new() };
        capture.threads = threads?;
        // Without these the devices' traffic leaks past the engine, so a
        // failure here is a failure to capture (and the kill switch cuts off).
        for (filter, layer, what) in sharing_copies_filters(subnet, gateway, own_ttl()) {
            let (handle, thread) = self.swallow(&filter, layer, what).map_err(|e| {
                CaptureError::Driver(format!("cannot stop Windows' sharing from sending copies of the devices' traffic: {e}"))
            })?;
            capture.handles.push(handle);
            capture.threads.push(thread);
        }
        let if_index = if_index.load(Ordering::Relaxed);
        info!(%subnet, if_index, dns = config.dns, "capturing the network's traffic for the engine");
        Ok(capture)
    }

    /// Lets the driver hold more of a capture handle's packets, so a burst
    /// that comes while the handle's thread is busy waits for it instead of
    /// being lost. The driver's own smaller queue still works, so a refusal is
    /// only said, once.
    fn raise_queue(&self, handle: &ffi::Handle) {
        let length = handle.set_param(ffi::PARAM_QUEUE_LENGTH, DRIVER_QUEUE_LENGTH);
        let size = handle.set_param(ffi::PARAM_QUEUE_SIZE, DRIVER_QUEUE_SIZE);
        if let Err(e) = length.and(size)
            && !self.shared.queue_refused.swap(true, Ordering::Relaxed)
        {
            warn!("the packet driver kept its smaller queue, so bursts of traffic may lose packets: {e}");
        }
    }

    /// Takes the packets matching `filter` ahead of everything else and drops
    /// them, counting and describing the first few.
    fn swallow(&self, filter: &str, layer: i32, what: &'static str) -> io::Result<(Arc<ffi::Handle>, JoinHandle<()>)> {
        let handle = Arc::new(ffi::Handle::open_with(&self.shared.api, filter, layer, SHARING_COPIES_PRIORITY, ffi::FLAG_RECV_ONLY)?);
        let taken = handle.clone();
        let thread = std::thread::Builder::new().name("captun-guard".into()).spawn(move || {
            let mut inbox = Inbox::new();
            let mut dropped = 0u64;
            while let Ok(batch) = inbox.recv(&taken) {
                for (packet, _) in batch {
                    dropped += 1;
                    if dropped <= 10 || dropped.is_power_of_two() {
                        info!(dropped, "dropped a copy Windows' sharing {what} by itself: {}", describe(packet));
                    }
                }
            }
        })?;
        Ok((handle, thread))
    }

    /// Packets taken from devices since the capture opened.
    pub fn captured_packets(&self) -> u64 {
        self.shared.captured.load(Ordering::Relaxed)
    }

    /// Of those, the packets dropped because the engine had fallen behind and
    /// its queue was full.
    pub fn dropped_packets(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

/// Above the drop rules and the capture, so Windows' copies go before
/// anything else sees them. The engine's own replies, sent from priority 0,
/// never reach handles this high.
const SHARING_COPIES_PRIORITY: i16 = 3000;

/// What Windows' own sharing (ICS) does with the devices' packets besides
/// the capture: its NAT driver takes them too, sends translated copies out
/// itself (from this computer's address, with the device's TTL minus two),
/// and passes the servers' answers back to the devices, which then hear two
/// servers and reset the engine's connections. Its packets are ones another
/// driver injected ("impostors").
///
/// At the forward layer, where the copies arrive, every impostor bound for a
/// single address is dropped, whatever its TTL: a device may start at any
/// TTL, and this computer's own packets never cross that layer. At the
/// network layer the impostors dropped are those going to the devices and
/// those leaving with a TTL other than `own_ttl`, this computer's own, so its
/// own traffic, which other software (a VPN client, a security suite) may
/// inject again there, keeps going.
///
/// What Windows sends from the network's own address (its DHCP answers,
/// NetBIOS) can look injected too, and so can its multicast (discovery, sent
/// with a TTL of 1 to 4): both are left alone. Virtual machines that reach
/// the internet through Windows' own sharing (WSL, Docker Desktop, Hyper-V's
/// Default Switch) look the same as the copies, so while a network is
/// captured they may lose the internet.
pub(crate) fn sharing_copies_filters(subnet: Ipv4Net, gateway: Ipv4Addr, own_ttl: u8) -> [(String, i32, &'static str); 2] {
    let (first, last) = (subnet.network(), subnet.broadcast());
    let devices = |field: &str| format!("({field} >= {first} and {field} <= {last})");
    // Not multicast or broadcast to everyone. The devices' own addresses are
    // below this too.
    let one_address = format!("ip.DstAddr < {}", Ipv4Addr::new(224, 0, 0, 0));
    [
        (
            format!("impostor and ip and ip.SrcAddr != {gateway} and ({} or {one_address})", devices("ip.SrcAddr")),
            ffi::LAYER_NETWORK_FORWARD,
            "forwarded",
        ),
        (
            format!(
                "impostor and ip and outbound and ip.SrcAddr != {gateway} and ({} or (ip.TTL != {own_ttl} and {one_address}))",
                devices("ip.DstAddr")
            ),
            ffi::LAYER_NETWORK,
            "sent",
        ),
    ]
}

/// The TTL Windows gives this computer's own IPv4 packets, as a new socket
/// reports it: 128 unless the system was set to another.
fn own_ttl() -> u8 {
    std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.ttl())
        .ok()
        .and_then(|ttl| u8::try_from(ttl).ok())
        .filter(|&ttl| ttl > 0)
        .unwrap_or(WINDOWS_DEFAULT_TTL)
}

/// Windows' own default TTL, for when a socket cannot say.
const WINDOWS_DEFAULT_TTL: u8 = 128;

/// One line about a packet: protocol, addresses, ports, TCP flags and TTL.
fn describe(packet: &[u8]) -> String {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return format!("{} bytes, not IPv4", packet.len());
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let ports = packet.get(ihl..ihl + 4).map(|p| (u16::from_be_bytes([p[0], p[1]]), u16::from_be_bytes([p[2], p[3]])));
    let (proto, ports) = match (packet[9], ports) {
        (6, Some((s, d))) => {
            let flags = packet.get(ihl + 13).copied().unwrap_or(0);
            let named: String = [(0x02, 'S'), (0x10, 'A'), (0x08, 'P'), (0x01, 'F'), (0x04, 'R')]
                .iter()
                .filter_map(|&(bit, c)| (flags & bit != 0).then_some(c))
                .collect();
            (format!("tcp [{named}]"), format!(":{s} > {dst}:{d}"))
        }
        (17, Some((s, d))) => ("udp".to_owned(), format!(":{s} > {dst}:{d}")),
        (p, _) => (format!("protocol {p}"), format!(" > {dst}")),
    };
    format!("{proto} {src}{ports} ttl={} len={}", packet[8], packet.len())
}

/// Hands one handle's captured packets to the engine, a batch per driver call.
/// With `learn`, it also records the adapter the packets came in on. If the
/// engine is gone the thread stops but the handle stays open, so the network's
/// packets are still taken from Windows and dropped rather than sent out
/// directly.
fn receive(handle: &ffi::Handle, shared: &Shared, learn: Option<&AtomicU32>) {
    let mut inbox = Inbox::new();
    loop {
        match inbox.recv(handle) {
            Ok(batch) => {
                for (packet, addr) in batch {
                    shared.captured.fetch_add(1, Ordering::Relaxed);
                    let if_index = addr.if_index();
                    if let Some(learn) = learn
                        && !addr.is_outbound()
                        && if_index != 0
                        && learn.load(Ordering::Relaxed) != if_index
                        && learn.swap(if_index, Ordering::Relaxed) != if_index
                    {
                        info!(if_index, "the devices' adapter is known from their packets");
                    }
                    if !hand_on(&shared.inbound, &shared.dropped, packet) {
                        return;
                    }
                }
            }
            // Shutdown (the network stopped being captured) also lands here,
            // as ERROR_NO_DATA; anything else means the capture broke.
            Err(e) => {
                if e.raw_os_error() == Some(232) {
                    debug!("capture thread ends: {e}");
                } else {
                    warn!("packet capture stopped taking the devices' packets: {e}");
                }
                return;
            }
        }
    }
}

/// Hands one captured packet to the engine. A full queue drops it, as a
/// congested link would, and counts it, said at powers of two. False once the
/// engine is gone.
fn hand_on(inbound: &mpsc::Sender<Vec<u8>>, dropped: &AtomicU64, packet: &[u8]) -> bool {
    // A place first, so a dropped packet is never copied.
    match inbound.try_reserve() {
        Ok(place) => {
            place.send(packet.to_vec());
            true
        }
        Err(mpsc::error::TrySendError::Full(())) => {
            let dropped = dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                info!(dropped, "packets from the devices dropped: Captun's routing is falling behind");
            }
            true
        }
        Err(mpsc::error::TrySendError::Closed(())) => false,
    }
}

/// One network being captured. Dropping it gives the network back to Windows.
pub struct NetworkCapture {
    shared: Arc<Shared>,
    id: u64,
    handles: Vec<Arc<ffi::Handle>>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for NetworkCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkCapture").field("id", &self.id).finish_non_exhaustive()
    }
}

impl Drop for NetworkCapture {
    fn drop(&mut self) {
        lock(&self.shared.routes).retain(|r| r.id != self.id);
        for handle in &self.handles {
            handle.shutdown();
        }
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                warn!("a capture thread panicked");
            }
        }
    }
}

/// Where a [`DropRule`] looks at packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layer {
    /// Packets to and from this computer.
    Local,
    /// Packets Windows forwards for others.
    Forward,
}

/// Ahead of the engine's capture (priority 0), so what a rule refuses never
/// reaches the engine, and what it lets through still does.
const DROP_PRIORITY: i16 = 1000;

/// Silently drops the packets that match a filter for as long as it lives.
pub(crate) struct DropRule {
    _handle: ffi::Handle,
}

impl std::fmt::Debug for DropRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropRule").finish_non_exhaustive()
    }
}

/// Starts dropping packets that match `filter` at `layer`. Needs
/// administrator rights.
pub(crate) fn drop_rule(filter: &str, layer: Layer) -> io::Result<DropRule> {
    let api = load_api().map_err(|e| match e {
        LoadError::Untrusted(why) => io::Error::other(format!(
            "other programs on this computer can change Captun's files; reinstall Captun for all users ({why})"
        )),
        LoadError::Failed(e) => e,
    })?;
    let layer = match layer {
        Layer::Local => ffi::LAYER_NETWORK,
        Layer::Forward => ffi::LAYER_NETWORK_FORWARD,
    };
    let handle = ffi::Handle::open_with(&api, filter, layer, DROP_PRIORITY, ffi::FLAG_DROP)?;
    Ok(DropRule { _handle: handle })
}

/// WinDivert 2.2's C API, loaded from WinDivert.dll at run time.
#[allow(unsafe_code)]
mod ffi {
    use std::{
        ffi::{CString, c_void},
        io,
        path::Path,
        sync::Arc,
    };

    use libloading::Library;

    pub(super) const LAYER_NETWORK: i32 = 0;
    pub(super) const LAYER_NETWORK_FORWARD: i32 = 1;
    pub(super) const FLAG_DROP: u64 = 0x0002;
    pub(super) const FLAG_RECV_ONLY: u64 = 0x0004;
    pub(super) const FLAG_SEND_ONLY: u64 = 0x0008;
    /// `WINDIVERT_BATCH_MAX`: the most packets one call takes or sends.
    pub(super) const BATCH_MAX: usize = 255;
    /// `WINDIVERT_MTU_MAX`: the largest packet the driver captures.
    pub(super) const MTU_MAX: usize = 40 + 0xffff;
    /// `WINDIVERT_PARAM_QUEUE_LENGTH` and `_SIZE`: how many captured packets,
    /// and how many bytes of them, a handle's queue holds.
    pub(super) const PARAM_QUEUE_LENGTH: i32 = 0;
    pub(super) const PARAM_QUEUE_SIZE: i32 = 2;
    const SHUTDOWN_BOTH: i32 = 0x3;
    const INVALID_HANDLE: isize = -1;
    /// Bit position of `Outbound` in the address's flag word (after Layer:8,
    /// Event:8, Sniffed:1).
    const OUTBOUND_BIT: u32 = 17;

    /// `WINDIVERT_ADDRESS`: 80 bytes, the network-layer data first in the union.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct Address {
        timestamp: i64,
        flags: u32,
        reserved: u32,
        data: [u8; 64],
    }

    const _: () = assert!(std::mem::size_of::<Address>() == 80);
    /// An address's size, as WinDivert counts address buffers (in bytes).
    const ADDRESS_LEN: u32 = std::mem::size_of::<Address>() as u32;

    impl Address {
        /// A blank address, for the driver to fill in.
        pub(super) fn zeroed() -> Self {
            Self { timestamp: 0, flags: 0, reserved: 0, data: [0; 64] }
        }

        /// An outbound packet at `layer`, leaving through interface `if_index`.
        pub(super) fn outbound(layer: i32, if_index: u32) -> Self {
            let mut addr = Self::zeroed();
            addr.flags = (layer as u32 & 0xff) | (1 << OUTBOUND_BIT);
            addr.data[..4].copy_from_slice(&if_index.to_ne_bytes());
            addr
        }

        /// Moves the address to `layer`, for a handle there to send.
        pub(super) fn set_layer(&mut self, layer: i32) {
            self.flags = (self.flags & !0xff) | (layer as u32 & 0xff);
        }

        /// The interface the packet arrived on (inbound) or leaves by (outbound).
        pub(super) fn if_index(&self) -> u32 {
            u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
        }

        pub(super) fn is_outbound(&self) -> bool {
            self.flags & (1 << OUTBOUND_BIT) != 0
        }

        #[cfg(test)]
        pub(super) fn layer(&self) -> i32 {
            (self.flags & 0xff) as i32
        }

        /// Whether the address marks the IP, TCP and UDP checksums as right.
        #[cfg(test)]
        pub(super) fn checksums_marked(&self) -> [bool; 3] {
            [21, 22, 23].map(|bit| self.flags & (1 << bit) != 0)
        }
    }

    type OpenFn = unsafe extern "C" fn(*const std::ffi::c_char, i32, i16, u64) -> isize;
    type RecvExFn = unsafe extern "C" fn(isize, *mut c_void, u32, *mut u32, u64, *mut Address, *mut u32, *mut c_void) -> i32;
    type SendExFn = unsafe extern "C" fn(isize, *const c_void, u32, *mut u32, u64, *const Address, u32, *mut c_void) -> i32;
    type SetParamFn = unsafe extern "C" fn(isize, i32, u64) -> i32;
    type ShutdownFn = unsafe extern "C" fn(isize, i32) -> i32;
    type CloseFn = unsafe extern "C" fn(isize) -> i32;
    type ChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

    pub(super) struct Api {
        open: OpenFn,
        recv_ex: RecvExFn,
        send_ex: SendExFn,
        set_param: SetParamFn,
        shutdown: ShutdownFn,
        close: CloseFn,
        checksums: ChecksumsFn,
        /// Keeps the DLL, and with it the function pointers above, loaded.
        _library: Library,
    }

    impl Api {
        /// Loads WinDivert.dll by full path from `dir` (never the DLL search
        /// path), next to which WinDivert64.sys must also be.
        pub(super) fn load(dir: &Path) -> io::Result<Self> {
            let path = dir.join("WinDivert.dll");
            if !dir.join("WinDivert64.sys").is_file() || !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("WinDivert is missing from {}; reinstall Captun", dir.display()),
                ));
            }
            // SAFETY: loading the DLL runs its initialisation, which only sets
            // up the library; it comes from the service's own folder.
            let library = unsafe { Library::new(&path) }
                .map_err(|e| io::Error::other(format!("cannot load {}: {e}", path.display())))?;
            let symbol = |name: &[u8]| io::Error::other(format!("WinDivert.dll lacks {}", String::from_utf8_lossy(name)));
            // SAFETY: each symbol is looked up by its exported name and given
            // the exact signature windivert.h (2.2) declares for it; the
            // pointers stay valid while `_library` keeps the DLL loaded.
            unsafe {
                Ok(Self {
                    open: *library.get::<OpenFn>(b"WinDivertOpen\0").map_err(|_| symbol(b"WinDivertOpen"))?,
                    recv_ex: *library.get::<RecvExFn>(b"WinDivertRecvEx\0").map_err(|_| symbol(b"WinDivertRecvEx"))?,
                    send_ex: *library.get::<SendExFn>(b"WinDivertSendEx\0").map_err(|_| symbol(b"WinDivertSendEx"))?,
                    set_param: *library
                        .get::<SetParamFn>(b"WinDivertSetParam\0")
                        .map_err(|_| symbol(b"WinDivertSetParam"))?,
                    shutdown: *library
                        .get::<ShutdownFn>(b"WinDivertShutdown\0")
                        .map_err(|_| symbol(b"WinDivertShutdown"))?,
                    close: *library.get::<CloseFn>(b"WinDivertClose\0").map_err(|_| symbol(b"WinDivertClose"))?,
                    checksums: *library
                        .get::<ChecksumsFn>(b"WinDivertHelperCalcChecksums\0")
                        .map_err(|_| symbol(b"WinDivertHelperCalcChecksums"))?,
                    _library: library,
                })
            }
        }

        /// Fixes `packet`'s checksums in place and marks in `addr` the ones it
        /// fixed.
        pub(super) fn fix_checksums(&self, packet: &mut [u8], addr: &mut Address) {
            let Ok(size) = u32::try_from(packet.len()) else { return };
            // SAFETY: `packet` and `addr` are live and writable for the call;
            // the helper rewrites the checksum fields in place.
            unsafe { (self.checksums)(packet.as_mut_ptr().cast(), size, addr, 0) };
        }
    }

    /// An open WinDivert handle; closed on drop.
    pub(super) struct Handle {
        raw: isize,
        api: Arc<Api>,
    }

    /// What the common failures to open mean, in words that say what to do.
    fn open_error(e: io::Error) -> io::Error {
        let why = match e.raw_os_error() {
            Some(2) => "the WinDivert driver file is missing next to the service; reinstall Captun",
            Some(5) => "packet capture needs administrator rights",
            Some(87) => "the capture filter was rejected",
            Some(577) => "Windows refused the WinDivert driver's signature",
            Some(654) => "an older WinDivert driver is still loaded; restart Windows",
            Some(1275) => "Windows or security software blocked the WinDivert driver",
            Some(1753) => "the Windows Base Filtering Engine service is not running",
            _ => return io::Error::other(format!("cannot start packet capture: {e}")),
        };
        io::Error::other(format!("cannot start packet capture: {why}"))
    }

    impl Handle {
        pub(super) fn open(api: &Arc<Api>, filter: &str, layer: i32, flags: u64) -> io::Result<Self> {
            Self::open_with(api, filter, layer, 0, flags)
        }

        /// Opens a handle at `priority`: higher priorities see packets first.
        pub(super) fn open_with(api: &Arc<Api>, filter: &str, layer: i32, priority: i16, flags: u64) -> io::Result<Self> {
            let filter = CString::new(filter).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            // SAFETY: `filter` is NUL-terminated and outlives the call; the
            // other arguments are plain values.
            let raw = unsafe { (api.open)(filter.as_ptr(), layer, priority, flags) };
            if raw == INVALID_HANDLE {
                return Err(open_error(io::Error::last_os_error()));
            }
            Ok(Self { raw, api: api.clone() })
        }

        /// The DLL's functions the handle was opened with.
        pub(super) fn api(&self) -> &Api {
            &self.api
        }

        /// Blocks until the driver has captured packets, then takes as many as
        /// are waiting, up to a batch: written back to back into `buf`, with
        /// an address each into `addrs`. Gives the bytes and the packets
        /// taken. A packet that does not fit after others waits for the next
        /// call.
        pub(super) fn recv_batch(&self, buf: &mut [u8], addrs: &mut [Address]) -> io::Result<(usize, usize)> {
            let size = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            let room = addrs.len().min(BATCH_MAX);
            // In bytes, both ways; the driver refuses none or more than a batch.
            let mut addr_len = room as u32 * ADDRESS_LEN;
            let mut len = 0u32;
            // SAFETY: `buf` is writable for `size` bytes and `addrs` for
            // `addr_len` bytes, and `len` and `addr_len` are live locals
            // WinDivert writes into. Without an OVERLAPPED the call returns
            // only once the driver is done with all of them.
            let ok = unsafe {
                (self.api.recv_ex)(
                    self.raw,
                    buf.as_mut_ptr().cast(),
                    size,
                    &mut len,
                    0,
                    addrs.as_mut_ptr(),
                    &mut addr_len,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let packets = (addr_len / ADDRESS_LEN) as usize;
            Ok(((len as usize).min(buf.len()), packets.min(room)))
        }

        /// Injects a batch as each packet's address describes: `packets` back
        /// to back, each as long as its header says, with an address each in
        /// `addrs`, at most [`BATCH_MAX`]. An error can come after some went
        /// out: the driver goes on past a packet it cannot inject and reports
        /// the last failure.
        pub(super) fn send_batch(&self, packets: &[u8], addrs: &[Address]) -> io::Result<()> {
            if addrs.is_empty() {
                return Ok(());
            }
            if addrs.len() > BATCH_MAX {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many packets for one call"));
            }
            let size = u32::try_from(packets.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "batch too large"))?;
            let addr_len = addrs.len() as u32 * ADDRESS_LEN;
            let mut sent = 0u32;
            // SAFETY: WinDivert only reads `packets` (`size` bytes) and `addrs`
            // (`addr_len` bytes), and without an OVERLAPPED it is done with
            // them when the call returns.
            let ok = unsafe {
                (self.api.send_ex)(self.raw, packets.as_ptr().cast(), size, &mut sent, 0, addrs.as_ptr(), addr_len, std::ptr::null_mut())
            };
            if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }

        /// Sets one of the handle's driver parameters, such as
        /// [`PARAM_QUEUE_LENGTH`].
        pub(super) fn set_param(&self, param: i32, value: u64) -> io::Result<()> {
            // SAFETY: the handle is open until `drop`; the other arguments are
            // plain values.
            let ok = unsafe { (self.api.set_param)(self.raw, param, value) };
            if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }

        /// Wakes a thread blocked in [`recv_batch`](Self::recv_batch) with an
        /// error once the packets already captured are taken, so it can stop.
        pub(super) fn shutdown(&self) {
            // SAFETY: the handle is open until `drop`; shutting down from
            // another thread is what this call is for.
            unsafe { (self.api.shutdown)(self.raw, SHUTDOWN_BOTH) };
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from WinDivertOpen and is closed once.
            unsafe { (self.api.close)(self.raw) };
        }
    }

    /// Compiles `filter` with WinDivert's own compiler, which needs neither the
    /// driver nor administrator rights. Tests use it to check filters.
    #[cfg(test)]
    pub(crate) fn compile(dll: &Path, filter: &str, layer: i32) -> Result<(), String> {
        type CompileFn = unsafe extern "C" fn(
            *const std::ffi::c_char,
            i32,
            *mut std::ffi::c_char,
            u32,
            *mut *const std::ffi::c_char,
            *mut u32,
        ) -> i32;
        // SAFETY: loading the DLL runs only its own initialisation.
        let library = unsafe { Library::new(dll) }.map_err(|e| e.to_string())?;
        // SAFETY: the symbol has this signature in windivert.h (2.2).
        let compile = unsafe { library.get::<CompileFn>(b"WinDivertHelperCompileFilter\0") }.map_err(|e| e.to_string())?;
        let text = CString::new(filter).map_err(|e| e.to_string())?;
        let mut error: *const std::ffi::c_char = std::ptr::null();
        let mut position = 0u32;
        // SAFETY: `text` is NUL-terminated; no object buffer is passed (null,
        // length 0), and `error`/`position` are live locals it writes into.
        let ok = unsafe { compile(text.as_ptr(), layer, std::ptr::null_mut(), 0, &mut error, &mut position) };
        if ok != 0 {
            return Ok(());
        }
        let why = if error.is_null() {
            "rejected".to_owned()
        } else {
            // SAFETY: WinDivert returns a static NUL-terminated message.
            unsafe { std::ffi::CStr::from_ptr(error) }.to_string_lossy().into_owned()
        };
        Err(format!("{why} at {position}"))
    }

    /// Whether `filter` matches `packet` as seen at `layer`, arriving on (or,
    /// `outbound`, leaving by) interface `if_index`, by WinDivert's own
    /// evaluator. Tests use it to check what a filter does.
    #[cfg(test)]
    pub(crate) fn eval(dll: &Path, filter: &str, packet: &[u8], layer: i32, outbound: bool, if_index: u32) -> Result<bool, String> {
        eval_marked(dll, filter, packet, layer, outbound, if_index, false)
    }

    /// As [`eval`], for a packet another driver injected, which WinDivert
    /// marks as an impostor.
    #[cfg(test)]
    pub(crate) fn eval_injected(
        dll: &Path,
        filter: &str,
        packet: &[u8],
        layer: i32,
        outbound: bool,
        if_index: u32,
    ) -> Result<bool, String> {
        eval_marked(dll, filter, packet, layer, outbound, if_index, true)
    }

    #[cfg(test)]
    fn eval_marked(
        dll: &Path,
        filter: &str,
        packet: &[u8],
        layer: i32,
        outbound: bool,
        if_index: u32,
        impostor: bool,
    ) -> Result<bool, String> {
        type EvalFn = unsafe extern "C" fn(*const std::ffi::c_char, *const c_void, u32, *const Address) -> i32;
        // SAFETY: loading the DLL runs only its own initialisation.
        let library = unsafe { Library::new(dll) }.map_err(|e| e.to_string())?;
        // SAFETY: the symbol has this signature in windivert.h (2.2).
        let eval = unsafe { library.get::<EvalFn>(b"WinDivertHelperEvalFilter\0") }.map_err(|e| e.to_string())?;
        let text = CString::new(filter).map_err(|e| e.to_string())?;
        let mut addr = Address::outbound(layer, if_index);
        if !outbound {
            addr.flags &= !(1 << OUTBOUND_BIT);
        }
        // The driver marks IPv6 packets so; the evaluator reads the mark.
        const IPV6_BIT: u32 = 20;
        if packet.first().is_some_and(|b| b >> 4 == 6) {
            addr.flags |= 1 << IPV6_BIT;
        }
        // `Impostor`, after Loopback (bit 18): set on packets another driver
        // injected.
        const IMPOSTOR_BIT: u32 = 19;
        if impostor {
            addr.flags |= 1 << IMPOSTOR_BIT;
        }
        let len = u32::try_from(packet.len()).map_err(|e| e.to_string())?;
        // SAFETY: `text` is NUL-terminated, `packet` is readable for `len`
        // bytes and `addr` is a live, fully initialised address.
        Ok(unsafe { eval(text.as_ptr(), packet.as_ptr().cast(), len, &addr) } != 0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn addresses_mark_layer_direction_and_interface() {
            let addr = Address::outbound(LAYER_NETWORK_FORWARD, 0x0102_0304);
            assert_eq!(addr.flags & 0xff, 1, "layer");
            assert_ne!(addr.flags & (1 << OUTBOUND_BIT), 0, "outbound");
            assert_eq!(u32::from_ne_bytes([addr.data[0], addr.data[1], addr.data[2], addr.data[3]]), 0x0102_0304);
            assert_eq!((addr.if_index(), addr.is_outbound()), (0x0102_0304, true));
            assert!(!Address::zeroed().is_outbound(), "inbound");
            let mut moved = addr;
            moved.set_layer(LAYER_NETWORK);
            assert_eq!((moved.layer(), moved.if_index(), moved.is_outbound()), (LAYER_NETWORK, 0x0102_0304, true));
            assert_eq!(moved.flags & !0xff, addr.flags & !0xff, "only the layer moves");
        }

        #[test]
        fn a_missing_driver_is_reported_before_loading_anything() {
            let empty = std::env::temp_dir().join(format!("captun-no-windivert-{}", std::process::id()));
            std::fs::create_dir_all(&empty).unwrap();
            let err = Api::load(&empty).err().unwrap();
            assert!(err.to_string().contains("WinDivert is missing"), "{err}");
            std::fs::remove_dir_all(&empty).unwrap();
        }

        #[test]
        fn the_dll_has_every_function_used() {
            let Some(dir) = super::super::test_dir() else { return };
            if let Err(e) = Api::load(&dir) {
                panic!("{e}");
            }
        }
    }
}

/// The WinDivert.dll next to the build (`target/<profile>`), if there is one.
#[cfg(test)]
fn test_dll() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // Test binaries live in target/<profile>/deps.
    let dll = exe.parent()?.parent()?.join("WinDivert.dll");
    dll.is_file().then_some(dll)
}

/// The folder of the build's WinDivert.dll, if the driver file is beside it
/// too, so the API loads there as it does next to the service.
#[cfg(test)]
fn test_dir() -> Option<std::path::PathBuf> {
    let dir = test_dll()?.parent()?.to_path_buf();
    dir.join("WinDivert64.sys").is_file().then_some(dir)
}

#[cfg(test)]
fn layer_number(layer: Layer) -> i32 {
    match layer {
        Layer::Local => ffi::LAYER_NETWORK,
        Layer::Forward => ffi::LAYER_NETWORK_FORWARD,
    }
}

/// Checks `filter` with WinDivert's compiler. `None` when the build has no
/// WinDivert.dll to check with.
#[cfg(test)]
pub(crate) fn check_filter(filter: &str, layer: Layer) -> Option<Result<(), String>> {
    Some(ffi::compile(&test_dll()?, filter, layer_number(layer)))
}

/// Whether `filter` matches `packet` seen at `layer` (inbound unless
/// `outbound`) on interface `if_index`, by WinDivert's own evaluator. `None`
/// when the build has no WinDivert.dll to check with.
#[cfg(test)]
pub(crate) fn filter_matches(filter: &str, packet: &[u8], layer: Layer, outbound: bool, if_index: u32) -> Option<bool> {
    let dll = test_dll()?;
    ffi::compile(&dll, filter, layer_number(layer)).unwrap_or_else(|e| panic!("{e}: {filter}"));
    Some(ffi::eval(&dll, filter, packet, layer_number(layer), outbound, if_index).unwrap_or_else(|e| panic!("{e}")))
}

/// As [`filter_matches`], for a packet another driver injected (an
/// impostor).
#[cfg(test)]
fn injected_matches(filter: &str, packet: &[u8], layer: Layer, outbound: bool, if_index: u32) -> Option<bool> {
    let dll = test_dll()?;
    ffi::compile(&dll, filter, layer_number(layer)).unwrap_or_else(|e| panic!("{e}: {filter}"));
    Some(ffi::eval_injected(&dll, filter, packet, layer_number(layer), outbound, if_index).unwrap_or_else(|e| panic!("{e}")))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    /// A TCP-over-IPv4 packet of `len` bytes from `src` to `dst`, with a bare
    /// 20-byte TCP header.
    fn ipv4(src: [u8; 4], dst: [u8; 4], len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        if len >= 40 {
            p[32] = 0x50;
        }
        p
    }

    /// An IPv6 packet carrying `payload` bytes.
    fn ipv6(payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&u16::try_from(payload).unwrap().to_be_bytes());
        p
    }

    #[test]
    fn packets_the_engine_has_no_room_for_are_counted() {
        let (inbound, mut engine) = mpsc::channel(2);
        let dropped = AtomicU64::new(0);
        let packet = ipv4([192, 168, 137, 2], [1, 1, 1, 1], 40);
        for _ in 0..5 {
            assert!(hand_on(&inbound, &dropped, &packet), "the engine is still there");
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 3, "two fit in the queue");
        assert_eq!(engine.try_recv().unwrap(), packet);
        assert!(hand_on(&inbound, &dropped, &packet), "room again");
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
        drop(engine);
        assert!(!hand_on(&inbound, &dropped, &packet), "the engine is gone: the thread stops");
        assert_eq!(dropped.load(Ordering::Relaxed), 3, "not counted as a full queue");
    }

    /// A folder in the temporary folder holding stand-ins for WinDivert's
    /// files, and a junction to it, both removed when dropped.
    struct LinkedFolder {
        folder: std::path::PathBuf,
        junction: std::path::PathBuf,
    }

    impl LinkedFolder {
        fn new(name: &str) -> Option<Self> {
            let base = std::env::temp_dir().join(format!("captun-{name}-{}", std::process::id()));
            let (folder, junction) = (base.join("real"), base.join("link"));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&folder).ok()?;
            for file in ["WinDivert.dll", "WinDivert64.sys"] {
                std::fs::write(folder.join(file), b"not a program").ok()?;
            }
            let made = std::process::Command::new(crate::tools::system_tool(r"System32\cmd.exe"))
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&junction)
                .arg(&folder)
                .output()
                .is_ok_and(|out| out.status.success());
            let linked = Self { folder, junction };
            made.then_some(linked)
        }
    }

    impl Drop for LinkedFolder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.junction);
            if let Some(base) = self.folder.parent() {
                let _ = std::fs::remove_dir_all(base);
            }
        }
    }

    #[test]
    fn windivert_is_loaded_from_where_a_link_really_leads() {
        let Some(linked) = LinkedFolder::new("divert-link") else { return };
        let real = crate::trust::real_path(&linked.folder).unwrap();
        // The folder the files are loaded from is the link's target, written
        // plainly, not the link the service may have been started through.
        let dir = windivert_folder(&linked.junction, false).unwrap();
        assert_eq!(dir, real);
        assert!(!dir.to_string_lossy().starts_with(r"\\?\"), "{}", dir.display());
        // And that real folder, which the user owns, is refused.
        match windivert_folder(&linked.junction, true) {
            Err(LoadError::Untrusted(why)) => {
                let said = why.to_string();
                assert!(!said.contains(&*linked.junction.to_string_lossy()), "{said}");
            }
            other => panic!("a folder the user owns passed: {other:?}"),
        }
    }

    #[test]
    fn a_service_folder_that_cannot_be_found_is_said_plainly() {
        let gone = std::env::temp_dir().join(format!("captun-no-such-folder-{}", std::process::id()));
        match windivert_folder(&gone, true) {
            Err(LoadError::Failed(e)) => assert!(e.to_string().starts_with("cannot find the service's folder"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    /// The hotspot, its adapter known, and a cable network whose adapter is not.
    fn routes() -> Vec<Route> {
        let route = |id, subnet: &str, if_index| Route {
            id,
            subnet: subnet.parse().unwrap(),
            gateway: subnet.parse::<Ipv4Net>().unwrap().hosts().next().unwrap(),
            if_index: Arc::new(AtomicU32::new(if_index)),
        };
        vec![route(1, "192.168.137.0/24", 7), route(2, "10.42.0.0/24", 0)]
    }

    /// Each address's layer, direction and interface.
    fn described(batch: &Batch) -> Vec<(i32, bool, u32)> {
        batch.addrs.iter().map(|a| (a.layer(), a.is_outbound(), a.if_index())).collect()
    }

    /// A batch a stand-in handle was given: the handle's name, each packet's
    /// address, and the packets back to back.
    type Sent = (&'static str, Vec<(i32, bool, u32)>, Vec<u8>);

    /// A stand-in for a handle that sends replies. It records each batch, and
    /// with `refuse` fails them all, as Windows can refuse forward-layer
    /// injection.
    struct FakeOutlet {
        name: &'static str,
        refuse: bool,
        sent: Rc<RefCell<Vec<Sent>>>,
    }

    impl Outlet for FakeOutlet {
        fn fix_checksums(&self, _batch: &mut Batch) {}

        fn send(&self, batch: &Batch) -> io::Result<()> {
            // As with the driver's handle, an empty batch is no call.
            if batch.addrs.is_empty() {
                return Ok(());
            }
            self.sent.borrow_mut().push((self.name, described(batch), batch.data.clone()));
            if self.refuse { Err(io::Error::other("refused")) } else { Ok(()) }
        }
    }

    /// Writes `packet` to the device as the engine does. The device never
    /// keeps a write waiting.
    fn write_reply(device: &mut DivertDevice, packet: &[u8]) -> io::Result<usize> {
        match Pin::new(device).poll_write(&mut Context::from_waker(std::task::Waker::noop()), packet) {
            Poll::Ready(written) => written,
            Poll::Pending => panic!("the write was kept waiting"),
        }
    }

    #[test]
    fn the_capture_filters_compile() {
        let subnet = "192.168.137.0/24".parse().unwrap();
        let filter = divert_filter(subnet, Some(Ipv4Addr::new(192, 168, 137, 1)));
        let Some(forward) = check_filter(&filter, Layer::Forward) else { return };
        assert_eq!(forward, Ok(()));
        assert_eq!(check_filter(&format!("inbound and {filter}"), Layer::Local), Some(Ok(())));
        assert!(matches!(check_filter("ip and (udp.DstPort == ", Layer::Local), Some(Err(_))), "the check itself works");
        for (filter, layer, what) in sharing_copies_filters(subnet, Ipv4Addr::new(192, 168, 137, 1), own_ttl()) {
            let layer = if layer == ffi::LAYER_NETWORK { Layer::Local } else { Layer::Forward };
            assert_eq!(check_filter(&filter, layer), Some(Ok(())), "{what}: {filter}");
        }
    }

    /// A TCP SYN from `src` to `dst`:443 that carries `ttl`.
    fn syn(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut p = ipv4(src, dst, 40);
        p[8] = ttl;
        p[20..22].copy_from_slice(&50_000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[33] = 0x02;
        p
    }

    /// Windows' sharing sends its copies of a device's packets from this
    /// computer's own address (192.168.1.2, say) with the device's TTL minus
    /// two: 62 from a phone, 126 from a Windows laptop, 253 from a device
    /// that starts at 255. At the forward layer each is dropped, whatever the
    /// TTL, as is what comes back for the devices.
    #[test]
    fn copies_of_the_devices_traffic_are_dropped_whatever_their_ttl() {
        let subnet = "192.168.137.0/24".parse().unwrap();
        let gateway = Ipv4Addr::new(192, 168, 137, 1);
        let [(forward, forward_layer, _), (sent, sent_layer, _)] = sharing_copies_filters(subnet, gateway, 128);
        assert_eq!((forward_layer, sent_layer), (ffi::LAYER_NETWORK_FORWARD, ffi::LAYER_NETWORK));
        let (uplink, server, device, hotspot) = ([192, 168, 8, 2], [142, 250, 1, 1], [192, 168, 137, 23], [192, 168, 137, 1]);
        if test_dll().is_none() {
            return;
        }
        let forwarded = |packet: &[u8]| injected_matches(&forward, packet, Layer::Forward, true, 7);

        for ttl in [30, 62, 126, 128, 253] {
            assert_eq!(forwarded(&syn(uplink, server, ttl)), Some(true), "a copy at TTL {ttl}");
        }
        assert_eq!(forwarded(&syn(server, device, 115)), Some(true), "an answer for a device");
        // Not copies: the device's own packet as Windows forwards it, what
        // this computer sends from its address on the network, discovery.
        assert_eq!(filter_matches(&forward, &syn(uplink, server, 126), Layer::Forward, true, 7), Some(false), "not injected");
        assert_eq!(forwarded(&syn(hotspot, device, 128)), Some(false), "from the hotspot's own address");
        assert_eq!(forwarded(&syn(uplink, [239, 255, 255, 250], 4)), Some(false), "multicast");

        // At the network layer, this computer's own traffic (TTL 128 here)
        // keeps going, even when other software injects it again.
        let sent_out = |packet: &[u8]| injected_matches(&sent, packet, Layer::Local, true, 7);
        assert_eq!(sent_out(&syn(uplink, server, 128)), Some(false), "this computer's own");
        assert_eq!(sent_out(&syn(uplink, server, 62)), Some(true), "a copy");
        assert_eq!(sent_out(&syn(server, device, 128)), Some(true), "an answer for a device");
        assert_eq!(sent_out(&syn(hotspot, device, 64)), Some(false), "from the hotspot's own address");
        assert_eq!(sent_out(&syn(uplink, [224, 0, 0, 251], 1)), Some(false), "multicast");
        assert_eq!(filter_matches(&sent, &syn(uplink, server, 62), Layer::Local, true, 7), Some(false), "not injected");
    }

    /// The network layer spares the TTL this computer itself uses, whatever
    /// it was set to, and only that.
    #[test]
    fn this_computers_own_ttl_is_the_one_spared() {
        let subnet = "192.168.137.0/24".parse().unwrap();
        let [_, (sent, ..)] = sharing_copies_filters(subnet, Ipv4Addr::new(192, 168, 137, 1), 65);
        assert!(sent.contains("ip.TTL != 65"), "{sent}");
        let sent_out = |ttl| injected_matches(&sent, &syn([192, 168, 8, 2], [142, 250, 1, 1], ttl), Layer::Local, true, 7);
        let Some(own) = sent_out(65) else { return };
        assert!(!own, "TTL 65 is this computer's own here");
        assert_eq!(sent_out(128), Some(true));
        assert_eq!(sent_out(64), Some(true));
    }

    #[test]
    fn this_computers_ttl_is_read_from_windows() {
        let ttl = own_ttl();
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        assert_eq!(u32::from(ttl), socket.ttl().unwrap());
    }

    #[test]
    fn packets_are_described_in_a_line() {
        let mut syn = vec![0u8; 40];
        syn[0] = 0x45;
        syn[8] = 63;
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[192, 168, 1, 100]);
        syn[16..20].copy_from_slice(&[142, 250, 1, 1]);
        syn[20..22].copy_from_slice(&50_000u16.to_be_bytes());
        syn[22..24].copy_from_slice(&443u16.to_be_bytes());
        syn[33] = 0x02;
        assert_eq!(describe(&syn), "tcp [S] 192.168.1.100:50000 > 142.250.1.1:443 ttl=63 len=40");
        assert_eq!(describe(&[0x60; 40]), "40 bytes, not IPv4");
    }

    #[test]
    fn replies_are_routed_by_their_destination() {
        let packet = {
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[16..20].copy_from_slice(&[192, 168, 137, 23]);
            p
        };
        assert_eq!(ipv4_destination(&packet), Some(Ipv4Addr::new(192, 168, 137, 23)));
        assert_eq!(ipv4_source(&packet), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(ipv4_destination(&[0x60; 40]), None, "IPv6 is not handled");
        assert_eq!(ipv4_destination(&[0x45; 10]), None, "too short");
    }

    #[test]
    fn a_received_batch_splits_by_each_packets_own_length() {
        let small = ipv4([192, 168, 137, 23], [142, 250, 1, 1], 40);
        let v6 = ipv6(20);
        let full = ipv4([192, 168, 137, 24], [1, 1, 1, 1], 1500);
        let mut with_options = ipv4([192, 168, 137, 25], [8, 8, 8, 8], 64);
        with_options[0] = 0x46;
        let batch = [&small[..], &v6, &full, &with_options].concat();
        assert_eq!(packets(&batch).collect::<Vec<_>>(), [&small[..], &v6, &full, &with_options]);
        assert_eq!(packets(&small).count(), 1, "a batch of one");
        assert_eq!(packets(&[]).count(), 0);
        assert_eq!(packets(&ipv6(0)).collect::<Vec<_>>(), [&ipv6(0)[..]], "an IPv6 header alone");
    }

    #[test]
    fn a_received_batch_ends_at_a_length_that_does_not_fit() {
        let first = ipv4([192, 168, 137, 23], [142, 250, 1, 1], 60);
        let second = ipv4([192, 168, 137, 23], [142, 250, 1, 1], 1500);
        let ends_after_first = |rest: &[u8]| {
            let batch = [&first[..], rest].concat();
            assert_eq!(packets(&batch).collect::<Vec<_>>(), [&first[..]], "{:02x?}", &rest[..rest.len().min(8)]);
        };
        ends_after_first(&second[..100]);
        ends_after_first(&ipv6(100)[..80]);
        ends_after_first(&[0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6]);
        let mut garbage = second.clone();
        for total in [0u16, 19] {
            garbage[2..4].copy_from_slice(&total.to_be_bytes());
            ends_after_first(&garbage);
        }
        garbage[2..4].copy_from_slice(&40u16.to_be_bytes());
        garbage[0] = 0x44;
        ends_after_first(&garbage);
        garbage[0] = 0x4f;
        ends_after_first(&garbage);
        for version in [0x05, 0x55, 0xf5] {
            garbage[0] = version;
            ends_after_first(&garbage);
        }
        ends_after_first(&ipv6(20)[..39]);
    }

    #[test]
    fn replies_are_packed_for_the_handle_that_sends_them() {
        let routes = routes();
        let from_server = ipv4([142, 250, 1, 1], [192, 168, 137, 23], 60);
        let from_this_computer = ipv4([192, 168, 137, 1], [192, 168, 137, 23], 70);
        let adapter_unknown = ipv4([1, 1, 1, 1], [10, 42, 0, 5], 50);
        let padded = [ipv4([142, 250, 1, 2], [192, 168, 137, 24], 40), vec![0xee; 6]].concat();
        let mut out = Outgoing::default();
        for reply in [&from_server, &from_this_computer, &adapter_unknown, &padded] {
            out.add(reply, &routes, true);
        }
        // Not delivered: for no captured network, not IPv4, shorter than it says.
        out.add(&ipv4([1, 1, 1, 1], [172, 16, 0, 9], 40), &routes, true);
        out.add(&ipv6(20), &routes, true);
        out.add(&from_server[..50], &routes, true);

        assert_eq!(out.forward.data, [&from_server[..], &padded[..40]].concat());
        assert_eq!(out.forward.ends, [60, 100]);
        let forwarded = (ffi::LAYER_NETWORK_FORWARD, true, 7);
        assert_eq!(described(&out.forward), [forwarded, forwarded], "one address per packet");
        assert_eq!(out.network.data, [&from_this_computer[..], &adapter_unknown].concat());
        assert_eq!(out.network.ends, [70, 120]);
        assert_eq!(described(&out.network), [(ffi::LAYER_NETWORK, true, 7), (ffi::LAYER_NETWORK, true, 0)]);

        // The adapter becomes known.
        routes[1].if_index.store(9, Ordering::Relaxed);
        out.clear();
        out.add(&adapter_unknown, &routes, true);
        assert_eq!((described(&out.forward), out.network.len()), (vec![(ffi::LAYER_NETWORK_FORWARD, true, 9)], 0));
    }

    #[test]
    fn once_forwarding_is_refused_every_reply_is_sent() {
        let routes = Mutex::new(routes());
        let sent = Rc::new(RefCell::new(Vec::new()));
        let handle = |name, refuse| FakeOutlet { name, refuse, sent: sent.clone() };
        let mut injector = Injector {
            forward_send: handle("forward", true),
            network_send: handle("network", false),
            use_network_send: false,
            out: Outgoing::default(),
        };
        let from_server = ipv4([142, 250, 1, 1], [192, 168, 137, 23], 60);
        let from_this_computer = ipv4([192, 168, 137, 1], [192, 168, 137, 23], 70);
        let (forwarded, as_sent) = ((ffi::LAYER_NETWORK_FORWARD, true, 7), (ffi::LAYER_NETWORK, true, 7));

        // Refused at the forward layer: that batch goes again, whole and once,
        // as sent, ahead of the replies that were to be sent anyway.
        injector.inject(&[from_server.clone(), from_this_computer.clone(), from_server.clone()], &routes);
        let twice = [&from_server[..], &from_server].concat();
        assert_eq!(
            sent.take(),
            [
                ("forward", vec![forwarded, forwarded], twice.clone()),
                ("network", vec![as_sent, as_sent], twice),
                ("network", vec![as_sent], from_this_computer.clone()),
            ]
        );
        assert!(injector.use_network_send);

        // From then on every reply is sent, and none is offered for forwarding.
        injector.inject(&[from_server.clone(), from_this_computer.clone()], &routes);
        assert_eq!(sent.take(), [("network", vec![as_sent, as_sent], [&from_server[..], &from_this_computer].concat())]);
    }

    #[test]
    fn writing_a_reply_only_queues_it() {
        let (_, rx) = mpsc::channel(1);
        let (replies, queue) = std::sync::mpsc::sync_channel(1);
        let mut device = DivertDevice { rx, replies, dropped: 0 };
        // On a thread of its own, so a write that waited for room would fail
        // the test instead of hanging it.
        let (done, written) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let lens = [write_reply(&mut device, &[1; 40]).unwrap(), write_reply(&mut device, &[2; 50]).unwrap()];
            done.send((lens, device)).unwrap();
        });
        let (lens, mut device) = written.recv_timeout(std::time::Duration::from_secs(10)).expect("a write waited for room");
        assert_eq!(lens, [40, 50]);
        assert_eq!(device.dropped, 1, "the second found the queue full and was dropped");
        assert_eq!(queue.try_iter().collect::<Vec<_>>(), [vec![1u8; 40]]);

        // The thread that sends replies has stopped.
        drop(queue);
        assert_eq!(write_reply(&mut device, &[3; 40]).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    /// The ones' complement sum IP checksums use, over `parts` in turn: 0 when
    /// the checksum inside them is right.
    fn checksum(parts: &[&[u8]]) -> u16 {
        let mut sum: u32 = parts
            .iter()
            .flat_map(|part| part.chunks(2))
            .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The header TCP and UDP checksums also cover: addresses, protocol, length.
    fn pseudo_header(packet: &[u8]) -> Vec<u8> {
        let len = u16::try_from(packet.len() - 20).unwrap();
        [&packet[12..20], &[0, packet[9]], &len.to_be_bytes()].concat()
    }

    #[test]
    fn each_reply_in_a_batch_gets_its_checksums() {
        let Some(dir) = test_dir() else { return };
        let api = ffi::Api::load(&dir).unwrap();
        let mut tcp = ipv4([142, 250, 1, 1], [192, 168, 137, 23], 46);
        tcp[20..24].copy_from_slice(&[0x01, 0xbb, 0xc3, 0x50]);
        tcp[40..].copy_from_slice(b"hello!");
        let mut udp = ipv4([192, 168, 137, 1], [192, 168, 137, 23], 37);
        udp[9] = 17;
        udp[20..26].copy_from_slice(&[0, 53, 0xd4, 0x31, 0, 17]);
        udp[28..].copy_from_slice(b"answer!!!");
        let mut batch = Batch::default();
        batch.push(&tcp, ffi::Address::outbound(ffi::LAYER_NETWORK_FORWARD, 7));
        batch.push(&udp, ffi::Address::outbound(ffi::LAYER_NETWORK, 7));
        batch.fix_checksums(&api);

        let (tcp, udp) = batch.data.split_at(46);
        assert_eq!(checksum(&[&tcp[..20]]), 0, "IPv4 header");
        assert_ne!(&tcp[36..38], [0, 0], "TCP checksum written");
        assert_eq!(checksum(&[&pseudo_header(tcp), &tcp[20..]]), 0, "TCP");
        assert_eq!(checksum(&[&udp[..20]]), 0, "IPv4 header");
        assert_eq!(checksum(&[&pseudo_header(udp), &udp[20..]]), 0, "UDP");
        assert_eq!(batch.addrs[0].checksums_marked(), [true, true, false]);
        assert_eq!(batch.addrs[1].checksums_marked(), [true, false, true]);
    }
}
