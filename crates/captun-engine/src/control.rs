//! Ending open flows when settings change, so a change applies to connections
//! already open, not only to new ones. A change to one device ends only that
//! device's flows; a change for everyone ends every flow. Devices reconnect
//! and their new connections are decided again under the new settings.
//!
//! Rules, time windows and the device limit are checked again instead: every
//! open flow asks the dispatcher whether it may go on, and only those it no
//! longer allows end.

use std::{collections::HashMap, future::Future, io, sync::Arc};

use captun_core::MacAddr;
use tokio::sync::watch;

/// Devices whose last reset is remembered one by one, since the last reset of
/// every flow. Past it, a reset of devices ends every flow instead: more
/// flows end than needed, never fewer.
const MAX_DEVICE_MARKS: usize = 4096;

/// The resets so far. It only ever grows, so a flow that sees the latest
/// value has seen every reset that concerns it, however many came at once: a
/// watch keeps only its latest value.
#[derive(Debug, Default)]
struct Resets {
    /// Counts the resets; a flow remembers the count it started at.
    generation: u64,
    /// The count at the last reset of every flow.
    all: u64,
    /// The count at each device's last reset. A reset of every flow covers
    /// them all, so it clears them.
    devices: HashMap<MacAddr, u64>,
}

impl Resets {
    /// Whether a flow started at `started` of `device` has been reset since.
    fn reach(&self, started: u64, device: Option<MacAddr>) -> bool {
        self.all > started || device.and_then(|device| self.devices.get(&device)).is_some_and(|&at| at > started)
    }

    fn next(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.generation
    }
}

/// Ends open flows when settings change, and has them checked against the
/// rules again. Clones share one state: the daemon keeps one, every flow the
/// engine and the proxy inbound start watches it.
#[derive(Clone, Debug)]
pub struct FlowControl {
    resets: Arc<watch::Sender<Resets>>,
    /// Counts the times the rules were checked again; only its changes matter.
    rechecks: Arc<watch::Sender<u64>>,
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowControl {
    pub fn new() -> Self {
        Self { resets: Arc::new(watch::channel(Resets::default()).0), rechecks: Arc::new(watch::channel(0).0) }
    }

    /// Ends every flow started before this call.
    pub fn reset_all(&self) {
        self.resets.send_modify(|resets| {
            resets.all = resets.next();
            resets.devices.clear();
        });
    }

    /// Ends the flows of `devices` started before this call. Other devices'
    /// flows go on.
    pub fn reset_devices(&self, devices: &[MacAddr]) {
        if devices.is_empty() {
            return;
        }
        self.resets.send_modify(|resets| {
            let at = resets.next();
            for &device in devices {
                resets.devices.insert(device, at);
            }
            if resets.devices.len() > MAX_DEVICE_MARKS {
                resets.all = at;
                resets.devices.clear();
            }
        });
    }

    /// Asks every open flow whether the rules in force now still let it go on
    /// ([`Dispatcher::still_allowed`](crate::Dispatcher::still_allowed)), and
    /// ends those they no longer do. Flows the rules refused end at once, so
    /// their next packet is decided again.
    pub fn recheck_all(&self) {
        self.rechecks.send_modify(|count| *count = count.wrapping_add(1));
    }

    /// The times the rules were checked again: it changes at each
    /// [`recheck_all`](Self::recheck_all).
    pub(crate) fn rechecks(&self) -> watch::Receiver<u64> {
        self.rechecks.subscribe()
    }

    /// A new flow's watch. Taken when the flow starts, before it is decided,
    /// so neither a reset nor a recheck between its decision and its watch is
    /// missed.
    pub(crate) fn watch(&self) -> FlowWatch {
        let mut resets = self.resets.subscribe();
        // The count of the value just marked seen, so a reset at this moment
        // is either before the flow or seen by it, never lost between.
        let started = resets.borrow_and_update().generation;
        FlowWatch { resets, rechecks: self.rechecks(), started, device: None }
    }
}

/// What ends one flow early: a reset that reaches it, or a recheck the
/// dispatcher no longer allows it through.
#[derive(Debug)]
pub(crate) struct FlowWatch {
    resets: watch::Receiver<Resets>,
    rechecks: watch::Receiver<u64>,
    started: u64,
    /// The flow's device, once its decision named one.
    device: Option<MacAddr>,
}

impl FlowWatch {
    /// The flow's device is known: from now on a reset of that device ends
    /// it too. Fails when that device was reset since the flow started, which
    /// the flow could not see before it knew its device.
    pub(crate) fn set_device(&mut self, device: Option<MacAddr>) -> io::Result<()> {
        self.device = device;
        if self.resets.borrow().reach(self.started, device) { Err(reset_error()) } else { Ok(()) }
    }

    /// Runs `flow` until it ends or a reset reaches the flow.
    pub(crate) async fn until_reset<T>(&mut self, flow: impl Future<Output = T>) -> io::Result<T> {
        let Self { resets, started, device, .. } = self;
        tokio::select! {
            output = flow => Ok(output),
            error = reset(resets, *started, *device) => Err(error),
        }
    }

    /// Runs `flow` until it ends, a reset reaches the flow, or the rules are
    /// checked again and `allowed` says it may not go on.
    pub(crate) async fn guard<T>(
        &mut self,
        flow: impl Future<Output = io::Result<T>>,
        allowed: impl Fn() -> bool,
    ) -> io::Result<T> {
        let Self { resets, rechecks, started, device } = self;
        let disallowed = async {
            loop {
                changed(rechecks).await;
                if !allowed() {
                    return io::Error::new(io::ErrorKind::ConnectionAborted, "ended so the rules in force now apply");
                }
            }
        };
        tokio::select! {
            result = flow => result,
            error = reset(resets, *started, *device) => Err(error),
            error = disallowed => Err(error),
        }
    }

    /// Runs `flow` until it ends, a reset reaches the flow, or the rules are
    /// checked again: for a refused flow, whose next packet is then decided
    /// again. `None` when cut short.
    pub(crate) async fn until_recheck<T>(&mut self, flow: impl Future<Output = T>) -> Option<T> {
        let Self { resets, rechecks, started, device } = self;
        tokio::select! {
            output = flow => Some(output),
            _ = reset(resets, *started, *device) => None,
            () = changed(rechecks) => None,
        }
    }
}

fn reset_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "ended so new settings apply")
}

/// Waits for a reset that reaches a flow started at `started` of `device`.
async fn reset(resets: &mut watch::Receiver<Resets>, started: u64, device: Option<MacAddr>) -> io::Error {
    loop {
        changed(resets).await;
        if resets.borrow_and_update().reach(started, device) {
            return reset_error();
        }
    }
}

/// Waits for the next change. The control being gone never happens while
/// its owner runs; the flow is then let be.
async fn changed<T>(receiver: &mut watch::Receiver<T>) {
    if receiver.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use super::*;

    const A: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0xa]);
    const B: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 0xb]);

    /// A flow of `device` that runs until something ends it.
    fn flow_of(control: &FlowControl, device: Option<MacAddr>) -> tokio::task::JoinHandle<io::Result<()>> {
        let mut watch = control.watch();
        tokio::spawn(async move {
            watch.set_device(device)?;
            watch.until_reset(std::future::pending::<()>()).await
        })
    }

    async fn ended(flow: tokio::task::JoinHandle<io::Result<()>>) -> io::Error {
        let result = tokio::time::timeout(Duration::from_secs(1), flow).await.expect("the flow went on").unwrap();
        result.expect_err("the flow ended on its own")
    }

    /// A flow that never ends on its own.
    fn forever() -> impl Future<Output = io::Result<()>> {
        std::future::pending()
    }

    /// Lets the spawned flows run up to their waits.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn reset_ends_running_flows_but_not_later_ones() {
        let control = FlowControl::new();
        let running = flow_of(&control, None);
        settle().await;
        control.reset_all();
        assert_eq!(ended(running).await.kind(), io::ErrorKind::ConnectionAborted);

        // A flow started after the reset is not affected by it.
        let later = control.watch().until_reset(async {}).await;
        assert!(later.is_ok());
    }

    #[tokio::test]
    async fn a_device_reset_ends_only_that_devices_flows() {
        let control = FlowControl::new();
        let (a, b, unknown) = (flow_of(&control, Some(A)), flow_of(&control, Some(B)), flow_of(&control, None));
        settle().await;
        control.reset_devices(&[A]);
        assert_eq!(ended(a).await.kind(), io::ErrorKind::ConnectionAborted);
        settle().await;
        assert!(!b.is_finished(), "another device's flow ended");
        assert!(!unknown.is_finished(), "a flow of no known device ended");

        // A flow of the device started after its reset goes on.
        let mut later = control.watch();
        assert!(later.set_device(Some(A)).is_ok());
    }

    /// Two resets of different devices, one right after the other, before
    /// any flow runs: the second must not hide the first.
    #[tokio::test]
    async fn two_quick_resets_of_different_devices_both_take_effect() {
        let control = FlowControl::new();
        let third = MacAddr::new([2; 6]);
        let (a, b, c) = (flow_of(&control, Some(A)), flow_of(&control, Some(B)), flow_of(&control, Some(third)));
        settle().await;
        control.reset_devices(&[A]);
        control.reset_devices(&[B]);
        ended(a).await;
        ended(b).await;
        settle().await;
        assert!(!c.is_finished(), "a third device's flow ended");
    }

    /// The device is known only once the flow is decided. A reset of it
    /// while the flow was still being looked at (its name sniffed) ends it
    /// as soon as it is known.
    #[tokio::test]
    async fn a_flow_whose_device_is_learned_after_its_reset_still_ends() {
        let control = FlowControl::new();
        let mut watch = control.watch();
        let sniffing = watch.until_reset(async {
            control.reset_devices(&[A]);
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        assert!(sniffing.await.is_ok(), "a device reset ended a flow of no known device yet");
        assert_eq!(watch.set_device(Some(A)).unwrap_err().kind(), io::ErrorKind::ConnectionAborted);

        // Another device's flow in the same moment goes on.
        let mut other = control.watch();
        control.reset_devices(&[A]);
        assert!(other.set_device(Some(B)).is_ok());
    }

    #[tokio::test]
    async fn reset_all_still_ends_everything() {
        let control = FlowControl::new();
        let flows = [flow_of(&control, Some(A)), flow_of(&control, Some(B)), flow_of(&control, None)];
        settle().await;
        control.reset_devices(&[A]);
        control.reset_all();
        for flow in flows {
            ended(flow).await;
        }
        // It covers every device's reset before it, so it forgets them.
        assert!(control.resets.borrow().devices.is_empty());
    }

    /// Past the devices it remembers one by one, a reset of devices ends
    /// every flow rather than miss one.
    #[tokio::test]
    async fn too_many_device_resets_end_every_flow() {
        let control = FlowControl::new();
        let other = flow_of(&control, Some(B));
        settle().await;
        let many: Vec<MacAddr> = (0..=MAX_DEVICE_MARKS as u32)
            .map(|i| MacAddr::new([0x06, 0, 0, (i >> 16) as u8, (i >> 8) as u8, i as u8]))
            .collect();
        control.reset_devices(&many);
        ended(other).await;
        assert!(control.resets.borrow().devices.is_empty());
    }

    #[tokio::test]
    async fn a_recheck_ends_a_flow_only_when_it_is_no_longer_allowed() {
        let control = FlowControl::new();
        let allowed = Arc::new(AtomicBool::new(true));
        let mut watch = control.watch();
        let flow = tokio::spawn({
            let allowed = allowed.clone();
            async move { watch.guard(forever(), || allowed.load(Ordering::SeqCst)).await }
        });
        settle().await;
        control.recheck_all();
        settle().await;
        assert!(!flow.is_finished(), "a flow still allowed ended");

        allowed.store(false, Ordering::SeqCst);
        control.recheck_all();
        assert_eq!(ended(flow).await.kind(), io::ErrorKind::ConnectionAborted);
    }

    /// A recheck between the flow's watch and its decision is not missed.
    #[tokio::test]
    async fn a_recheck_before_the_decision_is_not_missed() {
        let control = FlowControl::new();
        let mut watch = control.watch();
        control.recheck_all();
        let result = tokio::time::timeout(Duration::from_secs(1), watch.guard(forever(), || false)).await;
        assert!(result.expect("the recheck was missed").is_err());
    }

    #[tokio::test]
    async fn a_refused_flow_ends_at_the_first_recheck_or_its_devices_reset() {
        let control = FlowControl::new();
        let mut watch = control.watch();
        let held = tokio::spawn(async move { watch.until_recheck(std::future::pending::<()>()).await });
        settle().await;
        control.recheck_all();
        assert!(tokio::time::timeout(Duration::from_secs(1), held).await.unwrap().unwrap().is_none());

        let mut watch = control.watch();
        let held = tokio::spawn(async move {
            watch.set_device(Some(A)).unwrap();
            watch.until_recheck(std::future::pending::<()>()).await
        });
        settle().await;
        control.reset_devices(&[A]);
        assert!(tokio::time::timeout(Duration::from_secs(1), held).await.unwrap().unwrap().is_none());
    }

    /// Flows outlive a control that is gone.
    #[tokio::test]
    async fn flows_go_on_when_the_control_is_gone() {
        let control = FlowControl::new();
        let mut watch = control.watch();
        drop(control);
        let result = tokio::time::timeout(Duration::from_millis(50), watch.guard(forever(), || false)).await;
        assert!(result.is_err(), "the flow ended");
    }
}
