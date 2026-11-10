use std::{net::IpAddr, sync::Arc};

use captun_core::{EgressId, MacAddr, TargetAddr, config::Protocol};
use captun_outbound::Outbound;

/// A flow the engine is about to set up, as seen before it is dialed.
#[derive(Clone, Debug)]
pub struct FlowRequest<'a> {
    /// Hotspot-side source address of the flow.
    pub client_ip: IpAddr,
    pub protocol: Protocol,
    /// Where the client is trying to reach.
    pub destination: &'a TargetAddr,
    /// Destination name, when the engine learned it from the TLS SNI or the
    /// HTTP `Host` header. `None` for UDP and un-sniffable flows.
    pub domain: Option<&'a str>,
}

/// What the engine should do with a flow.
#[derive(Clone)]
pub enum FlowAction {
    /// Drop it without a word: denied, quarantined, or its egress cannot carry
    /// this traffic. The device's packets go unanswered.
    Drop,
    /// Refuse it out loud (a TCP reset, or "port unreachable" for UDP), so the
    /// device's apps give up at once.
    Reject,
    /// Relay it through `outbound`, applying the limits below.
    Forward(Forward),
}

#[derive(Clone, Debug)]
pub struct Forward {
    /// The station this flow belongs to, for traffic accounting; `None` when
    /// the source IP did not map to a known station.
    pub client: Option<MacAddr>,
    pub outbound: Arc<dyn Outbound>,
    /// Download / upload caps in kbit/s; `None` means unlimited.
    pub down_kbps: Option<u64>,
    pub up_kbps: Option<u64>,
}

impl std::fmt::Debug for FlowAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Drop => f.write_str("Drop"),
            Self::Reject => f.write_str("Reject"),
            Self::Forward(fwd) => f
                .debug_struct("Forward")
                .field("client", &fwd.client)
                .field("outbound", &fwd.outbound.id())
                .field("down_kbps", &fwd.down_kbps)
                .field("up_kbps", &fwd.up_kbps)
                .finish(),
        }
    }
}

/// Whose budget of connections and flows a source address draws on. The
/// engine's caps count per key, so a device is one budget whichever of its
/// addresses it uses, and addresses no listed device holds cannot take the
/// slots of the devices that are listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// A device on the device list, let in: a budget of its own.
    Device(MacAddr),
    /// An address with a budget of its own: what every address gets unless
    /// the dispatcher says otherwise.
    Address(IpAddr),
    /// An address no listed device holds: a device too new to be on the list
    /// yet, a waiting or blocked one, or a made-up address. All of them share
    /// one small budget.
    Unlisted,
}

/// Decides, per flow, whether and how it is relayed. Implemented by the daemon
/// over its policy engine, client registry and egress set.
pub trait Dispatcher: Send + Sync + 'static {
    /// Whether any active rule matches on domains. When false, the engine does
    /// not wait to sniff a name before dialing, so server-speaks-first flows
    /// are not delayed.
    fn needs_domain(&self) -> bool;

    fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction;

    /// Decides a flow as [`dispatch`](Self::dispatch) does, and names the
    /// device it belongs to whatever the decision, so a reset of that device
    /// ([`FlowControl::reset_devices`](crate::FlowControl::reset_devices))
    /// ends it. A refused flow too: letting a device in then ends the
    /// refusals it is still being given. The engine calls this, not
    /// `dispatch`. By default, the device a forwarded flow is counted
    /// against, and none for a refused one.
    fn dispatch_device(&self, request: &FlowRequest<'_>) -> (FlowAction, Option<MacAddr>) {
        let action = self.dispatch(request);
        let device = match &action {
            FlowAction::Forward(forward) => forward.client,
            FlowAction::Drop | FlowAction::Reject => None,
        };
        (action, device)
    }

    /// Whether an open flow, forwarded through `outbound` for `device` (as
    /// [`dispatch_device`](Self::dispatch_device) named it), may go on under
    /// the rules in force now. Asked of every open flow after
    /// [`FlowControl::recheck_all`](crate::FlowControl::recheck_all): false
    /// ends it. True only when the flow would still be let through the same
    /// outbound. It is not a new connection, so it counts no rule hits.
    /// Asked by thousands of flows at once, so it must answer from memory.
    /// By default every flow may go on.
    fn still_allowed(&self, _request: &FlowRequest<'_>, _device: Option<MacAddr>, _outbound: &EgressId) -> bool {
        true
    }

    /// Whose budget a new connection or flow from `ip` draws on. Asked when one
    /// opens (a SYN, or a datagram the engine has no flow for), and once a
    /// second for each one still counted as [`SourceKey::Unlisted`], so it
    /// moves to its device's own budget once the device is listed. Asked on
    /// the task that reads every device's packets, so it must answer from
    /// memory and never block. By default every address is a budget of its
    /// own.
    fn source_key(&self, ip: IpAddr) -> SourceKey {
        SourceKey::Address(ip)
    }
}
