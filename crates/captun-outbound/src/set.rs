use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use captun_core::{EgressConfig, EgressId, EgressKind, Secret, TargetAddr, UdpPolicy};

use crate::{Block, Credentials, Direct, HttpConnect, InterfaceBinding, Outbound, Socks5, Unavailable};

/// Validation already rejects cycles; this only guards against a config that
/// skipped validation.
const MAX_CHAIN_DEPTH: usize = 8;

/// Where the Xray sidecar exposes one egress: a loopback SOCKS5 inbound with
/// per-run random credentials.
#[derive(Clone, Debug)]
pub struct XrayEndpoint {
    pub addr: SocketAddr,
    pub auth: Option<Credentials>,
}

/// Host facts needed while building egresses, supplied by the platform layer.
pub trait OutboundEnv {
    fn interface(&self, name: &str) -> Option<InterfaceBinding>;
    /// Where the sidecar serves egress `id`, or why it does not right now.
    fn xray_endpoint(&self, id: &EgressId) -> Result<XrayEndpoint, String>;
}

/// Every configured egress, ready to use. Rebuilt whenever the config, the
/// interface list or the sidecar state changes.
#[derive(Debug, Default, Clone)]
pub struct OutboundSet {
    outbounds: HashMap<EgressId, Arc<dyn Outbound>>,
    udp: HashMap<EgressId, UdpPolicy>,
}

impl OutboundSet {
    /// Problems that depend on the host's current state, such as a missing
    /// interface or a stopped sidecar, produce an [`Unavailable`] egress rather
    /// than an error, so one broken egress never takes the others down.
    pub fn build(egresses: &[EgressConfig], env: &dyn OutboundEnv) -> Self {
        let configs: HashMap<&EgressId, &EgressConfig> = egresses.iter().map(|e| (&e.id, e)).collect();
        let mut outbounds = HashMap::with_capacity(egresses.len());
        for egress in egresses {
            build_one(&egress.id, &configs, env, &mut outbounds, 0);
        }
        let udp = egresses.iter().map(|e| (e.id.clone(), e.udp.clone())).collect();
        Self { outbounds, udp }
    }

    pub fn get(&self, id: &EgressId) -> Option<&Arc<dyn Outbound>> {
        self.outbounds.get(id)
    }

    /// The outbound that carries UDP for egress `id`, honouring its UDP
    /// policy. `None` means UDP is blocked for it.
    pub fn for_udp(&self, id: &EgressId) -> Option<&Arc<dyn Outbound>> {
        match self.udp.get(id)? {
            UdpPolicy::Native => self.outbounds.get(id),
            UdpPolicy::Block => None,
            UdpPolicy::Via(other) => self.outbounds.get(other),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&EgressId, &Arc<dyn Outbound>)> {
        self.outbounds.iter()
    }
}

fn credentials(username: &Option<String>, password: &Option<Secret>) -> Option<Credentials> {
    username
        .as_ref()
        .map(|username| Credentials { username: username.clone(), password: password.clone().unwrap_or_default() })
}

fn build_one(
    id: &EgressId,
    configs: &HashMap<&EgressId, &EgressConfig>,
    env: &dyn OutboundEnv,
    built: &mut HashMap<EgressId, Arc<dyn Outbound>>,
    depth: usize,
) -> Arc<dyn Outbound> {
    if let Some(existing) = built.get(id) {
        return existing.clone();
    }
    let unavailable = |reason: String| -> Arc<dyn Outbound> { Arc::new(Unavailable::new(id.clone(), reason)) };

    let outbound: Arc<dyn Outbound> = match configs.get(id) {
        None => unavailable("not configured".into()),
        Some(_) if depth > MAX_CHAIN_DEPTH => unavailable("proxy chain is too long or loops".into()),
        Some(config) => {
            // A proxy's own server is the service's connection, not a
            // device's: its name is looked up apart from devices' names.
            let mut dialer = |via: &Option<EgressId>| -> Arc<dyn Outbound> {
                match via {
                    Some(via) => build_one(via, configs, env, built, depth + 1),
                    None => Arc::new(Direct::for_service(id.clone())),
                }
            };
            match &config.kind {
                EgressKind::Direct { interface: None } => Arc::new(Direct::new(id.clone(), None)),
                EgressKind::Direct { interface: Some(name) } => match env.interface(name) {
                    Some(binding) => Arc::new(Direct::new(id.clone(), Some(binding))),
                    None => unavailable(format!("interface {name:?} not found or down")),
                },
                EgressKind::Socks5 { server, username, password, via } => {
                    let dialer = dialer(via);
                    Arc::new(Socks5::new(id.clone(), server.clone(), credentials(username, password), dialer))
                }
                EgressKind::Http { server, username, password, tls, via } => {
                    let dialer = dialer(via);
                    Arc::new(
                        HttpConnect::new(id.clone(), server.clone(), credentials(username, password), dialer)
                            .with_tls(*tls),
                    )
                }
                EgressKind::Xray { .. } => match env.xray_endpoint(id) {
                    Ok(endpoint) => Arc::new(Socks5::new(
                        id.clone(),
                        TargetAddr::Ip(endpoint.addr),
                        endpoint.auth,
                        Arc::new(Direct::for_service(id.clone())),
                    )),
                    Err(reason) => unavailable(reason),
                },
                EgressKind::Block => Arc::new(Block::new(id.clone())),
            }
        }
    };
    built.insert(id.clone(), outbound.clone());
    outbound
}
