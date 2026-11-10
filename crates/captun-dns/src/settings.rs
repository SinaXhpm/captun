use std::{collections::HashMap, net::IpAddr, sync::Arc};

use captun_core::{
    DomainPattern, DomainSet,
    config::{BlockResponse, DnsConfig},
};
use rustls::{ClientConfig, RootCertStore};

use crate::{
    DnsError,
    upstream::{TlsConfigs, Upstream},
};

/// The DNS part of the config, compiled for fast lookups. Swapped atomically
/// on hot reload via [`crate::DnsHandler::update_settings`].
#[derive(Debug)]
pub struct DnsSettings {
    pub(crate) blocklist: DomainSet,
    pub(crate) block_response: BlockResponse,
    /// First match wins, in config order.
    pub(crate) overrides: Vec<(DomainSet, Vec<IpAddr>)>,
    pub(crate) upstreams: HashMap<String, Arc<Upstream>>,
    pub(crate) cache_size: usize,
    pub(crate) min_ttl: u32,
    pub(crate) max_ttl: u32,
}

impl DnsSettings {
    /// Compiles the config, trusting the bundled Mozilla root store for
    /// DoT/DoH. A fixed bundle, rather than the OS store, gives the same
    /// behaviour on every platform and cannot be widened by a root that some
    /// other software installed on the host.
    pub fn from_config(cfg: &DnsConfig) -> Result<Self, DnsError> {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        Self::from_config_with_roots(cfg, roots)
    }

    /// Like [`DnsSettings::from_config`] with an explicit trust store (tests,
    /// or resolvers on a private CA).
    pub fn from_config_with_roots(cfg: &DnsConfig, roots: RootCertStore) -> Result<Self, DnsError> {
        let tls = tls_configs(roots)?;
        let upstreams = cfg
            .upstreams
            .iter()
            .map(|u| Ok((u.id.clone(), Arc::new(Upstream::from_config(u, &tls)?))))
            .collect::<Result<_, DnsError>>()?;
        Ok(Self {
            blocklist: cfg.blocklist.iter().cloned().collect(),
            block_response: cfg.block_response,
            overrides: cfg
                .overrides
                .iter()
                .map(|o| (std::iter::once::<DomainPattern>(o.domain.clone()).collect(), o.addrs.clone()))
                .collect(),
            upstreams,
            cache_size: cfg.cache_size,
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl,
        })
    }

    pub fn upstream(&self, id: &str) -> Option<&Arc<Upstream>> {
        self.upstreams.get(id)
    }

    pub(crate) fn override_for(&self, name: &str) -> Option<&[IpAddr]> {
        self.overrides.iter().find(|(set, _)| set.matches(name)).map(|(_, addrs)| addrs.as_slice())
    }
}

fn tls_configs(roots: RootCertStore) -> Result<TlsConfigs, DnsError> {
    // An explicit provider instead of the process default: other crates in
    // the final binary may enable a second provider, which would make
    // `ClientConfig::builder()` panic at runtime.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let base = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let dot = base.clone();
    let mut doh = base;
    // We speak HTTP/1.1 only; without ALPN a server might pick h2 for us.
    doh.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConfigs { dot: Arc::new(dot), doh: Arc::new(doh) })
}
