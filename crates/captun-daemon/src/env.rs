use captun_core::EgressId;
use captun_outbound::{InterfaceBinding, OutboundEnv, XrayEndpoint};
use captun_platform::iface::Interface;
use captun_xray::Sidecar;

/// Live host facts for building egresses.
#[derive(Debug)]
pub(crate) struct HostEnv<'a> {
    pub(crate) xray: &'a Sidecar,
    /// The network adapters, read before the build: a read can take seconds
    /// on Windows, which must not happen on an async thread or under the
    /// build's lock.
    pub(crate) interfaces: &'a [Interface],
}

impl OutboundEnv for HostEnv<'_> {
    fn interface(&self, name: &str) -> Option<InterfaceBinding> {
        captun_platform::iface::binding_in(self.interfaces, name)
    }

    fn xray_endpoint(&self, id: &EgressId) -> Result<XrayEndpoint, String> {
        self.xray.endpoint(id)
    }
}

#[cfg(test)]
mod tests {
    use captun_core::InterfaceKind;

    use super::*;

    #[tokio::test]
    async fn outbounds_tied_to_an_adapter_find_it_in_the_list_given() {
        let xray = Sidecar::start(None, None, || {});
        let wifi = Interface {
            index: 7,
            name: "Wi-Fi".into(),
            system_name: "{wifi}".into(),
            description: None,
            kind: InterfaceKind::Wifi,
            physical: true,
            mac: None,
            ipv4: vec!["192.168.1.20".parse().unwrap()],
            ipv6: Vec::new(),
            up: true,
            loopback: false,
            has_gateway: true,
            gateway: None,
            default_route: true,
            speed_mbps: None,
        };
        let interfaces = [wifi];
        let env = HostEnv { xray: &xray, interfaces: &interfaces };
        let binding = env.interface("wi-fi").unwrap();
        assert_eq!((binding.index, binding.ipv4), (7, Some("192.168.1.20".parse().unwrap())));
        assert!(env.interface("Ethernet").is_none(), "only what the list holds");
        assert!(HostEnv { xray: &xray, interfaces: &[] }.interface("Wi-Fi").is_none());
    }
}
