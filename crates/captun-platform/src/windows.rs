//! Windows Mobile Hotspot through the WinRT tethering API, the same switch as
//! Settings → Network → Mobile hotspot. Windows' own ICS does NAT and DHCP;
//! no driver or registry tinkering is involved.

use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use ipnet::Ipv4Net;
use captun_core::{
    MacAddr, ObservedClient,
    config::{HotspotConfig, WifiBand},
};
use windows::{
    Devices::WiFi::WiFiAdapter,
    Networking::{
        Connectivity::{NetworkAdapter, NetworkInformation},
        HostNameType,
        NetworkOperators::{
            NetworkOperatorTetheringManager, TetheringCapability, TetheringOperationStatus, TetheringOperationalState,
            TetheringWiFiBand,
        },
    },
    core::HSTRING,
};

use crate::{BackendState, HotspotBackend, HotspotError, PlatformNotes, StartOptions, hotspot::check_config, iface};

/// ICS serves the hotspot from this address unless its registry scope was edited.
const ICS_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 137, 1);
/// ICS's network around its gateway.
const ICS_PREFIX_LEN: u8 = 24;

/// The address ICS serves the hotspot from: its registry scope when someone
/// set one (people do, to move the hotspot off a network they already use),
/// else Windows' default.
fn ics_gateway() -> Ipv4Addr {
    gateway_from(registry::scope_address().as_deref())
}

/// The gateway an ICS scope value names, or the default when there is none
/// or it does not name one.
fn gateway_from(scope: Option<&str>) -> Ipv4Addr {
    scope
        .and_then(|text| text.trim().parse::<Ipv4Addr>().ok())
        .filter(|a| !(a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.is_loopback()))
        .unwrap_or(ICS_GATEWAY)
}

/// ICS's network around `gateway`.
fn ics_network(gateway: Ipv4Addr) -> Option<Ipv4Net> {
    Ipv4Net::new(gateway, ICS_PREFIX_LEN).ok().map(|net| net.trunc())
}

/// Reading ICS's settings from the registry.
#[allow(unsafe_code)]
mod registry {
    use std::ptr;

    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW},
    };

    /// ICS's `ScopeAddress`, as written, when it is set.
    pub(super) fn scope_address() -> Option<String> {
        let key: Vec<u16> =
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters".encode_utf16().chain([0]).collect();
        let value: Vec<u16> = "ScopeAddress".encode_utf16().chain([0]).collect();
        // An address is 15 characters at most; anything longer is not one.
        let mut buf = [0u16; 64];
        let mut size = u32::try_from(size_of_val(&buf)).ok()?;
        // SAFETY: `key` and `value` are NUL-terminated and outlive the call;
        // `buf` is live and writable for `size` bytes, and Windows writes no
        // more; the type is not asked for, so its pointer may be null.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        // `size` counts bytes, the closing NUL included.
        let text = buf.get(..(size as usize / 2).min(buf.len()))?;
        let end = text.iter().position(|&unit| unit == 0).unwrap_or(text.len());
        String::from_utf16(text.get(..end)?).ok()
    }
}

#[derive(Debug, Default)]
pub(crate) struct MobileHotspot;

impl MobileHotspot {
    pub(crate) fn new() -> Self {
        Self
    }
}

fn failed(context: &str, e: windows::core::Error) -> HotspotError {
    HotspotError::Failed(format!("{context}: {}", e.message()))
}

/// WinRT calls block (the async operations are awaited with `.get()`), so
/// they run on the blocking pool.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, HotspotError> + Send + 'static,
) -> Result<T, HotspotError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| HotspotError::Failed(format!("hotspot worker crashed: {e}")))?
}

/// HRESULT_FROM_WIN32(ERROR_NOT_FOUND): no adapter Windows can host an AP on.
const NO_CAPABLE_ADAPTER: u32 = 0x8007_0490;

/// The tethering manager for the internet connection, or for any connection
/// when there is no internet (Mobile hotspot always shares one). Failing here
/// means this way of hosting is unavailable, not that hosting is impossible.
fn manager() -> Result<NetworkOperatorTetheringManager, HotspotError> {
    let unavailable = |e: windows::core::Error| {
        if e.code().0 as u32 == NO_CAPABLE_ADAPTER {
            HotspotError::Unavailable("Windows found no adapter it can host a Mobile hotspot on".into())
        } else {
            HotspotError::Unavailable(format!("this connection cannot be shared as a Mobile hotspot ({})", e.message()))
        }
    };
    if let Ok(profile) = NetworkInformation::GetInternetConnectionProfile() {
        return NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile).map_err(unavailable);
    }
    let profiles = NetworkInformation::GetConnectionProfiles()
        .map_err(|e| HotspotError::Unavailable(format!("cannot list network connections ({})", e.message())))?;
    let mut last = None;
    for profile in &profiles {
        match NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile) {
            Ok(mgr) => return Ok(mgr),
            Err(e) => last = Some(e),
        }
    }
    Err(last.map(unavailable).unwrap_or_else(|| {
        HotspotError::Unavailable("Mobile hotspot needs a network connection to share, and there is none".into())
    }))
}

/// The tethering manager that hosts the Mobile hotspot on the Wi-Fi adapter
/// `wanted`, sharing the internet connection (or, without one, any
/// connection). Not hosting it there is a refusal, never a reason to try the
/// hosted network, which would pick an adapter of its own.
fn manager_on(wanted: &str) -> Result<NetworkOperatorTetheringManager, HotspotError> {
    let adapter = wifi_adapter(wanted)?;
    let refused = |e: windows::core::Error| {
        HotspotError::Failed(format!(
            "Windows cannot host its Mobile hotspot on the Wi-Fi adapter \"{wanted}\" ({}). Pick another adapter in the hotspot settings, or Automatic",
            e.message()
        ))
    };
    if let Ok(profile) = NetworkInformation::GetInternetConnectionProfile() {
        return NetworkOperatorTetheringManager::CreateFromConnectionProfileWithTargetAdapter(&profile, &adapter).map_err(refused);
    }
    let profiles = NetworkInformation::GetConnectionProfiles()
        .map_err(|e| HotspotError::Failed(format!("cannot list network connections ({})", e.message())))?;
    let mut last = None;
    for profile in &profiles {
        match NetworkOperatorTetheringManager::CreateFromConnectionProfileWithTargetAdapter(&profile, &adapter) {
            Ok(mgr) => return Ok(mgr),
            Err(e) => last = Some(e),
        }
    }
    Err(last.map(refused).unwrap_or_else(|| {
        HotspotError::Failed("Mobile hotspot needs a network connection to share, and there is none".into())
    }))
}

/// The Wi-Fi adapter `wanted` names (its name in the adapter list, or its
/// system name), as Windows' tethering API takes it.
fn wifi_adapter(wanted: &str) -> Result<NetworkAdapter, HotspotError> {
    let not_found = || {
        HotspotError::InvalidConfig(format!(
            "the Wi-Fi adapter \"{wanted}\" was not found: it may be turned off or unplugged. Turn it on, or pick another adapter (or Automatic) in the hotspot settings"
        ))
    };
    let id = iface::list()
        .into_iter()
        .find(|i| i.name.eq_ignore_ascii_case(wanted) || i.system_name.eq_ignore_ascii_case(wanted))
        .map(|i| i.system_name)
        .ok_or_else(not_found)?;
    let adapters = WiFiAdapter::FindAllAdaptersAsync()
        .and_then(|op| op.get())
        .map_err(|e| HotspotError::Failed(format!("cannot list the Wi-Fi adapters ({})", e.message())))?;
    for adapter in &adapters {
        let Ok(network) = adapter.NetworkAdapter() else { continue };
        if network.NetworkAdapterId().is_ok_and(|guid| same_guid(&guid, &id)) {
            return Ok(network);
        }
    }
    Err(not_found())
}

/// Whether `text` (`{GUID}` as the adapter list gives it, braces or not)
/// is `guid`.
fn same_guid(guid: &windows::core::GUID, text: &str) -> bool {
    let text = text.trim().trim_start_matches('{').trim_end_matches('}');
    format!("{guid:?}").eq_ignore_ascii_case(text)
}

/// Why Windows will not host a Mobile hotspot here, when it says so up front.
/// Without an internet connection there is nothing to ask about; starting
/// then fails with its own message.
pub(crate) fn hotspot_blocker() -> Option<&'static str> {
    let profile = NetworkInformation::GetInternetConnectionProfile().ok()?;
    let capability = NetworkOperatorTetheringManager::GetTetheringCapabilityFromConnectionProfile(&profile).ok()?;
    capability_blocker(capability)
}

fn capability_blocker(capability: TetheringCapability) -> Option<&'static str> {
    Some(match capability {
        TetheringCapability::Enabled => return None,
        TetheringCapability::DisabledByGroupPolicy => "Your organization's policy turns off Windows Mobile hotspot.",
        TetheringCapability::DisabledByHardwareLimitation => "Windows Mobile hotspot does not support this Wi-Fi adapter.",
        TetheringCapability::DisabledByOperator => "The mobile carrier does not allow sharing this connection.",
        TetheringCapability::DisabledBySku => "This edition of Windows does not include Mobile hotspot.",
        TetheringCapability::DisabledByRequiredAppNotInstalled => "Windows needs the carrier's app to share this connection.",
        _ => "Windows reports that Mobile hotspot is not available.",
    })
}

/// Start results that mean "not this way", so the fallback can try.
fn unavailable_status(status: TetheringOperationStatus) -> bool {
    matches!(
        status,
        TetheringOperationStatus::NetworkLimitedConnectivity
            | TetheringOperationStatus::EntitlementCheckTimeout
            | TetheringOperationStatus::EntitlementCheckFailure
            | TetheringOperationStatus::MobileBroadbandDeviceOff
    )
}

fn status_hint(status: TetheringOperationStatus) -> &'static str {
    match status {
        TetheringOperationStatus::WiFiDeviceOff => "Wi-Fi is turned off",
        TetheringOperationStatus::MobileBroadbandDeviceOff => "the mobile broadband device is off",
        TetheringOperationStatus::BluetoothDeviceOff => "Bluetooth is off",
        TetheringOperationStatus::EntitlementCheckTimeout | TetheringOperationStatus::EntitlementCheckFailure => {
            "the carrier does not allow tethering on this connection"
        }
        TetheringOperationStatus::OperationInProgress => "another hotspot operation is in progress",
        TetheringOperationStatus::NetworkLimitedConnectivity => "the shared connection has no internet access",
        TetheringOperationStatus::AlreadyOn => "the hotspot is already on",
        TetheringOperationStatus::RadioRestriction => "the Wi-Fi radio is restricted (airplane mode or policy)",
        TetheringOperationStatus::BandInterference => "the requested band conflicts with the current Wi-Fi connection",
        _ => "unknown reason",
    }
}

fn wifi_band(band: WifiBand) -> TetheringWiFiBand {
    match band {
        WifiBand::Auto => TetheringWiFiBand::Auto,
        WifiBand::Ghz2_4 => TetheringWiFiBand::TwoPointFourGigahertz,
        WifiBand::Ghz5 => TetheringWiFiBand::FiveGigahertz,
        WifiBand::Ghz6 => TetheringWiFiBand::SixGigahertz,
    }
}

fn snapshot(mgr: &NetworkOperatorTetheringManager) -> Result<BackendState, HotspotError> {
    let state = mgr.TetheringOperationalState().map_err(|e| failed("cannot read hotspot state", e))?;
    let running = state == TetheringOperationalState::On;
    let ssid = mgr.GetCurrentAccessPointConfiguration().and_then(|ap| ap.Ssid()).ok().map(|s| s.to_string());
    // The adapter list can be stale (it keeps the last good read while some
    // adapter confuses it); Windows' own host names never are. Without the
    // adapter the network is not captured, and its devices would go direct.
    let holding = |gateway: Ipv4Addr| {
        iface::find_by_addr(&IpAddr::V4(gateway)).map(|a| a.name).or_else(|| adapter_holding(gateway)).map(|a| (gateway, a))
    };
    // The registry's scope first; Windows' default after, in case this
    // Windows does not follow the scope for its hotspot.
    let scope = ics_gateway();
    let found = running.then(|| holding(scope).or_else(|| (scope != ICS_GATEWAY).then(|| holding(ICS_GATEWAY)).flatten())).flatten();
    let (gateway, adapter) = found.map_or((None, None), |(gateway, adapter)| (Some(IpAddr::V4(gateway)), Some(adapter)));
    Ok(BackendState {
        running,
        transitioning: state == TetheringOperationalState::InTransition,
        ssid,
        gateway,
        interface: adapter,
        max_clients: mgr.MaxClientCount().ok(),
    })
}

/// The id (`{GUID}`, the adapter's system name) of the adapter holding
/// `address`, from Windows' host names.
fn adapter_holding(address: Ipv4Addr) -> Option<String> {
    let wanted = address.to_string();
    for host in &NetworkInformation::GetHostNames().ok()? {
        if host.Type().ok() != Some(HostNameType::Ipv4) || host.CanonicalName().ok().map(|n| n.to_string()) != Some(wanted.clone()) {
            continue;
        }
        let id = host.IPInformation().and_then(|info| info.NetworkAdapter()).and_then(|a| a.NetworkAdapterId()).ok()?;
        return Some(format!("{{{id:?}}}"));
    }
    None
}

#[async_trait]
impl HotspotBackend for MobileHotspot {
    fn notes(&self) -> PlatformNotes {
        PlatformNotes {
            hotspot: true,
            band_selection: true,
            notes: vec![
                "Uses Windows Mobile hotspot, which shares one of this computer's connections.".into(),
                "The hotspot network is 192.168.137.0/24 and its DHCP is managed by Windows (no static leases).".into(),
                "Station-to-station isolation depends on the Wi-Fi driver and cannot be enforced by Captun.".into(),
            ],
        }
    }

    async fn start(&self, config: &HotspotConfig, _options: StartOptions) -> Result<BackendState, HotspotError> {
        check_config(config)?;
        let ssid = HSTRING::from(config.ssid.as_str());
        let passphrase = HSTRING::from(config.passphrase.expose());
        let band = config.band;
        let adapter = config.interface.clone().filter(|name| !name.trim().is_empty());
        blocking(move || {
            if let Some(why) = hotspot_blocker() {
                return Err(HotspotError::Unavailable(why.into()));
            }
            // An adapter of the user's choosing, or the one Windows picks.
            let mgr = match adapter.as_deref() {
                Some(name) => manager_on(name)?,
                None => manager()?,
            };
            let ap = mgr.GetCurrentAccessPointConfiguration().map_err(|e| failed("cannot read hotspot settings", e))?;
            ap.SetSsid(&ssid).map_err(|e| failed("cannot set SSID", e))?;
            ap.SetPassphrase(&passphrase).map_err(|e| failed("cannot set passphrase", e))?;
            match ap.IsBandSupported(wifi_band(band)) {
                Ok(true) => ap.SetBand(wifi_band(band)).map_err(|e| failed("cannot set band", e))?,
                Ok(false) => {
                    return Err(HotspotError::InvalidConfig(format!(
                        "this Wi-Fi adapter cannot host a hotspot on the {band:?} band"
                    )));
                }
                // Builds before Windows 10 2004 have no band API; "auto" is all they do.
                Err(_) if band == WifiBand::Auto => {}
                Err(e) => return Err(failed("band selection needs Windows 10 2004 or newer", e)),
            }

            // A running hotspot keeps its old settings until restarted.
            if mgr.TetheringOperationalState().ok() == Some(TetheringOperationalState::On) {
                mgr.StopTetheringAsync()
                    .and_then(|op| op.get())
                    .map_err(|e| failed("cannot restart hotspot", e))?;
            }
            mgr.ConfigureAccessPointAsync(&ap)
                .and_then(|op| op.get())
                .map_err(|e| failed("Windows rejected the hotspot settings", e))?;
            let result =
                mgr.StartTetheringAsync().and_then(|op| op.get()).map_err(|e| failed("cannot start hotspot", e))?;
            let status = result.Status().map_err(|e| failed("cannot read start result", e))?;
            if status != TetheringOperationStatus::Success {
                let detail = result.AdditionalErrorMessage().map(|m| m.to_string()).unwrap_or_default();
                let mut message = format!("Windows refused to start the hotspot: {}", status_hint(status));
                if !detail.is_empty() {
                    message.push_str(&format!(" ({detail})"));
                }
                return Err(if unavailable_status(status) {
                    HotspotError::Unavailable(message)
                } else {
                    HotspotError::Failed(message)
                });
            }
            snapshot(&mgr)
        })
        .await
    }

    async fn stop(&self) -> Result<(), HotspotError> {
        blocking(|| {
            let mgr = match manager() {
                Ok(mgr) => mgr,
                // Nothing Mobile hotspot could run on, so nothing to stop.
                Err(HotspotError::Unavailable(_)) => return Ok(()),
                Err(e) => return Err(e),
            };
            if mgr.TetheringOperationalState().ok() == Some(TetheringOperationalState::Off) {
                return Ok(());
            }
            let result =
                mgr.StopTetheringAsync().and_then(|op| op.get()).map_err(|e| failed("cannot stop hotspot", e))?;
            match result.Status() {
                Ok(TetheringOperationStatus::Success) => Ok(()),
                Ok(status) => Err(HotspotError::Failed(format!("cannot stop hotspot: {}", status_hint(status)))),
                Err(e) => Err(failed("cannot read stop result", e)),
            }
        })
        .await
    }

    async fn state(&self) -> Result<BackendState, HotspotError> {
        blocking(|| snapshot(&manager()?)).await
    }

    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
        blocking(|| {
            let mgr = manager()?;
            let list = mgr.GetTetheringClients().map_err(|e| failed("cannot list hotspot clients", e))?;
            let mut clients = Vec::new();
            for client in &list {
                let Ok(mac) = client.MacAddress().map(|m| m.to_string()) else { continue };
                let Ok(mac) = mac.parse::<MacAddr>() else { continue };
                let mut observed = ObservedClient { mac, addrs: Vec::new(), hostname: None };
                if let Ok(names) = client.HostNames() {
                    for name in &names {
                        let (Ok(kind), Ok(text)) = (name.Type(), name.CanonicalName()) else { continue };
                        let text = text.to_string();
                        if kind == HostNameType::Ipv4 || kind == HostNameType::Ipv6 {
                            if let Ok(ip) = text.parse() {
                                observed.addrs.push(ip);
                            }
                        } else if kind == HostNameType::DomainName && observed.hostname.is_none() {
                            observed.hostname = Some(text);
                        }
                    }
                }
                clients.push(observed);
            }
            Ok(clients)
        })
        .await
    }

    /// ICS's network, known before Windows gives the adapter its address:
    /// around the registry's scope, when someone set one.
    fn expected_network(&self) -> Option<Ipv4Net> {
        ics_network(ics_gateway())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_adapter_is_matched_by_its_guid_whatever_the_braces_and_case() {
        let guid = windows::core::GUID::from_u128(0x6b29fc40_ca47_1067_b31d_00dd010662da);
        assert!(same_guid(&guid, "{6B29FC40-CA47-1067-B31D-00DD010662DA}"));
        assert!(same_guid(&guid, "6b29fc40-ca47-1067-b31d-00dd010662da"));
        assert!(!same_guid(&guid, "{6B29FC40-CA47-1067-B31D-00DD010662DB}"));
        assert!(!same_guid(&guid, "Wi-Fi"));
    }

    #[test]
    fn the_mobile_hotspots_network_is_known_before_it_starts() {
        let net = MobileHotspot::new().expected_network().unwrap();
        assert_eq!(net.prefix_len(), 24);
        assert!(net.contains(&ics_gateway()));
        assert_eq!(ics_network(ICS_GATEWAY).unwrap().to_string(), "192.168.137.0/24");
    }

    #[test]
    fn an_edited_scope_moves_the_network() {
        assert_eq!(gateway_from(Some("10.5.7.1")), Ipv4Addr::new(10, 5, 7, 1));
        assert_eq!(gateway_from(Some(" 192.168.50.1 ")), Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(ics_network(gateway_from(Some("10.5.7.1"))).unwrap().to_string(), "10.5.7.0/24");
        // Missing, or not an address a gateway can have: Windows' default.
        for scope in [None, Some(""), Some("bogus"), Some("10.5.7"), Some("0.0.0.0"), Some("255.255.255.255"), Some("224.0.0.1"), Some("127.0.0.1")] {
            assert_eq!(gateway_from(scope), ICS_GATEWAY, "{scope:?}");
        }
    }

    #[test]
    fn the_scope_is_read_from_the_registry() {
        // Set on every Windows with ICS; when it is, it names an address.
        if let Some(scope) = registry::scope_address() {
            assert!(scope.parse::<Ipv4Addr>().is_ok(), "{scope:?}");
        }
    }
}
