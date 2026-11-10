//! The Wi-Fi hosted network (wlanapi): the soft access point many drivers
//! offer where Windows Mobile hotspot is unavailable, for instance with no
//! connection to share or an older driver. Windows gives it no addresses or
//! internet, so Captun runs that part itself ([`OwnNetwork`]).
//!
//! The access point is held with `WlanHostedNetworkStartUsing`, so Windows
//! takes it down by itself if the service exits.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use ipnet::Ipv4Net;
use captun_core::{MacAddr, ObservedClient, config::HotspotConfig};

use crate::{
    BackendState, HotspotBackend, HotspotError, PlatformNotes, StartOptions,
    hotspot::check_config,
    iface,
    own_net::{self, GATEWAY, OwnNetwork, StationReader},
};

/// The driver's default peer limit, used when no device limit is set.
const DEFAULT_MAX_PEERS: u32 = 100;

struct Session {
    wlan: ffi::Wlan,
    network: OwnNetwork,
    ssid: String,
    interface: String,
    max_peers: u32,
}

#[derive(Default)]
pub(crate) struct HostedNetwork {
    session: Mutex<Option<Session>>,
    /// Captun's routing engine carries the traffic, so the system shares none.
    engine_routed: AtomicBool,
}

impl std::fmt::Debug for HostedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedNetwork").finish_non_exhaustive()
    }
}

impl HostedNetwork {
    fn take(&self) -> Option<Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, the form Windows names adapters by.
fn guid_string(g: &windows_sys::core::GUID) -> String {
    let d = g.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// Sets up and starts the access point; returns the held handle and the
/// adapter Windows created for it.
fn start_ap(ssid: &str, passphrase: &str, max_peers: u32) -> Result<(ffi::Wlan, String), String> {
    let mut wlan = ffi::Wlan::open()?;
    wlan.allow()?;
    wlan.configure(ssid.as_bytes(), max_peers)?;
    wlan.set_passphrase(passphrase)?;
    wlan.start()?;
    let status = wlan.status()?;
    Ok((wlan, guid_string(&status.device)))
}

/// The access point's peers, for DHCP to answer only them. It reads through
/// a WLAN handle of its own: the session's handle holds the access point and
/// must close when the session ends, not when the DHCP server lets go. With no
/// handle the list cannot be read, and DHCP answers everyone.
fn station_reader(wlan: Option<ffi::Wlan>) -> StationReader {
    let wlan = Mutex::new(wlan);
    Box::new(move || {
        let wlan = wlan.lock().unwrap_or_else(|e| e.into_inner());
        let status = wlan.as_ref()?.status().ok()?;
        Some(status.peers.into_iter().map(MacAddr::new).collect())
    })
}

#[async_trait]
impl HotspotBackend for HostedNetwork {
    fn notes(&self) -> PlatformNotes {
        PlatformNotes {
            hotspot: true,
            band_selection: false,
            notes: vec!["The hosted network picks its band by itself; Captun hands out 10.74.0.0/24 addresses on it.".into()],
        }
    }

    async fn start(&self, config: &HotspotConfig, options: StartOptions) -> Result<BackendState, HotspotError> {
        check_config(config)?;
        if let Some(old) = self.take() {
            drop(tokio::task::spawn_blocking(move || drop(old)).await);
        }
        let ssid = config.ssid.clone();
        let passphrase = config.passphrase.clone();
        let max_peers = config.max_clients.unwrap_or(DEFAULT_MAX_PEERS);
        let (wlan, device, reader) = tokio::task::spawn_blocking({
            let ssid = ssid.clone();
            move || start_ap(&ssid, passphrase.expose(), max_peers).map(|(wlan, device)| (wlan, device, ffi::Wlan::open().ok()))
        })
        .await
        .map_err(|e| HotspotError::Failed(format!("hosted network worker crashed: {e}")))?
        .map_err(HotspotError::Unavailable)?;

        // The virtual adapter appears a moment after the access point starts.
        let mut adapter = None;
        for _ in 0..20 {
            adapter = iface::list().into_iter().find(|i| i.system_name.eq_ignore_ascii_case(&device) && i.up);
            if adapter.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let Some(adapter) = adapter else {
            drop(tokio::task::spawn_blocking(move || drop((wlan, reader))).await);
            return Err(HotspotError::Failed("the hosted network started but its network adapter did not appear".into()));
        };
        let nat = !self.engine_routed.load(Ordering::SeqCst);
        let network = match OwnNetwork::bring_up(&adapter, options.dns_on_gateway, nat, Some(station_reader(reader))) {
            Ok(network) => network,
            Err(e) => {
                drop(tokio::task::spawn_blocking(move || drop(wlan)).await);
                return Err(e);
            }
        };
        let state = BackendState {
            running: true,
            transitioning: false,
            ssid: Some(ssid.clone()),
            interface: Some(adapter.name.clone()),
            gateway: Some(GATEWAY.into()),
            max_clients: Some(max_peers),
        };
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Session { wlan, network, ssid, interface: adapter.name, max_peers });
        Ok(state)
    }

    async fn stop(&self) -> Result<(), HotspotError> {
        if let Some(session) = self.take() {
            // Reverting the network runs system commands; keep them off the runtime.
            drop(tokio::task::spawn_blocking(move || drop(session)).await);
        }
        Ok(())
    }

    async fn state(&self) -> Result<BackendState, HotspotError> {
        let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = guard.as_ref() else { return Ok(BackendState::default()) };
        let running = session.wlan.status().is_ok_and(|s| s.active);
        Ok(BackendState {
            running,
            transitioning: false,
            ssid: Some(session.ssid.clone()),
            interface: Some(session.interface.clone()),
            gateway: Some(GATEWAY.into()),
            max_clients: Some(session.max_peers),
        })
    }

    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
        let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = guard.as_ref() else { return Ok(Vec::new()) };
        let stations: Option<Vec<MacAddr>> =
            session.wlan.status().ok().map(|s| s.peers.into_iter().map(MacAddr::new).collect());
        Ok(session.network.clients(stations.as_deref()))
    }

    fn expected_network(&self) -> Option<Ipv4Net> {
        own_net::network()
    }

    fn set_engine_routed(&self, routed: bool) {
        self.engine_routed.store(routed, Ordering::SeqCst);
    }

    /// Its NAT is set as it starts, from `set_engine_routed`.
    fn shares_through_system(&self) -> bool {
        false
    }
}

/// Read-only: whether the hosted network can be used right now (the driver
/// offers it and Wi-Fi is on). Changes nothing.
#[cfg(test)]
fn available() -> bool {
    ffi::Wlan::open().and_then(|w| w.status()).is_ok_and(|s| s.available)
}

#[allow(unsafe_code)]
mod ffi {
    use std::{mem::size_of, ptr};

    use windows_sys::{
        Win32::{
            Foundation::{
                BOOL, ERROR_ACCESS_DENIED, ERROR_INVALID_STATE, ERROR_NOT_SUPPORTED, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS,
                HANDLE,
            },
            NetworkManagement::WiFi::{
                DOT11_SSID, WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS, WLAN_HOSTED_NETWORK_PEER_STATE, WLAN_HOSTED_NETWORK_REASON,
                WLAN_HOSTED_NETWORK_STATUS, WlanCloseHandle, WlanFreeMemory, WlanHostedNetworkQueryStatus,
                WlanHostedNetworkSetProperty, WlanHostedNetworkSetSecondaryKey, WlanHostedNetworkStartUsing,
                WlanHostedNetworkStopUsing, WlanOpenHandle, wlan_hosted_network_active,
                wlan_hosted_network_opcode_connection_settings, wlan_hosted_network_opcode_enable,
                wlan_hosted_network_reason_bad_parameters, wlan_hosted_network_reason_elevation_required,
                wlan_hosted_network_reason_gp_denied, wlan_hosted_network_reason_interface_unavailable,
                wlan_hosted_network_reason_service_unavailable, wlan_hosted_network_unavailable,
            },
        },
        core::GUID,
    };
    use zeroize::Zeroize;

    /// The Vista-and-later WLAN API version.
    const CLIENT_VERSION: u32 = 2;

    /// An open WLAN client handle, holding the hosted network once started.
    pub(super) struct Wlan {
        handle: HANDLE,
        using: bool,
    }

    // SAFETY: a WLAN client handle is not bound to the thread that opened it;
    // wlanapi serializes calls on a handle internally.
    unsafe impl Send for Wlan {}

    pub(super) struct Status {
        pub(super) active: bool,
        #[cfg_attr(not(test), allow(dead_code))]
        pub(super) available: bool,
        pub(super) device: GUID,
        pub(super) peers: Vec<[u8; 6]>,
    }

    // The reason constants are named in lowercase by the Windows headers.
    #[allow(non_upper_case_globals)]
    fn describe(code: u32, reason: WLAN_HOSTED_NETWORK_REASON) -> String {
        let why = match reason {
            wlan_hosted_network_reason_elevation_required => "it needs administrator rights",
            wlan_hosted_network_reason_gp_denied => "your organization's policy blocks it",
            wlan_hosted_network_reason_bad_parameters => "Windows rejected the network name or password",
            wlan_hosted_network_reason_service_unavailable => "the Wi-Fi service (WLAN AutoConfig) is not running",
            wlan_hosted_network_reason_interface_unavailable => "this Wi-Fi driver does not offer it, or Wi-Fi is off",
            _ => match code {
                ERROR_INVALID_STATE | ERROR_NOT_SUPPORTED => "this Wi-Fi driver does not offer it, or Wi-Fi is off",
                ERROR_ACCESS_DENIED => "it needs administrator rights",
                ERROR_SERVICE_NOT_ACTIVE => "the Wi-Fi service (WLAN AutoConfig) is not running",
                _ => "",
            },
        };
        if why.is_empty() { format!("Windows error {code} (reason {reason})") } else { why.to_owned() }
    }

    fn check(code: u32, reason: WLAN_HOSTED_NETWORK_REASON) -> Result<(), String> {
        if code == ERROR_SUCCESS { Ok(()) } else { Err(describe(code, reason)) }
    }

    impl Wlan {
        pub(super) fn open() -> Result<Self, String> {
            let mut negotiated = 0u32;
            let mut handle: HANDLE = ptr::null_mut();
            // SAFETY: both out-pointers are valid for one write each; the reserved
            // argument must be null.
            let code = unsafe { WlanOpenHandle(CLIENT_VERSION, ptr::null(), &mut negotiated, &mut handle) };
            check(code, 0)?;
            Ok(Self { handle, using: false })
        }

        /// Allows the hosted network (`netsh wlan set hostednetwork mode=allow`).
        pub(super) fn allow(&self) -> Result<(), String> {
            let enable: BOOL = 1;
            let mut reason = 0;
            // SAFETY: the data pointer and size describe one BOOL, which is what
            // this opcode takes; `reason` is valid for a write.
            let code = unsafe {
                WlanHostedNetworkSetProperty(
                    self.handle,
                    wlan_hosted_network_opcode_enable,
                    size_of::<BOOL>() as u32,
                    ptr::from_ref(&enable).cast(),
                    &mut reason,
                    ptr::null(),
                )
            };
            check(code, reason)
        }

        /// Sets the network name (at most 32 bytes, checked by the caller) and
        /// the peer limit.
        pub(super) fn configure(&self, ssid: &[u8], max_peers: u32) -> Result<(), String> {
            let len = ssid.len().min(32);
            let mut settings = WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS {
                hostedNetworkSSID: DOT11_SSID { uSSIDLength: len as u32, ucSSID: [0; 32] },
                dwMaxNumberOfPeers: max_peers,
            };
            settings.hostedNetworkSSID.ucSSID[..len].copy_from_slice(&ssid[..len]);
            let mut reason = 0;
            // SAFETY: the data pointer and size describe one connection-settings
            // struct, which is what this opcode takes.
            let code = unsafe {
                WlanHostedNetworkSetProperty(
                    self.handle,
                    wlan_hosted_network_opcode_connection_settings,
                    size_of::<WLAN_HOSTED_NETWORK_CONNECTION_SETTINGS>() as u32,
                    ptr::from_ref(&settings).cast(),
                    &mut reason,
                    ptr::null(),
                )
            };
            check(code, reason)
        }

        /// Sets the WPA2 key for this run only (not saved by Windows).
        pub(super) fn set_passphrase(&self, passphrase: &str) -> Result<(), String> {
            // A passphrase goes with its terminating NUL; a 64-digit raw key without.
            let raw_key = passphrase.len() == 64 && passphrase.bytes().all(|b| b.is_ascii_hexdigit());
            let mut key = passphrase.as_bytes().to_vec();
            if !raw_key {
                key.push(0);
            }
            let mut reason = 0;
            // SAFETY: `key` holds exactly `key.len()` readable bytes for the call.
            let code = unsafe {
                WlanHostedNetworkSetSecondaryKey(
                    self.handle,
                    key.len() as u32,
                    key.as_ptr(),
                    BOOL::from(!raw_key),
                    0,
                    &mut reason,
                    ptr::null(),
                )
            };
            key.zeroize();
            check(code, reason)
        }

        /// Starts the access point and holds it for as long as this handle lives.
        pub(super) fn start(&mut self) -> Result<(), String> {
            let mut reason = 0;
            // SAFETY: plain call on our open handle; `reason` is valid for a write.
            let code = unsafe { WlanHostedNetworkStartUsing(self.handle, &mut reason, ptr::null()) };
            check(code, reason)?;
            self.using = true;
            Ok(())
        }

        pub(super) fn status(&self) -> Result<Status, String> {
            let mut status: *mut WLAN_HOSTED_NETWORK_STATUS = ptr::null_mut();
            // SAFETY: `status` is valid for a write; on success it points at a block
            // wlanapi allocated, freed below.
            let code = unsafe { WlanHostedNetworkQueryStatus(self.handle, &mut status, ptr::null()) };
            check(code, 0)?;
            if status.is_null() {
                return Err("Windows returned no hosted network status".into());
            }
            // SAFETY: `status` is a valid status block. Its peer list holds
            // `dwNumberOfPeers` entries laid out from `PeerList` inside the same
            // allocation, so the slice is taken from the raw block pointer.
            let result = unsafe {
                let peers_ptr = ptr::addr_of!((*status).PeerList).cast::<WLAN_HOSTED_NETWORK_PEER_STATE>();
                let count = (*status).dwNumberOfPeers as usize;
                let peers = std::slice::from_raw_parts(peers_ptr, count).iter().map(|p| p.PeerMacAddress).collect();
                Status {
                    active: (*status).HostedNetworkState == wlan_hosted_network_active,
                    available: (*status).HostedNetworkState != wlan_hosted_network_unavailable,
                    device: (*status).IPDeviceID,
                    peers,
                }
            };
            // SAFETY: allocated by WlanHostedNetworkQueryStatus, freed exactly once.
            unsafe { WlanFreeMemory(status.cast()) };
            Ok(result)
        }
    }

    impl Drop for Wlan {
        fn drop(&mut self) {
            if self.using {
                let mut reason = 0;
                // SAFETY: releases our hold on the access point started with this handle.
                unsafe { WlanHostedNetworkStopUsing(self.handle, &mut reason, ptr::null()) };
            }
            // SAFETY: the handle came from WlanOpenHandle and is closed exactly once.
            unsafe { WlanCloseHandle(self.handle, ptr::null()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_are_written_the_way_windows_names_adapters() {
        let g = windows_sys::core::GUID {
            data1: 0x2E9E_E635,
            data2: 0x8953,
            data3: 0x4C26,
            data4: [0x86, 0x43, 0x03, 0x52, 0x79, 0xF4, 0xDD, 0x59],
        };
        assert_eq!(guid_string(&g), "{2E9EE635-8953-4C26-8643-035279F4DD59}");
    }

    #[test]
    fn without_a_wlan_handle_the_station_list_is_unreadable() {
        // Unreadable, not empty: an empty list would turn every device away.
        assert_eq!(station_reader(None)(), None);
    }

    #[test]
    fn the_network_is_known_before_it_starts_and_routing_is_remembered() {
        let hosted = HostedNetwork::default();
        assert_eq!(hosted.expected_network().map(|n| n.to_string()).as_deref(), Some("10.74.0.0/24"));
        assert!(!hosted.engine_routed.load(Ordering::SeqCst), "the system shares the internet until told otherwise");
        hosted.set_engine_routed(true);
        assert!(hosted.engine_routed.load(Ordering::SeqCst));
        assert!(!hosted.shares_through_system(), "it shares only as told at its start");
    }

    #[test]
    fn availability_can_be_asked_without_changing_anything() {
        // Only queries the status; true or false depends on the machine.
        let _ = available();
    }
}
