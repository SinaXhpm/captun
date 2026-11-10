//! Linux access point through hostapd, for systems without NetworkManager or
//! where it manages no Wi-Fi device. hostapd only runs the radio, so Captun
//! hands out addresses and shares the internet itself ([`OwnNetwork`]).

use std::fmt::Write as _;

use captun_core::config::WifiBand;

use crate::HotspotError;

/// What goes into a hostapd configuration file.
pub(crate) struct HostapdSpec<'a> {
    pub(crate) interface: &'a str,
    pub(crate) ssid: &'a str,
    pub(crate) passphrase: &'a str,
    pub(crate) band: WifiBand,
    pub(crate) isolate_clients: bool,
    pub(crate) max_clients: Option<u32>,
}

/// A WPA2-Personal access point. The SSID is written as hex (`ssid2`) so any
/// byte is safe; the passphrase is validated printable ASCII (or a raw key).
pub(crate) fn hostapd_conf(spec: &HostapdSpec<'_>) -> Result<String, HotspotError> {
    let (hw_mode, channel) = match spec.band {
        WifiBand::Auto | WifiBand::Ghz2_4 => ("g", 6),
        WifiBand::Ghz5 => ("a", 36),
        WifiBand::Ghz6 => {
            return Err(HotspotError::InvalidConfig(
                "6 GHz needs NetworkManager on Linux; pick Automatic, 2.4 GHz or 5 GHz".into(),
            ));
        }
    };
    let ssid_hex: String = spec.ssid.bytes().map(|b| format!("{b:02x}")).collect();
    let mut conf = String::new();
    let _ = writeln!(conf, "interface={}", spec.interface);
    conf.push_str("driver=nl80211\n");
    let _ = writeln!(conf, "ssid2={ssid_hex}");
    let _ = writeln!(conf, "hw_mode={hw_mode}\nchannel={channel}");
    conf.push_str("ieee80211n=1\nwmm_enabled=1\nauth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n");
    let raw_key = spec.passphrase.len() == 64 && spec.passphrase.bytes().all(|b| b.is_ascii_hexdigit());
    if raw_key {
        let _ = writeln!(conf, "wpa_psk={}", spec.passphrase);
    } else {
        let _ = writeln!(conf, "wpa_passphrase={}", spec.passphrase);
    }
    if spec.isolate_clients {
        conf.push_str("ap_isolate=1\n");
    }
    if let Some(max) = spec.max_clients {
        let _ = writeln!(conf, "max_num_sta={max}");
    }
    Ok(conf)
}

#[cfg(target_os = "linux")]
pub(crate) use backend::HostapdHotspot;

#[cfg(target_os = "linux")]
mod backend {
    use std::{
        io::Read as _,
        path::PathBuf,
        process::Stdio,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use async_trait::async_trait;
    use ipnet::Ipv4Net;
    use captun_core::{InterfaceKind, MacAddr, ObservedClient, config::HotspotConfig};
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        process::{Child, Command},
        sync::Mutex,
        time::timeout,
    };
    use tracing::debug;

    use super::{HostapdSpec, hostapd_conf};
    use crate::{
        BackendState, HotspotBackend, HotspotError, PlatformNotes, StartOptions,
        hotspot::check_config,
        iface,
        own_net::{self, GATEWAY, OwnNetwork, StationReader},
        parse,
        wifi::on_path,
    };

    const RUN_DIR: &str = "/run/captun";
    const START_TIMEOUT: Duration = Duration::from_secs(20);
    /// `iw` answers at once; one that hangs must not stall DHCP.
    const IW_TIMEOUT: Duration = Duration::from_secs(2);

    struct Session {
        child: Child,
        network: OwnNetwork,
        conf: PathBuf,
        device: String,
        ssid: String,
        max_clients: Option<u32>,
        /// NetworkManager was told to leave the device alone; give it back.
        unmanaged: bool,
    }

    impl Session {
        async fn end(mut self) {
            let _ = self.child.kill().await;
            drop(self.network);
            let _ = std::fs::remove_file(&self.conf);
            if self.unmanaged {
                let _ = Command::new("nmcli").args(["device", "set", &self.device, "managed", "yes"]).output().await;
            }
        }
    }

    #[derive(Default)]
    pub(crate) struct HostapdHotspot {
        session: Mutex<Option<Session>>,
        /// Captun's routing engine carries the traffic, so the system shares none.
        engine_routed: AtomicBool,
    }

    impl std::fmt::Debug for HostapdHotspot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HostapdHotspot").finish_non_exhaustive()
        }
    }

    /// `iw dev <device> station dump`: the stations associated right now.
    /// Blocking, for the DHCP server's check (run off the async threads) and
    /// the device list; `None` when `iw` is missing, fails or hangs.
    fn read_stations(device: &str) -> Option<Vec<MacAddr>> {
        let mut child = std::process::Command::new("iw")
            .args(["dev", device, "station", "dump"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        };
        // Read on a helper thread so a hung `iw` can be killed; reading here
        // and waiting would block on a full pipe with many stations.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = tx.send(stdout.read_to_string(&mut text).map(|_| text));
        });
        let text = rx.recv_timeout(IW_TIMEOUT);
        if text.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().ok()?;
        let text = text.ok()?.ok()?;
        status.success().then(|| parse::iw_stations(&text))
    }

    fn station_reader(device: String) -> StationReader {
        Box::new(move || read_stations(&device))
    }

    fn write_private(path: &PathBuf, contents: &str) -> Result<(), HotspotError> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let err = |e: std::io::Error| HotspotError::Failed(format!("cannot write {}: {e}", path.display()));
        std::fs::create_dir_all(RUN_DIR).map_err(err)?;
        let mut file =
            std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).map_err(err)?;
        file.write_all(contents.as_bytes()).map_err(err)
    }

    #[async_trait]
    impl HotspotBackend for HostapdHotspot {
        fn notes(&self) -> PlatformNotes {
            PlatformNotes {
                hotspot: true,
                band_selection: true,
                notes: vec!["Uses hostapd; Captun hands out 10.74.0.0/24 addresses.".into()],
            }
        }

        async fn start(&self, config: &HotspotConfig, options: StartOptions) -> Result<BackendState, HotspotError> {
            check_config(config)?;
            if !on_path("hostapd") {
                return Err(HotspotError::Unavailable("hostapd is not installed".into()));
            }
            let mut session = self.session.lock().await;
            if let Some(old) = session.take() {
                old.end().await;
            }
            let device = match &config.interface {
                Some(dev) => dev.clone(),
                None => iface::list()
                    .into_iter()
                    .find(|i| i.kind == InterfaceKind::Wifi)
                    .map(|i| i.system_name)
                    .ok_or_else(|| HotspotError::Unavailable("no Wi-Fi adapter found".into()))?,
            };
            let conf_text = hostapd_conf(&HostapdSpec {
                interface: &device,
                ssid: &config.ssid,
                passphrase: config.passphrase.expose(),
                band: config.band,
                isolate_clients: options.isolate_clients,
                max_clients: config.max_clients,
            })?;
            let conf = PathBuf::from(RUN_DIR).join(format!("hostapd-{device}.conf"));
            write_private(&conf, &conf_text)?;

            // NetworkManager would fight hostapd for the device.
            let unmanaged = on_path("nmcli")
                && Command::new("nmcli")
                    .args(["device", "set", &device, "managed", "no"])
                    .output()
                    .await
                    .is_ok_and(|o| o.status.success());

            let mut child = Command::new("hostapd")
                .arg(&conf)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| HotspotError::Failed(format!("cannot run hostapd: {e}")))?;
            let Some(stdout) = child.stdout.take() else {
                return Err(HotspotError::Failed("hostapd gave no output".into()));
            };
            let mut lines = BufReader::new(stdout).lines();
            let mut seen = Vec::new();
            let enabled = timeout(START_TIMEOUT, async {
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.contains("AP-ENABLED") {
                        return true;
                    }
                    seen.push(line);
                }
                false
            })
            .await
            .unwrap_or(false);
            if !enabled {
                let _ = child.kill().await;
                let _ = std::fs::remove_file(&conf);
                if unmanaged {
                    let _ = Command::new("nmcli").args(["device", "set", &device, "managed", "yes"]).output().await;
                }
                let tail = seen.iter().rev().take(3).rev().cloned().collect::<Vec<_>>().join(" / ");
                return Err(HotspotError::Failed(format!(
                    "hostapd could not start the access point (the adapter may not support access-point mode): {tail}"
                )));
            }
            // Keep reading so hostapd never blocks on a full pipe.
            tokio::spawn(async move {
                while let Ok(Some(line)) = lines.next_line().await {
                    debug!(target: "hostapd", "{line}");
                }
            });

            let Some(adapter) = iface::list().into_iter().find(|i| i.system_name == device) else {
                let _ = child.kill().await;
                return Err(HotspotError::Failed(format!("Wi-Fi adapter {device} disappeared")));
            };
            let nat = !self.engine_routed.load(Ordering::SeqCst);
            let stations = station_reader(device.clone());
            let network = match OwnNetwork::bring_up(&adapter, options.dns_on_gateway, nat, Some(stations)) {
                Ok(network) => network,
                Err(e) => {
                    let _ = child.kill().await;
                    return Err(e);
                }
            };
            *session = Some(Session {
                child,
                network,
                conf,
                device: device.clone(),
                ssid: config.ssid.clone(),
                max_clients: config.max_clients,
                unmanaged,
            });
            Ok(BackendState {
                running: true,
                transitioning: false,
                ssid: Some(config.ssid.clone()),
                interface: Some(device),
                gateway: Some(GATEWAY.into()),
                max_clients: config.max_clients,
            })
        }

        async fn stop(&self) -> Result<(), HotspotError> {
            if let Some(session) = self.session.lock().await.take() {
                session.end().await;
            }
            Ok(())
        }

        async fn state(&self) -> Result<BackendState, HotspotError> {
            let mut guard = self.session.lock().await;
            let Some(session) = guard.as_mut() else { return Ok(BackendState::default()) };
            let running = matches!(session.child.try_wait(), Ok(None));
            Ok(BackendState {
                running,
                transitioning: false,
                ssid: Some(session.ssid.clone()),
                interface: Some(session.device.clone()),
                gateway: Some(GATEWAY.into()),
                max_clients: session.max_clients,
            })
        }

        async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
            let guard = self.session.lock().await;
            let Some(session) = guard.as_ref() else { return Ok(Vec::new()) };
            let device = session.device.clone();
            let stations = tokio::task::spawn_blocking(move || read_stations(&device)).await.ok().flatten();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(band: WifiBand, passphrase: &str) -> String {
        hostapd_conf(&HostapdSpec {
            interface: "wlan0",
            ssid: "Café #1",
            passphrase,
            band,
            isolate_clients: true,
            max_clients: Some(8),
        })
        .unwrap()
    }

    #[test]
    fn writes_a_wpa2_access_point_with_a_hex_ssid() {
        let conf = spec(WifiBand::Auto, "long enough");
        assert!(conf.contains("interface=wlan0\n"));
        assert!(conf.contains("ssid2=436166c3a9202331\n"), "{conf}");
        assert!(conf.contains("hw_mode=g\nchannel=6\n"));
        assert!(conf.contains("wpa=2\n") && conf.contains("wpa_passphrase=long enough\n"));
        assert!(conf.contains("ap_isolate=1\n") && conf.contains("max_num_sta=8\n"));
    }

    #[test]
    fn five_ghz_and_raw_keys_are_spelled_out() {
        let key = "a".repeat(64);
        let conf = spec(WifiBand::Ghz5, &key);
        assert!(conf.contains("hw_mode=a\nchannel=36\n"));
        assert!(conf.contains(&format!("wpa_psk={key}\n")));
        assert!(!conf.contains("wpa_passphrase"));
    }

    #[test]
    fn six_ghz_is_refused_with_a_way_out() {
        let result = hostapd_conf(&HostapdSpec {
            interface: "wlan0",
            ssid: "x",
            passphrase: "long enough",
            band: WifiBand::Ghz6,
            isolate_clients: false,
            max_clients: None,
        });
        assert!(matches!(result, Err(HotspotError::InvalidConfig(_))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn it_shares_only_as_told_at_its_start() {
        use crate::HotspotBackend;
        assert!(!HostapdHotspot::default().shares_through_system());
    }
}
