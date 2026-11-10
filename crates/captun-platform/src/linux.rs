//! Linux hotspot through NetworkManager: a keyfile describes a WPA2 access
//! point in "shared" mode (NAT + dnsmasq DHCP), and nmcli switches it on/off.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use captun_core::{ObservedClient, config::HotspotConfig};
use tokio::{process::Command, time::timeout};

use crate::{
    BackendState, HotspotBackend, HotspotError, PlatformNotes, StartOptions,
    hotspot::check_config,
    iface,
    parse::{self, KeyfileSpec},
};

const CONNECTION_ID: &str = "captun-hotspot";
const KEYFILE_DIR: &str = "/etc/NetworkManager/system-connections";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(crate) struct NetworkManagerHotspot {
    keyfile: PathBuf,
}

impl NetworkManagerHotspot {
    pub(crate) fn new() -> Self {
        Self { keyfile: Path::new(KEYFILE_DIR).join(format!("{CONNECTION_ID}.nmconnection")) }
    }
}

/// Runs a tool with discrete arguments (never through a shell). A missing
/// tool or a NetworkManager that is not running makes this way unavailable.
async fn run(program: &str, args: &[&str]) -> Result<String, HotspotError> {
    let output = timeout(COMMAND_TIMEOUT, Command::new(program).args(args).kill_on_drop(true).output())
        .await
        .map_err(|_| HotspotError::Failed(format!("{program} timed out")))?
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => HotspotError::Unavailable(format!("{program} is not installed")),
            _ => HotspotError::Failed(format!("cannot run {program}: {e}")),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("NetworkManager is not running") {
            return Err(HotspotError::Unavailable("NetworkManager is not running".into()));
        }
        return Err(HotspotError::Failed(format!("{program} {}: {}", args.join(" "), stderr.trim())));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn first_wifi_device() -> Result<String, HotspotError> {
    let out = run("nmcli", &["-t", "-f", "DEVICE,TYPE", "device"]).await?;
    out.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(_, kind)| *kind == "wifi")
        .map(|(dev, _)| dev.to_owned())
        .ok_or_else(|| HotspotError::Unavailable("NetworkManager manages no Wi-Fi device".into()))
}

fn write_keyfile(path: &Path, contents: &str) -> Result<(), HotspotError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let err = |e: std::io::Error| HotspotError::Failed(format!("cannot write {}: {e}", path.display()));
    // NetworkManager ignores keyfiles that are not root-owned 0600.
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(err)?;
    file.write_all(contents.as_bytes()).map_err(err)?;
    file.sync_all().map_err(err)?;
    std::fs::rename(&tmp, path).map_err(err)
}

#[async_trait]
impl HotspotBackend for NetworkManagerHotspot {
    fn notes(&self) -> PlatformNotes {
        PlatformNotes {
            hotspot: true,
            band_selection: true,
            notes: vec![
                "Uses NetworkManager in shared mode (10.42.0.0/24 by default).".into(),
                "Hosting an access point while staying connected to Wi-Fi needs a card that supports concurrent AP+STA; otherwise use Ethernet or a second adapter for the uplink.".into(),
            ],
        }
    }

    async fn start(&self, config: &HotspotConfig, options: StartOptions) -> Result<BackendState, HotspotError> {
        let isolate_clients = options.isolate_clients;
        check_config(config)?;
        let device = match &config.interface {
            Some(dev) => dev.clone(),
            None => first_wifi_device().await?,
        };
        let uuid = parse::uuid_v4();
        let contents = parse::nm_keyfile(&KeyfileSpec {
            id: CONNECTION_ID,
            uuid: &uuid,
            interface: Some(&device),
            ssid: &config.ssid,
            passphrase: config.passphrase.expose(),
            band: config.band,
            isolate_clients,
        });
        write_keyfile(&self.keyfile, &contents)?;
        let path = self.keyfile.display().to_string();
        run("nmcli", &["connection", "load", &path]).await?;
        run("nmcli", &["connection", "up", "id", CONNECTION_ID]).await?;
        self.state().await
    }

    async fn stop(&self) -> Result<(), HotspotError> {
        match run("nmcli", &["connection", "down", "id", CONNECTION_ID]).await {
            Ok(_) => Ok(()),
            // Already down or never created.
            Err(_) if !matches!(self.state().await, Ok(BackendState { running: true, .. })) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn state(&self) -> Result<BackendState, HotspotError> {
        let Ok(out) = run(
            "nmcli",
            &["-t", "-f", "GENERAL.STATE,GENERAL.DEVICES,802-11-wireless.ssid", "connection", "show", "id", CONNECTION_ID],
        )
        .await
        else {
            return Ok(BackendState::default());
        };
        let fields = parse::nmcli_fields(&out);
        let state = fields.get("GENERAL.STATE").map(String::as_str).unwrap_or_default();
        let interface = fields.get("GENERAL.DEVICES").filter(|d| !d.is_empty()).cloned();
        let gateway = interface.as_deref().and_then(|dev| {
            iface::list().into_iter().find(|i| i.system_name == dev).and_then(|i| i.ipv4.first().copied().map(IpAddr::V4))
        });
        Ok(BackendState {
            running: state == "activated",
            transitioning: state == "activating" || state == "deactivating",
            ssid: fields.get("802-11-wireless.ssid").cloned(),
            interface,
            gateway,
            max_clients: None,
        })
    }

    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
        let Some(device) = self.state().await?.interface else { return Ok(Vec::new()) };
        let stations = run("iw", &["dev", &device, "station", "dump"]).await.ok().map(|t| parse::iw_stations(&t));
        let neigh = run("ip", &["-j", "neigh", "show", "dev", &device]).await.map(|t| parse::ip_neigh(&t)).unwrap_or_default();
        let leases = tokio::fs::read_to_string(format!("/var/lib/NetworkManager/dnsmasq-{device}.leases"))
            .await
            .map(|t| parse::dnsmasq_leases(&t))
            .unwrap_or_default();
        Ok(parse::merge(stations, &neigh, &leases))
    }
}
