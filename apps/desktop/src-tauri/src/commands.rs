//! Tauri commands, one per service request. Each returns the payload of the
//! response variant its request calls for, so the webview gets typed data.

use captun_core::{
    Config, EgressId, LinkSummary, MacAddr, ShareLink, TargetAddr,
    config::{ClientProfile, ConfigError, Protocol},
};
use captun_ipc::{
    AdbDeviceInfo, ClientView, EgressTestResult, InterfaceInfo, ListsProgress, Request, Response, ReverseTetherMethod,
    RuleHits, RuleTestResult, ServiceStatus, TetherOutcome,
};
use captun_platform::HotspotSupport;
use tauri::{AppHandle, State};

use crate::{
    error::{CommandError, ErrorKind},
    launch,
    state::{AppState, ConnectionStatus},
};

type CommandResult<T> = Result<T, CommandError>;

async fn expect_ok(state: &AppState, request: Request) -> CommandResult<()> {
    match state.call(request).await? {
        Response::Ok => Ok(()),
        other => Err(CommandError::unexpected(&other)),
    }
}

#[tauri::command]
pub(crate) fn connection_status(state: State<'_, AppState>) -> ConnectionStatus {
    state.status()
}

#[tauri::command]
pub(crate) async fn start_service(state: State<'_, AppState>) -> CommandResult<()> {
    let token_path = state.token_path().to_owned();
    // The elevation prompt blocks the calling thread until the user answers.
    tauri::async_runtime::spawn_blocking(move || launch::start_service(&token_path))
        .await
        .map_err(|e| CommandError::new(ErrorKind::LaunchFailed, format!("Launcher task failed: {e}")))?
        .map_err(|message| CommandError::new(ErrorKind::LaunchFailed, message))
}

#[tauri::command]
pub(crate) async fn get_status(state: State<'_, AppState>) -> CommandResult<ServiceStatus> {
    match state.call(Request::GetStatus).await? {
        Response::Status(status) => Ok(*status),
        other => Err(CommandError::unexpected(&other)),
    }
}

#[tauri::command]
pub(crate) async fn start_hotspot(state: State<'_, AppState>) -> CommandResult<()> {
    expect_ok(&state, Request::StartHotspot).await
}

#[tauri::command]
pub(crate) async fn stop_hotspot(state: State<'_, AppState>) -> CommandResult<()> {
    expect_ok(&state, Request::StopHotspot).await
}

#[tauri::command]
pub(crate) async fn start_access_network(state: State<'_, AppState>) -> CommandResult<()> {
    expect_ok(&state, Request::StartAccessNetwork).await
}

#[tauri::command]
pub(crate) async fn stop_access_network(state: State<'_, AppState>) -> CommandResult<()> {
    expect_ok(&state, Request::StopAccessNetwork).await
}

/// Asks the service to stop cleanly (sharing off, changes reverted), so it can
/// be started again, for example after Captun was updated.
#[tauri::command]
pub(crate) async fn stop_service(state: State<'_, AppState>) -> CommandResult<()> {
    expect_ok(&state, Request::Shutdown).await
}

#[tauri::command]
pub(crate) async fn list_clients(state: State<'_, AppState>) -> CommandResult<Vec<ClientView>> {
    match state.call(Request::ListClients).await? {
        Response::Clients(clients) => Ok(clients),
        other => Err(CommandError::unexpected(&other)),
    }
}

/// The service changed a device's profile; the settings are saved from its copy.
#[tauri::command]
pub(crate) async fn set_client_profile(state: State<'_, AppState>, profile: ClientProfile) -> CommandResult<()> {
    expect_ok(&state, Request::SetClientProfile(profile)).await?;
    state.save_from_service().await;
    Ok(())
}

#[tauri::command]
pub(crate) async fn forget_client(state: State<'_, AppState>, mac: MacAddr) -> CommandResult<()> {
    expect_ok(&state, Request::ForgetClient { mac }).await?;
    state.save_from_service().await;
    Ok(())
}

fn save_error(e: ConfigError) -> CommandError {
    match e {
        ConfigError::Invalid(errors) => CommandError::new(ErrorKind::InvalidConfig, errors.join("\n")),
        other => CommandError::new(ErrorKind::Internal, format!("The settings could not be saved: {other}")),
    }
}

/// The service's settings while connected; otherwise the saved ones. Saved
/// settings the service refused stay on show until they are fixed.
#[tauri::command]
pub(crate) async fn get_config(state: State<'_, AppState>) -> CommandResult<Config> {
    if state.sync_failed() {
        return Ok(state.saved_or_default().await);
    }
    match state.call(Request::GetConfig).await {
        Ok(Response::Config(config)) => Ok(*config),
        Ok(other) => Err(CommandError::unexpected(&other)),
        Err(e) if e.code == ErrorKind::NotConnected => Ok(state.saved_or_default().await),
        Err(e) => Err(e),
    }
}

/// Applies the settings through the service while connected, then saves
/// them; otherwise only saves them, and the service gets them when it starts.
#[tauri::command]
pub(crate) async fn set_config(app: AppHandle, state: State<'_, AppState>, config: Config) -> CommandResult<()> {
    match state.call(Request::SetConfig(Box::new(config.clone()))).await {
        Ok(Response::Ok) => state.save_accepted(&app, &config).await.map_err(|e| {
            CommandError::new(ErrorKind::Internal, format!("The change is in effect, but it could not be saved: {e}"))
        }),
        Ok(other) => Err(CommandError::unexpected(&other)),
        Err(e) if e.code == ErrorKind::NotConnected => state.save_offline(&app, &config).await.map_err(save_error),
        Err(e) => Err(e),
    }
}

/// Whether this computer can host a Wi-Fi hotspot. Asked locally (it needs no
/// privileges) so the GUI can say so before the service runs.
#[tauri::command]
pub(crate) async fn hotspot_support() -> CommandResult<HotspotSupport> {
    // Windows answers through blocking WinRT calls.
    tauri::async_runtime::spawn_blocking(captun_platform::hotspot_support)
        .await
        .map_err(|e| CommandError::new(ErrorKind::Internal, format!("Wi-Fi check failed: {e}")))
}

/// The version and the project's links, for the About dialog.
#[tauri::command]
pub(crate) fn app_info() -> crate::about::AppInfo {
    crate::about::app_info()
}

/// Opens one of Captun's own pages (website, GitHub, a release) in the
/// default browser; any other address is refused.
#[tauri::command]
pub(crate) fn open_link(url: String) -> CommandResult<()> {
    crate::about::open(&url).map_err(|e| CommandError::new(ErrorKind::Internal, e.to_string()))
}

/// Asks GitHub for the newest release and compares it with this version.
#[tauri::command]
pub(crate) async fn check_update() -> CommandResult<crate::about::UpdateInfo> {
    crate::about::check_update().await.map_err(|e| CommandError::new(ErrorKind::Internal, e))
}

/// Reads a pasted proxy or VPN link, so the editor can fill itself in and
/// say what the link is before anything is saved. Parsed locally: the link
/// never leaves this process until the user saves it.
#[tauri::command]
pub(crate) fn describe_link(link: String) -> CommandResult<LinkSummary> {
    ShareLink::parse(&link).map(|l| l.summary()).map_err(|e| CommandError::new(ErrorKind::InvalidConfig, e.to_string()))
}

/// Adapters as listed on this computer, for when the service is not there to
/// say which one carries the hotspot.
fn local_interfaces() -> Vec<InterfaceInfo> {
    captun_platform::iface::list()
        .into_iter()
        .filter(|i| !i.loopback)
        .map(|i| InterfaceInfo {
            index: i.index,
            name: i.name,
            description: i.description,
            kind: i.kind,
            physical: i.physical,
            mac: i.mac,
            ipv4: i.ipv4,
            ipv6: i.ipv6,
            up: i.up,
            has_gateway: i.has_gateway,
            gateway: i.gateway,
            default_route: i.default_route,
            speed_mbps: i.speed_mbps,
            is_hotspot: false,
        })
        .collect()
}

#[tauri::command]
pub(crate) async fn list_interfaces(state: State<'_, AppState>) -> CommandResult<Vec<InterfaceInfo>> {
    match state.call(Request::ListInterfaces).await {
        Ok(Response::Interfaces(interfaces)) => Ok(interfaces),
        Ok(other) => Err(CommandError::unexpected(&other)),
        Err(e) if e.code == ErrorKind::NotConnected => Ok(local_interfaces()),
        Err(e) => Err(e),
    }
}

#[tauri::command]
pub(crate) async fn test_egress(
    state: State<'_, AppState>,
    id: EgressId,
    target: Option<TargetAddr>,
) -> CommandResult<EgressTestResult> {
    match state.call(Request::TestEgress { id, target }).await? {
        Response::EgressTest(result) => Ok(result),
        other => Err(CommandError::unexpected(&other)),
    }
}

/// How each online list the rules use stands, and whether an update is under
/// way; none known while the service is not running.
#[tauri::command]
pub(crate) async fn get_lists(state: State<'_, AppState>) -> CommandResult<ListsProgress> {
    match state.call(Request::GetLists).await {
        Ok(Response::Lists(progress)) => Ok(progress),
        Ok(other) => Err(CommandError::unexpected(&other)),
        Err(e) if e.code == ErrorKind::NotConnected => Ok(ListsProgress::default()),
        Err(e) => Err(e),
    }
}

/// Starts downloading every online list the rules use, through `through` or
/// the default outbound. The service answers at once; how the update goes
/// comes as `lists` events. Only ever on the user's request.
#[tauri::command]
pub(crate) async fn update_lists(state: State<'_, AppState>, through: Option<EgressId>) -> CommandResult<ListsProgress> {
    match state.call(Request::UpdateLists { through }).await? {
        Response::Lists(progress) => Ok(progress),
        other => Err(CommandError::unexpected(&other)),
    }
}

/// How often each rule decided since the rules last changed, one entry per
/// rule; none known while the service is not running.
#[tauri::command]
pub(crate) async fn get_rule_hits(state: State<'_, AppState>) -> CommandResult<Vec<RuleHits>> {
    match state.call(Request::GetRuleHits).await {
        Ok(Response::RuleHits(hits)) => Ok(hits),
        Ok(other) => Err(CommandError::unexpected(&other)),
        Err(e) if e.code == ErrorKind::NotConnected => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// What the rules do with a website or an address, for one device or any.
#[tauri::command]
pub(crate) async fn test_rules(
    state: State<'_, AppState>,
    target: String,
    device: Option<MacAddr>,
    port: Option<u16>,
    protocol: Option<Protocol>,
) -> CommandResult<RuleTestResult> {
    match state.call(Request::TestRules { target, device, port, protocol }).await? {
        Response::RuleTest(result) => Ok(*result),
        other => Err(CommandError::unexpected(&other)),
    }
}

#[tauri::command]
pub(crate) async fn list_adb_devices(state: State<'_, AppState>) -> CommandResult<Vec<AdbDeviceInfo>> {
    match state.call(Request::ListAdbDevices).await? {
        Response::AdbDevices(devices) => Ok(devices),
        other => Err(CommandError::unexpected(&other)),
    }
}

#[tauri::command]
pub(crate) async fn set_reverse_tether(
    state: State<'_, AppState>,
    serial: String,
    enable: bool,
    method: ReverseTetherMethod,
) -> CommandResult<TetherOutcome> {
    match state.call(Request::SetReverseTether { serial, enable, method }).await? {
        Response::Tether(outcome) => {
            // Sharing may have added the phone as a device.
            state.save_from_service().await;
            Ok(outcome)
        }
        other => Err(CommandError::unexpected(&other)),
    }
}

/// Data use over time: what was used between each two neighbouring `bounds`
/// (ms since the epoch), by one device or all, and by each device.
#[tauri::command]
pub(crate) async fn get_usage(
    state: State<'_, AppState>,
    bounds: Vec<u64>,
    device: Option<MacAddr>,
) -> CommandResult<captun_ipc::UsageReport> {
    match state.call(Request::GetUsage { bounds, device }).await? {
        Response::Usage(report) => Ok(report),
        other => Err(CommandError::unexpected(&other)),
    }
}

/// Starts a device's data allowance over now.
#[tauri::command]
pub(crate) async fn reset_quota(state: State<'_, AppState>, mac: MacAddr) -> CommandResult<()> {
    expect_ok(&state, Request::ResetQuota { mac }).await
}

/// Gives a device `mb` more megabytes for this period of its allowance.
#[tauri::command]
pub(crate) async fn add_quota(state: State<'_, AppState>, mac: MacAddr, mb: u64) -> CommandResult<()> {
    expect_ok(&state, Request::AddQuota { mac, mb }).await
}
