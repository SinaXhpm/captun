//! Captun desktop GUI. It holds no privileges: everything it changes goes
//! through the authenticated IPC connection to the Captun service. It keeps
//! the settings, encrypted next to the app (`settings.rs`), and hands them to
//! the service whenever it connects.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod about;
mod commands;
mod error;
mod launch;
mod paths;
mod settings;
mod state;
#[cfg(windows)]
mod window_icon;

use tauri::Manager;

fn main() {
    let result = tauri::Builder::default()
        .manage(state::AppState::new())
        .setup(|app| {
            #[cfg(windows)]
            if let Some(window) = app.get_webview_window("main")
                && let Ok(hwnd) = window.hwnd()
            {
                window_icon::apply(hwnd.0);
            }
            state::spawn_connection_loop(app.app_handle().clone());
            Ok(())
        })
        .on_window_event(|_window, _event| {
            // Moved to a screen with another scale: load the icons at its sizes.
            #[cfg(windows)]
            if let tauri::WindowEvent::ScaleFactorChanged { .. } = _event
                && let Ok(hwnd) = _window.hwnd()
            {
                window_icon::apply(hwnd.0);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::connection_status,
            commands::start_service,
            commands::get_status,
            commands::start_hotspot,
            commands::stop_hotspot,
            commands::hotspot_support,
            commands::describe_link,
            commands::app_info,
            commands::open_link,
            commands::check_update,
            commands::start_access_network,
            commands::stop_access_network,
            commands::stop_service,
            commands::list_clients,
            commands::set_client_profile,
            commands::forget_client,
            commands::get_config,
            commands::set_config,
            commands::list_interfaces,
            commands::test_egress,
            commands::list_adb_devices,
            commands::set_reverse_tether,
            commands::get_lists,
            commands::update_lists,
            commands::get_rule_hits,
            commands::test_rules,
        ])
        .run(tauri::generate_context!());

    if let Err(e) = result {
        eprintln!("Captun failed to start: {e}");
        std::process::exit(1);
    }
}
