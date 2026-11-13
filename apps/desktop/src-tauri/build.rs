use std::{collections::BTreeSet, path::Path};

/// Commands the webview may invoke. Declaring them in the app manifest turns
/// on Tauri's ACL for app commands, so `capabilities/default.json` has to
/// grant each one explicitly.
const COMMANDS: &[&str] = &[
    "connection_status",
    "start_service",
    "get_status",
    "start_hotspot",
    "stop_hotspot",
    "hotspot_support",
    "describe_link",
    "app_info",
    "open_link",
    "check_update",
    "start_access_network",
    "stop_access_network",
    "stop_service",
    "list_clients",
    "set_client_profile",
    "forget_client",
    "get_config",
    "set_config",
    "list_interfaces",
    "test_egress",
    "list_adb_devices",
    "set_reverse_tether",
    "get_lists",
    "update_lists",
    "get_rule_hits",
    "test_rules",
    "get_usage",
    "reset_quota",
    "add_quota",
];

fn main() {
    check_commands_are_granted();
    let attributes = tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(e) = tauri_build::try_build(attributes) {
        panic!("tauri build step failed: {e:#}");
    }
}

/// Fails the build when the three lists of commands disagree: the ones
/// `src/main.rs` registers, [`COMMANDS`], and the ones
/// `capabilities/default.json` grants. Tauri refuses a registered command
/// that is not granted only at run time, with a message no test sees.
fn check_commands_are_granted() {
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=capabilities/default.json");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
    };

    let main = read("src/main.rs");
    let Some(start) = main.find("generate_handler![") else {
        panic!("src/main.rs no longer registers its commands with generate_handler!");
    };
    let Some(len) = main[start..].find(']') else {
        panic!("generate_handler! in src/main.rs has no closing ]");
    };
    let registered: BTreeSet<&str> = main[start..start + len]
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|word| word.strip_prefix("commands::"))
        .collect();

    let capabilities = read("capabilities/default.json");
    let granted: BTreeSet<String> = capabilities
        .split('"')
        .filter_map(|text| text.strip_prefix("allow-"))
        .map(|name| name.replace('-', "_"))
        .collect();

    let declared: BTreeSet<&str> = COMMANDS.iter().copied().collect();
    let mut problems = Vec::new();
    for name in registered.difference(&declared) {
        problems.push(format!("{name} is registered in src/main.rs but missing from COMMANDS in build.rs"));
    }
    for name in declared.difference(&registered) {
        problems.push(format!("{name} is in COMMANDS in build.rs but not registered in src/main.rs"));
    }
    for name in &declared {
        if !granted.contains(*name) {
            let permission = name.replace('_', "-");
            problems.push(format!("{name} is not granted: add \"allow-{permission}\" to capabilities/default.json"));
        }
    }
    for name in &granted {
        if !declared.contains(name.as_str()) {
            problems.push(format!("capabilities/default.json grants {name}, which COMMANDS in build.rs does not list"));
        }
    }
    assert!(problems.is_empty(), "the app's command lists disagree:\n{}", problems.join("\n"));
}
