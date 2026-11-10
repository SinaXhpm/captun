//! Minimal command-line client for poking a running service:
//! `cargo run -p captun-ipc --example ctl -- <token-file> <command> [endpoint]`
//! where command is `status`, `clients`, `config`, `interfaces`, `adb-devices`
//! or `test:<egress-id>`.

use std::path::PathBuf;

use captun_ipc::{Endpoint, IpcClient, Request, Token};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: ctl <token-file> <status|clients|config|interfaces|adb-devices|test:<egress>> [endpoint]";
    let token_file = PathBuf::from(args.next().ok_or(usage)?);
    let command = args.next().ok_or(usage)?;
    let endpoint = args.next().map(Endpoint::new).unwrap_or_else(Endpoint::default_service);

    let request = match command.as_str() {
        "status" => Request::GetStatus,
        "clients" => Request::ListClients,
        "config" => Request::GetConfig,
        "interfaces" => Request::ListInterfaces,
        "adb-devices" => Request::ListAdbDevices,
        other => match other.strip_prefix("test:") {
            Some(id) => Request::TestEgress { id: id.into(), target: None },
            None => return Err(usage.into()),
        },
    };

    let token = Token::read(&token_file)?;
    let (client, _events) = IpcClient::connect(&endpoint, &token).await?;
    let response = client.call(request).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
