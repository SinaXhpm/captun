//! Read-only probe: prints interfaces and the hotspot state without changing
//! anything. `cargo run -p captun-platform --example probe`

#[tokio::main]
async fn main() {
    for i in captun_platform::iface::list().iter().filter(|i| !i.loopback) {
        println!(
            "iface #{:<3} {:<28} {:<9} physical={:<5} up={:<5} v4={:?} gw={:?} default={} speed={:?}",
            i.index,
            i.name,
            format!("{:?}", i.kind),
            i.physical,
            i.up,
            i.ipv4,
            i.gateway,
            i.default_route,
            i.speed_mbps
        );
    }
    println!("hotspot support: {:?}", captun_platform::hotspot_support());
    let backend = captun_platform::default_backend();
    println!("notes: {:?}", backend.notes());
    println!("state: {:?}", backend.state().await);
    println!("clients: {:?}", backend.clients().await);
}
