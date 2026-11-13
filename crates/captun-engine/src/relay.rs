use std::{io, time::Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::meter::{Direction, FlowMeter, SharedBucket};

/// Read buffer per direction. Big enough to keep throughput up, small enough
/// that a rate-limited flow is paced smoothly rather than in large bursts.
const CHUNK: usize = 16 * 1024;

/// Waits as long as `bucket` (the device's limit in one direction, shared by
/// its flows, and the limit on all devices together) asks before `bytes` may
/// go.
pub(crate) async fn pace(bucket: Option<&SharedBucket>, bytes: usize) {
    let Some(bucket) = bucket else { return };
    let wait = bucket.take(bytes, Instant::now());
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

/// Whether a datagram of `bytes` may go now under `bucket`, the device's
/// limit in one direction and the one on all devices together. One that may
/// not is dropped, as a link at its limit would drop it: datagrams are never
/// held back, so no queue of them builds up behind the limit, and the apps
/// that send them slow down.
pub(crate) fn within_limit(bucket: Option<&SharedBucket>, bytes: usize) -> bool {
    bucket.is_none_or(|bucket| bucket.try_take(bytes, Instant::now()))
}

/// Copies one direction of a flow until EOF, pacing it to the device's limit
/// (when set) and recording every byte. Returns the total copied.
///
/// The destination is shut down for writing on EOF so the peer sees the
/// half-close; the whole-flow helpers below tie the two directions together.
pub(crate) async fn pump<R, W>(
    mut from: R,
    mut to: W,
    direction: Direction,
    limit: Option<SharedBucket>,
    meter: &FlowMeter,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        pace(limit.as_ref(), n).await;
        to.write_all(&buf[..n]).await?;
        total += n as u64;
        meter.add(direction, n as u64);
    }
    // Best-effort half-close; the peer may already be gone.
    let _ = to.shutdown().await;
    Ok(total)
}

/// Relays a bidirectional stream flow between a hotspot client and an upstream,
/// applying the download/upload limits and metering both directions. Finishes
/// when either side closes.
pub(crate) async fn relay_stream<C, U>(
    client: C,
    upstream: U,
    down_limit: Option<SharedBucket>,
    up_limit: Option<SharedBucket>,
    meter: FlowMeter,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (client_r, client_w) = tokio::io::split(client);
    let (upstream_r, upstream_w) = tokio::io::split(upstream);

    // Upload: client → internet. Download: internet → client.
    let up = pump(client_r, upstream_w, Direction::Up, up_limit, &meter);
    let down = pump(upstream_r, client_w, Direction::Down, down_limit, &meter);

    tokio::pin!(up, down);
    let mut up_done = false;
    let mut down_done = false;
    // When one direction ends, keep the other going until it, too, closes, so
    // a server that answers after the client finished sending is not cut off.
    loop {
        tokio::select! {
            result = &mut up, if !up_done => {
                up_done = true;
                result?;
            }
            result = &mut down, if !down_done => {
                down_done = true;
                result?;
            }
            else => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::meter::TrafficMeter;

    #[tokio::test]
    async fn pump_copies_and_meters() {
        let (mut src_w, src_r) = duplex(4096);
        let (dst_w, mut dst_r) = duplex(4096);
        let meter = TrafficMeter::new();
        let flow = FlowMeter::new(meter.counters(None));

        let task = tokio::spawn(async move { pump(src_r, dst_w, Direction::Down, None, &flow).await });
        src_w.write_all(b"hello world").await.unwrap();
        drop(src_w);

        let mut got = Vec::new();
        dst_r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world");
        assert_eq!(task.await.unwrap().unwrap(), 11);
        assert_eq!(meter.unattributed().down_bytes, 11);
    }

    #[tokio::test]
    async fn pump_respects_rate_limit() {
        let (mut src_w, src_r) = duplex(1 << 20);
        let (dst_w, mut dst_r) = duplex(1 << 20);
        let meter = TrafficMeter::new();
        let flow = FlowMeter::new(meter.counters(None));

        // 800 kbit/s = 100 000 B/s, burst a quarter second (25 000 B, above the
        // 16 KiB floor). Sending 100 000 bytes incurs ~75 000 B of debt, i.e.
        // ~0.75 s of pacing. `TokenBucket` keeps real (std) time, so this must
        // run unpaused.
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            dst_r.read_to_end(&mut got).await.unwrap();
            got.len()
        });
        let start = Instant::now();
        let limit = meter.bucket(None, Direction::Up, Some(800));
        let task = tokio::spawn(async move { pump(src_r, dst_w, Direction::Up, limit, &flow).await });
        src_w.write_all(&vec![7u8; 100_000]).await.unwrap();
        drop(src_w);

        assert_eq!(reader.await.unwrap(), 100_000);
        assert!(start.elapsed() >= Duration::from_millis(400), "rate limit not applied: {:?}", start.elapsed());
        assert_eq!(task.await.unwrap().unwrap(), 100_000);
    }

    #[tokio::test]
    async fn a_devices_flows_share_its_limit() {
        // Two flows of one device at 800 kbit/s (100 000 B/s, 25 000 B burst):
        // 120 000 bytes together run ~95 000 B into debt, ~0.95 s. With a
        // bucket per flow each would pay only its own ~35 000 B (~0.35 s).
        let meter = TrafficMeter::new();
        let device = Some(captun_core::MacAddr::new([2, 0, 0, 0, 0, 1]));
        let start = Instant::now();
        let flows: Vec<_> = (0..2)
            .map(|_| {
                let (mut src_w, src_r) = duplex(1 << 20);
                let (dst_w, mut dst_r) = duplex(1 << 20);
                let flow = FlowMeter::new(meter.counters(device));
                let limit = meter.bucket(device, Direction::Down, Some(800));
                tokio::spawn(async move {
                    let reader = tokio::spawn(async move {
                        let mut got = Vec::new();
                        dst_r.read_to_end(&mut got).await.unwrap();
                        got.len()
                    });
                    let pumped = tokio::spawn(async move { pump(src_r, dst_w, Direction::Down, limit, &flow).await });
                    src_w.write_all(&vec![7u8; 60_000]).await.unwrap();
                    drop(src_w);
                    assert_eq!(reader.await.unwrap(), 60_000);
                    pumped.await.unwrap().unwrap()
                })
            })
            .collect();
        for flow in flows {
            assert_eq!(flow.await.unwrap(), 60_000);
        }
        assert!(start.elapsed() >= Duration::from_millis(700), "the flows did not share the limit: {:?}", start.elapsed());
    }

    #[tokio::test]
    async fn relay_is_bidirectional() {
        // Upstream echoes; client sends and expects the echo back.
        let (client_side, client_inner) = duplex(4096);
        let (upstream_outer, mut upstream_inner) = duplex(4096);
        let meter = TrafficMeter::new();
        let flow = FlowMeter::new(meter.counters(None));

        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = upstream_inner.read(&mut buf).await.unwrap();
            upstream_inner.write_all(&buf[..n]).await.unwrap();
            upstream_inner.shutdown().await.unwrap();
        });
        let relay = tokio::spawn(relay_stream(client_inner, upstream_outer, None, None, flow));

        let (mut cr, mut cw) = tokio::io::split(client_side);
        cw.write_all(b"ping").await.unwrap();
        cw.shutdown().await.unwrap();
        let mut got = Vec::new();
        cr.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");

        echo.await.unwrap();
        relay.await.unwrap().unwrap();
        let snap = meter.unattributed();
        assert_eq!((snap.down_bytes, snap.up_bytes), (4, 4));
    }
}
