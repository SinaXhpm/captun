//! Accepts GUI connections: each proves, both ways, that it holds this run's
//! token (see `captun_ipc::handshake`), then requests are served
//! concurrently and hub events fanned out.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use captun_ipc::{
    ClientFrame, ErrorCode, Event, FrameError, FrameWriter, IpcError, IpcListener, IpcStream, ServerFrame, Token, handshake,
    split,
};
use tokio::{
    io::AsyncWrite,
    sync::{broadcast::error::RecvError, mpsc},
};
use tracing::{debug, warn};

use crate::hub::Hub;

const MAX_SESSIONS: usize = 16;
const OUTBOX: usize = 256;
/// Updates too large to send are skipped; a warning says so at most this often.
const SKIPPED_WARNING_EVERY: Duration = Duration::from_secs(60);

pub(crate) async fn serve(mut listener: IpcListener, hub: Arc<Hub>, token: Token) -> anyhow::Result<()> {
    let token = Arc::new(token);
    let sessions = Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS));
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                warn!("IPC accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Ok(permit) = sessions.clone().try_acquire_owned() else {
            warn!("too many GUI connections; refusing a new one");
            continue;
        };
        let (hub, token) = (hub.clone(), token.clone());
        tokio::spawn(async move {
            session(stream, hub, &token).await;
            drop(permit);
        });
    }
}

async fn session(stream: IpcStream, hub: Arc<Hub>, token: &Token) {
    let (mut rx, mut tx) = split::<_, ClientFrame, ServerFrame>(stream);

    if let Err(why) = handshake::accept(&mut rx, &mut tx, token, env!("CARGO_PKG_VERSION")).await {
        warn!("refused a connection: {why}");
        return;
    }
    debug!("GUI connected");

    let (outbox, outbox_rx) = mpsc::channel::<ServerFrame>(OUTBOX);
    let mut writer = tokio::spawn(write_frames(tx, outbox_rx));

    let forwarder = {
        let outbox = outbox.clone();
        let mut events = hub.subscribe();
        let initial = [Event::Hotspot(hub.hotspot_status()), Event::Clients(hub.client_views())];
        tokio::spawn(async move {
            for event in initial {
                if outbox.send(ServerFrame::Event { event }).await.is_err() {
                    return;
                }
            }
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if outbox.send(ServerFrame::Event { event }).await.is_err() {
                            break;
                        }
                    }
                    // A slow GUI misses some events; snapshots catch it up.
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
        })
    };

    // A writer that stopped ends the session too: the connection closes, and
    // the GUI notices and connects again rather than wait on answers that
    // never come.
    let writer_done = loop {
        tokio::select! {
            frame = rx.next() => match frame {
                Ok(Some(ClientFrame::Request { id, request })) => {
                    let (hub, outbox) = (hub.clone(), outbox.clone());
                    tokio::spawn(async move {
                        let result = hub.handle(request).await;
                        let _ = outbox.send(ServerFrame::Response { id, result }).await;
                    });
                }
                Ok(Some(ClientFrame::Hello { .. } | ClientFrame::Auth { .. })) => {}
                Ok(None) => break false,
                Err(e) => {
                    warn!("dropping GUI connection: {e}");
                    break false;
                }
            },
            _ = &mut writer => {
                debug!("stopped answering the GUI; closing its connection");
                break true;
            }
        }
    };

    forwarder.abort();
    drop(outbox);
    // Finished already when select! saw it end; a JoinHandle is not polled again.
    if !writer_done {
        let _ = writer.await;
    }
    debug!("GUI disconnected");
}

/// Sends queued frames in order until the queue closes or the connection
/// fails. A frame too large to send never ends the connection: an answer
/// becomes an error the GUI can show, an update is skipped (the next
/// snapshot replaces it).
async fn write_frames<W: AsyncWrite + Unpin>(
    mut tx: FrameWriter<W, ServerFrame>,
    mut outbox: mpsc::Receiver<ServerFrame>,
) {
    let mut last_skip_warning: Option<Instant> = None;
    while let Some(frame) = outbox.recv().await {
        let error = match tx.send(&frame).await {
            Ok(()) => continue,
            Err(e) => e,
        };
        if !matches!(error, FrameError::TooLarge) {
            debug!("cannot write to the GUI: {error}");
            break;
        }
        match frame {
            ServerFrame::Response { id, .. } => {
                warn!("an answer to the GUI was too large to send; it gets an error instead");
                let error = IpcError::new(ErrorCode::Internal, "The answer was too large to send.");
                if tx.send(&ServerFrame::Response { id, result: Err(error) }).await.is_err() {
                    break;
                }
            }
            ServerFrame::Event { event } => {
                let what = match &event {
                    Event::Clients(devices) => format!("the device list ({} devices)", devices.len()),
                    _ => "an update".to_owned(),
                };
                if last_skip_warning.is_none_or(|at| at.elapsed() >= SKIPPED_WARNING_EVERY) {
                    warn!("skipped sending {what} to the GUI: it was too large to send");
                    last_skip_warning = Some(Instant::now());
                } else {
                    debug!("skipped sending {what} to the GUI: it was too large to send");
                }
            }
            // Only the greeting sends these, never this large.
            ServerFrame::Challenge { .. } | ServerFrame::Welcome { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };

    use captun_core::Config;
    use captun_ipc::{Endpoint, FrameReader, IpcClient, MAX_FRAME_BYTES, PipeAccess, Request, Response};
    use tokio::{
        io::{AsyncRead, ReadBuf, duplex},
        sync::broadcast,
    };

    use super::*;

    /// A connection whose writes fail once `broken` is set, while reading
    /// goes on.
    struct BreakableWrites {
        inner: IpcStream,
        broken: Arc<AtomicBool>,
    }

    impl AsyncRead for BreakableWrites {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for BreakableWrites {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.broken.load(Ordering::SeqCst) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn a_session_whose_writer_stopped_closes_the_connection() {
        #[cfg(windows)]
        let endpoint = Endpoint::new(format!(r"\\.\pipe\captun-daemon-test-writer-{}", std::process::id()));
        #[cfg(unix)]
        let endpoint = Endpoint::new(
            std::env::temp_dir().join(format!("captun-daemon-test-writer-{}.sock", std::process::id())).display().to_string(),
        );
        let mut listener = IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).unwrap();
        let token = Token::generate();
        let (events, _events) = broadcast::channel(16);
        let hub = Hub::new(None, Config::default(), captun_platform::default_backend(), events, None);
        let broken = Arc::new(AtomicBool::new(false));
        let served = {
            let (token, broken) = (token.clone(), broken.clone());
            tokio::spawn(async move {
                let stream = listener.accept().await.unwrap();
                session(Box::new(BreakableWrites { inner: stream, broken }), hub, &token).await;
            })
        };

        let (client, _updates) = IpcClient::connect(&endpoint, &token).await.unwrap();
        broken.store(true, Ordering::SeqCst);
        // The answer cannot be written, so the writer stops...
        let answer = tokio::time::timeout(Duration::from_secs(10), client.call(Request::GetRuleHits)).await.unwrap();
        assert!(answer.is_err(), "{answer:?}");
        // ...and the session ends with it, closing the connection, though
        // the GUI's side could still be read.
        tokio::time::timeout(Duration::from_secs(10), served).await.unwrap().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while client.is_connected() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!client.is_connected(), "the GUI saw the connection close, so it connects again");
    }

    #[tokio::test]
    async fn frames_too_large_to_send_never_end_the_connection() {
        let (service, gui) = duplex(64 * 1024);
        let (_, tx) = split::<_, ClientFrame, ServerFrame>(service);
        let mut gui = FrameReader::<_, ServerFrame>::new(gui);
        let (outbox, outbox_rx) = mpsc::channel(8);
        let writer = tokio::spawn(write_frames(tx, outbox_rx));

        let huge = "x".repeat(MAX_FRAME_BYTES);
        let log = |message: &str| {
            Event::Log(captun_ipc::LogLine {
                at_ms: 0,
                level: captun_ipc::LogLevel::Info,
                target: "test".into(),
                message: message.into(),
            })
        };
        // An answer too large: the GUI gets an error under the same id.
        let config_error = IpcError::new(ErrorCode::InvalidConfig, huge.clone());
        outbox.send(ServerFrame::Response { id: 7, result: Err(config_error) }).await.unwrap();
        // An update too large: skipped, and what follows still arrives.
        outbox.send(ServerFrame::Event { event: log(&huge) }).await.unwrap();
        outbox.send(ServerFrame::Event { event: log("small") }).await.unwrap();
        outbox.send(ServerFrame::Response { id: 8, result: Ok(Response::Ok) }).await.unwrap();

        let Some(ServerFrame::Response { id: 7, result: Err(e) }) = gui.next().await.unwrap() else { panic!("no error answer") };
        assert_eq!((e.code, e.message.as_str()), (ErrorCode::Internal, "The answer was too large to send."));
        let Some(ServerFrame::Event { event: Event::Log(line) }) = gui.next().await.unwrap() else { panic!("no update") };
        assert_eq!(line.message, "small");
        assert!(matches!(gui.next().await.unwrap(), Some(ServerFrame::Response { id: 8, result: Ok(_) })));

        drop(outbox);
        writer.await.unwrap();
        assert!(gui.next().await.unwrap().is_none(), "the queue closed, so did the connection");
    }

    #[tokio::test]
    async fn a_connection_that_fails_stops_the_writer() {
        let (service, gui) = duplex(1024);
        let (_, tx) = split::<_, ClientFrame, ServerFrame>(service);
        drop(gui);
        let (outbox, outbox_rx) = mpsc::channel(8);
        let writer = tokio::spawn(write_frames(tx, outbox_rx));
        outbox.send(ServerFrame::Response { id: 1, result: Ok(Response::Ok) }).await.unwrap();
        // It ends on its own, while the queue is still open.
        tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap();
        assert!(outbox.send(ServerFrame::Response { id: 2, result: Ok(Response::Ok) }).await.is_err());
    }
}
