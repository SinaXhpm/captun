use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    ClientFrame, Endpoint, Event, FrameError, FrameReader, FrameWriter, IpcError, IpcStream, PROTOCOL_VERSION, Request,
    Response, ServerFrame, Token, connect,
    handshake::{self, HANDSHAKE_TIMEOUT},
    legacy, split,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_BUFFER: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("cannot reach the Captun service: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// What answered could not prove it holds the token, so it was sent
    /// nothing: another program holding the service's name, or a service
    /// that wrote a different token.
    #[error("the program that answered could not prove it is the Captun service, so nothing was sent to it")]
    NotTheService,
    /// The service refused the greeting outright, as services from before
    /// version 2 do; [`IpcClient::shutdown_legacy`] can stop one.
    #[error("the service refused this app's greeting, as older Captun services do")]
    OlderService,
    #[error("the service speaks protocol version {service}, this app {}", PROTOCOL_VERSION)]
    VersionMismatch { service: u32 },
    #[error("the service closed the connection")]
    Disconnected,
    #[error("the service did not answer in time")]
    Timeout,
    #[error("{}", .0.message)]
    Service(#[from] IpcError),
}

impl CallError {
    /// Whether a failed [`IpcClient::connect`] means a service older than
    /// this app holds the name, one [`IpcClient::shutdown_legacy`] can stop.
    /// Only the refusal older services give: an older version named in a
    /// challenge or a welcome comes from no real service.
    pub fn is_older_service(&self) -> bool {
        matches!(self, Self::OlderService)
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Response, IpcError>>>>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// GUI-side connection. Requests may be issued concurrently from many tasks;
/// pushed events arrive on the receiver returned by [`IpcClient::connect`].
pub struct IpcClient {
    next_id: AtomicU64,
    pending: Pending,
    writer: tokio::sync::Mutex<FrameWriter<WriteHalf<IpcStream>, ClientFrame>>,
    service_version: String,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for IpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcClient")
            .field("service_version", &self.service_version)
            .field("connected", &self.is_connected())
            .finish_non_exhaustive()
    }
}

impl IpcClient {
    /// Connects and proves both ways that each side holds `token`, which
    /// never crosses the connection: nothing at all is sent before the
    /// service has proved itself (see [`crate::handshake`]).
    pub async fn connect(endpoint: &Endpoint, token: &Token) -> Result<(Self, mpsc::Receiver<Event>), CallError> {
        let stream = connect(endpoint).await?;
        let (mut reader, mut writer) = split::<_, ServerFrame, ClientFrame>(stream);
        let service_version = timeout(HANDSHAKE_TIMEOUT, handshake::open(&mut reader, &mut writer, token))
            .await
            .map_err(|_| CallError::Timeout)??;

        let pending: Pending = Arc::default();
        let (events_tx, events_rx) = mpsc::channel(EVENT_BUFFER);
        let reader = tokio::spawn(read_loop(reader, pending.clone(), events_tx));
        let client = Self {
            next_id: AtomicU64::new(1),
            pending,
            writer: tokio::sync::Mutex::new(writer),
            service_version,
            reader,
        };
        Ok((client, events_rx))
    }

    /// Stops a service from before version 2 so a new one can take the name
    /// it holds. Speaks the old protocol only that far: the old greeting,
    /// which carries `token` itself, then `Shutdown`; never settings or
    /// anything else. Returns once the service has closed the connection,
    /// which it does only as its process ends, after it has turned sharing
    /// off and removed its token. Until then this connection keeps the pipe
    /// name taken (on Windows), so a new service cannot start too early and
    /// then lose its token to the old one's last step. One still running
    /// after 2 minutes is reported as [`CallError::Timeout`].
    ///
    /// Only for what refused [`IpcClient::connect`]'s greeting
    /// ([`CallError::is_older_service`]). Something posing as an old service
    /// gains nothing from the token: while a service runs it holds the name
    /// itself, so whatever answers in its place can only meet a stale token.
    pub async fn shutdown_legacy(endpoint: &Endpoint, token: &Token) -> Result<(), CallError> {
        legacy::shutdown(connect(endpoint).await?, token).await
    }

    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    pub fn is_connected(&self) -> bool {
        !self.reader.is_finished()
    }

    pub async fn call(&self, request: Request) -> Result<Response, CallError> {
        if !self.is_connected() {
            return Err(CallError::Disconnected);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, tx);

        let sent = self.writer.lock().await.send(&ClientFrame::Request { id, request }).await;
        if let Err(e) = sent {
            lock(&self.pending).remove(&id);
            return Err(e.into());
        }
        match timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(result)) => result.map_err(CallError::Service),
            Ok(Err(_)) => Err(CallError::Disconnected),
            Err(_) => {
                lock(&self.pending).remove(&id);
                Err(CallError::Timeout)
            }
        }
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn read_loop(
    mut reader: FrameReader<ReadHalf<IpcStream>, ServerFrame>,
    pending: Pending,
    events: mpsc::Sender<Event>,
) {
    loop {
        match reader.next().await {
            Ok(Some(ServerFrame::Response { id, result })) => {
                if let Some(tx) = lock(&pending).remove(&id) {
                    let _ = tx.send(result);
                }
            }
            // Snapshots supersede each other, so a slow GUI losing one is fine.
            Ok(Some(ServerFrame::Event { event })) => {
                let _ = events.try_send(event);
            }
            Ok(Some(ServerFrame::Welcome { .. } | ServerFrame::Challenge { .. })) => {}
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("IPC connection lost: {e}");
                break;
            }
        }
    }
    // Dropping the senders wakes every waiting caller with `Disconnected`.
    lock(&pending).clear();
}
