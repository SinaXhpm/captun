//! Just enough of protocol version 1 to stop a service from before version 2,
//! so a new one can take the name it holds: such a service refuses the new
//! greeting outright ([`CallError::OlderService`]). The old greeting carries
//! the token itself, so nothing but that greeting and `Shutdown` is ever sent.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

use crate::{CallError, FrameError, IpcError, Token, handshake::HANDSHAKE_TIMEOUT, split};

const VERSION: u32 = 1;
const SHUTDOWN_ID: u64 = 1;
/// How long the stopped service may take to close the connection. It does so
/// only as its process ends, after turning sharing off (USB, cable sharing,
/// the hotspot, device rules) and then removing its token, which can take a
/// while.
const EXIT_WAIT: Duration = Duration::from_secs(120);

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Outgoing<'a> {
    Hello { version: u32, token: &'a str },
    Request { id: u64, request: Stop },
}

/// The one request there is.
#[derive(Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum Stop {
    Shutdown,
}

/// What an old service sends, read loosely: its events and answers may not
/// match today's.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Incoming {
    Welcome { version: u32 },
    Response { id: u64, result: Value },
    #[serde(other)]
    Other,
}

/// Greets the old service with `token`, asks it to stop, and waits until it
/// has closed the connection; [`CallError::Timeout`] if that takes longer
/// than [`EXIT_WAIT`].
pub(crate) async fn shutdown<S>(stream: S, token: &Token) -> Result<(), CallError>
where
    S: AsyncRead + AsyncWrite,
{
    shutdown_within(stream, token, HANDSHAKE_TIMEOUT, EXIT_WAIT).await
}

async fn shutdown_within<S>(stream: S, token: &Token, limit: Duration, exit_wait: Duration) -> Result<(), CallError>
where
    S: AsyncRead + AsyncWrite,
{
    let (mut reader, mut writer) = split::<_, Incoming, Outgoing<'_>>(stream);
    let asked = async {
        writer.send(&Outgoing::Hello { version: VERSION, token: token.as_str() }).await?;
        match reader.next().await? {
            Some(Incoming::Welcome { version: VERSION }) => {}
            Some(Incoming::Welcome { version }) => return Err(CallError::VersionMismatch { service: version }),
            Some(Incoming::Response { result, .. }) => {
                outcome(&result)?;
                return Err(CallError::Handshake("the older service answered before greeting this app".into()));
            }
            Some(Incoming::Other) => {
                return Err(CallError::Handshake("the older service sent something else than a greeting".into()));
            }
            None => return Err(CallError::Disconnected),
        }
        writer.send(&Outgoing::Request { id: SHUTDOWN_ID, request: Stop::Shutdown }).await?;
        loop {
            match reader.next().await? {
                Some(Incoming::Response { id: SHUTDOWN_ID, result }) => return outcome(&result),
                // Events it pushes meanwhile.
                Some(_) => {}
                None => return Err(CallError::Disconnected),
            }
        }
    };
    timeout(limit, asked).await.map_err(|_| CallError::Timeout)??;
    // Held open until the old service closes it. Its listener is gone by
    // now, but on Windows this connection still holds the pipe name, so no
    // new service can start before the old one has removed its token, which
    // shares the new one's path. Lines it sends meanwhile, readable or not,
    // change nothing.
    let closed = async {
        loop {
            match reader.next().await {
                Ok(Some(_)) | Err(FrameError::Json(_) | FrameError::TooLarge) => {}
                Ok(None) | Err(FrameError::Io(_)) => return,
            }
        }
    };
    timeout(exit_wait, closed).await.map_err(|_| CallError::Timeout)
}

/// An old answer: `{"Ok": …}` or `{"Err": {"code": …, "message": …}}`.
fn outcome(result: &Value) -> Result<(), CallError> {
    match result.get("Err") {
        None => Ok(()),
        Some(error) => Err(serde_json::from_value::<IpcError>(error.clone())
            .map_or_else(|_| CallError::Handshake("the older service refused".into()), CallError::Service)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf, duplex};

    use super::*;
    use crate::{ErrorCode, FrameReader};

    /// The old service's end, read and written as plain lines of JSON.
    struct OldService {
        reader: FrameReader<ReadHalf<DuplexStream>, Value>,
        writer: WriteHalf<DuplexStream>,
    }

    impl OldService {
        fn new(stream: DuplexStream) -> Self {
            let (reader, writer) = tokio::io::split(stream);
            Self { reader: FrameReader::new(reader), writer }
        }

        async fn read(&mut self) -> Option<Value> {
            self.reader.next().await.unwrap()
        }

        async fn send(&mut self, frame: Value) {
            self.writer.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn an_old_service_is_greeted_then_asked_to_stop_and_nothing_else() {
        let token = Token::generate();
        let (service, app) = duplex(64 * 1024);
        let mut old = OldService::new(service);
        let stopping = {
            let token = token.clone();
            tokio::spawn(async move { shutdown(app, &token).await })
        };

        assert_eq!(old.read().await, Some(json!({ "type": "hello", "version": 1, "token": token.as_str() })));
        old.send(json!({ "type": "welcome", "version": 1, "service_version": "0.1.0" })).await;
        // Events of its own kind come first, as an old service sends them.
        old.send(json!({ "type": "event", "event": { "kind": "something_new", "data": [1, 2] } })).await;
        assert_eq!(old.read().await, Some(json!({ "type": "request", "id": 1, "request": { "method": "shutdown" } })));
        old.send(json!({ "type": "response", "id": 1, "result": { "Ok": { "kind": "ok" } } })).await;
        // It exits, closing the connection.
        old.writer.shutdown().await.unwrap();

        stopping.await.unwrap().unwrap();
        assert_eq!(old.read().await, None, "nothing else was sent");
    }

    #[tokio::test]
    async fn an_old_service_that_refuses_the_token_is_not_asked_anything() {
        let (service, app) = duplex(64 * 1024);
        let mut old = OldService::new(service);
        let stopping = tokio::spawn(async move { shutdown(app, &Token::generate()).await });

        assert_eq!(old.read().await.unwrap()["type"], "hello");
        old.send(json!({ "type": "response", "id": 0, "result": { "Err": { "code": "unauthorized", "message": "invalid IPC token" } } }))
            .await;
        let err = stopping.await.unwrap().unwrap_err();
        assert!(matches!(err, CallError::Service(IpcError { code: ErrorCode::Unauthorized, .. })), "{err:?}");
        assert_eq!(old.read().await, None);
    }

    /// Greets and stops `old`, leaving the connection open.
    async fn agree_to_stop(old: &mut OldService) {
        old.read().await.unwrap();
        old.send(json!({ "type": "welcome", "version": 1, "service_version": "0.1.0" })).await;
        old.read().await.unwrap();
        old.send(json!({ "type": "response", "id": 1, "result": { "Ok": { "kind": "ok" } } })).await;
    }

    #[tokio::test]
    async fn the_connection_stays_open_until_the_old_service_closes_it() {
        let (service, app) = duplex(64 * 1024);
        let mut old = OldService::new(service);
        let stopping = tokio::spawn(async move { shutdown(app, &Token::generate()).await });
        agree_to_stop(&mut old).await;

        // While it turns sharing off it may still send updates, of any shape.
        old.send(json!({ "type": "event", "event": { "kind": "hotspot", "data": {} } })).await;
        old.writer.write_all(b"not json\n").await.unwrap();
        old.send(json!({ "type": "welcome", "version": "one" })).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!stopping.is_finished(), "the app let go before the old service was gone");

        // Its process ends.
        old.writer.shutdown().await.unwrap();
        stopping.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_service_that_agrees_but_does_not_stop_is_reported_after_the_wait() {
        let (service, app) = duplex(64 * 1024);
        let mut old = OldService::new(service);
        let stopping = tokio::spawn(async move {
            shutdown_within(app, &Token::generate(), HANDSHAKE_TIMEOUT, Duration::from_millis(50)).await
        });
        agree_to_stop(&mut old).await;
        let err = stopping.await.unwrap().unwrap_err();
        assert!(matches!(err, CallError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn a_newer_or_silent_service_is_not_asked_to_stop() {
        let (service, app) = duplex(64 * 1024);
        let mut old = OldService::new(service);
        let stopping = tokio::spawn(async move { shutdown(app, &Token::generate()).await });
        old.read().await.unwrap();
        old.send(json!({ "type": "welcome", "version": 3, "service_version": "9.0.0" })).await;
        assert!(matches!(stopping.await.unwrap(), Err(CallError::VersionMismatch { service: 3 })));
        assert_eq!(old.read().await, None);

        let (_service, app) = duplex(64 * 1024);
        let limit = Duration::from_millis(50);
        let silent = shutdown_within(app, &Token::generate(), limit, limit).await;
        assert!(matches!(silent, Err(CallError::Timeout)), "{silent:?}");
    }
}
