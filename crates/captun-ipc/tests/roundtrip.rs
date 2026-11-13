#![allow(clippy::unwrap_used)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use captun_ipc::{
    CallError, ClientFrame, Endpoint, ErrorCode, Event, IpcClient, IpcError, IpcListener, PipeAccess, Request, Response,
    ServerFrame, Token, handshake, split,
};
use serde_json::{Value, json};

fn test_endpoint(name: &str) -> Endpoint {
    #[cfg(windows)]
    return Endpoint::new(format!(r"\\.\pipe\captun-test-{name}-{}", std::process::id()));
    #[cfg(unix)]
    return Endpoint::new(std::env::temp_dir().join(format!("captun-test-{name}-{}.sock", std::process::id())).display().to_string());
}

/// A tiny service: proves itself with the token, answers GetStatus with an
/// error and everything else with Ok, and pushes one event after the handshake.
fn spawn_service(endpoint: &Endpoint, token: Token) {
    let mut listener = IpcListener::bind(endpoint, &PipeAccess::InteractiveUsers).unwrap();
    tokio::spawn(async move {
        loop {
            let stream = listener.accept().await.unwrap();
            let token = token.clone();
            tokio::spawn(async move {
                let (mut rx, mut tx) = split::<_, ClientFrame, ServerFrame>(stream);
                if handshake::accept(&mut rx, &mut tx, &token, "test").await.is_err() {
                    return;
                }
                tx.send(&ServerFrame::Event { event: Event::ConfigChanged }).await.unwrap();
                while let Ok(Some(ClientFrame::Request { id, request })) = rx.next().await {
                    let result = match request {
                        Request::GetStatus => Err(IpcError::new(ErrorCode::Internal, "no status in tests")),
                        _ => Ok(Response::Ok),
                    };
                    tx.send(&ServerFrame::Response { id, result }).await.unwrap();
                }
            });
        }
    });
}

/// A service from before version 2, as far as it matters here: it wants the
/// token in the greeting and stops when asked. Returns every frame it was
/// sent, in order.
fn spawn_old_service(endpoint: &Endpoint, token: Token) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut listener = IpcListener::bind(endpoint, &PipeAccess::InteractiveUsers).unwrap();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let stream = listener.accept().await.unwrap();
            let (token, log) = (token.clone(), log.clone());
            tokio::spawn(async move {
                let (mut rx, mut tx) = split::<_, Value, Value>(stream);
                let Ok(Some(hello)) = rx.next().await else { return };
                log.lock().unwrap().push(hello.clone());
                if hello["type"] != "hello" || hello["token"] != token.as_str() {
                    let refusal = json!({ "code": "unauthorized", "message": "invalid IPC token" });
                    tx.send(&json!({ "type": "response", "id": 0, "result": { "Err": refusal } })).await.unwrap();
                    return;
                }
                tx.send(&json!({ "type": "welcome", "version": 1, "service_version": "0.0.9" })).await.unwrap();
                tx.send(&json!({ "type": "event", "event": { "kind": "config_changed" } })).await.unwrap();
                while let Ok(Some(frame)) = rx.next().await {
                    log.lock().unwrap().push(frame.clone());
                    if frame["request"]["method"] == "shutdown" {
                        tx.send(&json!({ "type": "response", "id": frame["id"], "result": { "Ok": { "kind": "ok" } } }))
                            .await
                            .unwrap();
                        // Anything sent after this would be recorded too.
                        if let Ok(Ok(Some(more))) = tokio::time::timeout(Duration::from_millis(200), rx.next()).await {
                            log.lock().unwrap().push(more);
                        }
                        // ...then it exits, closing the connection.
                        return;
                    }
                }
            });
        }
    });
    seen
}

#[tokio::test]
async fn authenticated_session() {
    let endpoint = test_endpoint("auth");
    let token = Token::generate();
    spawn_service(&endpoint, token.clone());

    let (client, mut events) = IpcClient::connect(&endpoint, &token).await.unwrap();
    assert_eq!(client.service_version(), "test");
    assert!(matches!(events.recv().await, Some(Event::ConfigChanged)));

    assert!(matches!(client.call(Request::StartHotspot).await.unwrap(), Response::Ok));
    let err = client.call(Request::GetStatus).await.unwrap_err();
    assert!(matches!(err, CallError::Service(IpcError { code: ErrorCode::Internal, .. })));

    // Concurrent calls are matched to their own responses.
    let (a, b) = tokio::join!(client.call(Request::StopHotspot), client.call(Request::ListClients));
    assert!(a.is_ok() && b.is_ok());
}

#[tokio::test]
async fn a_service_with_another_token_is_not_trusted() {
    let endpoint = test_endpoint("deny");
    spawn_service(&endpoint, Token::generate());
    let err = IpcClient::connect(&endpoint, &Token::generate()).await.unwrap_err();
    assert!(matches!(err, CallError::NotTheService), "{err:?}");
    assert!(!err.is_older_service());
}

#[tokio::test]
async fn an_older_service_is_recognised_and_stopped_over_the_old_protocol() {
    let endpoint = test_endpoint("old");
    let token = Token::generate();
    let seen = spawn_old_service(&endpoint, token.clone());

    let err = IpcClient::connect(&endpoint, &token).await.unwrap_err();
    assert!(err.is_older_service(), "{err:?}");
    IpcClient::shutdown_legacy(&endpoint, &token).await.unwrap();

    let seen = seen.lock().unwrap().clone();
    let [new_greeting, old_greeting, stop] = seen.as_slice() else { panic!("{seen:?}") };
    // The new greeting carried no token; then the old one, Shutdown, and nothing else.
    assert_eq!(new_greeting["type"], "hello");
    assert!(new_greeting.get("token").is_none(), "{new_greeting}");
    assert_eq!(*old_greeting, json!({ "type": "hello", "version": 1, "token": token.as_str() }));
    assert_eq!(*stop, json!({ "type": "request", "id": 1, "request": { "method": "shutdown" } }));
}

/// An older service that was asked to stop has dropped its listener and
/// still turns sharing off; it removes its token, at the path a new service
/// writes to, only as it exits. Until then no new service may take the name.
#[cfg(windows)]
#[tokio::test]
async fn the_name_stays_taken_until_a_stopped_older_service_has_exited() {
    use tokio::sync::oneshot;

    let endpoint = test_endpoint("old-exit");
    let token = Token::generate();
    let mut listener = IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).unwrap();
    let (answered, answered_rx) = oneshot::channel();
    let (exit, exit_rx) = oneshot::channel::<()>();
    let old = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (mut rx, mut tx) = split::<_, Value, Value>(stream);
        rx.next().await.unwrap().unwrap();
        tx.send(&json!({ "type": "welcome", "version": 1, "service_version": "0.0.9" })).await.unwrap();
        let stop = rx.next().await.unwrap().unwrap();
        tx.send(&json!({ "type": "response", "id": stop["id"], "result": { "Ok": { "kind": "ok" } } })).await.unwrap();
        // No new connections from here on...
        drop(listener);
        answered.send(()).unwrap();
        // ...while it turns sharing off, then exits.
        let _ = exit_rx.await;
    });
    let stopping = {
        let (endpoint, token) = (endpoint.clone(), token.clone());
        tokio::spawn(async move { IpcClient::shutdown_legacy(&endpoint, &token).await })
    };

    answered_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!stopping.is_finished(), "the app let go while the old service was still running");
    assert!(IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).is_err(), "a new service could start too early");

    exit.send(()).unwrap();
    old.await.unwrap();
    stopping.await.unwrap().unwrap();
    IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).expect("the name is free once the old service is gone");
}

#[cfg(windows)]
#[tokio::test]
async fn pipe_name_cannot_be_squatted() {
    let endpoint = test_endpoint("squat");
    let _first = IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).unwrap();
    assert!(IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).is_err());
}

/// How the GUI and the service look for a running service: seen while it
/// listens, also while its one instance is busy with a client, and not once
/// it has stopped (on Unix its socket file stays behind).
#[tokio::test]
async fn a_listening_service_is_seen_without_talking_to_it() {
    let endpoint = test_endpoint("in-use");
    assert!(!endpoint.is_in_use(), "nothing listens yet");
    let listener = IpcListener::bind(&endpoint, &PipeAccess::InteractiveUsers).unwrap();
    assert!(endpoint.is_in_use());
    let busy = captun_ipc::connect(&endpoint).await.unwrap();
    assert!(endpoint.is_in_use(), "its one instance is taken");
    drop(busy);
    drop(listener);
    assert!(!endpoint.is_in_use(), "stopped");
}
