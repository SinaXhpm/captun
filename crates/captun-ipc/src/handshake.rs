//! The opening exchange of every connection. Each side proves it holds this
//! run's token, and the token itself never crosses the connection:
//!
//! 1. app: `Hello { version, nonce: c }`
//! 2. service: `Challenge { version, nonce: s, proof: HMAC-SHA256(token, "captun-server" ‖ c ‖ s) }`
//! 3. the app checks that proof, and only then: `Auth { proof: HMAC-SHA256(token, "captun-client" ‖ s ‖ c) }`
//! 4. the service checks it: `Welcome`
//!
//! A program posing as the service (one that took the pipe name first, say)
//! cannot answer step 2, so the app stops there, having sent it nothing but
//! random bytes. A proof seen on one connection is useless on the next, as
//! the service picks a new nonce for each. The two labels keep one side's
//! proof from ever passing as the other's.

use std::time::Duration;

use rand::RngCore;
use ring::hmac;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

use crate::{
    CallError, ClientFrame, ErrorCode, FrameError, FrameReader, FrameWriter, IpcError, PROTOCOL_VERSION, ServerFrame,
    Token,
};

/// The whole exchange must finish within this, so a connection that stalls
/// cannot hold one of the service's sessions.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

const NONCE_BYTES: usize = 32;
const PROOF_BYTES: usize = 32;
const SERVICE_LABEL: &[u8] = b"captun-server";
const CLIENT_LABEL: &[u8] = b"captun-client";

/// What a refused program is told; an app shows it.
const OLDER_APP: &str = "This Captun app is older than the Captun service that is running. Open the newer app.";
const NOT_ALLOWED: &str = "This program could not prove it may use the Captun service.";

type Nonce = [u8; NONCE_BYTES];

/// Why the service refused a connection. Each reads after "refused a
/// connection: " in the service log.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    #[error("it did not finish the greeting in time")]
    TimedOut,
    #[error("it hung up during the greeting")]
    HungUp,
    #[error("it is a Captun app older than this service")]
    OlderApp,
    #[error("it did not follow the greeting")]
    Unexpected,
    #[error("it could not prove it holds this run's key")]
    WrongProof,
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// The service's side: answers the greeting with proof that it holds `token`,
/// checks the app's proof, and welcomes it. Anything else, or taking longer
/// than [`HANDSHAKE_TIMEOUT`] in all, is answered `Unauthorized`, as before.
pub async fn accept<R, W>(
    reader: &mut FrameReader<R, ClientFrame>,
    writer: &mut FrameWriter<W, ServerFrame>,
    token: &Token,
    service_version: &str,
) -> Result<(), Refused>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    accept_within(reader, writer, token, service_version, HANDSHAKE_TIMEOUT).await
}

async fn accept_within<R, W>(
    reader: &mut FrameReader<R, ClientFrame>,
    writer: &mut FrameWriter<W, ServerFrame>,
    token: &Token,
    service_version: &str,
    limit: Duration,
) -> Result<(), Refused>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let refused = match timeout(limit, exchange(reader, writer, token, service_version)).await {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(why)) => why,
        Err(_) => Refused::TimedOut,
    };
    if !matches!(refused, Refused::HungUp) {
        let message = if matches!(refused, Refused::OlderApp) { OLDER_APP } else { NOT_ALLOWED };
        let refusal = ServerFrame::Response { id: 0, result: Err(IpcError::new(ErrorCode::Unauthorized, message)) };
        // Bounded too: a peer that never reads must not hold the session.
        let _ = timeout(limit, writer.send(&refusal)).await;
    }
    Err(refused)
}

async fn exchange<R, W>(
    reader: &mut FrameReader<R, ClientFrame>,
    writer: &mut FrameWriter<W, ServerFrame>,
    token: &Token,
    service_version: &str,
) -> Result<(), Refused>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let client_nonce = match reader.next().await? {
        Some(ClientFrame::Hello { version, nonce }) => match from_hex::<NONCE_BYTES>(&nonce) {
            Some(nonce) => nonce,
            // An app from before version 2 sends its token, not a nonce.
            None if version < PROTOCOL_VERSION => return Err(Refused::OlderApp),
            None => return Err(Refused::Unexpected),
        },
        Some(_) => return Err(Refused::Unexpected),
        None => return Err(Refused::HungUp),
    };
    // Whatever version the app named: the challenge names this one, and the
    // app decides whether to go on in it.
    let service_nonce = new_nonce();
    let challenge = ServerFrame::Challenge {
        version: PROTOCOL_VERSION,
        nonce: to_hex(&service_nonce),
        proof: prove(token, SERVICE_LABEL, &client_nonce, &service_nonce),
    };
    writer.send(&challenge).await?;
    match reader.next().await? {
        Some(ClientFrame::Auth { proof }) if proves(token, CLIENT_LABEL, &service_nonce, &client_nonce, &proof) => {}
        Some(ClientFrame::Auth { .. }) => return Err(Refused::WrongProof),
        Some(_) => return Err(Refused::Unexpected),
        None => return Err(Refused::HungUp),
    }
    let welcome = ServerFrame::Welcome { version: PROTOCOL_VERSION, service_version: service_version.to_owned() };
    writer.send(&welcome).await?;
    Ok(())
}

/// The app's side: sends a fresh nonce, checks the service's proof, and only
/// then proves itself. Returns the service's version.
pub(crate) async fn open<R, W>(
    reader: &mut FrameReader<R, ServerFrame>,
    writer: &mut FrameWriter<W, ClientFrame>,
    token: &Token,
) -> Result<String, CallError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let client_nonce = new_nonce();
    writer.send(&ClientFrame::Hello { version: PROTOCOL_VERSION, nonce: to_hex(&client_nonce) }).await?;
    let first = match reader.next().await {
        Ok(frame) => frame,
        // Nothing the service sends would fail to read.
        Err(FrameError::Json(_) | FrameError::TooLarge) => return Err(CallError::NotTheService),
        Err(e) => return Err(e.into()),
    };
    // Nothing in this first answer is proved yet, so only what a real
    // service sends here leads anywhere but "not the service".
    let service_nonce = match first {
        // A newer service names its version before any proof this app knows.
        Some(ServerFrame::Challenge { version, .. }) if version > PROTOCOL_VERSION => {
            return Err(CallError::VersionMismatch { service: version });
        }
        Some(ServerFrame::Challenge { version, nonce, proof }) if version == PROTOCOL_VERSION => {
            match from_hex::<NONCE_BYTES>(&nonce) {
                Some(nonce) if proves(token, SERVICE_LABEL, &client_nonce, &nonce, &proof) => nonce,
                _ => return Err(CallError::NotTheService),
            }
        }
        // How a service from before version 2 answers a greeting without a token.
        Some(ServerFrame::Response { result: Err(e), .. }) if e.code == ErrorCode::Unauthorized => {
            return Err(CallError::OlderService);
        }
        // No service sends anything else first: older ones never challenge
        // and welcome only a greeting with the token, and a refusal of
        // another kind would only put a stranger's words on screen.
        Some(_) => return Err(CallError::NotTheService),
        None => return Err(CallError::Disconnected),
    };
    writer.send(&ClientFrame::Auth { proof: prove(token, CLIENT_LABEL, &service_nonce, &client_nonce) }).await?;
    match reader.next().await? {
        Some(ServerFrame::Welcome { version, service_version }) if version == PROTOCOL_VERSION => Ok(service_version),
        Some(ServerFrame::Welcome { version, .. }) => Err(CallError::VersionMismatch { service: version }),
        Some(ServerFrame::Response { result: Err(e), .. }) => Err(CallError::Service(e)),
        Some(_) => Err(CallError::Handshake("the service gave an unexpected answer to this app's proof".into())),
        None => Err(CallError::Disconnected),
    }
}

fn new_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn key(token: &Token) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, token.as_str().as_bytes())
}

/// Fixed lengths throughout, so the label and the two nonces cannot be
/// shifted against each other.
fn message(label: &[u8], first: &Nonce, second: &Nonce) -> Vec<u8> {
    [label, first.as_slice(), second.as_slice()].concat()
}

fn prove(token: &Token, label: &[u8], first: &Nonce, second: &Nonce) -> String {
    to_hex(hmac::sign(&key(token), &message(label, first, second)).as_ref())
}

/// Checks a hex proof in constant time.
fn proves(token: &Token, label: &[u8], first: &Nonce, second: &Nonce, proof: &str) -> bool {
    from_hex::<PROOF_BYTES>(proof).is_some_and(|tag| hmac::verify(&key(token), &message(label, first, second), &tag).is_ok())
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes.iter().flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0x0f)]]).map(char::from).collect()
}

/// Exactly `N` bytes as `2 * N` hex digits, or `None`.
fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, &[high, low]) in out.iter_mut().zip(pairs) {
        let (high, low) = (char::from(high).to_digit(16)?, char::from(low).to_digit(16)?);
        *byte = u8::try_from((high << 4) | low).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::split;

    type ServiceEnd = (FrameReader<tokio::io::ReadHalf<DuplexStream>, ClientFrame>, FrameWriter<tokio::io::WriteHalf<DuplexStream>, ServerFrame>);
    type AppEnd = (FrameReader<tokio::io::ReadHalf<DuplexStream>, ServerFrame>, FrameWriter<tokio::io::WriteHalf<DuplexStream>, ClientFrame>);

    fn pair() -> (ServiceEnd, AppEnd) {
        let (service, app) = duplex(64 * 1024);
        (split(service), split(app))
    }

    /// Runs the service's side on its own task with a short limit.
    fn serve(service: ServiceEnd, token: Token, limit: Duration) -> tokio::task::JoinHandle<Result<(), Refused>> {
        tokio::spawn(async move {
            let (mut reader, mut writer) = service;
            accept_within(&mut reader, &mut writer, &token, "test", limit).await
        })
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_lengths_and_digits() {
        let bytes: [u8; 4] = [0x00, 0x7f, 0xa5, 0xff];
        assert_eq!(to_hex(&bytes), "007fa5ff");
        assert_eq!(from_hex::<4>("007fa5ff"), Some(bytes));
        assert_eq!(from_hex::<4>("007FA5FF"), Some(bytes));
        assert_eq!(from_hex::<4>("007fa5f"), None);
        assert_eq!(from_hex::<4>("007fa5ff00"), None);
        assert_eq!(from_hex::<4>("007fa5fg"), None);
        assert_eq!(from_hex::<4>("+07fa5ff"), None);
        assert_eq!(from_hex::<2>("é00"), None, "the two bytes of one character are not two digits");
    }

    #[test]
    fn the_two_proofs_never_stand_in_for_each_other() {
        let token = Token::generate();
        let (a, b) = (new_nonce(), new_nonce());
        let service = prove(&token, SERVICE_LABEL, &a, &b);
        assert!(proves(&token, SERVICE_LABEL, &a, &b, &service));
        // Not as the app's proof, not with the nonces swapped, not under another token.
        assert!(!proves(&token, CLIENT_LABEL, &b, &a, &service));
        assert!(!proves(&token, CLIENT_LABEL, &a, &b, &service));
        assert!(!proves(&token, SERVICE_LABEL, &b, &a, &service));
        assert!(!proves(&Token::generate(), SERVICE_LABEL, &a, &b, &service));
        assert!(!proves(&token, SERVICE_LABEL, &a, &b, &service[2..]));
        assert_ne!(new_nonce(), new_nonce());
    }

    #[tokio::test]
    async fn the_same_token_on_both_sides_opens_the_connection() {
        let token = Token::generate();
        let (service, (mut reader, mut writer)) = pair();
        let served = serve(service, token.clone(), HANDSHAKE_TIMEOUT);
        assert_eq!(open(&mut reader, &mut writer, &token).await.unwrap(), "test");
        served.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_app_with_another_token_stops_at_the_service_proof_and_sends_nothing_more() {
        let (service, (mut reader, mut writer)) = pair();
        let served = serve(service, Token::generate(), HANDSHAKE_TIMEOUT);
        let err = open(&mut reader, &mut writer, &Token::generate()).await.unwrap_err();
        assert!(matches!(err, CallError::NotTheService), "{err:?}");
        drop((reader, writer));
        // The service saw the app hang up instead of answering its challenge.
        assert!(matches!(served.await.unwrap(), Err(Refused::HungUp)));
    }

    #[tokio::test]
    async fn the_service_refuses_an_app_proof_made_with_another_token() {
        let token = Token::generate();
        let ((mut service_reader, mut service_writer), (mut reader, mut writer)) = pair();
        let served = tokio::spawn(async move {
            accept_within(&mut service_reader, &mut service_writer, &token, "test", HANDSHAKE_TIMEOUT).await
        });

        // An app that skips checking the service and proves itself with a
        // token of its own.
        let (client_nonce, wrong) = (new_nonce(), Token::generate());
        writer.send(&ClientFrame::Hello { version: PROTOCOL_VERSION, nonce: to_hex(&client_nonce) }).await.unwrap();
        let Some(ServerFrame::Challenge { nonce, .. }) = reader.next().await.unwrap() else { panic!("no challenge") };
        let service_nonce = from_hex::<NONCE_BYTES>(&nonce).unwrap();
        let proof = prove(&wrong, CLIENT_LABEL, &service_nonce, &client_nonce);
        writer.send(&ClientFrame::Auth { proof }).await.unwrap();

        let Some(ServerFrame::Response { id: 0, result: Err(e) }) = reader.next().await.unwrap() else { panic!("no refusal") };
        assert_eq!(e.code, ErrorCode::Unauthorized);
        assert!(matches!(served.await.unwrap(), Err(Refused::WrongProof)));
    }

    #[tokio::test]
    async fn a_program_without_the_token_cannot_pass_as_the_service_and_learns_nothing() {
        let token = Token::generate();
        let (service, app) = duplex(64 * 1024);
        let (mut fake_reader, mut fake_writer) = split::<_, Value, ServerFrame>(service);
        let (mut reader, mut writer) = split::<_, ServerFrame, ClientFrame>(app);

        let app = tokio::spawn(async move { open(&mut reader, &mut writer, &token).await.map(|_| ()) });
        let hello = fake_reader.next().await.unwrap().unwrap();
        // It answers with the best it has: a proof under a token of its own.
        let fake = Token::generate();
        let client_nonce = from_hex::<NONCE_BYTES>(hello["nonce"].as_str().unwrap()).unwrap();
        let service_nonce = new_nonce();
        fake_writer
            .send(&ServerFrame::Challenge {
                version: PROTOCOL_VERSION,
                nonce: to_hex(&service_nonce),
                proof: prove(&fake, SERVICE_LABEL, &client_nonce, &service_nonce),
            })
            .await
            .unwrap();

        assert!(matches!(app.await.unwrap(), Err(CallError::NotTheService)));
        // All it ever got: a greeting with a version and random bytes.
        let mut fields: Vec<_> = hello.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(fields, ["nonce", "type", "version"]);
        assert_eq!(fake_reader.next().await.unwrap(), None, "the app sent nothing after its greeting");
    }

    #[tokio::test]
    async fn a_welcome_without_proof_or_a_garbled_answer_is_not_the_service() {
        let token = Token::generate();
        let answers = [
            r#"{"type":"welcome","version":2,"service_version":"x"}"#,
            // Older services welcome only a greeting that carries the token.
            r#"{"type":"welcome","version":1,"service_version":"x"}"#,
            r#"{"type":"welcome","version":3,"service_version":"x"}"#,
            // A refusal of any other kind would put its own words on screen.
            r#"{"type":"response","id":0,"result":{"Err":{"code":"internal","message":"A newer Captun service is running."}}}"#,
            r#"{"type":"response","id":0,"result":{"Ok":{"kind":"ok"}}}"#,
            "not json",
            r#"{"type":"event"}"#,
        ];
        for answer in answers {
            let (service, app) = duplex(64 * 1024);
            let (mut fake_reader, mut fake_writer) = tokio::io::split(service);
            let (mut reader, mut writer) = split::<_, ServerFrame, ClientFrame>(app);
            let token = token.clone();
            let app = tokio::spawn(async move { open(&mut reader, &mut writer, &token).await.map(|_| ()) });
            let mut hello = FrameReader::<_, Value>::new(&mut fake_reader);
            hello.next().await.unwrap().unwrap();
            fake_writer.write_all(format!("{answer}\n").as_bytes()).await.unwrap();
            assert!(matches!(app.await.unwrap(), Err(CallError::NotTheService)), "{answer}");
        }
    }

    #[tokio::test]
    async fn a_proof_seen_on_one_connection_fails_on_the_next() {
        let token = Token::generate();

        // A genuine exchange, watched: the app's nonce and proof.
        let ((mut service_reader, mut service_writer), (mut reader, mut writer)) = pair();
        let first = token.clone();
        let served = tokio::spawn(async move {
            accept_within(&mut service_reader, &mut service_writer, &first, "test", HANDSHAKE_TIMEOUT).await
        });
        let client_nonce = new_nonce();
        writer.send(&ClientFrame::Hello { version: PROTOCOL_VERSION, nonce: to_hex(&client_nonce) }).await.unwrap();
        let Some(ServerFrame::Challenge { nonce, .. }) = reader.next().await.unwrap() else { panic!("no challenge") };
        let service_nonce = from_hex::<NONCE_BYTES>(&nonce).unwrap();
        let seen = prove(&token, CLIENT_LABEL, &service_nonce, &client_nonce);
        writer.send(&ClientFrame::Auth { proof: seen.clone() }).await.unwrap();
        assert!(matches!(reader.next().await.unwrap(), Some(ServerFrame::Welcome { .. })));
        served.await.unwrap().unwrap();

        // Replayed with the same greeting on a new connection: the service
        // picked a new nonce, so the old proof does not fit.
        let ((mut service_reader, mut service_writer), (mut reader, mut writer)) = pair();
        let second = token.clone();
        let served = tokio::spawn(async move {
            accept_within(&mut service_reader, &mut service_writer, &second, "test", HANDSHAKE_TIMEOUT).await
        });
        writer.send(&ClientFrame::Hello { version: PROTOCOL_VERSION, nonce: to_hex(&client_nonce) }).await.unwrap();
        let Some(ServerFrame::Challenge { nonce, .. }) = reader.next().await.unwrap() else { panic!("no challenge") };
        assert_ne!(from_hex::<NONCE_BYTES>(&nonce).unwrap(), service_nonce);
        writer.send(&ClientFrame::Auth { proof: seen }).await.unwrap();
        assert!(matches!(reader.next().await.unwrap(), Some(ServerFrame::Response { result: Err(_), .. })));
        assert!(matches!(served.await.unwrap(), Err(Refused::WrongProof)));
    }

    #[tokio::test]
    async fn an_old_app_sending_its_token_is_told_it_is_older() {
        let token = Token::generate();
        let (service, app) = duplex(64 * 1024);
        let served = serve(split(service), token.clone(), HANDSHAKE_TIMEOUT);
        let (mut reader, mut writer) = split::<_, ServerFrame, Value>(app);
        writer.send(&serde_json::json!({ "type": "hello", "version": 1, "token": token.as_str() })).await.unwrap();
        let Some(ServerFrame::Response { result: Err(e), .. }) = reader.next().await.unwrap() else { panic!("no refusal") };
        assert_eq!((e.code, e.message.as_str()), (ErrorCode::Unauthorized, OLDER_APP));
        assert!(matches!(served.await.unwrap(), Err(Refused::OlderApp)));
    }

    #[tokio::test]
    async fn requests_before_the_greeting_and_bad_nonces_are_refused() {
        let token = Token::generate();
        let frames = [
            ClientFrame::Request { id: 1, request: crate::Request::Shutdown },
            ClientFrame::Auth { proof: "00".repeat(PROOF_BYTES) },
            ClientFrame::Hello { version: PROTOCOL_VERSION, nonce: "00".repeat(NONCE_BYTES - 1) },
        ];
        for frame in frames {
            let (service, (mut reader, mut writer)) = pair();
            let served = serve(service, token.clone(), HANDSHAKE_TIMEOUT);
            writer.send(&frame).await.unwrap();
            let Some(ServerFrame::Response { result: Err(e), .. }) = reader.next().await.unwrap() else { panic!("no refusal") };
            assert_eq!(e.code, ErrorCode::Unauthorized);
            assert!(matches!(served.await.unwrap(), Err(Refused::Unexpected)), "{frame:?}");
        }
    }

    #[tokio::test]
    async fn a_greeting_that_stalls_is_refused_after_the_limit() {
        let token = Token::generate();
        let (service, (mut reader, mut writer)) = pair();
        let served = serve(service, token.clone(), Duration::from_millis(50));
        writer.send(&ClientFrame::Hello { version: PROTOCOL_VERSION, nonce: to_hex(&new_nonce()) }).await.unwrap();
        assert!(matches!(reader.next().await.unwrap(), Some(ServerFrame::Challenge { .. })));
        // ...and never proves itself.
        let Some(ServerFrame::Response { result: Err(e), .. }) = reader.next().await.unwrap() else { panic!("no refusal") };
        assert_eq!(e.code, ErrorCode::Unauthorized);
        assert!(matches!(served.await.unwrap(), Err(Refused::TimedOut)));
    }

    /// Plays a service that answers the greeting with `first`, and returns
    /// how the app took it.
    async fn first_answer(first: ServerFrame) -> CallError {
        let token = Token::generate();
        let (service, app) = duplex(64 * 1024);
        let (mut fake_reader, mut fake_writer) = split::<_, Value, ServerFrame>(service);
        let (mut reader, mut writer) = split::<_, ServerFrame, ClientFrame>(app);
        let app = tokio::spawn(async move { open(&mut reader, &mut writer, &token).await.map(|_| ()) });
        fake_reader.next().await.unwrap().unwrap();
        fake_writer.send(&first).await.unwrap();
        app.await.unwrap().unwrap_err()
    }

    #[tokio::test]
    async fn the_app_names_a_newer_service_but_an_older_challenge_is_not_the_service() {
        let challenge =
            |version| ServerFrame::Challenge { version, nonce: to_hex(&new_nonce()), proof: "00".repeat(PROOF_BYTES) };
        let newer = first_answer(challenge(PROTOCOL_VERSION + 1)).await;
        assert!(matches!(newer, CallError::VersionMismatch { service } if service == PROTOCOL_VERSION + 1), "{newer:?}");
        assert!(!newer.is_older_service());
        // Services from before version 2 never challenge: only something
        // without the token would, and it must not be offered the old way in.
        for version in [0, 1] {
            let older = first_answer(challenge(version)).await;
            assert!(matches!(older, CallError::NotTheService), "{older:?}");
            assert!(!older.is_older_service());
        }
    }

    #[tokio::test]
    async fn only_a_refusal_of_the_greeting_means_an_older_service() {
        let refusal = |code| ServerFrame::Response { id: 0, result: Err(IpcError::new(code, "invalid IPC token")) };
        let older = first_answer(refusal(ErrorCode::Unauthorized)).await;
        assert!(matches!(older, CallError::OlderService), "{older:?}");
        assert!(older.is_older_service());
        for code in [ErrorCode::Internal, ErrorCode::BadRequest] {
            let other = first_answer(refusal(code)).await;
            assert!(matches!(other, CallError::NotTheService), "{other:?}");
        }
    }
}
