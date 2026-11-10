//! Site certificates on demand: made the first time a site is asked for,
//! kept for the next connection, and made again a day before they run out.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use rustls::{
    SignatureScheme,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use time::OffsetDateTime;
use tracing::warn;

use crate::{CertAuthority, SiteName, TlsError, ca::RENEW_BEFORE};

/// How many sites [`SiteCerts::new`] keeps certificates for. The site used
/// longest ago makes room for a new one.
pub const DEFAULT_CAPACITY: usize = 4096;

/// At most this many certificates are made (signed by the CA key) at once,
/// across all sites. Each one is a call into the key's store (on Windows its
/// key isolation service), so one busy or hostile device asking for endless
/// new names cannot keep the key busy for everyone else.
const MAX_SIGNING: usize = 4;
/// How long a caller waits for its turn, or for a certificate another
/// caller is making for the same site, before giving up: the connection is
/// then passed through unopened rather than held.
const WAIT: Duration = Duration::from_secs(5);
/// Warnings about sites that got no certificate: at most one this often,
/// with how many were left out.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// Certificates for the sites devices open, signed by this install's CA:
/// one per site, kept for up to [`DEFAULT_CAPACITY`] sites, the least
/// recently used dropped first, and made again once less than a day is left.
/// Callers that ask for the same site at the same time share one signature,
/// and at most [`MAX_SIGNING`] signatures run at once. A limit per device
/// belongs to the caller, which knows the device (phase 3).
///
/// Also a rustls [`ResolvesServerCert`] that picks the certificate by the
/// name the client asks for (SNI). Making one costs a signature by the CA
/// key, so a handshake for a site not seen lately waits for that; call it
/// from a blocking thread, not an async task.
pub struct SiteCerts {
    ca: Arc<CertAuthority>,
    capacity: usize,
    cache: Mutex<Lru>,
    /// Sites a certificate is being made for right now.
    making: Mutex<HashMap<SiteName, Arc<Pending>>>,
    /// How many signatures are running, for [`MAX_SIGNING`].
    signing: Mutex<usize>,
    turn: Condvar,
    warnings: Mutex<Warnings>,
}

/// A certificate one caller is making that others for the same site wait for.
#[derive(Default)]
struct Pending {
    outcome: Mutex<Option<Result<Arc<CertifiedKey>, String>>>,
    done: Condvar,
}

#[derive(Default)]
struct Warnings {
    last: Option<Instant>,
    left_out: u64,
}

impl SiteCerts {
    pub fn new(ca: Arc<CertAuthority>) -> Self {
        Self::with_capacity(ca, DEFAULT_CAPACITY)
    }

    /// Keeps certificates for at most `capacity` sites (at least one).
    pub fn with_capacity(ca: Arc<CertAuthority>, capacity: usize) -> Self {
        Self {
            ca,
            capacity: capacity.max(1),
            cache: Mutex::new(Lru::default()),
            making: Mutex::new(HashMap::new()),
            signing: Mutex::new(0),
            turn: Condvar::new(),
            warnings: Mutex::new(Warnings::default()),
        }
    }

    pub fn authority(&self) -> &Arc<CertAuthority> {
        &self.ca
    }

    /// The certificate and key for `host`, a website name or IP address as a
    /// proxy request names it (the USB phone's CONNECT). See
    /// [`SiteName::parse`] for what is accepted.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, TlsError> {
        self.leaf_for_site(&SiteName::parse(host)?)
    }

    pub fn leaf_for_site(&self, site: &SiteName) -> Result<Arc<CertifiedKey>, TlsError> {
        if let Some(cert) = self.cache().get(site, self.ca.now()) {
            return Ok(cert);
        }
        // One maker per site: whoever comes second waits for the first.
        let (pending, maker) = {
            let mut making = lock(&self.making);
            match making.get(site) {
                Some(pending) => (Arc::clone(pending), false),
                None => {
                    // A maker may have finished between the look above and
                    // here: it keeps the certificate before it lets go of
                    // the site, so look again rather than sign a second one.
                    if let Some(cert) = self.cache().get(site, self.ca.now()) {
                        return Ok(cert);
                    }
                    let pending = Arc::new(Pending::default());
                    making.insert(site.clone(), Arc::clone(&pending));
                    (pending, true)
                }
            }
        };
        if !maker {
            return wait_for(&pending);
        }
        // Whatever happens below, even a panic, the guard tells those waiting
        // and lets the next caller try again.
        let making = Making { certs: self, site, pending };
        let outcome = self.make(site);
        *lock(&making.pending.outcome) = Some(outcome.as_ref().map(Arc::clone).map_err(ToString::to_string));
        drop(making);
        outcome
    }

    /// Makes and keeps the certificate for `site`, waiting for a signing turn.
    fn make(&self, site: &SiteName) -> Result<Arc<CertifiedKey>, TlsError> {
        let _turn = self.take_turn()?;
        // Made without holding the cache, so other sites are not kept waiting
        // for the signature.
        let (cert, not_after) = self.ca.issue_until(site)?;
        self.cache().put(site.clone(), Arc::clone(&cert), not_after, self.capacity);
        Ok(cert)
    }

    /// One of the [`MAX_SIGNING`] turns, given back when the guard drops.
    fn take_turn(&self) -> Result<Turn<'_>, TlsError> {
        let mut running = lock(&self.signing);
        let deadline = Instant::now() + WAIT;
        while *running >= MAX_SIGNING {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TlsError::Certificate("too many site certificates are being made right now".into()));
            }
            running = self.turn.wait_timeout(running, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        *running += 1;
        Ok(Turn(self))
    }

    /// Logs that `name` got no certificate, at most once per [`WARN_EVERY`].
    fn warn_left_out(&self, name: &str, error: &TlsError) {
        let mut warnings = lock(&self.warnings);
        let now = Instant::now();
        if warnings.last.is_some_and(|last| now.duration_since(last) < WARN_EVERY) {
            warnings.left_out += 1;
            return;
        }
        let also = std::mem::take(&mut warnings.left_out);
        warnings.last = Some(now);
        drop(warnings);
        if also > 0 {
            warn!("no HTTPS inspection certificate for {name}: {error} ({also} more left out since the last warning)");
        } else {
            warn!("no HTTPS inspection certificate for {name}: {error}");
        }
    }

    /// How many sites certificates are kept for now.
    pub fn len(&self) -> usize {
        self.cache().slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn cache(&self) -> MutexGuard<'_, Lru> {
        lock(&self.cache)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What another caller made for the same site, once it is ready.
fn wait_for(pending: &Pending) -> Result<Arc<CertifiedKey>, TlsError> {
    let outcome = lock(&pending.outcome);
    let (outcome, _) = pending
        .done
        .wait_timeout_while(outcome, WAIT, |outcome| outcome.is_none())
        .unwrap_or_else(PoisonError::into_inner);
    match outcome.as_ref() {
        Some(Ok(cert)) => Ok(Arc::clone(cert)),
        Some(Err(why)) => Err(TlsError::Certificate(why.clone())),
        None => Err(TlsError::Certificate("the certificate for this site took too long to make".into())),
    }
}

/// The one caller making a site's certificate. Dropping it wakes those
/// waiting (with a failure if no outcome was set) and forgets the site, so a
/// later caller may make it again.
struct Making<'a> {
    certs: &'a SiteCerts,
    site: &'a SiteName,
    pending: Arc<Pending>,
}

impl Drop for Making<'_> {
    fn drop(&mut self) {
        {
            let mut outcome = lock(&self.pending.outcome);
            if outcome.is_none() {
                *outcome = Some(Err("the certificate could not be made".into()));
            }
        }
        self.pending.done.notify_all();
        lock(&self.certs.making).remove(self.site);
    }
}

/// A signing turn; dropping it lets the next caller in.
struct Turn<'a>(&'a SiteCerts);

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        *lock(&self.0.signing) -= 1;
        self.0.turn.notify_one();
    }
}

impl ResolvesServerCert for SiteCerts {
    /// The certificate for the name the client asked for. `None` (no
    /// certificate, so rustls ends the handshake) when the client named no
    /// server (no SNI, as for an IP address) or cannot check the CA's
    /// signatures (P-256 with SHA-256): the caller should pass such a
    /// connection through unopened, from the ClientHello it kept.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        if !client_hello.signature_schemes().contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            return None;
        }
        match self.leaf_for(name) {
            Ok(cert) => Some(cert),
            Err(e) => {
                self.warn_left_out(name, &e);
                None
            }
        }
    }
}

impl fmt::Debug for SiteCerts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteCerts")
            .field("ca", &self.ca.name())
            .field("sites", &self.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// Certificates by site, with the order they were last used in.
#[derive(Default)]
struct Lru {
    slots: HashMap<SiteName, Slot>,
    /// Each site under the tick it was last used at, oldest first.
    order: BTreeMap<u64, SiteName>,
    tick: u64,
}

struct Slot {
    cert: Arc<CertifiedKey>,
    not_after: OffsetDateTime,
    used: u64,
}

impl Lru {
    /// The certificate kept for `site`, if it has a day or more left, now
    /// counted as used last. One with less is dropped.
    fn get(&mut self, site: &SiteName, now: OffsetDateTime) -> Option<Arc<CertifiedKey>> {
        let slot = self.slots.get_mut(site)?;
        self.order.remove(&slot.used);
        if slot.not_after - now < RENEW_BEFORE {
            self.slots.remove(site);
            return None;
        }
        self.tick += 1;
        slot.used = self.tick;
        self.order.insert(slot.used, site.clone());
        Some(Arc::clone(&slot.cert))
    }

    /// Keeps `cert` for `site`, dropping the sites used longest ago to keep
    /// at most `capacity`.
    fn put(&mut self, site: SiteName, cert: Arc<CertifiedKey>, not_after: OffsetDateTime, capacity: usize) {
        if let Some(old) = self.slots.remove(&site) {
            self.order.remove(&old.used);
        }
        while self.slots.len() >= capacity {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            self.slots.remove(&oldest);
        }
        self.tick += 1;
        self.order.insert(self.tick, site.clone());
        self.slots.insert(site, Slot { cert, not_after, used: self.tick });
    }
}
