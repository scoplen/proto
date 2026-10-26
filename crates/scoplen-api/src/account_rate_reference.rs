// SPDX-License-Identifier: Apache-2.0
//! D-128 admission algorithm and explicit trusted-adapter stages for owned test fixtures.
//!
//! Source admission precedes body collection. The adapter supplies decoded Device ids, the
//! original password-attempt binding and a verification callback before an Account bucket can
//! be selected. That callback is trusted fixture code, not cryptographic verification supplied
//! by this module. This peer is not connected to the Account registration peer, HTTP, durable
//! storage or a production audit chain. Its complete image covers admission state only.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use scoplen_crypto::{AccountProbeKey, validate_server_origin};
use scoplen_model::validate_uuid_v7;
use uuid::Uuid;

use crate::{
    account_admission::{AccountEntryOperation, AccountRequestIntent},
    account_registration_reference::ReferencePasswordAttempt,
    auth::AuthRateLimitHeaders,
};

/// Combined production row bound; smaller owned-fixture ceilings exercise boundary behavior.
pub const ACCOUNT_RATE_BUCKET_CEILING: usize = 131_072;
const WINDOW_MS: u64 = 60_000;
const QUIET_MS: u64 = 600_000;
const SOURCE_LIMIT: u8 = 30;
const PRIVATE_LIMIT: u8 = 10;

/// One confirmed precommit fixture failure; no uncertain business mutation is modeled here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceAccountRateFault {
    /// The next admission or outcome transaction cannot commit.
    BeforeCommit,
    /// The next generic-denial audit cannot commit its cooldown changes.
    DenialAudit,
}

/// Content-free fixture failures, with the exact common authentication rate headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceAccountRateError {
    /// Invalid configuration, identity, stage order or outcome for the selected endpoint.
    #[error("invalid Account admission fixture request")]
    InvalidRequest,
    /// A quota, cooldown or the combined row ceiling prevents admission.
    #[error("Account admission rate limited")]
    RateLimited(AuthRateLimitHeaders),
    /// Admission or mandatory denial audit could not be confirmed.
    #[error("Account admission storage unavailable")]
    StorageUnavailable,
}

/// The private subject established by a trusted adapter after structural decoding or lookup.
/// No variant accepts a caller-selected Account id.
pub enum ReferenceAccountRateSubject<'a> {
    /// The canonical username in a password-options body, regardless of Account existence.
    OptionsUsername(&'a str),
    /// Login uses only its original stored attempt. `None` models an unusable unknown attempt.
    PasswordAttempt(Option<&'a ReferencePasswordAttempt>),
    /// Challenge, registration or admission uses the structurally decoded Device and intent.
    DecodedDevice { device_id: Uuid, intent: AccountRequestIntent },
}

/// The endpoint outcome after its separately implemented business/audit transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceAccountRateOutcome {
    /// Parsing, policy, conflict, issuance or another outcome that does not change the streak.
    Other,
    /// An admitted generic authentication denial adds cooldown with mandatory denial audit.
    AuthenticationDenied,
    /// Confirmed authentication/registration/admission clears streaks, preserving counts.
    Authenticated,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
enum Identity {
    Source(IpAddr),
    Username([u8; 32]),
    Device(Uuid),
    Account(Uuid),
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct BucketKey(u8, Identity);

impl BucketKey {
    fn limit(&self) -> u8 {
        if matches!(self.1, Identity::Source(_)) { SOURCE_LIMIT } else { PRIVATE_LIMIT }
    }
}

// Fixed key plus these scalars is below the contract's 256 application-byte row budget.
#[derive(Clone, Copy)]
struct Bucket {
    window_start: u64,
    count: u8,
    last_admitted: u64,
    last_failure: Option<u64>,
    streak: u8,
    cooldown_until: u64,
}

impl Bucket {
    fn due(self) -> Result<u64, ReferenceAccountRateError> {
        Ok(self
            .last_admitted
            .checked_add(QUIET_MS)
            .ok_or(ReferenceAccountRateError::StorageUnavailable)?
            .max(
                self.window_start
                    .checked_add(WINDOW_MS)
                    .ok_or(ReferenceAccountRateError::StorageUnavailable)?,
            )
            .max(self.cooldown_until))
    }

    fn wait(self, now: u64, limit: u8) -> u64 {
        let window_end = self.window_start.saturating_add(WINDOW_MS);
        let quota = if self.count >= limit { window_end.saturating_sub(now) } else { 0 };
        quota.max(self.cooldown_until.saturating_sub(now))
    }
}

#[derive(Clone)]
struct State {
    origin: String,
    probe: Arc<AccountProbeKey>,
    ceiling: usize,
    high_water: u64,
    next_cleanup: u64,
    buckets: BTreeMap<BucketKey, Bucket>,
    expiry: BTreeSet<(u64, BucketKey)>,
    denials: u64,
    fault: Option<ReferenceAccountRateFault>,
}

impl State {
    fn time(&mut self, observed: u64) -> u64 {
        self.high_water = self.high_water.max(observed);
        self.high_water
    }

    fn retire(&mut self, now: u64) -> Result<usize, ReferenceAccountRateError> {
        if now < self.next_cleanup {
            return Ok(0);
        }
        let next = now.checked_add(1_000).ok_or(ReferenceAccountRateError::StorageUnavailable)?;
        if self.fault == Some(ReferenceAccountRateFault::BeforeCommit) {
            self.fault = None;
            return Err(ReferenceAccountRateError::StorageUnavailable);
        }
        self.next_cleanup = next;
        let mut retired = 0;
        while retired < 100 {
            let Some((due, key)) = self.expiry.first().cloned() else { break };
            if due > now {
                break;
            }
            self.expiry.remove(&(due, key.clone()));
            self.buckets.remove(&key);
            retired += 1;
        }
        Ok(retired)
    }

    fn put(&mut self, key: BucketKey, bucket: Bucket, due: u64) {
        if let Some(old) = self.buckets.insert(key.clone(), bucket) {
            self.expiry
                .remove(&(old.due().expect("admitted bucket has a bounded deadline"), key.clone()));
        }
        self.expiry.insert((due, key));
    }

    fn limited(&self, wait: u64, established: &[BucketKey], now: u64) -> ReferenceAccountRateError {
        let greatest = established
            .iter()
            .filter_map(|key| self.buckets.get(key).map(|b| b.wait(now, key.limit())))
            .fold(wait, u64::max);
        let seconds =
            u16::try_from(greatest.div_ceil(1_000).clamp(1, 300)).expect("bounded rate delay");
        ReferenceAccountRateError::RateLimited(
            AuthRateLimitHeaders::new(seconds).expect("bounded rate delay"),
        )
    }

    fn charge(
        &mut self,
        key: BucketKey,
        established: &[BucketKey],
        now: u64,
    ) -> Result<(), ReferenceAccountRateError> {
        let mut bucket = self.buckets.get(&key).copied().unwrap_or(Bucket {
            window_start: now / WINDOW_MS * WINDOW_MS,
            count: 0,
            last_admitted: now,
            last_failure: None,
            streak: 0,
            cooldown_until: 0,
        });
        let wait = bucket.wait(now, key.limit());
        if wait > 0 {
            return Err(self.limited(wait, established, now));
        }
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.ceiling {
            return Err(self.limited(1_000, established, now));
        }
        let window = now / WINDOW_MS * WINDOW_MS;
        if bucket.window_start != window {
            bucket.window_start = window;
            bucket.count = 0;
        }
        if bucket.last_failure.is_some_and(|last| now.saturating_sub(last) >= QUIET_MS) {
            bucket.streak = 0;
            bucket.last_failure = None;
        }
        bucket.count += 1;
        bucket.last_admitted = now;
        let due = bucket.due()?;
        if self.fault == Some(ReferenceAccountRateFault::BeforeCommit) {
            self.fault = None;
            return Err(ReferenceAccountRateError::StorageUnavailable);
        }
        self.put(key, bucket, due);
        Ok(())
    }
}

/// Shared serialized admission state across independent cloned reference API instances.
#[derive(Clone)]
pub struct ReferenceAccountRatePeer(Arc<Mutex<State>>);

/// Complete admission-only restart image, including its probe key, debt and cleanup index.
#[derive(Clone)]
pub struct ReferenceAccountRateImage(State);

/// Content-free owned-fixture inspection; this is not an authentication or HTTP result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceAccountRateSummary {
    /// Retained source and private rows across all five Account endpoints.
    pub rows: usize,
    /// Exactly one indexed expiry per retained row.
    pub indexed_rows: usize,
    /// Durable reference time; a backward supplied clock cannot reduce it.
    pub high_water_ms: u64,
    /// Committed generic-denial audit events.
    pub denials: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Private,
    Account,
    Ready,
    Denied,
    Closed,
}

/// A single noncloneable staged request. Dropping it never refunds prior admission.
pub struct ReferenceAccountRateRequest {
    peer: ReferenceAccountRatePeer,
    operation: AccountEntryOperation,
    keys: Vec<BucketKey>,
    phase: Phase,
}

macro_rules! redacted {
    ($($name:ty),+ $(,)?) => {$(impl fmt::Debug for $name {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
        }
    })+};
}
redacted!(ReferenceAccountRatePeer, ReferenceAccountRateImage, ReferenceAccountRateRequest,);

impl fmt::Debug for ReferenceAccountRateSubject<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceAccountRateSubject([REDACTED])")
    }
}

impl ReferenceAccountRatePeer {
    /// Initialize an owned reference deployment with the exact production row ceiling.
    /// # Errors
    /// Rejects a noncanonical trusted origin or a probe key other than 32 bytes.
    pub fn new(origin: &str, probe_key: &[u8]) -> Result<Self, ReferenceAccountRateError> {
        Self::with_ceiling(origin, probe_key, ACCOUNT_RATE_BUCKET_CEILING)
    }

    /// Use an explicitly smaller owned-fixture bound without changing a wire or production quota.
    /// # Errors
    /// Rejects invalid origin/key or a zero/greater-than-production row bound.
    pub fn with_ceiling(
        origin: &str,
        probe_key: &[u8],
        ceiling: usize,
    ) -> Result<Self, ReferenceAccountRateError> {
        validate_server_origin(origin).map_err(|_| ReferenceAccountRateError::InvalidRequest)?;
        let probe = AccountProbeKey::new(probe_key)
            .map_err(|_| ReferenceAccountRateError::InvalidRequest)?;
        if ceiling == 0 || ceiling > ACCOUNT_RATE_BUCKET_CEILING {
            return Err(ReferenceAccountRateError::InvalidRequest);
        }
        Ok(Self(Arc::new(Mutex::new(State {
            origin: origin.into(),
            probe: Arc::new(probe),
            ceiling,
            high_water: 0,
            next_cleanup: 0,
            buckets: BTreeMap::new(),
            expiry: BTreeSet::new(),
            denials: 0,
            fault: None,
        }))))
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, ReferenceAccountRateError> {
        self.0.lock().map_err(|_| ReferenceAccountRateError::StorageUnavailable)
    }

    /// Admit the actual peer before body collection; forwarding headers are not accepted here.
    /// IPv4-mapped IPv6 and IPv4 select the same source. Endpoint windows remain independent.
    /// # Errors
    /// Fails on source quota/cooldown/capacity or unavailable admission storage.
    pub fn begin(
        &self,
        operation: AccountEntryOperation,
        actual_peer: IpAddr,
        clock: impl FnOnce() -> u64,
    ) -> Result<ReferenceAccountRateRequest, ReferenceAccountRateError> {
        let source = match actual_peer {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(actual_peer, IpAddr::V4),
            IpAddr::V4(_) => actual_peer,
        };
        let key = BucketKey(endpoint(operation), Identity::Source(source));
        let mut state = self.lock()?;
        let now = state.time(clock());
        state.retire(now)?;
        state.charge(key.clone(), &[], now)?;
        Ok(ReferenceAccountRateRequest {
            peer: self.clone(),
            operation,
            keys: vec![key],
            phase: Phase::Private,
        })
    }

    /// Retire at most 100 indexed eligible rows, at most once per reference second.
    /// # Errors
    /// Fails closed on unavailable admission storage or unrepresentable time.
    pub fn maintain(
        &self,
        clock: impl FnOnce() -> u64,
    ) -> Result<usize, ReferenceAccountRateError> {
        let mut state = self.lock()?;
        let now = state.time(clock());
        state.retire(now)
    }

    /// Capture complete admission state. One-shot fault controls are not persisted.
    /// # Errors
    /// Fails closed if a fixture worker poisoned storage.
    pub fn checkpoint(&self) -> Result<ReferenceAccountRateImage, ReferenceAccountRateError> {
        let mut state = self.lock()?.clone();
        state.fault = None;
        Ok(ReferenceAccountRateImage(state))
    }

    /// Restore the complete admission image with its existing key, row bound and trusted origin.
    /// This cannot restore or authorize any Account business state.
    #[must_use]
    pub fn restore(image: ReferenceAccountRateImage) -> Self {
        Self(Arc::new(Mutex::new(image.0)))
    }

    /// Inspect content-free counts without exposing bucket identities or the probe key.
    /// # Errors
    /// Fails closed if a fixture worker poisoned storage.
    pub fn summary(&self) -> Result<ReferenceAccountRateSummary, ReferenceAccountRateError> {
        let state = self.lock()?;
        Ok(ReferenceAccountRateSummary {
            rows: state.buckets.len(),
            indexed_rows: state.expiry.len(),
            high_water_ms: state.high_water,
            denials: state.denials,
        })
    }

    /// Script a confirmed admission/denial-audit failure, never an Account business outcome.
    /// # Errors
    /// Fails closed if a fixture worker poisoned storage.
    pub fn set_fault(
        &self,
        fault: ReferenceAccountRateFault,
    ) -> Result<(), ReferenceAccountRateError> {
        self.lock()?.fault = Some(fault);
        Ok(())
    }
}

impl ReferenceAccountRateRequest {
    /// Admit exactly the endpoint's decoded or attempt-bound private subject, without an
    /// Account-existence lookup. An unusable unknown login attempt establishes no username.
    /// # Errors
    /// Rejects wrong/repeated stages, invalid identities, rate/capacity limits or storage failure.
    /// Any failure closes this handle while preserving already committed admission counts.
    pub fn admit_private(
        &mut self,
        subject: ReferenceAccountRateSubject<'_>,
        clock: impl FnOnce() -> u64,
    ) -> Result<(), ReferenceAccountRateError> {
        if self.phase != Phase::Private {
            self.phase = Phase::Closed;
            return Err(ReferenceAccountRateError::InvalidRequest);
        }
        self.phase = Phase::Closed;
        let mut state = self.peer.lock()?;
        let (identity, account) = match (self.operation, subject) {
            (
                AccountEntryOperation::PasswordOptions,
                ReferenceAccountRateSubject::OptionsUsername(username),
            ) => {
                let digest = state
                    .probe
                    .username_admission_identity(&state.origin, username)
                    .map_err(|_| ReferenceAccountRateError::InvalidRequest)?;
                (Identity::Username(*digest.as_bytes()), false)
            }
            (
                AccountEntryOperation::PasswordLogin,
                ReferenceAccountRateSubject::PasswordAttempt(Some(attempt)),
            ) => {
                let digest = state
                    .probe
                    .username_admission_identity(&state.origin, &attempt.username)
                    .map_err(|_| ReferenceAccountRateError::InvalidRequest)?;
                (Identity::Username(*digest.as_bytes()), true)
            }
            (
                AccountEntryOperation::PasswordLogin,
                ReferenceAccountRateSubject::PasswordAttempt(None),
            ) => {
                self.phase = Phase::Denied;
                return Ok(());
            }
            (
                AccountEntryOperation::RequestChallenge
                | AccountEntryOperation::Register
                | AccountEntryOperation::DeviceAdmission,
                ReferenceAccountRateSubject::DecodedDevice { device_id, intent },
            ) => {
                validate_uuid_v7(device_id)
                    .map_err(|_| ReferenceAccountRateError::InvalidRequest)?;
                (
                    Identity::Device(device_id),
                    self.operation == AccountEntryOperation::DeviceAdmission
                        || self.operation == AccountEntryOperation::Register
                            && intent == AccountRequestIntent::Confirm,
                )
            }
            _ => return Err(ReferenceAccountRateError::InvalidRequest),
        };
        let key = BucketKey(endpoint(self.operation), identity);
        let now = state.time(clock());
        state.charge(key.clone(), &self.keys, now)?;
        self.keys.push(key);
        self.phase = if account { Phase::Account } else { Phase::Ready };
        Ok(())
    }

    /// Run trusted adapter verification before selecting the established Account bucket.
    /// `None` establishes no Account; it permits only denial or a nonauthentication outcome.
    /// The callback must verify credentials or fresh possession with a bound capability/receipt.
    /// This module cannot verify that caller-supplied callback and confers no authentication.
    /// # Errors
    /// Rejects stage misuse/invalid verified id, rate/capacity limits or storage failure.
    pub fn verify_account(
        &mut self,
        verify: impl FnOnce() -> Option<Uuid>,
        clock: impl FnOnce() -> u64,
    ) -> Result<bool, ReferenceAccountRateError> {
        if self.phase != Phase::Account {
            self.phase = Phase::Closed;
            return Err(ReferenceAccountRateError::InvalidRequest);
        }
        self.phase = Phase::Closed;
        let Some(account) = verify() else {
            self.phase = Phase::Denied;
            return Ok(false);
        };
        validate_uuid_v7(account).map_err(|_| ReferenceAccountRateError::InvalidRequest)?;
        let key = BucketKey(endpoint(self.operation), Identity::Account(account));
        let mut state = self.peer.lock()?;
        let now = state.time(clock());
        state.charge(key.clone(), &self.keys, now)?;
        self.keys.push(key);
        self.phase = Phase::Ready;
        Ok(true)
    }

    /// Consume the request and atomically update only already established admission buckets.
    /// Issuing options/challenges never clears a streak. Generic denial audit failure rolls
    /// back every cooldown change while earlier admission counts remain committed.
    /// # Errors
    /// Rejects impossible success/stage combinations, unavailable storage or denial audit.
    pub fn finish(
        self,
        outcome: ReferenceAccountRateOutcome,
        clock: impl FnOnce() -> u64,
    ) -> Result<(), ReferenceAccountRateError> {
        if self.phase == Phase::Closed
            || outcome == ReferenceAccountRateOutcome::Authenticated
                && (self.phase != Phase::Ready
                    || matches!(
                        self.operation,
                        AccountEntryOperation::RequestChallenge
                            | AccountEntryOperation::PasswordOptions
                    ))
        {
            return Err(ReferenceAccountRateError::InvalidRequest);
        }
        let mut state = self.peer.lock()?;
        let now = state.time(clock());
        if outcome == ReferenceAccountRateOutcome::Other {
            return Ok(());
        }
        let denials = state
            .denials
            .checked_add(u64::from(outcome == ReferenceAccountRateOutcome::AuthenticationDenied))
            .ok_or(ReferenceAccountRateError::StorageUnavailable)?;
        let mut updates = Vec::with_capacity(self.keys.len());
        for key in self.keys {
            let mut bucket =
                *state.buckets.get(&key).ok_or(ReferenceAccountRateError::StorageUnavailable)?;
            if outcome == ReferenceAccountRateOutcome::Authenticated {
                bucket.streak = 0;
                bucket.last_failure = None;
                bucket.cooldown_until = 0;
            } else {
                if bucket.last_failure.is_none_or(|last| now.saturating_sub(last) >= QUIET_MS) {
                    bucket.streak = 0;
                }
                bucket.streak = bucket.streak.saturating_add(1).min(10);
                bucket.last_failure = Some(now);
                let delay = (1_000_u64 << (bucket.streak - 1)).min(300_000);
                bucket.cooldown_until =
                    now.checked_add(delay).ok_or(ReferenceAccountRateError::StorageUnavailable)?;
            }
            let due = bucket.due()?;
            updates.push((key, bucket, due));
        }
        if state.fault == Some(ReferenceAccountRateFault::BeforeCommit)
            || outcome == ReferenceAccountRateOutcome::AuthenticationDenied
                && state.fault == Some(ReferenceAccountRateFault::DenialAudit)
        {
            state.fault = None;
            return Err(ReferenceAccountRateError::StorageUnavailable);
        }
        for (key, bucket, due) in updates {
            state.put(key, bucket, due);
        }
        state.denials = denials;
        Ok(())
    }
}

fn endpoint(operation: AccountEntryOperation) -> u8 {
    match operation {
        AccountEntryOperation::RequestChallenge => 0,
        AccountEntryOperation::Register => 1,
        AccountEntryOperation::PasswordOptions => 2,
        AccountEntryOperation::PasswordLogin => 3,
        AccountEntryOperation::DeviceAdmission => 4,
    }
}
