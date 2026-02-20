//! Router core: validation, security policy, and spec-driven forwarding.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

use crate::key_exchange::{KeyExchangeError, KeyExchangeMessage, mod_pow, parse_key_exchange};
use crate::policy::RoutingPolicy;
use crate::protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, ParseError, Signature, TransportKind,
    parse_message,
};

/// Compression-oracle failures.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// Backing compressor unavailable.
    #[error("compressor unavailable: {0}")]
    Unavailable(String),
    /// Backing compressor returned an error.
    #[error("compressor failure: {0}")]
    Failed(String),
}

/// Compression capability (intentionally abstracted from router process).
pub trait CompressionOracle: Send + Sync {
    /// Symmetric NCD-like distance.
    fn ncd_sym(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError>;
    /// CMR Section 3.2 compression distance from spec:
    /// `C(XY)-C(X) + C(YX)-C(Y)`.
    fn compression_distance(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError>;
    /// Intrinsic dependence.
    fn intrinsic_dependence(&self, data: &[u8], max_order: i64) -> Result<f64, CompressionError>;
    /// Batch CMR distance, defaulting to repeated scalar calls.
    fn batch_compression_distance(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        let mut out = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            out.push(self.compression_distance(target, candidate)?);
        }
        Ok(out)
    }
    /// Batch NCD, defaulting to repeated scalar calls.
    fn batch_ncd_sym(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        let mut out = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            out.push(self.ncd_sym(target, candidate)?);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
struct CacheEntry {
    key: String,
    message: CmrMessage,
    encoded_size: usize,
}

#[derive(Debug)]
struct MessageCache {
    entries: HashMap<String, CacheEntry>,
    order: VecDeque<String>,
    id_counts: HashMap<String, usize>,
    total_bytes: usize,
    max_messages: usize,
    max_bytes: usize,
}

impl MessageCache {
    fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            id_counts: HashMap::new(),
            total_bytes: 0,
            max_messages,
            max_bytes,
        }
    }

    fn has_seen_any_id(&self, message: &CmrMessage) -> bool {
        message
            .header
            .iter()
            .any(|id| self.id_counts.contains_key(&id.to_string()))
    }

    fn insert(&mut self, message: CmrMessage) {
        let key = cache_key(&message);
        if self.entries.contains_key(&key) {
            return;
        }
        let encoded_size = message.encoded_len();
        let entry = CacheEntry {
            key: key.clone(),
            message,
            encoded_size,
        };
        self.total_bytes = self.total_bytes.saturating_add(encoded_size);
        self.order.push_back(key.clone());
        self.add_message_ids(&entry.message);
        self.entries.insert(key, entry);
        self.evict_as_needed();
    }

    fn evict_as_needed(&mut self) {
        while self.entries.len() > self.max_messages || self.total_bytes > self.max_bytes {
            let Some(key) = self.order.pop_front() else {
                break;
            };
            let Some(entry) = self.entries.remove(&key) else {
                continue;
            };
            self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_size);
            self.remove_message_ids(&entry.message);
            debug_assert_eq!(entry.key, key);
        }
    }

    fn add_message_ids(&mut self, message: &CmrMessage) {
        for id in &message.header {
            *self.id_counts.entry(id.to_string()).or_default() += 1;
        }
    }

    fn remove_message_ids(&mut self, message: &CmrMessage) {
        for id in &message.header {
            let id_key = id.to_string();
            let mut remove = false;
            if let Some(count) = self.id_counts.get_mut(&id_key) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    remove = true;
                }
            }
            if remove {
                self.id_counts.remove(&id_key);
            }
        }
    }

    fn remove_by_key(&mut self, key: &str) -> Option<CacheEntry> {
        let entry = self.entries.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_size);
        self.remove_message_ids(&entry.message);
        self.order.retain(|existing| existing != key);
        Some(entry)
    }

    fn remove_if(&mut self, mut predicate: impl FnMut(&CmrMessage) -> bool) {
        let to_remove = self
            .order
            .iter()
            .filter_map(|key| {
                self.entries
                    .get(key)
                    .filter(|entry| predicate(&entry.message))
                    .map(|_| key.clone())
            })
            .collect::<Vec<_>>();
        for key in to_remove {
            let _ = self.remove_by_key(&key);
        }
    }
}

#[derive(Clone, Debug)]
struct PeerMetrics {
    reputation: f64,
    inbound_messages: u64,
    inbound_bytes: u64,
    outbound_messages: u64,
    outbound_bytes: u64,
    window: RateWindow,
}

impl Default for PeerMetrics {
    fn default() -> Self {
        Self {
            reputation: 0.0,
            inbound_messages: 0,
            inbound_bytes: 0,
            outbound_messages: 0,
            outbound_bytes: 0,
            window: RateWindow::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct RateWindow {
    window: VecDeque<(Instant, u64)>,
    bytes: u64,
}

impl RateWindow {
    fn new() -> Self {
        Self {
            window: VecDeque::new(),
            bytes: 0,
        }
    }

    fn allow_and_record(
        &mut self,
        message_bytes: usize,
        max_messages_per_minute: u32,
        max_bytes_per_minute: u64,
    ) -> bool {
        let now = Instant::now();
        let cutoff = Duration::from_secs(60);
        while let Some((ts, bytes)) = self.window.front().copied() {
            if now.duration_since(ts) < cutoff {
                break;
            }
            self.window.pop_front();
            self.bytes = self.bytes.saturating_sub(bytes);
        }
        let next_messages = self.window.len().saturating_add(1);
        let next_bytes = self
            .bytes
            .saturating_add(u64::try_from(message_bytes).unwrap_or(u64::MAX));
        if next_messages > usize::try_from(max_messages_per_minute).unwrap_or(usize::MAX)
            || next_bytes > max_bytes_per_minute
        {
            return false;
        }
        self.window
            .push_back((now, u64::try_from(message_bytes).unwrap_or(u64::MAX)));
        self.bytes = next_bytes;
        true
    }
}

#[derive(Clone, Debug)]
struct PendingRsaState {
    n: BigUint,
    d: BigUint,
}

#[derive(Clone, Debug)]
struct PendingDhState {
    p: BigUint,
    a_secret: BigUint,
}

const MIN_RSA_MODULUS_BITS: u64 = 2048;
const MIN_DH_MODULUS_BITS: u64 = 2048;

/// Forward reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ForwardReason {
    /// Forwarded incoming message `X` using matched message header addresses.
    MatchedForwardIncoming,
    /// Forwarded matched cached message `Y` using incoming header addresses.
    MatchedForwardCached,
    /// Compensatory response chosen when best peer already sent X.
    CompensatoryReply,
    /// Key-exchange protocol reply.
    KeyExchangeReply,
}

#[derive(Clone, Debug, Default)]
struct RoutingDecision {
    best_peer: Option<String>,
    matched_peers: Vec<String>,
    matched_messages: Vec<CmrMessage>,
    compensatory: Option<(String, CmrMessage)>,
}

/// Prepared outbound action.
#[derive(Clone, Debug)]
pub struct ForwardAction {
    /// Recipient peer address.
    pub destination: String,
    /// Wire bytes.
    pub message_bytes: Vec<u8>,
    /// Reason for forwarding.
    pub reason: ForwardReason,
}

/// Processing rejection reason.
#[derive(Debug, Error)]
pub enum ProcessError {
    /// Parse failure.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    /// Message duplicates cache by ID.
    #[error("duplicate message id in cache")]
    DuplicateMessageId,
    /// Peer throttled by anti-flood controls.
    #[error("peer exceeded flood limits")]
    FloodLimited,
    /// Global throttling triggered.
    #[error("global flood limits exceeded")]
    GlobalFloodLimited,
    /// Peer reputation below threshold.
    #[error("peer reputation below threshold")]
    ReputationTooLow,
    /// Unsigned message violates policy.
    #[error("unsigned message violates trust policy")]
    UnsignedRejected,
    /// Signature cannot be verified.
    #[error("signature verification failed")]
    BadSignature,
    /// Signed message from unknown key violates policy.
    #[error("signed message without known key rejected")]
    SignedWithoutKnownKey,
    /// Message body exceeds policy.
    #[error("message body exceeds content policy")]
    BodyTooLarge,
    /// Binary content blocked.
    #[error("binary content blocked by policy")]
    BinaryContentBlocked,
    /// Executable payload blocked.
    #[error("executable payload blocked by policy")]
    ExecutableBlocked,
    /// Intrinsic-dependence spam check failed.
    #[error("message failed intrinsic dependence spam check")]
    IntrinsicDependenceTooLow,
    /// Intrinsic-dependence score was not finite.
    #[error("message intrinsic dependence score was not finite")]
    IntrinsicDependenceInvalid,
    /// Compression oracle error.
    #[error("compression oracle error: {0}")]
    Compression(#[from] CompressionError),
    /// Key-exchange parse error.
    #[error("key exchange parse error: {0}")]
    KeyExchange(#[from] KeyExchangeError),
    /// Clear key exchange on insecure channel.
    #[error("clear key exchange requires secure channel")]
    ClearKeyOnInsecureChannel,
    /// Malformed key-exchange state.
    #[error("unexpected key exchange reply without pending state")]
    MissingPendingKeyExchangeState,
    /// Weak/unsafe key-exchange parameters.
    #[error("weak key exchange parameters: {0}")]
    WeakKeyExchangeParameters(&'static str),
}

/// Result of processing one inbound message.
#[derive(Debug)]
pub struct ProcessOutcome {
    /// Whether message was accepted.
    pub accepted: bool,
    /// Drop reason when not accepted.
    pub drop_reason: Option<ProcessError>,
    /// Parsed message if available.
    pub parsed_message: Option<CmrMessage>,
    /// Intrinsic dependence score when computed.
    pub intrinsic_dependence: Option<f64>,
    /// Generated forwarding actions.
    pub forwards: Vec<ForwardAction>,
    /// Number of semantic matches found.
    pub matched_count: usize,
    /// Whether this was a key exchange control message.
    pub key_exchange_control: bool,
}

impl ProcessOutcome {
    fn dropped(reason: ProcessError) -> Self {
        Self {
            accepted: false,
            drop_reason: Some(reason),
            parsed_message: None,
            intrinsic_dependence: None,
            forwards: Vec::new(),
            matched_count: 0,
            key_exchange_control: false,
        }
    }

    fn accepted(message: CmrMessage) -> Self {
        Self {
            accepted: true,
            drop_reason: None,
            parsed_message: Some(message),
            intrinsic_dependence: None,
            forwards: Vec::new(),
            matched_count: 0,
            key_exchange_control: false,
        }
    }
}

/// In-memory CMR router.
pub struct Router<O: CompressionOracle> {
    local_address: String,
    policy: RoutingPolicy,
    oracle: O,
    cache: MessageCache,
    peers: HashMap<String, PeerMetrics>,
    global_window: RateWindow,
    shared_keys: HashMap<String, Vec<u8>>,
    pending_rsa: HashMap<String, PendingRsaState>,
    pending_dh: HashMap<String, PendingDhState>,
    forward_counter: u64,
}

impl<O: CompressionOracle> Router<O> {
    /// Creates a router instance.
    #[must_use]
    pub fn new(local_address: String, policy: RoutingPolicy, oracle: O) -> Self {
        Self {
            local_address,
            cache: MessageCache::new(policy.cache_max_messages, policy.cache_max_bytes),
            policy,
            oracle,
            peers: HashMap::new(),
            global_window: RateWindow::new(),
            shared_keys: HashMap::new(),
            pending_rsa: HashMap::new(),
            pending_dh: HashMap::new(),
            forward_counter: 0,
        }
    }

    /// Registers a pairwise shared key.
    pub fn set_shared_key(&mut self, peer: impl Into<String>, key: Vec<u8>) {
        self.shared_keys.insert(peer.into(), key);
    }

    /// Gets known shared key.
    #[must_use]
    pub fn shared_key(&self, peer: &str) -> Option<&[u8]> {
        self.shared_keys.get(peer).map(Vec::as_slice)
    }

    /// Stores pending RSA initiator state for incoming replies.
    pub fn register_pending_rsa_state(&mut self, peer: impl Into<String>, n: BigUint, d: BigUint) {
        self.pending_rsa
            .insert(peer.into(), PendingRsaState { n, d });
    }

    /// Stores pending DH initiator state for incoming replies.
    pub fn register_pending_dh_state(
        &mut self,
        peer: impl Into<String>,
        p: BigUint,
        a_secret: BigUint,
    ) {
        self.pending_dh
            .insert(peer.into(), PendingDhState { p, a_secret });
    }

    /// Processes one inbound message.
    #[must_use]
    pub fn process_incoming(
        &mut self,
        raw_message: &[u8],
        transport: TransportKind,
        now: CmrTimestamp,
    ) -> ProcessOutcome {
        let parse_ctx = ParseContext {
            now: now.clone(),
            recipient_address: Some(self.local_address.as_str()),
            max_message_bytes: self.policy.content.max_message_bytes,
            max_header_ids: self.policy.content.max_header_ids,
            allow_legacy_v1_without_prefix: self
                .policy
                .content
                .allow_legacy_signature_without_version_prefix,
        };

        let parsed = match parse_message(raw_message, &parse_ctx) {
            Ok(m) => m,
            Err(err) => return ProcessOutcome::dropped(ProcessError::Parse(err)),
        };

        if parsed.body.len() > self.policy.content.max_body_bytes {
            return self.drop_for_peer(&parsed, ProcessError::BodyTooLarge, -2.0);
        }

        let sender = parsed.immediate_sender().to_owned();
        if !self.check_global_rate(raw_message.len()) {
            return self.drop_for_peer(&parsed, ProcessError::GlobalFloodLimited, -1.5);
        }
        if !self.check_peer_rate(&sender, raw_message.len()) {
            return self.drop_for_peer(&parsed, ProcessError::FloodLimited, -2.0);
        }
        if self.peer_reputation(&sender) < self.policy.trust.min_reputation_score {
            return self.drop_for_peer(&parsed, ProcessError::ReputationTooLow, -0.5);
        }
        if let Err(err) = self.validate_signature_policy(&parsed, &sender) {
            return self.drop_for_peer(&parsed, err, -4.0);
        }
        if self.cache.has_seen_any_id(&parsed) {
            return self.drop_for_peer(&parsed, ProcessError::DuplicateMessageId, -0.1);
        }
        if !self.policy.content.allow_binary_payloads && is_probably_binary(&parsed.body) {
            return self.drop_for_peer(&parsed, ProcessError::BinaryContentBlocked, -0.4);
        }
        if self.policy.content.block_executable_magic && looks_like_executable(&parsed.body) {
            return self.drop_for_peer(&parsed, ProcessError::ExecutableBlocked, -2.5);
        }

        match self.handle_key_exchange_control(&parsed, &sender, &transport, &now) {
            Ok(Some(forwards)) => {
                self.adjust_peer_reputation(&sender, 1.5);
                self.record_peer_inbound(&sender, raw_message.len());
                return ProcessOutcome {
                    accepted: true,
                    drop_reason: None,
                    parsed_message: Some(parsed),
                    intrinsic_dependence: None,
                    forwards,
                    matched_count: 0,
                    key_exchange_control: true,
                };
            }
            Ok(None) => {}
            Err(err) => return self.drop_for_peer(&parsed, err, -3.0),
        }

        let id_score = match self
            .oracle
            .intrinsic_dependence(&parsed.body, self.policy.spam.intrinsic_dependence_order)
        {
            Ok(score) => score,
            Err(err) => {
                return self.drop_for_peer(
                    &parsed,
                    ProcessError::Compression(err),
                    if self.policy.security_level == crate::policy::SecurityLevel::Trusted {
                        -0.2
                    } else {
                        -1.0
                    },
                );
            }
        };
        if !id_score.is_finite() {
            return self.drop_for_peer(&parsed, ProcessError::IntrinsicDependenceInvalid, -1.5);
        }
        if id_score < self.policy.spam.min_intrinsic_dependence {
            return self.drop_for_peer(&parsed, ProcessError::IntrinsicDependenceTooLow, -1.5);
        }

        let routing = match self.select_routing_decision(&parsed) {
            Ok(decision) => decision,
            Err(err) => return self.drop_for_peer(&parsed, err, -0.5),
        };
        let mut outcome = ProcessOutcome::accepted(parsed.clone());
        outcome.intrinsic_dependence = Some(id_score);
        outcome.matched_count = routing.matched_peers.len();

        self.cache.insert(parsed.clone());
        self.record_peer_inbound(&sender, raw_message.len());
        self.adjust_peer_reputation(&sender, 0.4);

        let mut limited = self.build_routing_forwards(&parsed, routing, &now);
        limited.truncate(self.policy.throughput.max_forward_actions);
        for action in &limited {
            self.record_peer_outbound(&action.destination, action.message_bytes.len());
        }
        outcome.forwards = limited;
        outcome
    }

    fn drop_for_peer(
        &mut self,
        parsed: &CmrMessage,
        reason: ProcessError,
        reputation_delta: f64,
    ) -> ProcessOutcome {
        let sender = parsed.immediate_sender().to_owned();
        self.adjust_peer_reputation(&sender, reputation_delta);
        ProcessOutcome {
            accepted: false,
            drop_reason: Some(reason),
            parsed_message: Some(parsed.clone()),
            intrinsic_dependence: None,
            forwards: Vec::new(),
            matched_count: 0,
            key_exchange_control: false,
        }
    }

    fn check_peer_rate(&mut self, peer: &str, message_bytes: usize) -> bool {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.window.allow_and_record(
            message_bytes,
            self.policy.throughput.per_peer_messages_per_minute,
            self.policy.throughput.per_peer_bytes_per_minute,
        )
    }

    fn check_global_rate(&mut self, message_bytes: usize) -> bool {
        self.global_window.allow_and_record(
            message_bytes,
            self.policy.throughput.global_messages_per_minute,
            self.policy.throughput.global_bytes_per_minute,
        )
    }

    fn peer_reputation(&self, peer: &str) -> f64 {
        self.peers.get(peer).map_or(0.0, |p| p.reputation)
    }

    fn adjust_peer_reputation(&mut self, peer: &str, delta: f64) {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.reputation = (metrics.reputation + delta).clamp(-100.0, 100.0);
    }

    fn record_peer_inbound(&mut self, peer: &str, bytes: usize) {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.inbound_messages = metrics.inbound_messages.saturating_add(1);
        metrics.inbound_bytes = metrics
            .inbound_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn record_peer_outbound(&mut self, peer: &str, bytes: usize) {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.outbound_messages = metrics.outbound_messages.saturating_add(1);
        metrics.outbound_bytes = metrics
            .outbound_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn can_forward_to_peer(&self, peer: &str) -> bool {
        let Some(metrics) = self.peers.get(peer) else {
            return true;
        };
        if metrics.inbound_bytes == 0 {
            return metrics.outbound_bytes == 0;
        }
        let ratio = metrics.outbound_bytes as f64 / metrics.inbound_bytes as f64;
        ratio <= self.policy.trust.max_outbound_inbound_ratio
    }

    fn validate_signature_policy(
        &self,
        message: &CmrMessage,
        sender: &str,
    ) -> Result<(), ProcessError> {
        let known_key = self.shared_keys.get(sender);
        match (&message.signature, known_key) {
            (Signature::Unsigned, Some(_))
                if self.policy.trust.require_signatures_from_known_peers =>
            {
                Err(ProcessError::UnsignedRejected)
            }
            (Signature::Unsigned, None) if !self.policy.trust.allow_unsigned_from_unknown_peers => {
                Err(ProcessError::UnsignedRejected)
            }
            (Signature::Sha256(_), None) if self.policy.trust.reject_signed_without_known_key => {
                Err(ProcessError::SignedWithoutKnownKey)
            }
            (Signature::Sha256(_), Some(key)) => {
                if message
                    .signature
                    .verifies(&message.payload_without_signature_line(), Some(key))
                {
                    Ok(())
                } else {
                    Err(ProcessError::BadSignature)
                }
            }
            _ => Ok(()),
        }
    }

    fn handle_key_exchange_control(
        &mut self,
        message: &CmrMessage,
        sender: &str,
        transport: &TransportKind,
        now: &CmrTimestamp,
    ) -> Result<Option<Vec<ForwardAction>>, ProcessError> {
        let Some(control) = parse_key_exchange(&message.body)? else {
            return Ok(None);
        };

        let old_key = self.shared_keys.get(sender).cloned();
        match control {
            KeyExchangeMessage::ClearKey { key } => {
                if !transport.is_secure_channel() {
                    return Err(ProcessError::ClearKeyOnInsecureChannel);
                }
                let derived =
                    derive_exchange_key_from_bytes(&self.local_address, sender, b"clear", &key);
                self.shared_keys.insert(sender.to_owned(), derived);
                self.purge_key_exchange_cache(sender);
                Ok(Some(Vec::new()))
            }
            KeyExchangeMessage::RsaRequest { n, e } => {
                validate_rsa_request_params(&n, &e)?;
                let key = random_nonzero_biguint_below(&n).ok_or(
                    ProcessError::WeakKeyExchangeParameters("failed to generate RSA session key"),
                )?;
                let c = mod_pow(&key, &e, &n);
                let reply_body = KeyExchangeMessage::RsaReply { c }.render().into_bytes();
                let reply = self.build_control_reply(sender, reply_body, old_key.as_deref(), now);
                self.shared_keys.insert(
                    sender.to_owned(),
                    derive_exchange_key(&self.local_address, sender, b"rsa", &key),
                );
                self.purge_key_exchange_cache(sender);
                Ok(Some(vec![reply]))
            }
            KeyExchangeMessage::RsaReply { c } => {
                let Some(state) = self.pending_rsa.remove(sender) else {
                    return Err(ProcessError::MissingPendingKeyExchangeState);
                };
                if c >= state.n {
                    return Err(ProcessError::WeakKeyExchangeParameters(
                        "RSA reply ciphertext out of range",
                    ));
                }
                let key = mod_pow(&c, &state.d, &state.n);
                if key.is_zero() {
                    return Err(ProcessError::WeakKeyExchangeParameters(
                        "RSA shared key reduced to zero",
                    ));
                }
                self.shared_keys.insert(
                    sender.to_owned(),
                    derive_exchange_key(&self.local_address, sender, b"rsa", &key),
                );
                self.purge_key_exchange_cache(sender);
                Ok(Some(Vec::new()))
            }
            KeyExchangeMessage::DhRequest { g, p, a_pub } => {
                validate_dh_request_params(&g, &p, &a_pub)?;
                let b_secret =
                    random_dh_secret(&p).ok_or(ProcessError::WeakKeyExchangeParameters(
                        "failed to generate DH secret exponent",
                    ))?;
                let b_pub = mod_pow(&g, &b_secret, &p);
                let shared = mod_pow(&a_pub, &b_secret, &p);
                if shared <= BigUint::one() {
                    return Err(ProcessError::WeakKeyExchangeParameters(
                        "DH derived weak shared key",
                    ));
                }
                let reply_body = KeyExchangeMessage::DhReply { b_pub }.render().into_bytes();
                let reply = self.build_control_reply(sender, reply_body, old_key.as_deref(), now);
                self.shared_keys.insert(
                    sender.to_owned(),
                    derive_exchange_key(&self.local_address, sender, b"dh", &shared),
                );
                self.purge_key_exchange_cache(sender);
                Ok(Some(vec![reply]))
            }
            KeyExchangeMessage::DhReply { b_pub } => {
                let Some(state) = self.pending_dh.remove(sender) else {
                    return Err(ProcessError::MissingPendingKeyExchangeState);
                };
                validate_dh_reply_params(&b_pub, &state.p)?;
                let shared = mod_pow(&b_pub, &state.a_secret, &state.p);
                if shared <= BigUint::one() {
                    return Err(ProcessError::WeakKeyExchangeParameters(
                        "DH derived weak shared key",
                    ));
                }
                self.shared_keys.insert(
                    sender.to_owned(),
                    derive_exchange_key(&self.local_address, sender, b"dh", &shared),
                );
                self.purge_key_exchange_cache(sender);
                Ok(Some(Vec::new()))
            }
        }
    }

    fn build_control_reply(
        &mut self,
        destination: &str,
        body: Vec<u8>,
        signing_key: Option<&[u8]>,
        now: &CmrTimestamp,
    ) -> ForwardAction {
        let mut msg = CmrMessage {
            signature: Signature::Unsigned,
            header: vec![MessageId {
                timestamp: self.next_forward_timestamp(now),
                address: self.local_address.clone(),
            }],
            body,
        };
        if let Some(key) = signing_key {
            msg.sign_with_key(key);
        }
        ForwardAction {
            destination: destination.to_owned(),
            message_bytes: msg.to_bytes(),
            reason: ForwardReason::KeyExchangeReply,
        }
    }

    fn purge_key_exchange_cache(&mut self, peer: &str) {
        let local = self.local_address.clone();
        self.cache.remove_if(|message| {
            parse_key_exchange(&message.body).ok().flatten().is_some()
                && (message_contains_sender(message, peer)
                    || message_contains_sender(message, &local))
        });
    }

    fn select_routing_decision(
        &self,
        incoming: &CmrMessage,
    ) -> Result<RoutingDecision, ProcessError> {
        let peer_corpora = self.collect_peer_corpora();
        if peer_corpora.is_empty() {
            return Ok(RoutingDecision::default());
        }

        let mut peers: Vec<(&String, &Vec<u8>)> = peer_corpora.iter().collect();
        peers.sort_by(|left, right| left.0.cmp(right.0));
        let peer_names: Vec<String> = peers.iter().map(|(peer, _)| (*peer).to_owned()).collect();
        let corpora: Vec<Vec<u8>> = peers.iter().map(|(_, corpus)| (*corpus).clone()).collect();
        let distances = self
            .oracle
            .batch_compression_distance(&incoming.body, &corpora)
            .map_err(ProcessError::Compression)?;

        let mut best: Option<(String, f64)> = None;
        let mut matched_peers = Vec::<String>::new();
        for (peer, distance) in peer_names.into_iter().zip(distances.into_iter()) {
            if !distance.is_finite() {
                continue;
            }
            if distance <= self.policy.spam.max_match_distance {
                matched_peers.push(peer.clone());
            }
            if best
                .as_ref()
                .is_none_or(|(_, best_distance)| distance < *best_distance)
            {
                best = Some((peer, distance));
            }
        }

        let Some((best_peer, best_distance)) = best else {
            return Ok(RoutingDecision::default());
        };
        if best_distance > self.policy.spam.max_match_distance || matched_peers.is_empty() {
            return Ok(RoutingDecision::default());
        }

        let matched_set = matched_peers
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let matched_messages = self
            .cache
            .order
            .iter()
            .filter_map(|key| self.cache.entries.get(key))
            .filter(|entry| matched_set.contains(entry.message.immediate_sender()))
            .map(|entry| entry.message.clone())
            .collect::<Vec<_>>();

        let compensatory = if message_contains_sender(incoming, &best_peer) {
            self.select_compensatory_message(incoming, &best_peer, &peer_corpora)?
                .map(|message| (best_peer.clone(), message))
        } else {
            None
        };

        Ok(RoutingDecision {
            best_peer: Some(best_peer),
            matched_peers,
            matched_messages,
            compensatory,
        })
    }

    fn collect_peer_corpora(&self) -> HashMap<String, Vec<u8>> {
        let mut peer_corpora = HashMap::<String, Vec<u8>>::new();
        for key in &self.cache.order {
            let Some(entry) = self.cache.entries.get(key) else {
                continue;
            };
            let sender = entry.message.immediate_sender();
            if sender == self.local_address.as_str() {
                continue;
            }
            peer_corpora
                .entry(sender.to_owned())
                .or_default()
                .extend_from_slice(&entry.message.body);
        }
        peer_corpora
    }

    fn select_compensatory_message(
        &self,
        incoming: &CmrMessage,
        best_peer: &str,
        peer_corpora: &HashMap<String, Vec<u8>>,
    ) -> Result<Option<CmrMessage>, ProcessError> {
        let ordered_entries = self
            .cache
            .order
            .iter()
            .filter_map(|key| self.cache.entries.get(key))
            .collect::<Vec<_>>();
        if ordered_entries.len() <= 1 {
            return Ok(None);
        }

        let total_bytes = ordered_entries
            .iter()
            .map(|entry| entry.message.body.len())
            .sum::<usize>();
        let mut x_guess = Vec::with_capacity(
            incoming.body.len() + peer_corpora.get(best_peer).map_or(0, std::vec::Vec::len),
        );
        x_guess.extend_from_slice(&incoming.body);
        if let Some(known_from_best_peer) = peer_corpora.get(best_peer) {
            x_guess.extend_from_slice(known_from_best_peer);
        }

        let mut best_score = f64::NEG_INFINITY;
        let mut best_message = None;
        for (idx, entry) in ordered_entries.iter().enumerate() {
            if message_contains_sender(&entry.message, best_peer) {
                continue;
            }
            let candidate_body = &entry.message.body;
            if total_bytes <= candidate_body.len() {
                continue;
            }

            let mut remainder =
                Vec::with_capacity(total_bytes.saturating_sub(candidate_body.len()));
            for (other_idx, other_entry) in ordered_entries.iter().enumerate() {
                if idx == other_idx {
                    continue;
                }
                remainder.extend_from_slice(&other_entry.message.body);
            }
            if remainder.is_empty() {
                continue;
            }

            let d_cache = self
                .oracle
                .compression_distance(candidate_body, &remainder)
                .map_err(ProcessError::Compression)?;
            let d_guess = self
                .oracle
                .compression_distance(&x_guess, candidate_body)
                .map_err(ProcessError::Compression)?;
            if !d_cache.is_finite() || !d_guess.is_finite() {
                continue;
            }
            let score = d_cache - d_guess;
            if score > best_score {
                best_score = score;
                best_message = Some(entry.message.clone());
            }
        }

        Ok(best_message)
    }

    fn build_routing_forwards(
        &mut self,
        incoming: &CmrMessage,
        decision: RoutingDecision,
        now: &CmrTimestamp,
    ) -> Vec<ForwardAction> {
        let mut out = Vec::new();
        let mut dedupe = HashSet::<(String, String)>::new();
        let incoming_key = cache_key(incoming);
        let incoming_destinations = sorted_unique_addresses(&incoming.header);
        let suppress_best = decision
            .best_peer
            .as_deref()
            .filter(|peer| message_contains_sender(incoming, peer));

        for matched in &decision.matched_messages {
            for destination in sorted_unique_addresses(&matched.header) {
                if destination == self.local_address {
                    continue;
                }
                if suppress_best.is_some_and(|peer| peer == destination) {
                    continue;
                }
                if !self.can_forward_to_peer(&destination) {
                    continue;
                }
                let dedupe_key = (destination.clone(), incoming_key.clone());
                if dedupe.insert(dedupe_key) {
                    out.push(self.wrap_and_forward(
                        incoming,
                        &destination,
                        now,
                        ForwardReason::MatchedForwardIncoming,
                    ));
                }
            }

            let matched_key = cache_key(matched);
            for destination in &incoming_destinations {
                if destination == &self.local_address {
                    continue;
                }
                if !self.can_forward_to_peer(destination) {
                    continue;
                }
                let dedupe_key = (destination.clone(), matched_key.clone());
                if dedupe.insert(dedupe_key) {
                    out.push(self.wrap_and_forward(
                        matched,
                        destination,
                        now,
                        ForwardReason::MatchedForwardCached,
                    ));
                }
            }
        }

        if let Some((destination, message)) = decision.compensatory
            && destination != self.local_address
            && self.can_forward_to_peer(&destination)
        {
            let dedupe_key = (destination.clone(), cache_key(&message));
            if dedupe.insert(dedupe_key) {
                out.push(self.wrap_and_forward(
                    &message,
                    &destination,
                    now,
                    ForwardReason::CompensatoryReply,
                ));
            }
        }
        out
    }

    fn wrap_and_forward(
        &mut self,
        message: &CmrMessage,
        destination: &str,
        now: &CmrTimestamp,
        reason: ForwardReason,
    ) -> ForwardAction {
        let mut forwarded = message.clone();
        forwarded.make_unsigned();
        forwarded.prepend_hop(MessageId {
            timestamp: self.next_forward_timestamp(now),
            address: self.local_address.clone(),
        });
        if let Some(key) = self.shared_keys.get(destination) {
            forwarded.sign_with_key(key);
        }
        ForwardAction {
            destination: destination.to_owned(),
            message_bytes: forwarded.to_bytes(),
            reason,
        }
    }

    fn next_forward_timestamp(&mut self, now: &CmrTimestamp) -> CmrTimestamp {
        self.forward_counter = self.forward_counter.saturating_add(1);
        let fraction = format!("{:020}", self.forward_counter);
        now.clone().with_fraction(fraction)
    }
}

fn cache_key(message: &CmrMessage) -> String {
    message
        .origin_id()
        .map_or_else(|| message.header[0].to_string(), MessageId::to_string)
}

fn message_contains_sender(message: &CmrMessage, sender: &str) -> bool {
    message.header.iter().any(|id| id.address == sender)
}

fn sorted_unique_addresses(header: &[MessageId]) -> Vec<String> {
    let mut addresses = header
        .iter()
        .map(|id| id.address.clone())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses
}

fn is_probably_binary(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let non_text = body
        .iter()
        .copied()
        .filter(|b| !matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E))
        .count();
    non_text * 10 > body.len() * 3
}

fn looks_like_executable(body: &[u8]) -> bool {
    body.starts_with(b"\x7fELF")
        || body.starts_with(b"MZ")
        || body.starts_with(b"\xfe\xed\xfa\xce")
        || body.starts_with(b"\xce\xfa\xed\xfe")
        || body.starts_with(b"\xcf\xfa\xed\xfe")
        || body.starts_with(b"\xfe\xed\xfa\xcf")
}

fn validate_rsa_request_params(n: &BigUint, e: &BigUint) -> Result<(), ProcessError> {
    if n.bits() < MIN_RSA_MODULUS_BITS {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "RSA modulus too small",
        ));
    }
    let two = BigUint::from(2_u8);
    if n <= &two || (n % &two).is_zero() {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "RSA modulus must be odd and > 2",
        ));
    }
    if e <= &two || (e % &two).is_zero() {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "RSA exponent must be odd and > 2",
        ));
    }
    if e >= n {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "RSA exponent must be smaller than modulus",
        ));
    }
    if is_probably_prime(n, 10) {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "RSA modulus must be composite",
        ));
    }
    Ok(())
}

fn validate_dh_request_params(
    g: &BigUint,
    p: &BigUint,
    a_pub: &BigUint,
) -> Result<(), ProcessError> {
    if p.bits() < MIN_DH_MODULUS_BITS {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH modulus too small",
        ));
    }
    let two = BigUint::from(2_u8);
    if p <= &two || (p % &two).is_zero() {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH modulus must be odd and > 2",
        ));
    }
    if !is_probably_safe_prime(p, 10) {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH modulus must be a safe prime",
        ));
    }

    let p_minus_one = p - BigUint::one();
    if g <= &BigUint::one() || g >= &p_minus_one {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH generator must be in range (1, p-1)",
        ));
    }
    if a_pub <= &BigUint::one() || a_pub >= &p_minus_one {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH public value must be in range (1, p-1)",
        ));
    }
    Ok(())
}

fn validate_dh_reply_params(b_pub: &BigUint, p: &BigUint) -> Result<(), ProcessError> {
    if !is_probably_safe_prime(p, 10) {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH modulus must be a safe prime",
        ));
    }
    let p_minus_one = p - BigUint::one();
    if b_pub <= &BigUint::one() || b_pub >= &p_minus_one {
        return Err(ProcessError::WeakKeyExchangeParameters(
            "DH reply value must be in range (1, p-1)",
        ));
    }
    Ok(())
}

fn random_nonzero_biguint_below(modulus: &BigUint) -> Option<BigUint> {
    let modulus_bits = usize::try_from(modulus.bits()).ok()?;
    if modulus_bits == 0 {
        return None;
    }
    let byte_len = modulus_bits.div_ceil(8);
    let excess_bits = byte_len.saturating_mul(8).saturating_sub(modulus_bits);
    let mut rng = rand::rng();
    let mut raw = vec![0_u8; byte_len];
    for _ in 0..256 {
        rng.fill_bytes(&mut raw);
        if excess_bits > 0 {
            raw[0] &= 0xff_u8 >> excess_bits;
        }
        let value = BigUint::from_bytes_be(&raw);
        if !value.is_zero() && &value < modulus {
            return Some(value);
        }
    }
    None
}

fn random_dh_secret(p: &BigUint) -> Option<BigUint> {
    if p <= &BigUint::one() {
        return None;
    }
    let upper_bound = p - BigUint::one();
    for _ in 0..256 {
        let candidate = random_nonzero_biguint_below(&upper_bound)?;
        if candidate > BigUint::one() {
            return Some(candidate);
        }
    }
    None
}

fn derive_exchange_key(local: &str, peer: &str, label: &[u8], secret: &BigUint) -> Vec<u8> {
    let mut ikm = secret.to_bytes_be();
    if ikm.is_empty() {
        ikm.push(0);
    }
    derive_exchange_key_from_bytes(local, peer, label, &ikm)
}

fn derive_exchange_key_from_bytes(local: &str, peer: &str, label: &[u8], secret: &[u8]) -> Vec<u8> {
    let (left, right) = if local <= peer {
        (local.as_bytes(), peer.as_bytes())
    } else {
        (peer.as_bytes(), local.as_bytes())
    };

    let hk = Hkdf::<Sha256>::new(Some(b"cmr-v1-key-exchange"), secret);
    let mut info = Vec::with_capacity(3 + label.len() + left.len() + right.len());
    info.extend_from_slice(b"cmr");
    info.push(0);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(left);
    info.push(0);
    info.extend_from_slice(right);

    let mut out = [0_u8; 32];
    hk.expand(&info, &mut out)
        .expect("HKDF expand length is fixed and valid");
    out.to_vec()
}

fn is_probably_safe_prime(p: &BigUint, rounds: usize) -> bool {
    if !is_probably_prime(p, rounds) {
        return false;
    }
    let one = BigUint::one();
    let two = BigUint::from(2_u8);
    if p <= &two {
        return false;
    }
    let q = (p - &one) >> 1;
    is_probably_prime(&q, rounds)
}

fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    let two = BigUint::from(2_u8);
    let three = BigUint::from(3_u8);
    if n < &two {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if (n % &two).is_zero() {
        return false;
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0_u32;
    while (&d % &two).is_zero() {
        d >>= 1;
        s = s.saturating_add(1);
    }

    const BASES: [u8; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for &base in &BASES {
        let a = BigUint::from(base);
        if a >= n_minus_one {
            continue;
        }
        if is_miller_rabin_witness(n, &d, s, &a) {
            return false;
        }
    }

    let three = BigUint::from(3_u8);
    let n_minus_three = n - &three;
    for _ in 0..rounds {
        let Some(offset) = random_nonzero_biguint_below(&n_minus_three) else {
            return false;
        };
        let a = offset + &two;
        if is_miller_rabin_witness(n, &d, s, &a) {
            return false;
        }
    }

    true
}

fn is_miller_rabin_witness(n: &BigUint, d: &BigUint, s: u32, a: &BigUint) -> bool {
    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut x = mod_pow(a, d, n);
    if x == one || x == n_minus_one {
        return false;
    }
    for _ in 1..s {
        x = (&x * &x) % n;
        if x == n_minus_one {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubOracle;

    impl CompressionOracle for StubOracle {
        fn ncd_sym(&self, _left: &[u8], _right: &[u8]) -> Result<f64, CompressionError> {
            Ok(0.4)
        }

        fn compression_distance(
            &self,
            _left: &[u8],
            _right: &[u8],
        ) -> Result<f64, CompressionError> {
            Ok(0.4)
        }

        fn intrinsic_dependence(
            &self,
            _data: &[u8],
            _max_order: i64,
        ) -> Result<f64, CompressionError> {
            Ok(0.5)
        }
    }

    fn now() -> CmrTimestamp {
        CmrTimestamp::parse("2030/01/01 00:00:10").expect("ts")
    }

    #[test]
    fn accepts_minimal_message() {
        let policy = RoutingPolicy::default();
        let mut router = Router::new("http://bob".to_owned(), policy, StubOracle);
        let raw = b"0\r\n2029/12/31 23:59:59 http://alice\r\n\r\n5\r\nhello";
        let outcome = router.process_incoming(raw, TransportKind::Http, now());
        assert!(outcome.accepted);
        assert!(outcome.drop_reason.is_none());
    }

    #[test]
    fn rejects_duplicate_id() {
        let policy = RoutingPolicy::default();
        let mut router = Router::new("http://bob".to_owned(), policy, StubOracle);
        let raw = b"0\r\n2029/12/31 23:59:59 http://alice\r\n\r\n5\r\nhello";
        let first = router.process_incoming(raw, TransportKind::Http, now());
        assert!(first.accepted);
        let second = router.process_incoming(raw, TransportKind::Http, now());
        assert!(!second.accepted);
        assert!(matches!(
            second.drop_reason,
            Some(ProcessError::DuplicateMessageId)
        ));
    }
}
