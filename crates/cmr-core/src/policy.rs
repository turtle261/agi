//! Router security and routing policy.

use serde::{Deserialize, Serialize};

/// Global security posture.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityLevel {
    /// Strict defaults for untrusted internet peers.
    #[default]
    Strict,
    /// Balanced defaults for mixed deployments.
    Balanced,
    /// Trusted peers where performance matters most.
    Trusted,
}

/// Throughput and anti-flood policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThroughputPolicy {
    /// Max inbound messages per peer per minute.
    pub per_peer_messages_per_minute: u32,
    /// Max inbound bytes per peer per minute.
    pub per_peer_bytes_per_minute: u64,
    /// Max total inbound messages per minute.
    pub global_messages_per_minute: u32,
    /// Max total inbound bytes per minute.
    pub global_bytes_per_minute: u64,
    /// Max forwarding fanout produced by one accepted message.
    pub max_forward_actions: usize,
}

/// Spam and semantic match policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpamPolicy {
    /// Minimum intrinsic dependence accepted for untrusted payloads.
    pub min_intrinsic_dependence: f64,
    /// Maximum distance for message match/forwarding.
    pub max_match_distance: f64,
    /// Estimator order for intrinsic-dependence checks.
    pub intrinsic_dependence_order: i64,
}

/// Identity/trust and reputation policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Minimum score required to accept traffic from a peer.
    pub min_reputation_score: f64,
    /// Require signatures from known peers that already have a shared key.
    pub require_signatures_from_known_peers: bool,
    /// Reject signed messages when no key exists for the immediate sender.
    pub reject_signed_without_known_key: bool,
    /// Allow unsigned messages from unknown peers.
    pub allow_unsigned_from_unknown_peers: bool,
    /// Max outbound/inbound byte ratio before throttling peer.
    pub max_outbound_inbound_ratio: f64,
    /// Automatic key-exchange method for unknown peers.
    #[serde(default)]
    pub auto_key_exchange_mode: AutoKeyExchangeMode,
}

/// Automatic first-contact key-exchange method.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoKeyExchangeMode {
    /// Initiate RSA key exchange.
    #[default]
    Rsa,
    /// Initiate Diffie-Hellman key exchange.
    Dh,
}

/// Content safety policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentPolicy {
    /// Max full message size.
    pub max_message_bytes: usize,
    /// Max body size.
    pub max_body_bytes: usize,
    /// Max header hop count.
    pub max_header_ids: usize,
    /// Allow non-text/binary payloads.
    pub allow_binary_payloads: bool,
    /// Drop likely executable payloads unless peer is trusted.
    pub block_executable_magic: bool,
    /// Parser compatibility mode for legacy signature line sample.
    pub allow_legacy_signature_without_version_prefix: bool,
}

/// Full router policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingPolicy {
    /// High-level security posture.
    pub security_level: SecurityLevel,
    /// Throughput controls.
    pub throughput: ThroughputPolicy,
    /// Spam controls.
    pub spam: SpamPolicy,
    /// Trust controls.
    pub trust: TrustPolicy,
    /// Content controls.
    pub content: ContentPolicy,
    /// Max messages retained in cache.
    pub cache_max_messages: usize,
    /// Max bytes retained in cache.
    pub cache_max_bytes: usize,
}

impl RoutingPolicy {
    /// Default policy for a chosen security level.
    #[must_use]
    pub fn for_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Strict => Self {
                security_level: level,
                throughput: ThroughputPolicy {
                    per_peer_messages_per_minute: 240,
                    per_peer_bytes_per_minute: 8 * 1024 * 1024,
                    global_messages_per_minute: 20_000,
                    global_bytes_per_minute: 512 * 1024 * 1024,
                    max_forward_actions: 64,
                },
                spam: SpamPolicy {
                    min_intrinsic_dependence: 0.02,
                    max_match_distance: 0.72,
                    intrinsic_dependence_order: 8,
                },
                trust: TrustPolicy {
                    min_reputation_score: -20.0,
                    require_signatures_from_known_peers: true,
                    reject_signed_without_known_key: true,
                    allow_unsigned_from_unknown_peers: true,
                    max_outbound_inbound_ratio: 1.8,
                    auto_key_exchange_mode: AutoKeyExchangeMode::Rsa,
                },
                content: ContentPolicy {
                    max_message_bytes: 4 * 1024 * 1024,
                    max_body_bytes: 2 * 1024 * 1024,
                    max_header_ids: 1024,
                    allow_binary_payloads: true,
                    block_executable_magic: true,
                    allow_legacy_signature_without_version_prefix: false,
                },
                cache_max_messages: 200_000,
                cache_max_bytes: 2 * 1024 * 1024 * 1024,
            },
            SecurityLevel::Balanced => Self {
                security_level: level,
                throughput: ThroughputPolicy {
                    per_peer_messages_per_minute: 600,
                    per_peer_bytes_per_minute: 16 * 1024 * 1024,
                    global_messages_per_minute: 40_000,
                    global_bytes_per_minute: 1024 * 1024 * 1024,
                    max_forward_actions: 128,
                },
                spam: SpamPolicy {
                    min_intrinsic_dependence: 0.01,
                    max_match_distance: 0.75,
                    intrinsic_dependence_order: 8,
                },
                trust: TrustPolicy {
                    min_reputation_score: -40.0,
                    require_signatures_from_known_peers: true,
                    reject_signed_without_known_key: false,
                    allow_unsigned_from_unknown_peers: true,
                    max_outbound_inbound_ratio: 2.5,
                    auto_key_exchange_mode: AutoKeyExchangeMode::Rsa,
                },
                content: ContentPolicy {
                    max_message_bytes: 8 * 1024 * 1024,
                    max_body_bytes: 4 * 1024 * 1024,
                    max_header_ids: 2048,
                    allow_binary_payloads: true,
                    block_executable_magic: true,
                    allow_legacy_signature_without_version_prefix: true,
                },
                cache_max_messages: 400_000,
                cache_max_bytes: 4 * 1024 * 1024 * 1024,
            },
            SecurityLevel::Trusted => Self {
                security_level: level,
                throughput: ThroughputPolicy {
                    per_peer_messages_per_minute: 6_000,
                    per_peer_bytes_per_minute: 128 * 1024 * 1024,
                    global_messages_per_minute: 200_000,
                    global_bytes_per_minute: 8 * 1024 * 1024 * 1024,
                    max_forward_actions: 512,
                },
                spam: SpamPolicy {
                    min_intrinsic_dependence: 0.0,
                    max_match_distance: 0.8,
                    intrinsic_dependence_order: 8,
                },
                trust: TrustPolicy {
                    min_reputation_score: -80.0,
                    require_signatures_from_known_peers: false,
                    reject_signed_without_known_key: false,
                    allow_unsigned_from_unknown_peers: true,
                    max_outbound_inbound_ratio: 4.0,
                    auto_key_exchange_mode: AutoKeyExchangeMode::Rsa,
                },
                content: ContentPolicy {
                    max_message_bytes: 16 * 1024 * 1024,
                    max_body_bytes: 12 * 1024 * 1024,
                    max_header_ids: 4096,
                    allow_binary_payloads: true,
                    block_executable_magic: false,
                    allow_legacy_signature_without_version_prefix: true,
                },
                cache_max_messages: 1_000_000,
                cache_max_bytes: 16 * 1024 * 1024 * 1024,
            },
        }
    }
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self::for_level(SecurityLevel::Strict)
    }
}
