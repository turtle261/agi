//! Core protocol and router primitives for CMR.
//!
//! This crate intentionally excludes compressor implementations so they can run
//! in a separate capability-limited process.

pub mod compressor_ipc;
pub mod key_exchange;
pub mod policy;
pub mod protocol;
pub mod router;

pub use policy::{
    AutoKeyExchangeMode, ContentPolicy, RoutingPolicy, SecurityLevel, SpamPolicy, ThroughputPolicy,
    TrustPolicy,
};
pub use protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, Signature, TransportKind, parse_message,
};
pub use router::{
    CacheEntryView, CacheStats, CompressionError, CompressionOracle, ForwardAction, ForwardReason,
    PeerSnapshot, ProcessError, ProcessOutcome, Router, RoutingDiagnostics,
};
