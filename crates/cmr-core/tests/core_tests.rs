use std::io::Cursor;
use std::sync::{Arc, Mutex};

use cmr_core::compressor_ipc::{
    CompressorRequest, CompressorResponse, IpcError, read_frame, write_frame,
};
use cmr_core::key_exchange::{KeyExchangeMessage, parse_key_exchange};
use cmr_core::policy::RoutingPolicy;
use cmr_core::protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, ParseError, Signature, TransportKind,
    parse_message,
};
use cmr_core::router::{CompressionError, CompressionOracle, ForwardReason, ProcessError, Router};
use num_bigint::BigUint;
use proptest::prelude::*;

struct StubOracle {
    intrinsic: f64,
    distance: f64,
    fail_intrinsic: bool,
    fail_distance: bool,
}

#[derive(Clone, Copy)]
struct JupiterOracle;

impl JupiterOracle {
    fn score(left: &[u8], right: &[u8]) -> f64 {
        let l = String::from_utf8_lossy(left).to_ascii_lowercase();
        let r = String::from_utf8_lossy(right).to_ascii_lowercase();
        if l.contains("largest planet") && r.contains("jupiter") {
            return 80.0;
        }
        if l.contains("largest planet") && r.contains("mercury") {
            return 320.0;
        }
        if l.contains("mercury") && r.contains("mercury") {
            return 40.0;
        }
        if l.contains("jupiter") && r.contains("jupiter") {
            return 40.0;
        }
        900.0
    }
}

impl CompressionOracle for JupiterOracle {
    fn compression_distance(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError> {
        Ok(Self::score(left, right))
    }

    fn intrinsic_dependence(&self, _data: &[u8], _max_order: i64) -> Result<f64, CompressionError> {
        Ok(0.9)
    }

    fn batch_compression_distance(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        Ok(candidates
            .iter()
            .map(|candidate| Self::score(target, candidate))
            .collect())
    }
}

impl StubOracle {
    fn ok(intrinsic: f64, distance: f64) -> Self {
        Self {
            intrinsic,
            distance,
            fail_intrinsic: false,
            fail_distance: false,
        }
    }

    fn with_distances(intrinsic: f64, distance: f64) -> Self {
        Self {
            intrinsic,
            distance,
            fail_intrinsic: false,
            fail_distance: false,
        }
    }
}

impl CompressionOracle for StubOracle {
    fn compression_distance(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError> {
        if self.fail_distance {
            Err(CompressionError::Failed("distance failed".to_owned()))
        } else if left == right {
            Ok(0.0)
        } else {
            Ok(self.distance)
        }
    }

    fn intrinsic_dependence(&self, _data: &[u8], _max_order: i64) -> Result<f64, CompressionError> {
        if self.fail_intrinsic {
            Err(CompressionError::Failed("intrinsic failed".to_owned()))
        } else {
            Ok(self.intrinsic)
        }
    }

    fn batch_compression_distance(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        if self.fail_distance {
            Err(CompressionError::Failed("distance failed".to_owned()))
        } else {
            candidates
                .iter()
                .map(|candidate| self.compression_distance(target, candidate))
                .collect()
        }
    }
}

fn ts(value: &str) -> CmrTimestamp {
    CmrTimestamp::parse(value).expect("timestamp")
}

fn parse_ctx<'a>(recipient: Option<&'a str>) -> ParseContext<'a> {
    ParseContext::secure(ts("2030/01/01 00:00:10"), recipient)
}

fn message_with_sender(
    sender: &str,
    body: &[u8],
    signature_key: Option<&[u8]>,
    timestamp: &str,
) -> Vec<u8> {
    let mut message = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: ts(timestamp),
            address: sender.to_owned(),
        }],
        body: body.to_vec(),
    };
    if let Some(key) = signature_key {
        message.sign_with_key(key);
    }
    message.to_bytes()
}

fn permissive_policy() -> RoutingPolicy {
    let mut policy = RoutingPolicy::default();
    policy.spam.min_intrinsic_dependence = 0.0;
    policy.trust.require_signatures_from_known_peers = false;
    policy.trust.reject_signed_without_known_key = false;
    policy.trust.allow_unsigned_from_unknown_peers = true;
    policy
}

proptest! {
    #[test]
    fn protocol_roundtrip_preserves_arbitrary_body_bytes(body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let message = CmrMessage {
            signature: Signature::Unsigned,
            header: vec![MessageId {
                timestamp: ts("2029/12/31 23:59:59"),
                address: "http://alice".to_owned(),
            }],
            body: body.clone(),
        };
        let wire = message.to_bytes();
        let parsed = parse_message(&wire, &parse_ctx(Some("http://bob"))).expect("parse");
        prop_assert_eq!(parsed.body, body);
    }

    #[test]
    fn protocol_rejects_duplicate_addresses_property(host in "[a-z0-9]{1,12}") {
        let addr = format!("http://{host}.example/cmr");
        let raw = format!(
            "0\r\n2029/12/31 23:59:59 {addr}\r\n2029/12/31 23:59:58 {addr}\r\n\r\n1\r\na"
        );
        let err = parse_message(raw.as_bytes(), &parse_ctx(Some("http://receiver")))
            .expect_err("must reject duplicate address");
        prop_assert!(matches!(err, ParseError::DuplicateAddress));
    }
}

#[test]
fn protocol_rejects_future_timestamp() {
    let raw = b"0\r\n2030/01/01 00:00:11 http://alice\r\n\r\n1\r\na";
    let err = parse_message(raw, &parse_ctx(Some("http://bob"))).expect_err("must reject");
    assert!(matches!(err, ParseError::FutureTimestamp));
}

#[test]
fn protocol_rejects_duplicate_address_and_nondescending_times() {
    let raw_dup =
        b"0\r\n2029/12/31 23:59:59 http://alice\r\n2029/12/31 23:59:58 http://alice\r\n\r\n1\r\na";
    let err = parse_message(raw_dup, &parse_ctx(Some("http://bob"))).expect_err("must reject");
    assert!(matches!(err, ParseError::DuplicateAddress));

    let raw_non_desc = b"0\r\n2029/12/31 23:59:58 http://alice\r\n2029/12/31 23:59:58 http://charlie\r\n\r\n1\r\na";
    let err = parse_message(raw_non_desc, &parse_ctx(Some("http://bob"))).expect_err("must reject");
    assert!(matches!(err, ParseError::NonDescendingTimestamps));
}

#[test]
fn protocol_rejects_legacy_signature_without_version_prefix() {
    let mut message = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: ts("2029/12/31 23:59:59"),
            address: "http://alice".to_owned(),
        }],
        body: b"hello".to_vec(),
    };
    message.sign_with_key(b"secret");
    let mut wire = message.to_bytes();
    // Replace `1<hash>` with `<hash>` (legacy v2.2 sample format).
    wire.remove(0);

    let strict_ctx = parse_ctx(Some("http://bob"));
    let err = parse_message(&wire, &strict_ctx).expect_err("must reject");
    assert!(matches!(err, ParseError::InvalidSignature));
}

#[test]
fn key_exchange_parses_all_message_variants() {
    let rsa_req = parse_key_exchange(b"RSA key exchange request=aa,11.")
        .expect("parse")
        .expect("control");
    assert!(matches!(rsa_req, KeyExchangeMessage::RsaRequest { .. }));

    let rsa_reply = parse_key_exchange(b"RSA key exchange reply=ff.")
        .expect("parse")
        .expect("control");
    assert!(matches!(rsa_reply, KeyExchangeMessage::RsaReply { .. }));

    let dh_req = parse_key_exchange(b"DH key exchange request=05,17,08.")
        .expect("parse")
        .expect("control");
    assert!(matches!(dh_req, KeyExchangeMessage::DhRequest { .. }));

    let dh_reply = parse_key_exchange(b"DH key exchange reply=13.")
        .expect("parse")
        .expect("control");
    assert!(matches!(dh_reply, KeyExchangeMessage::DhReply { .. }));

    let clear = parse_key_exchange(b"Clear key exchange=666f6f.")
        .expect("parse")
        .expect("control");
    assert_eq!(
        clear,
        KeyExchangeMessage::ClearKey {
            key: b"foo".to_vec()
        }
    );
}

#[test]
fn key_exchange_rejects_malformed_or_uppercase_hex() {
    assert!(parse_key_exchange(b"RSA key exchange request=AA,11.").is_err());
    assert!(parse_key_exchange(b"DH key exchange request=05,17.").is_err());
    assert!(parse_key_exchange(b"Clear key exchange=abc.").is_err());
}

#[test]
fn ipc_round_trip_and_bounds() {
    let request = CompressorRequest::BatchCompressionDistance {
        target: b"alpha".to_vec(),
        candidates: vec![b"beta".to_vec(), b"gamma".to_vec()],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &request).expect("write");
    let decoded: CompressorRequest = read_frame(&mut Cursor::new(bytes), 1024).expect("read");
    assert!(matches!(
        decoded,
        CompressorRequest::BatchCompressionDistance { .. }
    ));

    let oversized = {
        let mut v = Vec::new();
        v.extend_from_slice(&(16_u32.to_be_bytes()));
        v.extend_from_slice(b"{}");
        v
    };
    let err = read_frame::<CompressorResponse>(&mut Cursor::new(oversized), 4).expect_err("size");
    assert!(matches!(err, IpcError::FrameTooLarge));
}

#[test]
fn router_rejects_unsigned_from_known_peer_when_required() {
    let mut router = Router::new(
        "http://local".to_owned(),
        RoutingPolicy::default(),
        StubOracle::ok(0.8, 0.2),
    );
    router.set_shared_key("http://alice", b"shared".to_vec());

    let raw = message_with_sender("http://alice", b"hello", None, "2029/12/31 23:59:59");
    let out = router.process_incoming(&raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!out.accepted);
    assert!(matches!(
        out.drop_reason,
        Some(ProcessError::UnsignedRejected)
    ));
}

#[test]
fn router_accepts_valid_signature_and_rejects_invalid_signature() {
    let mut router = Router::new(
        "http://local".to_owned(),
        RoutingPolicy::default(),
        StubOracle::ok(0.8, 0.2),
    );
    router.set_shared_key("http://alice", b"shared".to_vec());

    let ok_raw = message_with_sender(
        "http://alice",
        b"hello",
        Some(b"shared"),
        "2029/12/31 23:59:59",
    );
    let ok_out = router.process_incoming(&ok_raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(ok_out.accepted);

    let bad_raw = message_with_sender(
        "http://alice",
        b"hello2",
        Some(b"wrong"),
        "2029/12/31 23:59:58",
    );
    let bad_out = router.process_incoming(&bad_raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!bad_out.accepted);
    assert!(matches!(
        bad_out.drop_reason,
        Some(ProcessError::BadSignature)
    ));
}

#[test]
fn router_rejects_signed_unknown_peer_when_policy_requires_known_key() {
    let policy = RoutingPolicy::default();
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.8, 0.2));
    let raw = message_with_sender(
        "http://alice",
        b"hello",
        Some(b"any"),
        "2029/12/31 23:59:59",
    );
    let out = router.process_incoming(&raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!out.accepted);
    assert!(matches!(
        out.drop_reason,
        Some(ProcessError::SignedWithoutKnownKey)
    ));
}

#[test]
fn router_clear_key_requires_secure_transport() {
    let mut policy = permissive_policy();
    policy.trust.reject_signed_without_known_key = false;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.8, 0.2));

    let body = b"Clear key exchange=aa.";
    let raw = message_with_sender("http://alice", body, None, "2029/12/31 23:59:59");
    let out = router.process_incoming(&raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!out.accepted);
    assert!(matches!(
        out.drop_reason,
        Some(ProcessError::ClearKeyOnInsecureChannel)
    ));

    let ok = router.process_incoming(&raw, TransportKind::Https, ts("2030/01/01 00:00:10"));
    assert!(ok.accepted);
    assert!(ok.key_exchange_control);
    let clear_key = router.shared_key("http://alice").expect("clear key");
    assert_eq!(clear_key.len(), 32);
    assert_ne!(clear_key, &[0_u8; 32]);
}

#[test]
fn router_rejects_unsigned_key_exchange_control_when_old_key_exists() {
    let mut policy = permissive_policy();
    policy.trust.require_signatures_from_known_peers = false;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.8, 0.2));
    router.set_shared_key("http://alice", b"old-key".to_vec());

    let raw = message_with_sender(
        "http://alice",
        b"Clear key exchange=aa.",
        None,
        "2029/12/31 23:59:59",
    );
    let out = router.process_incoming(&raw, TransportKind::Https, ts("2030/01/01 00:00:10"));
    assert!(!out.accepted);
    assert!(matches!(
        out.drop_reason,
        Some(ProcessError::UnsignedRejected)
    ));
}

#[test]
fn router_ignores_reputation_penalty_for_unexpected_key_exchange_reply_without_pending_state() {
    let mut router = Router::new(
        "http://local".to_owned(),
        permissive_policy(),
        StubOracle::ok(0.9, 0.1),
    );
    for idx in 0..10 {
        let ts_text = format!("2029/12/31 23:59:{:02}", 59 - idx);
        let reply = message_with_sender(
            "http://alice",
            b"RSA key exchange reply=ae6.",
            None,
            &ts_text,
        );
        let out = router.process_incoming(&reply, TransportKind::Http, ts("2030/01/01 00:00:10"));
        assert!(!out.accepted);
        assert!(matches!(
            out.drop_reason,
            Some(ProcessError::MissingPendingKeyExchangeState)
        ));
    }

    let normal = message_with_sender("http://alice", b"hello", None, "2029/12/31 23:58:40");
    let out = router.process_incoming(&normal, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
}

#[test]
fn router_rsa_and_dh_reply_paths_set_expected_keys() {
    let mut router = Router::new(
        "http://local".to_owned(),
        permissive_policy(),
        StubOracle::ok(0.9, 0.1),
    );

    // RSA reply decryption path: n=3233, d=2753, c=2790 decrypts to 65.
    router.register_pending_rsa_state(
        "http://alice",
        BigUint::from(3233_u32),
        BigUint::from(2753_u32),
    );
    let rsa_reply = message_with_sender(
        "http://alice",
        b"RSA key exchange reply=ae6.",
        None,
        "2029/12/31 23:59:59",
    );
    let rsa_out =
        router.process_incoming(&rsa_reply, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(rsa_out.accepted);
    assert!(rsa_out.key_exchange_control);
    let rsa_key = router.shared_key("http://alice").expect("rsa key");
    assert_eq!(rsa_key.len(), 32);
    assert_ne!(rsa_key, &[0_u8; 32]);

    // DH reply path: p=23, a=6, B=19 => shared=2.
    router.register_pending_dh_state("http://bob", BigUint::from(23_u32), BigUint::from(6_u32));
    let dh_reply = message_with_sender(
        "http://bob",
        b"DH key exchange reply=13.",
        None,
        "2029/12/31 23:59:58",
    );
    let dh_out = router.process_incoming(&dh_reply, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(dh_out.accepted);
    assert!(dh_out.key_exchange_control);
    let dh_key = router.shared_key("http://bob").expect("dh key");
    assert_eq!(dh_key.len(), 32);
    assert_ne!(dh_key, &[0_u8; 32]);
}

#[test]
fn router_rejects_weak_rsa_and_dh_request_parameters() {
    let mut router = Router::new(
        "http://local".to_owned(),
        permissive_policy(),
        StubOracle::ok(0.9, 0.1),
    );

    let weak_rsa = message_with_sender(
        "http://alice",
        b"RSA key exchange request=ca1,11.",
        None,
        "2029/12/31 23:59:59",
    );
    let rsa_out =
        router.process_incoming(&weak_rsa, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!rsa_out.accepted);
    assert!(matches!(
        rsa_out.drop_reason,
        Some(ProcessError::WeakKeyExchangeParameters(_))
    ));

    let weak_dh = message_with_sender(
        "http://alice",
        b"DH key exchange request=05,17,08.",
        None,
        "2029/12/31 23:59:58",
    );
    let dh_out = router.process_incoming(&weak_dh, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!dh_out.accepted);
    assert!(matches!(
        dh_out.drop_reason,
        Some(ProcessError::WeakKeyExchangeParameters(_))
    ));
}

#[test]
fn router_routes_compensatory_message_when_best_peer_already_sent_x() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new(
        "http://local".to_owned(),
        policy,
        StubOracle::with_distances(0.9, 0.1),
    );
    router.set_shared_key("http://bob", b"bob-key".to_vec());

    let seed_bob = message_with_sender("http://bob", b"topic bob", None, "2029/12/31 23:59:59");
    let seed_charlie = message_with_sender(
        "http://charlie",
        b"charlie payload",
        None,
        "2029/12/31 23:59:58",
    );
    assert!(
        router
            .process_incoming(&seed_bob, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    assert!(
        router
            .process_incoming(
                &seed_charlie,
                TransportKind::Http,
                ts("2030/01/01 00:00:10")
            )
            .accepted
    );

    let incoming_from_bob =
        message_with_sender("http://bob", b"topic bob", None, "2029/12/31 23:59:57");
    let out = router.process_incoming(
        &incoming_from_bob,
        TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    assert!(out.accepted);
    assert!(out.matched_count >= 1);
    assert!(!out.forwards.is_empty());
    let compensatory = out
        .forwards
        .iter()
        .find(|forward| forward.reason == ForwardReason::CompensatoryReply)
        .expect("compensatory forward");
    assert_eq!(compensatory.destination, "http://bob");

    let parsed = parse_message(
        &compensatory.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://bob")),
    )
    .expect("parse compensatory");
    assert_eq!(parsed.body, b"charlie payload");
}

#[test]
fn router_spam_binary_and_executable_filters_work() {
    let mut policy = permissive_policy();
    policy.content.allow_binary_payloads = false;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.2));

    let binary = message_with_sender(
        "http://alice",
        &[0x00, 0xFF, 0x11, 0x22, 0x33, 0x44],
        None,
        "2029/12/31 23:59:59",
    );
    let binary_out =
        router.process_incoming(&binary, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!binary_out.accepted);
    assert!(matches!(
        binary_out.drop_reason,
        Some(ProcessError::BinaryContentBlocked)
    ));

    let mut policy = permissive_policy();
    policy.content.allow_binary_payloads = true;
    policy.content.block_executable_magic = true;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.2));
    let elf = message_with_sender(
        "http://alice",
        b"\x7fELF\x00\x00payload",
        None,
        "2029/12/31 23:59:59",
    );
    let elf_out = router.process_incoming(&elf, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!elf_out.accepted);
    assert!(matches!(
        elf_out.drop_reason,
        Some(ProcessError::ExecutableBlocked)
    ));
}

#[test]
fn router_intrinsic_dependence_and_flood_controls_apply() {
    let mut policy = permissive_policy();
    policy.spam.min_intrinsic_dependence = 0.5;
    policy.throughput.per_peer_messages_per_minute = 1;
    policy.throughput.global_messages_per_minute = 10;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.1, 0.2));
    let raw = message_with_sender("http://alice", b"hello", None, "2029/12/31 23:59:59");
    let low_id = router.process_incoming(&raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!low_id.accepted);
    assert!(matches!(
        low_id.drop_reason,
        Some(ProcessError::IntrinsicDependenceTooLow)
    ));

    let mut policy = permissive_policy();
    policy.throughput.per_peer_messages_per_minute = 1;
    policy.spam.min_intrinsic_dependence = 0.0;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.2));
    let first = router.process_incoming(&raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(first.accepted);
    let second = router.process_incoming(
        &message_with_sender("http://alice", b"hello2", None, "2029/12/31 23:59:58"),
        TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    assert!(!second.accepted);
    assert!(matches!(
        second.drop_reason,
        Some(ProcessError::FloodLimited)
    ));
}

#[test]
fn router_rejects_non_finite_intrinsic_dependence() {
    let mut policy = permissive_policy();
    policy.spam.min_intrinsic_dependence = 0.0;
    let mut router = Router::new(
        "http://local".to_owned(),
        policy,
        StubOracle {
            intrinsic: f64::NAN,
            distance: 0.2,
            fail_intrinsic: false,
            fail_distance: false,
        },
    );
    let raw = message_with_sender("http://alice", b"hello", None, "2029/12/31 23:59:59");
    let out = router.process_incoming(&raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(!out.accepted);
    assert!(matches!(
        out.drop_reason,
        Some(ProcessError::IntrinsicDependenceInvalid)
    ));
}

#[test]
fn router_rejects_duplicate_message_when_any_id_already_exists_in_cache() {
    let mut router = Router::new(
        "http://local".to_owned(),
        permissive_policy(),
        StubOracle::ok(0.9, 0.2),
    );

    let first = b"0\r\n2029/12/31 23:59:59 http://relay-a\r\n2029/12/31 23:59:58 http://origin\r\n\r\n5\r\nhello";
    let out_first = router.process_incoming(first, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out_first.accepted);

    let duplicate_no_new =
        b"0\r\n2029/12/31 23:59:59 http://relay-a\r\n2029/12/31 23:59:58 http://origin\r\n\r\n5\r\nhello";
    let out_no_new = router.process_incoming(
        duplicate_no_new,
        TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    assert!(!out_no_new.accepted);
    assert!(matches!(
        out_no_new.drop_reason,
        Some(ProcessError::DuplicateMessageId)
    ));

    let duplicate_with_new = b"0\r\n2029/12/31 23:59:59.9 http://relay-b\r\n2029/12/31 23:59:59.1 http://relay-a\r\n2029/12/31 23:59:58 http://origin\r\n\r\n5\r\nhello";
    let out_with_new = router.process_incoming(
        duplicate_with_new,
        TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    assert!(!out_with_new.accepted);
    assert!(matches!(
        out_with_new.drop_reason,
        Some(ProcessError::DuplicateMessageId)
    ));
}

#[test]
fn router_matching_forwards_and_resigns_for_known_destination() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.8, 0.1));
    router.set_shared_key("http://sink", b"sink-key".to_vec());

    // Seed cache with a message containing sink address.
    let seed = message_with_sender(
        "http://sink",
        b"planet jupiter",
        None,
        "2029/12/31 23:59:59",
    );
    let first = router.process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(first.accepted);
    assert_eq!(first.forwards.len(), 0);

    // Matching message from another peer should produce forwards.
    let second_raw = message_with_sender(
        "http://origin",
        b"planet jupiter",
        None,
        "2029/12/31 23:59:58",
    );
    let second =
        router.process_incoming(&second_raw, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(second.accepted);
    assert!(second.matched_count >= 1);
    assert!(!second.forwards.is_empty());

    let signed_forward = second
        .forwards
        .iter()
        .find(|f| {
            f.destination == "http://sink" && f.reason == ForwardReason::MatchedForwardIncoming
        })
        .expect("sink forward");
    let parsed = parse_message(
        &signed_forward.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://sink")),
    )
    .expect("forward parse");
    assert_eq!(parsed.header[0].address, "http://local");
    assert!(matches!(parsed.signature, Signature::Sha256(_)));
    assert!(
        parsed
            .signature
            .verifies(&parsed.payload_without_signature_line(), Some(b"sink-key"))
    );
}

#[test]
fn router_jupiter_flow_forwards_cached_answer_back_to_alice_and_bob() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 500.0;
    policy.spam.max_match_distance_normalized = 1.0;
    policy.trust.max_outbound_inbound_ratio = 10.0;

    let mut bob = Router::new("http://bob/".to_owned(), policy.clone(), JupiterOracle);
    let mut charlie = Router::new("http://charlie/".to_owned(), policy, JupiterOracle);

    let mercury_at_bob = message_with_sender(
        "http://charlie/",
        b"Mercury is closest to the Sun.",
        None,
        "2029/12/31 23:59:59",
    );
    assert!(
        bob.process_incoming(
            &mercury_at_bob,
            TransportKind::Http,
            ts("2030/01/01 00:00:10")
        )
        .accepted
    );

    let jupiter_at_charlie = message_with_sender(
        "http://dave/",
        b"Jupiter is the largest planet in the solar system.",
        None,
        "2029/12/31 23:59:58",
    );
    assert!(
        charlie
            .process_incoming(
                &jupiter_at_charlie,
                TransportKind::Http,
                ts("2030/01/01 00:00:10")
            )
            .accepted
    );

    let alice_query = message_with_sender(
        "http://alice/",
        b"Which is the largest planet?",
        None,
        "2029/12/31 23:59:57",
    );
    let bob_out =
        bob.process_incoming(&alice_query, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(bob_out.accepted);
    let bob_to_charlie = bob_out
        .forwards
        .iter()
        .find(|forward| {
            forward.destination == "http://charlie/"
                && forward.reason == ForwardReason::MatchedForwardIncoming
        })
        .expect("bob should forward alice query toward charlie");

    let charlie_out = charlie.process_incoming(
        &bob_to_charlie.message_bytes,
        TransportKind::Http,
        ts("2030/01/01 00:00:11"),
    );
    assert!(charlie_out.accepted);

    let to_alice = charlie_out
        .forwards
        .iter()
        .find(|forward| {
            forward.destination == "http://alice/"
                && forward.reason == ForwardReason::MatchedForwardCached
        })
        .expect("charlie should forward cached jupiter answer to alice");
    let parsed_alice = parse_message(
        &to_alice.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:12"), Some("http://alice/")),
    )
    .expect("parse alice forward");
    assert!(
        String::from_utf8_lossy(&parsed_alice.body)
            .to_ascii_lowercase()
            .contains("jupiter is the largest planet")
    );

    let to_bob = charlie_out
        .forwards
        .iter()
        .find(|forward| {
            forward.destination == "http://bob/"
                && forward.reason == ForwardReason::MatchedForwardCached
        })
        .expect("charlie should forward cached jupiter answer to bob");
    let parsed_bob = parse_message(
        &to_bob.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:12"), Some("http://bob/")),
    )
    .expect("parse bob forward");
    assert!(
        String::from_utf8_lossy(&parsed_bob.body)
            .to_ascii_lowercase()
            .contains("jupiter is the largest planet")
    );
}

#[test]
fn router_does_not_forward_to_addresses_already_present_in_forwarded_message_header() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.8, 0.1));

    // Seed cache with a message from sink so sink is considered a match candidate.
    let seed = message_with_sender("http://sink", b"topic", None, "2029/12/31 23:59:59");
    let seed_out = router.process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(
        seed_out.accepted,
        "seed should be accepted, got: {:?}",
        seed_out.drop_reason
    );

    // Incoming message already contains sink in its header (relay + origin).
    let incoming = b"0\r\n2029/12/31 23:59:58 http://relay\r\n2029/12/31 23:59:57 http://sink\r\n\r\n5\r\ntopic";
    let out = router.process_incoming(incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);

    // No action should try to forward that same message back to sink.
    assert!(out.forwards.iter().all(|forward| {
        !(forward.destination == "http://sink"
            && forward.reason == ForwardReason::MatchedForwardIncoming)
    }));
}

#[test]
fn router_uses_compression_distance_metric_for_matching() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new(
        "http://local".to_owned(),
        policy,
        StubOracle::with_distances(0.9, 0.1),
    );

    let seed = message_with_sender(
        "http://sink",
        b"topic alpha",
        Some(b"sink-signer"),
        "2029/12/31 23:59:59",
    );
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender(
        "http://origin",
        b"topic beta",
        Some(b"origin-signer"),
        "2029/12/31 23:59:58",
    );
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert!(out.matched_count >= 1);
    assert!(out.forwards.iter().any(|f| f.destination == "http://sink"));
}

#[test]
fn router_match_threshold_is_normalized_and_size_aware() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.0;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 10.0));

    let seed = message_with_sender("http://sink", b"topic alpha", None, "2029/12/31 23:59:59");
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin", b"topic beta", None, "2029/12/31 23:59:58");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert_eq!(out.matched_count, 0);
    assert!(out.forwards.is_empty());
}

#[test]
fn router_match_threshold_one_effectively_disables_filtering() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 1.0e13;
    policy.spam.max_match_distance_normalized = 1.0;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new(
        "http://local".to_owned(),
        policy,
        StubOracle::ok(0.9, 1.0e12),
    );

    let seed = message_with_sender("http://sink", b"topic alpha", None, "2029/12/31 23:59:59");
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin", b"topic beta", None, "2029/12/31 23:59:58");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert!(out.matched_count >= 1);
    assert!(out.forwards.iter().any(|forward| {
        forward.destination == "http://sink"
            && forward.reason == ForwardReason::MatchedForwardIncoming
    }));
}

#[test]
fn router_uses_normalized_override_when_below_one() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.0;
    policy.spam.max_match_distance_normalized = 1.0;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new(
        "http://local".to_owned(),
        policy.clone(),
        StubOracle::ok(0.9, 10.0),
    );

    let seed = message_with_sender("http://sink", b"topic alpha", None, "2029/12/31 23:59:59");
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    let incoming = message_with_sender("http://origin", b"topic beta", None, "2029/12/31 23:59:58");
    let raw_mode =
        router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert_eq!(raw_mode.matched_count, 0);

    policy.spam.max_match_distance_normalized = 0.5;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 10.0));
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    let normalized_mode =
        router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(normalized_mode.matched_count >= 1);
}

#[derive(Clone)]
struct InspectOracle {
    calls: DistanceCallLog,
}

type DistanceCallLog = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;

impl CompressionOracle for InspectOracle {
    fn compression_distance(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError> {
        self.calls
            .lock()
            .expect("lock calls")
            .push((left.to_vec(), right.to_vec()));
        Ok(0.1)
    }

    fn intrinsic_dependence(&self, _data: &[u8], _max_order: i64) -> Result<f64, CompressionError> {
        Ok(0.9)
    }
}

#[test]
fn router_distance_inputs_use_full_serialized_messages() {
    let calls = Arc::new(Mutex::new(Vec::<(Vec<u8>, Vec<u8>)>::new()));
    let oracle = InspectOracle {
        calls: Arc::clone(&calls),
    };
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    let mut router = Router::new("http://local".to_owned(), policy, oracle);

    let seed = message_with_sender("http://sink", b"topic alpha", None, "2029/12/31 23:59:59");
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin", b"topic beta", None, "2029/12/31 23:59:58");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);

    let logged = calls.lock().expect("lock calls");
    assert!(!logged.is_empty());
    let (left, right) = &logged[0];
    assert_eq!(left, &incoming);
    assert!(right.starts_with(b"0\r\n2029/12/31 23:59:59 http://sink\r\n\r\n"));
}

#[test]
fn router_for_unknown_destination_emits_unsigned_forward_and_key_exchange_initiation() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    policy.trust.allow_unsigned_from_unknown_peers = false;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.1));

    let seed = message_with_sender(
        "http://sink",
        b"topic alpha",
        Some(b"sink-signer"),
        "2029/12/31 23:59:59",
    );
    let seed_out = router.process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(
        seed_out.accepted,
        "seed should be accepted, got: {:?}",
        seed_out.drop_reason
    );

    let incoming = message_with_sender(
        "http://origin",
        b"topic beta",
        Some(b"origin-signer"),
        "2029/12/31 23:59:58",
    );
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert!(!out.forwards.is_empty());

    let forward = out
        .forwards
        .iter()
        .find(|forward| {
            forward.destination == "http://sink"
                && forward.reason == ForwardReason::MatchedForwardIncoming
        })
        .expect("forward to sink");

    let parsed = parse_message(
        &forward.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://sink")),
    )
    .expect("parse forwarded message");
    assert!(matches!(parsed.signature, Signature::Unsigned));
    assert_eq!(parsed.body, b"topic beta");

    let key_init = out
        .forwards
        .iter()
        .find(|forward| {
            forward.destination == "http://sink"
                && forward.reason == ForwardReason::KeyExchangeInitiation
        })
        .expect("key exchange initiation toward sink");
    let parsed_init = parse_message(
        &key_init.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://sink")),
    )
    .expect("parse key-init forward");
    assert!(
        parse_key_exchange(&parsed_init.body)
            .expect("parse key exchange")
            .is_some()
    );
}

#[test]
fn router_for_unknown_destination_skips_auto_key_exchange_when_unsigned_unknown_allowed() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    policy.trust.allow_unsigned_from_unknown_peers = true;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.1));

    let seed = message_with_sender("http://sink", b"topic alpha", None, "2029/12/31 23:59:59");
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin", b"topic beta", None, "2029/12/31 23:59:58");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert!(out.forwards.iter().any(|forward| {
        forward.destination == "http://sink"
            && forward.reason == ForwardReason::MatchedForwardIncoming
    }));
    assert!(
        out.forwards
            .iter()
            .all(|forward| forward.reason != ForwardReason::KeyExchangeInitiation)
    );
}

#[test]
fn forwarded_timestamps_are_monotonic_across_messages() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.1));
    router.set_shared_key("http://sink", b"sink-key".to_vec());

    let seed = message_with_sender("http://sink", b"seed", None, "2029/12/31 23:59:59");
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let first_incoming =
        message_with_sender("http://origin-a", b"msg-a", None, "2029/12/31 23:59:58");
    let first = router.process_incoming(
        &first_incoming,
        TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    let first_forward = first.forwards.first().expect("first forwarded action");
    let first_parsed = parse_message(
        &first_forward.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://sink")),
    )
    .expect("parse first forward");

    let second_incoming =
        message_with_sender("http://origin-b", b"msg-b", None, "2029/12/31 23:59:57");
    let second = router.process_incoming(
        &second_incoming,
        TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    let second_forward = second.forwards.first().expect("second forwarded action");
    let second_parsed = parse_message(
        &second_forward.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://sink")),
    )
    .expect("parse second forward");

    assert!(second_parsed.header[0].timestamp > first_parsed.header[0].timestamp);
}
