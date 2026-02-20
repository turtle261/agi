use std::io::Cursor;

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
    ncd: f64,
    fail_intrinsic: bool,
    fail_ncd: bool,
}

impl StubOracle {
    fn ok(intrinsic: f64, ncd: f64) -> Self {
        Self {
            intrinsic,
            ncd,
            fail_intrinsic: false,
            fail_ncd: false,
        }
    }
}

impl CompressionOracle for StubOracle {
    fn ncd_sym(&self, _left: &[u8], _right: &[u8]) -> Result<f64, CompressionError> {
        if self.fail_ncd {
            Err(CompressionError::Failed("ncd failed".to_owned()))
        } else {
            Ok(self.ncd)
        }
    }

    fn intrinsic_dependence(&self, _data: &[u8], _max_order: i64) -> Result<f64, CompressionError> {
        if self.fail_intrinsic {
            Err(CompressionError::Failed("intrinsic failed".to_owned()))
        } else {
            Ok(self.intrinsic)
        }
    }

    fn batch_ncd_sym(
        &self,
        _target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        if self.fail_ncd {
            Err(CompressionError::Failed("ncd failed".to_owned()))
        } else {
            Ok(vec![self.ncd; candidates.len()])
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
fn protocol_legacy_signature_mode_toggle() {
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
    let strict_err = parse_message(&wire, &strict_ctx).expect_err("strict mode must reject");
    assert!(matches!(strict_err, ParseError::InvalidSignature));

    let mut legacy_ctx = parse_ctx(Some("http://bob"));
    legacy_ctx.allow_legacy_v1_without_prefix = true;
    let parsed = parse_message(&wire, &legacy_ctx).expect("legacy mode accepts");
    assert!(matches!(parsed.signature, Signature::Sha256(_)));
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
    let request = CompressorRequest::BatchNcdSym {
        target: b"alpha".to_vec(),
        candidates: vec![b"beta".to_vec(), b"gamma".to_vec()],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &request).expect("write");
    let decoded: CompressorRequest = read_frame(&mut Cursor::new(bytes), 1024).expect("read");
    assert!(matches!(decoded, CompressorRequest::BatchNcdSym { .. }));

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
    assert_eq!(router.shared_key("http://alice"), Some(&[0xaa][..]));
}

#[test]
fn router_rsa_and_dh_reply_paths_set_expected_keys() {
    let mut router = Router::new(
        "http://local".to_owned(),
        permissive_policy(),
        StubOracle::ok(0.9, 0.1),
    );

    // RSA reply decryption path: n=3233, d=2753, c=2790 decrypts to 65 ('A').
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
    assert_eq!(router.shared_key("http://alice"), Some(&[65_u8][..]));

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
    assert_eq!(router.shared_key("http://bob"), Some(&[2_u8][..]));
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
fn router_uses_near_duplicate_policy_to_collapse_redundant_matches() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.9;
    policy.spam.near_duplicate_distance = 0.2;
    policy.throughput.max_match_candidates = 16;
    let mut router = Router::new("http://local".to_owned(), policy, StubOracle::ok(0.9, 0.05));

    let seed_a = message_with_sender(
        "http://sink-a",
        b"same body for matching",
        None,
        "2029/12/31 23:59:59",
    );
    let seed_b = message_with_sender(
        "http://sink-b",
        b"same body for matching",
        None,
        "2029/12/31 23:59:58",
    );
    assert!(
        router
            .process_incoming(&seed_a, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    assert!(
        router
            .process_incoming(&seed_b, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender(
        "http://origin",
        b"same body for matching",
        None,
        "2029/12/31 23:59:57",
    );
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert_eq!(out.matched_count, 1);
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
            ncd: 0.2,
            fail_intrinsic: false,
            fail_ncd: false,
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
fn router_matching_forwards_and_resigns_for_known_destination() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.throughput.max_forward_actions = 8;
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
    assert!(
        second
            .forwards
            .iter()
            .any(|f| f.reason == ForwardReason::IncomingToMatchedHeader
                && f.destination == "http://sink")
    );

    let signed_forward = second
        .forwards
        .iter()
        .find(|f| f.destination == "http://sink")
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
