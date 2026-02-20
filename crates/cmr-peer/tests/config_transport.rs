use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cmr_core::policy::RoutingPolicy;
use cmr_core::protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, Signature, parse_message,
};
use cmr_core::router::{CompressionError, CompressionOracle, Router};
use cmr_peer::config::{PeerConfig, SshConfig};
use cmr_peer::transport::{
    HandshakeStore, TransportManager, extract_cmr_payload, extract_udp_payload,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::crypto::ring;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;

#[derive(Clone)]
struct Oracle {
    intrinsic: f64,
    ncd: f64,
}

impl CompressionOracle for Oracle {
    fn ncd_sym(&self, _left: &[u8], _right: &[u8]) -> Result<f64, CompressionError> {
        Ok(self.ncd)
    }

    fn compression_distance(&self, _left: &[u8], _right: &[u8]) -> Result<f64, CompressionError> {
        Ok(self.ncd)
    }

    fn intrinsic_dependence(&self, _data: &[u8], _max_order: i64) -> Result<f64, CompressionError> {
        Ok(self.intrinsic)
    }

    fn batch_ncd_sym(
        &self,
        _target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        Ok(vec![self.ncd; candidates.len()])
    }
}

#[derive(Debug)]
struct CapturedHttp {
    path_and_query: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn ts(value: &str) -> CmrTimestamp {
    CmrTimestamp::parse(value).expect("timestamp")
}

fn cmr_wire(sender: &str, body: &[u8], timestamp: &str) -> Vec<u8> {
    CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: ts(timestamp),
            address: sender.to_owned(),
        }],
        body: body.to_vec(),
    }
    .to_bytes()
}

fn permissive_policy() -> RoutingPolicy {
    let mut policy = RoutingPolicy::default();
    policy.spam.min_intrinsic_dependence = 0.0;
    policy.trust.require_signatures_from_known_peers = false;
    policy.trust.reject_signed_without_known_key = false;
    policy.trust.allow_unsigned_from_unknown_peers = true;
    policy
}

fn init_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        ring::default_provider()
            .install_default()
            .expect("install rustls crypto provider");
    });
}

async fn start_http_capture_server() -> (String, oneshot::Receiver<CapturedHttp>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind capture listener");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{addr}/cmr");

    let (tx, rx) = oneshot::channel::<CapturedHttp>();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = TokioIo::new(stream);
        let tx = std::sync::Mutex::new(Some(tx));
        let service = service_fn(move |req: Request<Incoming>| {
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let path_and_query = req.uri().to_string();
            let tx = tx.lock().expect("lock").take();
            async move {
                let body = req.into_body().collect().await.expect("collect").to_bytes();
                if let Some(tx) = tx {
                    let _ = tx.send(CapturedHttp {
                        path_and_query,
                        content_type,
                        body: body.to_vec(),
                    });
                }
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"ok",
                ))))
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await;
    });

    (url, rx)
}

#[test]
fn config_parses_and_effective_policy_works() {
    let toml = r#"
local_address = "http://127.0.0.1:8080/"
security_level = "strict"
prefer_http_handshake = false

[listen]
[listen.http]
bind = "127.0.0.1:8080"
path = "/"

[listen.udp]
bind = "127.0.0.1:9999"
service = "cmr"
"#;
    let path = std::env::temp_dir().join(format!("cmr-peer-test-{}.toml", std::process::id()));
    std::fs::write(&path, toml).expect("write config");
    let cfg = PeerConfig::from_toml_file(&path).expect("parse config");
    let policy = cfg.effective_policy();
    assert_eq!(cfg.local_address, "http://127.0.0.1:8080/");
    assert_eq!(cfg.listen.http.expect("http").path, "/");
    assert!(policy.content.max_message_bytes > 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn extract_payload_plain_and_multipart() {
    let plain = extract_cmr_payload(None, b"abc").expect("plain");
    assert_eq!(plain, b"abc");

    let boundary = "x-boundary";
    let mut multipart = Vec::new();
    multipart.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    multipart.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"cmr.msg\"\r\n",
    );
    multipart.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    multipart.extend_from_slice(b"payload");
    multipart.extend_from_slice(b"\r\n");
    multipart.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let extracted =
        extract_cmr_payload(Some("multipart/form-data; boundary=x-boundary"), &multipart)
            .expect("multipart");
    assert_eq!(extracted, b"payload");
}

#[test]
fn handshake_store_is_one_time() {
    let store = HandshakeStore::default();
    assert!(store.put("k1".to_owned(), b"hello".to_vec()));
    assert_eq!(store.take("k1").as_deref(), Some(&b"hello"[..]));
    assert!(store.take("k1").is_none());
}

#[test]
fn handshake_store_enforces_capacity_and_ttl() {
    let store = HandshakeStore::new(1, 8, Duration::from_millis(20));
    assert!(store.put("k1".to_owned(), b"12345678".to_vec()));
    assert!(!store.put("k2".to_owned(), b"123456789".to_vec()));
    std::thread::sleep(Duration::from_millis(30));
    assert!(store.take("k1").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_sends_udp_payload() {
    init_crypto_provider();
    let recv_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
    let recv_addr = recv_socket.local_addr().expect("recv addr");
    let handshake_store = Arc::new(HandshakeStore::default());
    let transport = TransportManager::new(
        "http://local".to_owned(),
        None,
        SshConfig::default(),
        false,
        handshake_store,
    )
    .await
    .expect("transport");

    let msg = b"udp message bytes";
    let url = format!("udp://127.0.0.1:{}/cmr", recv_addr.port());
    transport.send_message(&url, msg).await.expect("send udp");

    let mut buf = vec![0_u8; 1024];
    let (n, _) = recv_socket.recv_from(&mut buf).await.expect("recv");
    let decoded = extract_udp_payload("cmr", &buf[..n]).expect("decode udp payload");
    assert_eq!(decoded, msg);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_udp_rejects_missing_service_tag() {
    init_crypto_provider();
    let handshake_store = Arc::new(HandshakeStore::default());
    let transport = TransportManager::new(
        "http://local".to_owned(),
        None,
        SshConfig::default(),
        false,
        handshake_store,
    )
    .await
    .expect("transport");

    let err = transport
        .send_message("udp://127.0.0.1:9", b"hello")
        .await
        .expect_err("must reject missing service path");
    assert!(err.to_string().contains("invalid destination URL"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_rejects_invalid_handshake_callback_targets() {
    init_crypto_provider();
    let transport = TransportManager::new(
        "http://local".to_owned(),
        None,
        SshConfig::default(),
        false,
        Arc::new(HandshakeStore::default()),
    )
    .await
    .expect("transport");

    let scheme_err = transport
        .fetch_http_handshake_reply("ftp://example.com", "abc")
        .await
        .expect_err("must reject unsupported callback scheme");
    assert!(
        scheme_err
            .to_string()
            .contains("unsupported handshake callback scheme")
    );

    let userinfo_err = transport
        .fetch_http_handshake_reply("http://user@example.com:80/", "abc")
        .await
        .expect_err("must reject callback URL user info");
    assert!(
        userinfo_err
            .to_string()
            .contains("must not include user info")
    );

    let key_err = transport
        .fetch_http_handshake_reply("http://127.0.0.1:8080/", "")
        .await
        .expect_err("must reject invalid key");
    assert!(key_err.to_string().contains("invalid handshake key"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_handshake_stores_unsigned_payload() {
    init_crypto_provider();
    let (sink_url, sink_rx) = start_http_capture_server().await;
    let handshake_store = Arc::new(HandshakeStore::default());
    let transport = TransportManager::new(
        "http://local".to_owned(),
        None,
        SshConfig::default(),
        true,
        Arc::clone(&handshake_store),
    )
    .await
    .expect("transport");

    let mut signed = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: ts("2029/12/31 23:59:59"),
            address: "http://origin".to_owned(),
        }],
        body: b"handshake payload".to_vec(),
    };
    signed.sign_with_key(b"shared");
    let wire = signed.to_bytes();
    transport
        .send_message(&sink_url, &wire)
        .await
        .expect("send handshake request");

    let captured = sink_rx.await.expect("captured request");
    let query = captured
        .path_and_query
        .split_once('?')
        .expect("query params")
        .1;
    let params = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<std::collections::HashMap<String, String>>();
    let key = params.get("key").expect("key param");

    let stored = handshake_store.take(key).expect("stored payload");
    let parsed = parse_message(
        &stored,
        &ParseContext::secure(ts("2030/01/01 00:00:10"), None),
    )
    .expect("parse stored handshake payload");
    assert!(matches!(parsed.signature, Signature::Unsigned));
    assert_eq!(parsed.body, b"handshake payload");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_transport_rejects_command_injection_path() {
    init_crypto_provider();
    let transport = TransportManager::new(
        "http://local".to_owned(),
        None,
        SshConfig::default(),
        false,
        Arc::new(HandshakeStore::default()),
    )
    .await
    .expect("transport");

    let err = transport
        .send_message("ssh://localhost/cmr-peer;rm-rf", b"hello")
        .await
        .expect_err("must reject unsafe ssh command");
    assert!(err.to_string().contains("invalid ssh remote command"));
}

#[test]
fn extract_udp_payload_rejects_wrong_service() {
    let packet = b"cmr\npayload";
    assert_eq!(
        extract_udp_payload("cmr", packet).as_deref(),
        Some(&b"payload"[..])
    );
    assert!(extract_udp_payload("other", packet).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_router_and_http_transport_forwards_valid_cmr_message() {
    init_crypto_provider();
    let (sink_url, sink_rx) = start_http_capture_server().await;
    let handshake_store = Arc::new(HandshakeStore::default());
    let transport = TransportManager::new(
        "http://local".to_owned(),
        None,
        SshConfig::default(),
        false,
        Arc::clone(&handshake_store),
    )
    .await
    .expect("transport");

    let mut router = Router::new(
        "http://local".to_owned(),
        permissive_policy(),
        Oracle {
            intrinsic: 0.9,
            ncd: 0.1,
        },
    );

    let seed = cmr_wire(&sink_url, b"planet jupiter", "2029/12/31 23:59:59");
    let first = router.process_incoming(
        &seed,
        cmr_core::protocol::TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    assert!(first.accepted);
    assert!(first.forwards.is_empty());

    let incoming = cmr_wire("http://origin", b"planet jupiter", "2029/12/31 23:59:58");
    let second = router.process_incoming(
        &incoming,
        cmr_core::protocol::TransportKind::Http,
        ts("2030/01/01 00:00:10"),
    );
    assert!(second.accepted);
    assert!(second.matched_count >= 1);

    let sink_forward = second
        .forwards
        .iter()
        .find(|f| f.destination == sink_url)
        .expect("forward to sink");
    transport
        .send_message(&sink_forward.destination, &sink_forward.message_bytes)
        .await
        .expect("send forward");

    let captured = sink_rx.await.expect("captured request");
    assert_eq!(captured.path_and_query, "/cmr");
    let payload = extract_cmr_payload(captured.content_type.as_deref(), &captured.body)
        .expect("extract forwarded payload");
    let parsed = parse_message(
        &payload,
        &cmr_core::protocol::ParseContext::secure(ts("2030/01/01 00:01:00"), Some(&sink_url)),
    )
    .expect("parse forwarded cmr");
    assert_eq!(parsed.header[0].address, "http://local");
}
