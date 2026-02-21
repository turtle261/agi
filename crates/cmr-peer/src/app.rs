//! Peer runtime orchestration.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use cmr_core::policy::RoutingPolicy;
use cmr_core::protocol::{CmrMessage, CmrTimestamp, MessageId, Signature, TransportKind};
use cmr_core::router::{ForwardAction, ProcessOutcome, Router};
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;

use crate::compressor_client::{
    CompressorClient, CompressorClientConfig, CompressorClientInitError,
};
use crate::config::{HttpsListenConfig, PeerConfig};
use crate::transport::{
    HandshakeStore, TransportError, TransportManager, extract_cmr_payload, extract_udp_payload,
};

/// Runtime state shared by transport listeners.
#[derive(Clone)]
struct AppState {
    router: Arc<Mutex<Router<CompressorClient>>>,
    transport: Arc<TransportManager>,
    handshake_store: Arc<HandshakeStore>,
}

impl AppState {
    async fn ingest_and_forward(
        &self,
        payload: Vec<u8>,
        transport_kind: TransportKind,
    ) -> Result<ProcessOutcome, AppError> {
        let router = Arc::clone(&self.router);
        let outcome = tokio::task::spawn_blocking(move || {
            let mut guard = router
                .lock()
                .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
            Ok::<_, AppError>(guard.process_incoming(
                &payload,
                transport_kind,
                CmrTimestamp::now_utc(),
            ))
        })
        .await
        .map_err(|e| AppError::Runtime(format!("router task join error: {e}")))??;

        for forward in &outcome.forwards {
            if let Err(err) = self.send_forward(forward).await {
                eprintln!(
                    "forward to {} failed (reason={:?}): {err}",
                    forward.destination, forward.reason
                );
            }
        }
        Ok(outcome)
    }

    async fn send_forward(&self, forward: &ForwardAction) -> Result<(), AppError> {
        self.transport
            .send_message(&forward.destination, &forward.message_bytes)
            .await
            .map_err(AppError::Transport)
    }
}

/// Running peer instance started by [`start_peer`].
pub struct PeerRuntime {
    handles: Vec<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
}

impl PeerRuntime {
    /// Number of active listener tasks.
    #[must_use]
    pub fn listener_count(&self) -> usize {
        self.handles.len()
    }

    /// Requests shutdown and waits for listener tasks to finish.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}

/// Result of a local end-to-end HTTP self-test.
#[derive(Clone, Debug)]
pub struct SelfTestReport {
    /// HTTP ingest destination used for the probe.
    pub destination: String,
    /// HTTP status returned by the running peer.
    pub status: StatusCode,
    /// Probe message size in bytes.
    pub bytes_sent: usize,
}

impl SelfTestReport {
    /// Returns true when the probe was accepted.
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.status == StatusCode::OK
    }
}

/// App startup/runtime errors.
#[derive(Debug, Error)]
pub enum AppError {
    /// Config validation failure.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Runtime transport failure.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS setup failure.
    #[error("tls configuration error: {0}")]
    Tls(String),
    /// Runtime coordination failure.
    #[error("runtime error: {0}")]
    Runtime(String),
    /// Compressor setup failure.
    #[error("compressor setup error: {0}")]
    CompressorInit(#[from] CompressorClientInitError),
}

/// Starts peer listeners and returns a runtime handle.
pub async fn start_peer(config: PeerConfig) -> Result<PeerRuntime, AppError> {
    let state = build_app_state(&config).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut handles = Vec::new();
    if let Some(http_cfg) = config.listen.http.clone() {
        let listener = TcpListener::bind(&http_cfg.bind).await?;
        let state = state.clone();
        let mut local_shutdown = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) =
                run_http_listener(listener, http_cfg.path, state, false, &mut local_shutdown).await
            {
                eprintln!("http listener stopped with error: {err}");
            }
        }));
    }
    if let Some(https_cfg) = config.listen.https.clone() {
        let (listener, acceptor) = bind_https_listener(&https_cfg).await?;
        let state = state.clone();
        let mut local_shutdown = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_https_listener(
                listener,
                acceptor,
                https_cfg.path,
                state,
                &mut local_shutdown,
            )
            .await
            {
                eprintln!("https listener stopped with error: {err}");
            }
        }));
    }
    if let Some(udp_cfg) = config.listen.udp.clone() {
        let socket = UdpSocket::bind(&udp_cfg.bind).await?;
        let state = state.clone();
        let mut local_shutdown = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) =
                run_udp_listener(socket, udp_cfg.service, state, &mut local_shutdown).await
            {
                eprintln!("udp listener stopped with error: {err}");
            }
        }));
    }

    if handles.is_empty() {
        return Err(AppError::InvalidConfig(
            "at least one listener (http/https/udp) must be configured".to_owned(),
        ));
    }

    Ok(PeerRuntime {
        handles,
        shutdown_tx,
    })
}

/// Runs peer listeners until interrupted.
pub async fn run_peer(config: PeerConfig) -> Result<(), AppError> {
    let runtime = start_peer(config).await?;
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AppError::Runtime(format!("ctrl-c handler: {e}")))?;
    runtime.shutdown().await;
    Ok(())
}

/// Starts the runtime, executes a local HTTP self-test, and shuts down.
pub async fn run_http_self_test_with_runtime(
    config: PeerConfig,
) -> Result<SelfTestReport, AppError> {
    let runtime = start_peer(config.clone()).await?;
    // Give listener tasks one scheduler tick to enter their accept loops.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let result = run_http_self_test(&config).await;
    runtime.shutdown().await;
    result
}

/// Executes a local end-to-end HTTP self-test against a running peer instance.
pub async fn run_http_self_test(config: &PeerConfig) -> Result<SelfTestReport, AppError> {
    let report = probe_http_self_test(config).await?;
    if report.accepted() {
        Ok(report)
    } else {
        Err(AppError::Runtime(format!(
            "self-test message was rejected with status {}",
            report.status
        )))
    }
}

/// Ingests one message from stdin (useful for ssh forced-command mode).
pub async fn ingest_stdin_once(
    config: PeerConfig,
    transport: TransportKind,
) -> Result<(), AppError> {
    let policy: RoutingPolicy = config.effective_policy();
    let max_bytes = policy.content.max_message_bytes;
    let compressor_cfg = CompressorClientConfig {
        command: config.compressor.command.clone(),
        args: config.compressor.args.clone(),
        max_frame_bytes: config.compressor.max_frame_bytes,
    };
    let compressor = CompressorClient::new(compressor_cfg)?;
    let mut router = Router::new(config.local_address.clone(), policy, compressor);
    apply_static_keys(&mut router, &config)?;

    let payload = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, std::io::Error> {
        let mut payload = Vec::new();
        let mut stdin = std::io::stdin()
            .lock()
            .take((max_bytes.saturating_add(1)) as u64);
        stdin.read_to_end(&mut payload)?;
        Ok(payload)
    })
    .await
    .map_err(|e| AppError::Runtime(format!("stdin read join error: {e}")))??;
    if payload.len() > max_bytes {
        return Err(AppError::Runtime(format!(
            "stdin message exceeds configured max_message_bytes ({max_bytes})"
        )));
    }
    let outcome = router.process_incoming(&payload, transport, CmrTimestamp::now_utc());
    if !outcome.accepted {
        return Err(AppError::Runtime(format!(
            "stdin message rejected: {}",
            outcome
                .drop_reason
                .map_or_else(|| "unknown".to_owned(), |e| e.to_string())
        )));
    }
    Ok(())
}

async fn build_app_state(config: &PeerConfig) -> Result<AppState, AppError> {
    let policy = config.effective_policy();
    let compressor_cfg = CompressorClientConfig {
        command: config.compressor.command.clone(),
        args: config.compressor.args.clone(),
        max_frame_bytes: config.compressor.max_frame_bytes,
    };
    let compressor = CompressorClient::new(compressor_cfg)?;
    let mut router = Router::new(config.local_address.clone(), policy, compressor);
    apply_static_keys(&mut router, config)?;

    let handshake_store = Arc::new(HandshakeStore::default());
    let transport = Arc::new(
        TransportManager::new(
            config.local_address.clone(),
            config.smtp.clone(),
            config.ssh.clone(),
            config.prefer_http_handshake,
            Arc::clone(&handshake_store),
        )
        .await?,
    );
    Ok(AppState {
        router: Arc::new(Mutex::new(router)),
        transport,
        handshake_store,
    })
}

fn apply_static_keys(
    router: &mut Router<CompressorClient>,
    config: &PeerConfig,
) -> Result<(), AppError> {
    for entry in &config.static_keys {
        let key = hex::decode(&entry.hex_key)
            .map_err(|e| AppError::InvalidConfig(format!("invalid static hex key: {e}")))?;
        router.set_shared_key(entry.peer.clone(), key);
    }
    Ok(())
}

async fn bind_https_listener(
    cfg: &HttpsListenConfig,
) -> Result<(TcpListener, TlsAcceptor), AppError> {
    let tls_cfg = load_tls_config(&cfg.cert_path, &cfg.key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(&cfg.bind).await?;
    Ok((listener, acceptor))
}

async fn run_http_listener(
    listener: TcpListener,
    path: String,
    state: AppState,
    is_https: bool,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), AppError> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted?;
                let state = state.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        handle_http_request(req, path.clone(), state.clone(), is_https, Some(remote_addr.ip()))
                    });
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        eprintln!("http conn error: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn run_https_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    path: String,
    state: AppState,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), AppError> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted?;
                let state = state.clone();
                let acceptor = acceptor.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(err) => {
                            eprintln!("tls accept error: {err}");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(move |req| {
                        handle_http_request(req, path.clone(), state.clone(), true, Some(remote_addr.ip()))
                    });
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        eprintln!("https conn error: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn run_udp_listener(
    socket: UdpSocket,
    service: String,
    state: AppState,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), AppError> {
    eprintln!("udp listener active for service tag `{service}`");
    let mut buf = vec![0_u8; 65_536];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            recv_result = socket.recv_from(&mut buf) => {
                let (size, _) = recv_result?;
                let Some(payload) = extract_udp_payload(&service, &buf[..size]) else {
                    eprintln!("udp packet dropped: service tag mismatch");
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(err) = state.ingest_and_forward(payload, TransportKind::Udp).await {
                        eprintln!("udp ingest failed: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    ingest_path: String,
    state: AppState,
    is_https: bool,
    remote_ip: Option<IpAddr>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let transport_kind = if is_https {
        TransportKind::Https
    } else {
        TransportKind::Http
    };
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_owned();

    if method == Method::GET {
        let params = parse_query(uri.query().unwrap_or_default());
        if let (Some(requester), Some(key)) = (params.get("request"), params.get("key")) {
            let requester = requester.clone();
            let key = key.clone();
            let validated_requester =
                match validate_handshake_callback_request(&requester, &key, remote_ip) {
                    Ok(url) => url,
                    Err(err) => {
                        eprintln!("rejecting handshake callback request: {err}");
                        return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
                    }
                };
            let state2 = state.clone();
            tokio::spawn(async move {
                match state2
                    .transport
                    .fetch_http_handshake_reply(&validated_requester, &key)
                    .await
                {
                    Ok(reply_payload) => {
                        if let Err(err) = state2
                            .ingest_and_forward(reply_payload, transport_kind)
                            .await
                        {
                            eprintln!("handshake callback ingest failed: {err}");
                        }
                    }
                    Err(err) => eprintln!("handshake callback fetch failed: {err}"),
                }
            });
            return Ok(response(StatusCode::OK, Bytes::new()));
        }
        if let Some(reply_key) = params.get("reply") {
            if let Some(payload) = state.handshake_store.take(reply_key) {
                return Ok(response(StatusCode::OK, Bytes::from(payload)));
            }
            return Ok(response(StatusCode::NOT_FOUND, Bytes::new()));
        }
    }

    if method == Method::POST && path == ingest_path {
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                eprintln!("http body read failed: {err}");
                return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
            }
        };
        let payload = match extract_cmr_payload(content_type.as_deref(), &body) {
            Ok(payload) => payload,
            Err(err) => {
                eprintln!("http payload parse failed: {err}");
                return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
            }
        };
        let outcome = match state.ingest_and_forward(payload, transport_kind).await {
            Ok(outcome) => outcome,
            Err(err) => {
                eprintln!("ingest failed: {err}");
                return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
            }
        };
        if !outcome.accepted {
            return Ok(response_with_outcome_headers(
                StatusCode::BAD_REQUEST,
                Bytes::new(),
                &outcome,
            ));
        }
        return Ok(response_with_outcome_headers(
            StatusCode::OK,
            Bytes::new(),
            &outcome,
        ));
    }

    Ok(response(StatusCode::NOT_FOUND, Bytes::new()))
}

fn response_with_outcome_headers(
    status: StatusCode,
    body: Bytes,
    outcome: &ProcessOutcome,
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header("X-CMR-Accepted", if outcome.accepted { "1" } else { "0" })
        .header("X-CMR-Matched-Count", outcome.matched_count.to_string());
    if let Some(reason) = &outcome.drop_reason {
        builder = builder.header("X-CMR-Drop-Reason", reason.to_string());
    }
    if let Some(diag) = &outcome.routing_diagnostics {
        if let Some(peer) = &diag.best_peer {
            builder = builder.header("X-CMR-Best-Peer", peer);
        }
        if let Some(raw) = diag.best_distance_raw {
            builder = builder.header("X-CMR-Best-Distance-Raw", raw.to_string());
        }
        if let Some(norm) = diag.best_distance_normalized {
            builder = builder.header("X-CMR-Best-Distance-Norm", norm.to_string());
        }
        builder = builder
            .header("X-CMR-Threshold-Raw", diag.threshold_raw.to_string())
            .header(
                "X-CMR-Threshold-Norm",
                diag.threshold_normalized.to_string(),
            )
            .header(
                "X-CMR-Threshold-Mode",
                if diag.used_normalized_threshold {
                    "normalized"
                } else {
                    "raw"
                },
            );
    }
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn validate_handshake_callback_request(
    requester: &str,
    key: &str,
    remote_ip: Option<IpAddr>,
) -> Result<String, String> {
    if key.is_empty() || key.len() > 128 {
        return Err("invalid handshake key length".to_owned());
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("handshake key contains invalid characters".to_owned());
    }

    let url = url::Url::parse(requester).map_err(|e| format!("invalid requester URL: {e}"))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(format!("unsupported requester scheme `{other}`")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("requester URL must not include user info".to_owned());
    }
    if url.fragment().is_some() {
        return Err("requester URL must not include fragments".to_owned());
    }
    let Some(remote_ip) = remote_ip else {
        return Err("missing remote peer address".to_owned());
    };

    let Some(host) = url.host_str() else {
        return Err("requester URL missing host".to_owned());
    };
    if let Ok(parsed_ip) = host.parse::<IpAddr>() {
        if parsed_ip != remote_ip {
            return Err("requester host does not match remote peer IP".to_owned());
        }
        return Ok(url.to_string());
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| "requester URL missing port or known default for scheme".to_owned())?;
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve requester host: {e}"))?;
    if !resolved.into_iter().any(|addr| addr.ip() == remote_ip) {
        return Err("requester host does not resolve to remote peer IP".to_owned());
    }

    Ok(url.to_string())
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, AppError> {
    let cert_data = std::fs::read(cert_path)?;
    let key_data = std::fs::read(key_path)?;
    let certs = CertificateDer::pem_slice_iter(&cert_data)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| AppError::Tls(format!("failed to parse certs: {e}")))?;
    if certs.is_empty() {
        return Err(AppError::Tls("no certificates found".to_owned()));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_data)
        .map_err(|e| AppError::Tls(format!("failed to parse private key: {e}")))?;

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Tls(format!("invalid certificate/key pair: {e}")))?;
    Ok(cfg)
}

async fn probe_http_self_test(config: &PeerConfig) -> Result<SelfTestReport, AppError> {
    let http = config.listen.http.as_ref().ok_or_else(|| {
        AppError::InvalidConfig("self-test requires [listen.http] to be configured".to_owned())
    })?;
    let target = loopback_http_target(&http.bind, &http.path)?;
    let payload = build_self_test_message();
    let status = post_http_payload(target.clone(), payload.clone()).await?;
    Ok(SelfTestReport {
        destination: target,
        status,
        bytes_sent: payload.len(),
    })
}

async fn post_http_payload(target: String, payload: Vec<u8>) -> Result<StatusCode, AppError> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = target
        .parse()
        .map_err(|e| AppError::InvalidConfig(format!("invalid self-test uri `{target}`: {e}")))?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Content-Type", "application/octet-stream")
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| AppError::Runtime(format!("failed to build self-test request: {e}")))?;

    let resp = client
        .request(req)
        .await
        .map_err(|e| AppError::Runtime(format!("self-test request failed: {e}")))?;
    Ok(resp.status())
}

fn build_self_test_message() -> Vec<u8> {
    let mut body = Vec::with_capacity(16 * 80);
    for _ in 0..80 {
        body.extend_from_slice(b"cmr-self-test ");
    }

    CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: CmrTimestamp::now_utc(),
            address: "http://cmr-self-test.local/source".to_owned(),
        }],
        body,
    }
    .to_bytes()
}

fn loopback_http_target(bind: &str, path: &str) -> Result<String, AppError> {
    let socket: SocketAddr = bind
        .parse()
        .map_err(|e| AppError::InvalidConfig(format!("invalid HTTP bind address `{bind}`: {e}")))?;

    let host = match socket.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let normalized_path = normalize_ingest_path(path);

    Ok(match host {
        IpAddr::V4(ip) => format!("http://{ip}:{}{normalized_path}", socket.port()),
        IpAddr::V6(ip) => format!("http://[{ip}]:{}{normalized_path}", socket.port()),
    })
}

fn normalize_ingest_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{loopback_http_target, normalize_ingest_path, validate_handshake_callback_request};

    #[test]
    fn normalize_path_preserves_or_adds_leading_slash() {
        assert_eq!(normalize_ingest_path(""), "/");
        assert_eq!(normalize_ingest_path("/cmr"), "/cmr");
        assert_eq!(normalize_ingest_path("cmr"), "/cmr");
    }

    #[test]
    fn loopback_target_rewrites_unspecified_ipv4() {
        let url = loopback_http_target("0.0.0.0:8080", "/cmr").expect("target");
        assert_eq!(url, "http://127.0.0.1:8080/cmr");
    }

    #[test]
    fn loopback_target_supports_ipv6() {
        let url = loopback_http_target("[::]:9000", "cmr").expect("target");
        assert_eq!(url, "http://[::1]:9000/cmr");
    }

    #[test]
    fn handshake_callback_validation_accepts_matching_ip() {
        let out = validate_handshake_callback_request(
            "http://127.0.0.1:8080/",
            "abc123",
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        )
        .expect("valid callback");
        assert_eq!(out, "http://127.0.0.1:8080/");
    }

    #[test]
    fn handshake_callback_validation_rejects_mismatched_ip_and_bad_key() {
        let ip_err = validate_handshake_callback_request(
            "http://127.0.0.1:8080/",
            "abc123",
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3))),
        )
        .expect_err("must reject mismatched requester IP");
        assert!(ip_err.contains("does not match remote peer IP"));

        let key_err = validate_handshake_callback_request(
            "http://127.0.0.1:8080/",
            "bad$key",
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        )
        .expect_err("must reject invalid key");
        assert!(key_err.contains("invalid characters"));
    }

    #[test]
    fn handshake_callback_validation_accepts_domain_host_when_it_resolves_to_remote_ip() {
        let out = validate_handshake_callback_request(
            "http://localhost:8080/",
            "abc123",
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        )
        .expect("domain host should be accepted when it resolves to remote ip");
        assert_eq!(out, "http://localhost:8080/");
    }

    #[test]
    fn handshake_callback_validation_rejects_domain_host_when_resolution_mismatches() {
        let err = validate_handshake_callback_request(
            "http://localhost:8080/",
            "abc123",
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3))),
        )
        .expect_err("must reject mismatched resolved IP");
        assert!(err.contains("does not resolve to remote peer IP"));
    }
}
