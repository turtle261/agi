//! Outbound transport adapters and HTTP body helpers.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::Uri;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use lettre::message::header;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use rand::RngCore;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::process::Command;
use url::Url;

use crate::config::{SmtpConfig, SshConfig};

const UDP_MAX_PAYLOAD_BYTES: usize = 65_507;
const DEFAULT_HANDSHAKE_TTL_SECONDS: u64 = 300;
const DEFAULT_HANDSHAKE_MAX_ENTRIES: usize = 1024;
const DEFAULT_HANDSHAKE_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

/// Stored one-time HTTP handshake payloads.
pub struct HandshakeStore {
    inner: Mutex<HandshakeStoreInner>,
}

#[derive(Debug)]
struct HandshakeStoreInner {
    payloads: HashMap<String, StoredPayload>,
    order: VecDeque<(String, u64)>,
    total_bytes: usize,
    next_seq: u64,
    ttl: Duration,
    max_entries: usize,
    max_total_bytes: usize,
}

#[derive(Debug)]
struct StoredPayload {
    payload: Vec<u8>,
    inserted_at: Instant,
    seq: u64,
}

impl HandshakeStore {
    /// Creates a bounded one-time payload store.
    #[must_use]
    pub fn new(max_entries: usize, max_total_bytes: usize, ttl: Duration) -> Self {
        let bounded_entries = max_entries.max(1);
        let bounded_total_bytes = max_total_bytes.max(1);
        Self {
            inner: Mutex::new(HandshakeStoreInner {
                payloads: HashMap::new(),
                order: VecDeque::new(),
                total_bytes: 0,
                next_seq: 1,
                ttl,
                max_entries: bounded_entries,
                max_total_bytes: bounded_total_bytes,
            }),
        }
    }

    /// Stores one message payload under a one-time key.
    pub fn put(&self, key: String, payload: Vec<u8>) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        prune_expired(&mut guard);
        if payload.len() > guard.max_total_bytes {
            return false;
        }

        if let Some(previous) = guard.payloads.remove(&key) {
            guard.total_bytes = guard.total_bytes.saturating_sub(previous.payload.len());
        }

        let seq = guard.next_seq;
        guard.next_seq = guard.next_seq.saturating_add(1);
        guard.total_bytes = guard.total_bytes.saturating_add(payload.len());
        guard.payloads.insert(
            key.clone(),
            StoredPayload {
                payload,
                inserted_at: Instant::now(),
                seq,
            },
        );
        guard.order.push_back((key.clone(), seq));
        evict_handshake_store(&mut guard);
        guard.payloads.contains_key(&key)
    }

    /// Takes and removes one payload.
    pub fn take(&self, key: &str) -> Option<Vec<u8>> {
        let mut guard = self.inner.lock().ok()?;
        prune_expired(&mut guard);
        let entry = guard.payloads.remove(key)?;
        guard.total_bytes = guard.total_bytes.saturating_sub(entry.payload.len());
        Some(entry.payload)
    }
}

impl Default for HandshakeStore {
    fn default() -> Self {
        Self::new(
            DEFAULT_HANDSHAKE_MAX_ENTRIES,
            DEFAULT_HANDSHAKE_MAX_TOTAL_BYTES,
            Duration::from_secs(DEFAULT_HANDSHAKE_TTL_SECONDS),
        )
    }
}

/// Transport layer failures.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Invalid destination URL.
    #[error("invalid destination URL `{0}`")]
    InvalidDestination(String),
    /// Unsupported scheme.
    #[error("unsupported destination scheme `{0}`")]
    UnsupportedScheme(String),
    /// HTTP failure.
    #[error("http error: {0}")]
    Http(String),
    /// SMTP disabled.
    #[error("smtp transport not configured")]
    SmtpNotConfigured,
    /// SMTP failure.
    #[error("smtp send failed: {0}")]
    Smtp(String),
    /// UDP failure.
    #[error("udp send failed: {0}")]
    Udp(String),
    /// SSH failure.
    #[error("ssh send failed: {0}")]
    Ssh(String),
    /// Multipart payload malformed.
    #[error("malformed multipart payload")]
    MalformedMultipart,
    /// Handshake payload store is at capacity.
    #[error("handshake payload store capacity exceeded")]
    HandshakeStoreFull,
}

/// Outbound transport manager.
pub struct TransportManager {
    http_client: Client<HttpConnector, Full<Bytes>>,
    https_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    udp_socket: UdpSocket,
    smtp: Option<AsyncSmtpTransport<Tokio1Executor>>,
    smtp_from: Option<String>,
    ssh_cfg: SshConfig,
    local_address: String,
    prefer_http_handshake: bool,
    handshake_store: Arc<HandshakeStore>,
}

impl TransportManager {
    /// Builds transport manager.
    pub async fn new(
        local_address: String,
        smtp: Option<SmtpConfig>,
        ssh_cfg: SshConfig,
        prefer_http_handshake: bool,
        handshake_store: Arc<HandshakeStore>,
    ) -> Result<Self, TransportError> {
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        let http_client = Client::builder(TokioExecutor::new()).build(http_connector);

        let https_connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| TransportError::Http(format!("tls roots: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        let https_client = Client::builder(TokioExecutor::new()).build(https_connector);

        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| TransportError::Udp(e.to_string()))?;

        let (smtp_transport, smtp_from) = if let Some(cfg) = smtp {
            let mut builder = if cfg.allow_insecure {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.relay).port(cfg.port)
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.relay)
                    .map_err(|e| TransportError::Smtp(e.to_string()))?
                    .port(cfg.port)
            };
            if let (Some(user), Some(pass_env)) = (cfg.username.clone(), cfg.password_env.clone()) {
                let pass = std::env::var(pass_env).map_err(|e| {
                    TransportError::Smtp(format!("missing SMTP password env var: {e}"))
                })?;
                builder = builder.credentials(Credentials::new(user, pass));
            }
            (Some(builder.build()), Some(cfg.from))
        } else {
            (None, None)
        };

        Ok(Self {
            http_client,
            https_client,
            udp_socket,
            smtp: smtp_transport,
            smtp_from,
            ssh_cfg,
            local_address,
            prefer_http_handshake,
            handshake_store,
        })
    }

    /// Sends one message to CMR address.
    pub async fn send_message(
        &self,
        destination: &str,
        wire_message: &[u8],
    ) -> Result<(), TransportError> {
        if destination.starts_with("mailto:") {
            return self.send_smtp(destination, wire_message).await;
        }
        let url = Url::parse(destination)
            .map_err(|_| TransportError::InvalidDestination(destination.to_owned()))?;
        match url.scheme() {
            "http" | "https" => self.send_http_like(&url, wire_message).await,
            "udp" => self.send_udp(&url, wire_message).await,
            "ssh" => self.send_ssh(&url, wire_message).await,
            other => Err(TransportError::UnsupportedScheme(other.to_owned())),
        }
    }

    /// Performs HTTP callback for handshake receivers.
    pub async fn fetch_http_handshake_reply(
        &self,
        sender_url: &str,
        key: &str,
    ) -> Result<Vec<u8>, TransportError> {
        let mut url = Url::parse(sender_url)
            .map_err(|_| TransportError::InvalidDestination(sender_url.to_owned()))?;
        validate_handshake_callback_url(&url)?;
        if key.is_empty() || key.len() > 128 {
            return Err(TransportError::Http("invalid handshake key".to_owned()));
        }
        url.query_pairs_mut().append_pair("reply", key);
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|e| TransportError::Http(format!("invalid handshake uri: {e}")))?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let resp = if url.scheme() == "https" {
            self.https_client
                .request(req)
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?
        } else {
            self.http_client
                .request(req)
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?
        };
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!(
                "handshake reply status {}",
                resp.status()
            )));
        }
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?
            .to_bytes();
        Ok(body.to_vec())
    }

    async fn send_http_like(&self, url: &Url, wire_message: &[u8]) -> Result<(), TransportError> {
        if self.prefer_http_handshake {
            return self.send_http_handshake(url, wire_message).await;
        }
        self.send_http_upload(url, wire_message).await
    }

    async fn send_http_upload(&self, url: &Url, wire_message: &[u8]) -> Result<(), TransportError> {
        let boundary = random_hex(16);
        let multipart = encode_single_file_multipart(&boundary, wire_message);
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|e| TransportError::Http(format!("invalid uri: {e}")))?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Full::new(Bytes::from(multipart)))
            .map_err(|e| TransportError::Http(e.to_string()))?;

        let resp = if url.scheme() == "https" {
            self.https_client
                .request(req)
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?
        } else {
            self.http_client
                .request(req)
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?
        };
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(TransportError::Http(format!(
                "upload failed with status {}",
                resp.status()
            )))
        }
    }

    async fn send_http_handshake(
        &self,
        url: &Url,
        wire_message: &[u8],
    ) -> Result<(), TransportError> {
        let one_time_key = random_hex(12);
        let unsigned_payload = strip_signature_line(wire_message)?;
        if !self
            .handshake_store
            .put(one_time_key.clone(), unsigned_payload)
        {
            return Err(TransportError::HandshakeStoreFull);
        }
        let mut handshake_url = url.clone();
        handshake_url
            .query_pairs_mut()
            .append_pair("request", &self.local_address)
            .append_pair("key", &one_time_key);
        let uri: Uri = handshake_url
            .as_str()
            .parse()
            .map_err(|e| TransportError::Http(format!("invalid handshake uri: {e}")))?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let resp = if url.scheme() == "https" {
            self.https_client
                .request(req)
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?
        } else {
            self.http_client
                .request(req)
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?
        };
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(TransportError::Http(format!(
                "handshake request failed with status {}",
                resp.status()
            )))
        }
    }

    async fn send_udp(&self, url: &Url, wire_message: &[u8]) -> Result<(), TransportError> {
        let service = parse_udp_service_tag(url)?;
        let packet = encode_udp_packet(&service, wire_message)
            .map_err(|e| TransportError::Udp(format!("invalid UDP service tag: {e}")))?;
        if packet.len() > UDP_MAX_PAYLOAD_BYTES {
            return Err(TransportError::Udp(
                "message too large for UDP payload".to_owned(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| TransportError::InvalidDestination(url.as_str().to_owned()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TransportError::InvalidDestination(url.as_str().to_owned()))?;
        let addr = format!("{host}:{port}");
        self.udp_socket
            .send_to(&packet, &addr)
            .await
            .map_err(|e| TransportError::Udp(e.to_string()))?;
        Ok(())
    }

    async fn send_smtp(
        &self,
        destination: &str,
        wire_message: &[u8],
    ) -> Result<(), TransportError> {
        let Some(transport) = &self.smtp else {
            return Err(TransportError::SmtpNotConfigured);
        };
        let Some(from) = &self.smtp_from else {
            return Err(TransportError::SmtpNotConfigured);
        };
        let to = destination
            .strip_prefix("mailto:")
            .ok_or_else(|| TransportError::InvalidDestination(destination.to_owned()))?;
        let from_mailbox = from
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| TransportError::Smtp(e.to_string()))?;
        let to_mailbox = to
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| TransportError::Smtp(e.to_string()))?;
        let message = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject("cmr")
            .header(
                header::ContentType::parse("application/octet-stream")
                    .map_err(|e| TransportError::Smtp(e.to_string()))?,
            )
            .header(header::ContentTransferEncoding::Base64)
            .body(wire_message.to_vec())
            .map_err(|e| TransportError::Smtp(e.to_string()))?;
        transport
            .send(message)
            .await
            .map_err(|e| TransportError::Smtp(e.to_string()))?;
        Ok(())
    }

    async fn send_ssh(&self, url: &Url, wire_message: &[u8]) -> Result<(), TransportError> {
        let host = url
            .host_str()
            .ok_or_else(|| TransportError::InvalidDestination(url.as_str().to_owned()))?;
        let port = url.port().unwrap_or(22);
        let user = if url.username().is_empty() {
            None
        } else {
            Some(url.username())
        };
        let remote = if let Some(user) = user {
            format!("{user}@{host}")
        } else {
            host.to_owned()
        };
        let command = {
            let path = url.path().trim_start_matches('/');
            if path.is_empty() {
                self.ssh_cfg.default_remote_command.clone()
            } else {
                path.to_owned()
            }
        };

        let mut child = Command::new(&self.ssh_cfg.binary)
            .arg("-p")
            .arg(port.to_string())
            .arg(remote)
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| TransportError::Ssh(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(wire_message)
                .await
                .map_err(|e| TransportError::Ssh(e.to_string()))?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| TransportError::Ssh(e.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(TransportError::Ssh(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ))
        }
    }
}

/// Extracts CMR bytes from HTTP upload body.
pub fn extract_cmr_payload(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let Some(content_type) = content_type else {
        return Ok(body.to_vec());
    };
    let lower = content_type.to_ascii_lowercase();
    if !lower.starts_with("multipart/form-data") {
        return Ok(body.to_vec());
    }
    let boundary = parse_boundary(content_type).ok_or(TransportError::MalformedMultipart)?;
    parse_first_multipart_part(body, &boundary).ok_or(TransportError::MalformedMultipart)
}

fn parse_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';').map(str::trim) {
        if let Some(boundary) = part.strip_prefix("boundary=") {
            let clean = boundary.trim_matches('"');
            if !clean.is_empty() {
                return Some(clean.to_owned());
            }
        }
    }
    None
}

fn parse_first_multipart_part(body: &[u8], boundary: &str) -> Option<Vec<u8>> {
    let start = format!("--{boundary}\r\n").into_bytes();
    let end_marker = format!("\r\n--{boundary}").into_bytes();
    let start_idx = body.windows(start.len()).position(|w| w == start)?;
    let after_start = &body[(start_idx + start.len())..];
    let headers_end = after_start.windows(4).position(|w| w == b"\r\n\r\n")?;
    let payload = &after_start[(headers_end + 4)..];
    let end_idx = payload
        .windows(end_marker.len())
        .position(|w| w == end_marker)
        .unwrap_or(payload.len());
    Some(payload[..end_idx].to_vec())
}

fn encode_single_file_multipart(boundary: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 256);
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"cmr.msg\"\r\n",
    );
    out.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

fn validate_handshake_callback_url(url: &Url) -> Result<(), TransportError> {
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(TransportError::Http(format!(
                "unsupported handshake callback scheme `{other}`",
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TransportError::Http(
            "handshake callback URL must not include user info".to_owned(),
        ));
    }
    if url.fragment().is_some() {
        return Err(TransportError::Http(
            "handshake callback URL must not include fragments".to_owned(),
        ));
    }
    if url.host_str().is_none() {
        return Err(TransportError::Http(
            "handshake callback URL missing host".to_owned(),
        ));
    }
    Ok(())
}

fn parse_udp_service_tag(url: &Url) -> Result<String, TransportError> {
    let service = url.path().trim_start_matches('/');
    if service.is_empty() || service.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return Err(TransportError::InvalidDestination(url.as_str().to_owned()));
    }
    Ok(service.to_owned())
}

fn encode_udp_packet(service: &str, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    if service.is_empty() || service.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return Err("invalid service string");
    }
    let mut out = Vec::with_capacity(service.len() + 1 + payload.len());
    out.extend_from_slice(service.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    Ok(out)
}

/// Extracts CMR payload from a UDP datagram with service-tag prefix.
pub fn extract_udp_payload(expected_service: &str, datagram: &[u8]) -> Option<Vec<u8>> {
    if expected_service.is_empty() {
        return None;
    }
    let split = datagram.iter().position(|b| *b == b'\n')?;
    let service = std::str::from_utf8(&datagram[..split]).ok()?;
    if service != expected_service {
        return None;
    }
    Some(datagram[(split + 1)..].to_vec())
}

fn prune_expired(inner: &mut HandshakeStoreInner) {
    let now = Instant::now();
    let ttl = inner.ttl;
    let expired = inner
        .payloads
        .iter()
        .filter(|(_, entry)| now.duration_since(entry.inserted_at) >= ttl)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

    for key in expired {
        if let Some(removed) = inner.payloads.remove(&key) {
            inner.total_bytes = inner.total_bytes.saturating_sub(removed.payload.len());
        }
    }
}

fn evict_handshake_store(inner: &mut HandshakeStoreInner) {
    while inner.payloads.len() > inner.max_entries || inner.total_bytes > inner.max_total_bytes {
        let Some((key, seq)) = inner.order.pop_front() else {
            break;
        };
        let remove = inner
            .payloads
            .get(&key)
            .is_some_and(|entry| entry.seq == seq);
        if remove && let Some(removed) = inner.payloads.remove(&key) {
            inner.total_bytes = inner.total_bytes.saturating_sub(removed.payload.len());
        }
    }
}

fn strip_signature_line(message: &[u8]) -> Result<Vec<u8>, TransportError> {
    let Some(pos) = message.windows(2).position(|w| w == b"\r\n") else {
        return Err(TransportError::Http(
            "message missing signature line CRLF".to_owned(),
        ));
    };
    let mut out = Vec::with_capacity(message.len());
    out.extend_from_slice(b"0\r\n");
    out.extend_from_slice(&message[(pos + 2)..]);
    Ok(out)
}
