//! Peer runtime orchestration.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use cmr_core::policy::{RoutingPolicy, SecurityLevel};
use cmr_core::protocol::{CmrMessage, CmrTimestamp, MessageId, Signature, TransportKind};
use cmr_core::router::{ForwardAction, ProcessOutcome, Router};
use http::StatusCode;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngCore;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;

use crate::compressor_client::{
    CompressorClient, CompressorClientConfig, CompressorClientInitError,
};
use crate::config::{HttpsListenConfig, PeerConfig, SmtpListenConfig};
use crate::dashboard;
use crate::transport::{
    HandshakeStore, TransportError, TransportManager, extract_cmr_payload, extract_udp_payload,
};

const RECENT_EVENTS_CAP: usize = 500;
const INBOX_MESSAGES_CAP: usize = 1_000;
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) type PeerBody = BoxBody<Bytes, Infallible>;

#[derive(Clone, Debug, Serialize)]
pub struct DashboardForwardSummary {
    pub destination: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardEvent {
    pub id: u64,
    pub ts: String,
    pub accepted: bool,
    pub drop_reason: Option<String>,
    pub sender: Option<String>,
    pub intrinsic_dependence: Option<f64>,
    pub matched_count: usize,
    pub key_exchange_control: bool,
    pub best_peer: Option<String>,
    pub best_distance_raw: Option<f64>,
    pub best_distance_normalized: Option<f64>,
    pub threshold_raw: Option<f64>,
    pub threshold_normalized: Option<f64>,
    pub threshold_mode: Option<String>,
    pub forwards: Vec<DashboardForwardSummary>,
    pub transport: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardInboxMessage {
    pub id: u64,
    pub ts: String,
    pub sender: String,
    pub body_preview: String,
    pub body_text: String,
    pub encoded_size: usize,
    pub accepted: bool,
    pub key_exchange_control: bool,
    pub drop_reason: Option<String>,
    pub matched_count: usize,
    pub best_distance_raw: Option<f64>,
    pub best_distance_normalized: Option<f64>,
    pub threshold_mode: Option<String>,
    pub threshold_raw: Option<f64>,
    pub threshold_normalized: Option<f64>,
    pub forwards: Vec<DashboardForwardSummary>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PeerLiveStats {
    pub last_event_ts: Option<String>,
    pub last_distance_raw: Option<f64>,
    pub last_distance_normalized: Option<f64>,
    pub distance_hit_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComposeResult {
    pub ambient: bool,
    pub requested_destination: Option<String>,
    pub resolved_destinations: Vec<String>,
    pub destination: String,
    pub body_bytes: usize,
    pub signed: bool,
    pub local_event: DashboardEvent,
    pub transport_sent: bool,
    pub transport_error: Option<String>,
    pub transport_sent_count: usize,
    pub transport_failed_count: usize,
    pub deliveries: Vec<ComposeDeliveryResult>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComposeDeliveryResult {
    pub destination: String,
    pub transport_sent: bool,
    pub transport_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableConfigPayload {
    pub local_address: String,
    pub security_level: String,
    pub prefer_http_handshake: bool,
    pub compressor_command: String,
    pub compressor_args: Vec<String>,
    pub compressor_max_frame_bytes: usize,
    pub listen_http_bind: Option<String>,
    pub listen_http_path: Option<String>,
    pub listen_https_bind: Option<String>,
    pub listen_https_path: Option<String>,
    pub listen_https_cert_path: Option<String>,
    pub listen_https_key_path: Option<String>,
    pub listen_udp_bind: Option<String>,
    pub listen_udp_service: Option<String>,
    pub ssh_binary: String,
    pub ssh_default_remote_command: String,
    pub dashboard_enabled: bool,
    pub dashboard_path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigPreviewResult {
    pub valid: bool,
    pub diff: String,
    pub candidate_toml: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigApplyResult {
    pub applied: bool,
    pub backup_path: String,
    pub reloaded_policy: RoutingPolicy,
}

#[derive(Clone, Debug, Serialize)]
pub struct SetupStatus {
    pub node_health_ready: bool,
    pub config_ready: bool,
    pub peer_join_ready: bool,
    pub first_send_ready: bool,
    pub wizard_ready: bool,
}

/// Runtime state shared by transport listeners.
#[derive(Clone)]
pub(crate) struct AppState {
    router: Arc<Mutex<Router<CompressorClient>>>,
    transport: Arc<TransportManager>,
    handshake_store: Arc<HandshakeStore>,
    ingest_enabled: Arc<AtomicBool>,
    transport_enabled: Arc<AtomicBool>,
    event_tx: broadcast::Sender<DashboardEvent>,
    event_counter: Arc<AtomicU64>,
    recent_events: Arc<RwLock<VecDeque<DashboardEvent>>>,
    inbox_messages: Arc<RwLock<VecDeque<DashboardInboxMessage>>>,
    peer_live_stats: Arc<RwLock<HashMap<String, PeerLiveStats>>>,
    peer_connect_attempts: Arc<AtomicU64>,
    compose_actions: Arc<AtomicU64>,
    compose_transport_successes: Arc<AtomicU64>,
    active_config: Arc<RwLock<PeerConfig>>,
    config_path: Option<String>,
}

impl AppState {
    pub(crate) fn ingest_enabled(&self) -> bool {
        self.ingest_enabled.load(Ordering::Relaxed)
    }

    pub(crate) fn set_ingest_enabled(&self, enabled: bool) {
        self.ingest_enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn transport_enabled(&self) -> bool {
        self.transport_enabled.load(Ordering::Relaxed)
    }

    pub(crate) fn set_transport_enabled(&self, enabled: bool) {
        self.transport_enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn recent_events(&self) -> Vec<DashboardEvent> {
        self.recent_events
            .read()
            .map_or_else(|_| Vec::new(), |events| events.iter().cloned().collect())
    }

    pub(crate) fn inbox_messages(&self) -> Vec<DashboardInboxMessage> {
        self.inbox_messages
            .read()
            .map_or_else(|_| Vec::new(), |items| items.iter().cloned().collect())
    }

    pub(crate) fn inbox_message(&self, id: u64) -> Option<DashboardInboxMessage> {
        self.inbox_messages
            .read()
            .ok()
            .and_then(|items| items.iter().find(|entry| entry.id == id).cloned())
    }

    pub(crate) fn peer_live_stats(&self) -> HashMap<String, PeerLiveStats> {
        self.peer_live_stats
            .read()
            .map_or_else(|_| HashMap::new(), |map| map.clone())
    }

    pub(crate) fn peer_connect_attempts(&self) -> u64 {
        self.peer_connect_attempts.load(Ordering::Relaxed)
    }

    pub(crate) fn compose_transport_successes(&self) -> u64 {
        self.compose_transport_successes.load(Ordering::Relaxed)
    }

    pub(crate) fn note_peer_connect_attempt(&self) {
        self.peer_connect_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn subscribe_events(&self) -> broadcast::Receiver<DashboardEvent> {
        self.event_tx.subscribe()
    }

    pub(crate) fn config_snapshot(&self) -> Option<PeerConfig> {
        self.active_config.read().ok().map(|cfg| cfg.clone())
    }

    pub(crate) fn editable_config(&self) -> Option<EditableConfigPayload> {
        self.config_snapshot()
            .map(|cfg| EditableConfigPayload::from_config(&cfg))
    }

    pub(crate) fn update_policy(&self, policy: RoutingPolicy) -> Result<(), AppError> {
        let mut guard = self
            .router
            .lock()
            .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
        guard.set_policy(policy);
        Ok(())
    }

    pub(crate) fn router_snapshot<T>(
        &self,
        mut f: impl FnMut(&Router<CompressorClient>) -> T,
    ) -> Result<T, AppError> {
        let guard = self
            .router
            .lock()
            .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
        Ok(f(&guard))
    }

    pub(crate) fn router_mut<T>(
        &self,
        mut f: impl FnMut(&mut Router<CompressorClient>) -> T,
    ) -> Result<T, AppError> {
        let mut guard = self
            .router
            .lock()
            .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
        Ok(f(&mut guard))
    }

    pub(crate) fn setup_status(&self) -> Result<SetupStatus, AppError> {
        let peer_count = self.router_snapshot(|router| router.peer_count())?;
        let config_ready = self.config_path.is_some();
        let peer_join_ready = peer_count > 0 || self.peer_connect_attempts() > 0;
        let first_send_ready = setup_first_send_ready(self.compose_transport_successes());
        let node_health_ready = self.ingest_enabled() || self.transport_enabled();
        Ok(SetupStatus {
            node_health_ready,
            config_ready,
            peer_join_ready,
            first_send_ready,
            wizard_ready: node_health_ready && config_ready && peer_join_ready && first_send_ready,
        })
    }

    pub(crate) async fn send_message_to_destination(
        &self,
        destination: &str,
        body: Vec<u8>,
        sign: bool,
    ) -> Result<(), AppError> {
        if !self.transport_enabled() {
            return Err(AppError::Runtime(
                "transport plane is disabled (enable it before sending)".to_owned(),
            ));
        }
        let message = self.build_ui_message(body)?;
        let payload = self.render_ui_payload_for_destination(&message, destination, sign)?;
        match tokio::time::timeout(
            OUTBOUND_SEND_TIMEOUT,
            self.transport.send_message(destination, &payload),
        )
        .await
        {
            Ok(result) => result.map_err(AppError::Transport),
            Err(_) => Err(AppError::Runtime(format!(
                "send to {destination} timed out after {}s",
                OUTBOUND_SEND_TIMEOUT.as_secs()
            ))),
        }
    }

    pub(crate) async fn initiate_key_exchange(
        &self,
        peer: &str,
        mode: &str,
        clear_key: Option<Vec<u8>>,
    ) -> Result<String, AppError> {
        if !self.transport_enabled() {
            return Err(AppError::Runtime(
                "transport plane is disabled (enable it before key exchange)".to_owned(),
            ));
        }
        let mode_lc = mode.to_ascii_lowercase();
        let now = CmrTimestamp::now_utc();
        let action = {
            let mut guard = self
                .router
                .lock()
                .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
            match mode_lc.as_str() {
                "rsa" => guard.initiate_rsa_key_exchange(peer, &now),
                "dh" => guard.initiate_dh_key_exchange(peer, &now),
                "clear" => {
                    let clear = if let Some(bytes) = clear_key {
                        bytes
                    } else {
                        let mut key = vec![0_u8; 32];
                        rand::rng().fill_bytes(&mut key);
                        key
                    };
                    guard.initiate_clear_key_exchange(peer, clear, &now)
                }
                _ => {
                    return Err(AppError::Runtime(
                        "unsupported key exchange mode (use rsa|dh|clear)".to_owned(),
                    ));
                }
            }
        }
        .ok_or_else(|| AppError::Runtime("failed to create key exchange message".to_owned()))?;

        match tokio::time::timeout(
            OUTBOUND_SEND_TIMEOUT,
            self.transport
                .send_message(&action.destination, &action.message_bytes),
        )
        .await
        {
            Ok(result) => result.map_err(AppError::Transport)?,
            Err(_) => {
                return Err(AppError::Runtime(format!(
                    "key exchange send to {} timed out after {}s",
                    action.destination,
                    OUTBOUND_SEND_TIMEOUT.as_secs()
                )));
            }
        }

        self.peer_connect_attempts.fetch_add(1, Ordering::Relaxed);
        Ok(format!("{:?}", action.reason))
    }

    pub(crate) fn reload_policy_from_disk(&self) -> Result<RoutingPolicy, AppError> {
        let Some(path) = &self.config_path else {
            return Err(AppError::Runtime(
                "reload unavailable: config path not provided".to_owned(),
            ));
        };
        let next = PeerConfig::from_toml_file(path)
            .map_err(|err| AppError::Runtime(format!("reload config failed: {err}")))?;
        let effective = next.effective_policy();
        {
            let mut guard = self
                .router
                .lock()
                .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
            guard.set_policy(effective.clone());
        }
        if let Ok(mut cfg) = self.active_config.write() {
            *cfg = next;
        }
        Ok(effective)
    }

    pub(crate) fn config_preview(
        &self,
        editable: EditableConfigPayload,
    ) -> Result<ConfigPreviewResult, AppError> {
        let Some(path) = &self.config_path else {
            return Err(AppError::Runtime(
                "config preview unavailable: config path not provided".to_owned(),
            ));
        };
        let current_text = std::fs::read_to_string(path)
            .map_err(|err| AppError::Runtime(format!("failed reading current config: {err}")))?;
        let mut candidate = self.config_snapshot().ok_or_else(|| {
            AppError::Runtime("config preview unavailable: missing active config".to_owned())
        })?;
        editable.apply_to(&mut candidate)?;
        let candidate_toml = toml::to_string_pretty(&candidate).map_err(|err| {
            AppError::Runtime(format!("failed rendering candidate config: {err}"))
        })?;
        PeerConfig::from_toml_str(&candidate_toml).map_err(|err| {
            AppError::Runtime(format!("candidate config failed validation: {err}"))
        })?;
        Ok(ConfigPreviewResult {
            valid: true,
            diff: simple_line_diff(&current_text, &candidate_toml),
            candidate_toml,
        })
    }

    pub(crate) fn config_apply_atomic_with_backup(
        &self,
        editable: EditableConfigPayload,
    ) -> Result<ConfigApplyResult, AppError> {
        let Some(path) = &self.config_path else {
            return Err(AppError::Runtime(
                "config apply unavailable: config path not provided".to_owned(),
            ));
        };
        let preview = self.config_preview(editable)?;
        let config_path = PathBuf::from(path);
        let current_text = std::fs::read_to_string(&config_path).map_err(|err| {
            AppError::Runtime(format!("failed reading current config for backup: {err}"))
        })?;
        let backup_path = format!("{path}.bak.{}", unix_ts_secs());
        std::fs::write(&backup_path, current_text)
            .map_err(|err| AppError::Runtime(format!("failed writing backup file: {err}")))?;

        let tmp_path = format!("{path}.tmp.{}", std::process::id());
        std::fs::write(&tmp_path, preview.candidate_toml.as_bytes())
            .map_err(|err| AppError::Runtime(format!("failed writing temporary config: {err}")))?;
        std::fs::rename(&tmp_path, &config_path).map_err(|err| {
            AppError::Runtime(format!("failed replacing config atomically: {err}"))
        })?;

        let reloaded_policy = self.reload_policy_from_disk()?;
        Ok(ConfigApplyResult {
            applied: true,
            backup_path,
            reloaded_policy,
        })
    }

    pub(crate) async fn compose_and_send(
        &self,
        destination: Option<String>,
        extra_destinations: Vec<String>,
        body_text: String,
        sign: bool,
    ) -> Result<ComposeResult, AppError> {
        let requested_destination = destination
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let ambient = requested_destination.is_none();

        let message = self.build_ui_message(body_text.into_bytes())?;
        let payload = message.to_bytes();
        let local_event = self.inject_local_message(payload.clone()).await?;
        self.compose_actions.fetch_add(1, Ordering::Relaxed);

        let mut unique_destinations = Vec::new();
        let mut seen = HashSet::<String>::new();
        if let Some(primary) = requested_destination.as_ref() {
            seen.insert(primary.clone());
            unique_destinations.push(primary.clone());
        }
        for candidate in extra_destinations {
            if candidate.trim().is_empty() {
                continue;
            }
            if seen.insert(candidate.clone()) {
                unique_destinations.push(candidate);
            }
        }

        if unique_destinations.is_empty() {
            unique_destinations = self.known_peer_destinations()?;
        }
        if unique_destinations.is_empty() {
            return Err(AppError::Runtime("no destinations resolved".to_owned()));
        }

        let mut deliveries = Vec::with_capacity(unique_destinations.len());
        if !self.transport_enabled() {
            let detail =
                "transport plane is disabled (enable transport for outbound delivery)".to_owned();
            for peer in &unique_destinations {
                deliveries.push(ComposeDeliveryResult {
                    destination: peer.clone(),
                    transport_sent: false,
                    transport_error: Some(detail.clone()),
                });
            }
        } else {
            for peer in &unique_destinations {
                let delivery_payload =
                    self.render_ui_payload_for_destination(&message, peer, sign)?;
                let result = match tokio::time::timeout(
                    OUTBOUND_SEND_TIMEOUT,
                    self.transport.send_message(peer, &delivery_payload),
                )
                .await
                {
                    Ok(Ok(())) => ComposeDeliveryResult {
                        destination: peer.clone(),
                        transport_sent: true,
                        transport_error: None,
                    },
                    Ok(Err(err)) => ComposeDeliveryResult {
                        destination: peer.clone(),
                        transport_sent: false,
                        transport_error: Some(err.to_string()),
                    },
                    Err(_) => ComposeDeliveryResult {
                        destination: peer.clone(),
                        transport_sent: false,
                        transport_error: Some(format!(
                            "send timed out after {}s",
                            OUTBOUND_SEND_TIMEOUT.as_secs()
                        )),
                    },
                };
                deliveries.push(result);
            }
        }

        let transport_sent_count = deliveries.iter().filter(|d| d.transport_sent).count();
        let transport_failed_count = deliveries.len().saturating_sub(transport_sent_count);
        if transport_sent_count > 0 {
            self.compose_transport_successes.fetch_add(
                u64::try_from(transport_sent_count).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        let primary_delivery = if let Some(primary) = requested_destination.as_ref() {
            deliveries
                .iter()
                .find(|item| item.destination == *primary)
                .cloned()
                .unwrap_or(ComposeDeliveryResult {
                    destination: primary.clone(),
                    transport_sent: false,
                    transport_error: Some(
                        "primary destination missing from delivery set".to_owned(),
                    ),
                })
        } else {
            let destination = unique_destinations.first().cloned().unwrap_or_default();
            let transport_sent = transport_sent_count > 0;
            let transport_error = if transport_sent {
                None
            } else {
                deliveries
                    .iter()
                    .find_map(|item| item.transport_error.clone())
                    .or_else(|| Some("no destination transport send succeeded".to_owned()))
            };
            ComposeDeliveryResult {
                destination,
                transport_sent,
                transport_error,
            }
        };
        Ok(ComposeResult {
            ambient,
            requested_destination: requested_destination.clone(),
            resolved_destinations: unique_destinations,
            destination: primary_delivery.destination.clone(),
            body_bytes: payload.len(),
            signed: sign,
            local_event,
            transport_sent: primary_delivery.transport_sent,
            transport_error: primary_delivery.transport_error,
            transport_sent_count,
            transport_failed_count,
            deliveries,
        })
    }

    pub(crate) async fn inject_local_message(
        &self,
        payload: Vec<u8>,
    ) -> Result<DashboardEvent, AppError> {
        let (_, event) = self
            .process_payload(payload, TransportKind::Http, false, false, true)
            .await?;
        Ok(event)
    }

    fn record_event(
        &self,
        outcome: &ProcessOutcome,
        transport_kind: &TransportKind,
    ) -> DashboardEvent {
        let id = self
            .event_counter
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let sender = outcome
            .parsed_message
            .as_ref()
            .map(CmrMessage::immediate_sender)
            .map(str::to_owned);
        let mut threshold_mode = None;
        let mut threshold_raw = None;
        let mut threshold_normalized = None;
        let mut best_peer = None;
        let mut best_distance_raw = None;
        let mut best_distance_normalized = None;
        if let Some(diag) = &outcome.routing_diagnostics {
            threshold_mode = Some(if diag.used_normalized_threshold {
                "normalized".to_owned()
            } else {
                "raw".to_owned()
            });
            threshold_raw = Some(diag.threshold_raw);
            threshold_normalized = Some(diag.threshold_normalized);
            best_peer = diag.best_peer.clone();
            best_distance_raw = diag.best_distance_raw;
            best_distance_normalized = diag.best_distance_normalized;
        }
        let event = DashboardEvent {
            id,
            ts: CmrTimestamp::now_utc().to_string(),
            accepted: outcome.accepted,
            drop_reason: outcome.drop_reason.as_ref().map(ToString::to_string),
            sender,
            intrinsic_dependence: outcome.intrinsic_dependence,
            matched_count: outcome.matched_count,
            key_exchange_control: outcome.key_exchange_control,
            best_peer,
            best_distance_raw,
            best_distance_normalized,
            threshold_raw,
            threshold_normalized,
            threshold_mode,
            forwards: outcome
                .forwards
                .iter()
                .map(|f| DashboardForwardSummary {
                    destination: f.destination.clone(),
                    reason: format!("{:?}", f.reason),
                })
                .collect(),
            transport: transport_kind_label(transport_kind),
        };
        self.record_inbox_message(&event, outcome);
        self.update_peer_live_stats(&event);
        if let Ok(mut queue) = self.recent_events.write() {
            queue.push_back(event.clone());
            while queue.len() > RECENT_EVENTS_CAP {
                queue.pop_front();
            }
        }
        let _ = self.event_tx.send(event.clone());
        event
    }

    async fn ingest_and_forward(
        &self,
        payload: Vec<u8>,
        transport_kind: TransportKind,
    ) -> Result<ProcessOutcome, AppError> {
        self.process_payload(payload, transport_kind, true, true, false)
            .await
            .map(|(outcome, _)| outcome)
    }

    async fn process_payload(
        &self,
        payload: Vec<u8>,
        transport_kind: TransportKind,
        execute_forwards: bool,
        require_transport: bool,
        local_client_origin: bool,
    ) -> Result<(ProcessOutcome, DashboardEvent), AppError> {
        if !self.ingest_enabled.load(Ordering::Relaxed) {
            return Err(AppError::Runtime("ingest pipeline is stopped".to_owned()));
        }
        if require_transport && !self.transport_enabled.load(Ordering::Relaxed) {
            return Err(AppError::Runtime("transport plane is stopped".to_owned()));
        }
        let router = Arc::clone(&self.router);
        let transport_for_router = transport_kind.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let mut guard = router
                .lock()
                .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
            let processed = if local_client_origin {
                guard.process_local_client_message(
                    &payload,
                    transport_for_router,
                    CmrTimestamp::now_utc(),
                )
            } else {
                guard.process_incoming(&payload, transport_for_router, CmrTimestamp::now_utc())
            };
            Ok::<_, AppError>(processed)
        })
        .await
        .map_err(|e| AppError::Runtime(format!("router task join error: {e}")))??;

        if execute_forwards {
            for forward in outcome.forwards.clone() {
                let state = self.clone();
                tokio::spawn(async move {
                    if let Err(err) = state.send_forward(&forward).await {
                        let err_text = err.to_string();
                        let hint = if err_text.contains("upload failed with status 404") {
                            " (hint: destination path may not match peer ingest path)"
                        } else if (err_text.contains("Connection refused")
                            || err_text.contains("connection refused"))
                            && forward.destination.contains("localhost")
                        {
                            " (hint: for local testing use 127.0.0.1 instead of localhost)"
                        } else {
                            ""
                        };
                        eprintln!(
                            "forward to {} failed (reason={:?}): {}{}",
                            forward.destination, forward.reason, err_text, hint
                        );
                    }
                });
            }
        }
        let event = self.record_event(&outcome, &transport_kind);
        Ok((outcome, event))
    }

    async fn send_forward(&self, forward: &ForwardAction) -> Result<(), AppError> {
        if !self.transport_enabled() {
            return Err(AppError::Runtime(
                "transport plane is disabled (cannot send forward action)".to_owned(),
            ));
        }
        match tokio::time::timeout(
            OUTBOUND_SEND_TIMEOUT,
            self.transport
                .send_message(&forward.destination, &forward.message_bytes),
        )
        .await
        {
            Ok(result) => result.map_err(AppError::Transport),
            Err(_) => Err(AppError::Runtime(format!(
                "forward send to {} timed out after {}s",
                forward.destination,
                OUTBOUND_SEND_TIMEOUT.as_secs()
            ))),
        }
    }

    fn build_ui_message(&self, body: Vec<u8>) -> Result<CmrMessage, AppError> {
        let guard = self
            .router
            .lock()
            .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
        Ok(CmrMessage {
            signature: Signature::Unsigned,
            header: vec![MessageId {
                timestamp: CmrTimestamp::now_utc(),
                address: guard.local_address().to_owned(),
            }],
            body,
        })
    }

    fn render_ui_payload_for_destination(
        &self,
        base_message: &CmrMessage,
        destination: &str,
        sign: bool,
    ) -> Result<Vec<u8>, AppError> {
        let mut message = base_message.clone();
        message.make_unsigned();
        let guard = self
            .router
            .lock()
            .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
        let should_sign = sign || guard.policy().trust.require_signatures_from_known_peers;
        if should_sign && let Some(key) = guard.shared_key(destination) {
            message.sign_with_key(key);
        }
        Ok(message.to_bytes())
    }

    fn known_peer_destinations(&self) -> Result<Vec<String>, AppError> {
        self.router_snapshot(|router| {
            let mut peers = router
                .peer_snapshots()
                .into_iter()
                .map(|snapshot| snapshot.peer)
                .collect::<Vec<_>>();
            peers.sort();
            peers.dedup();
            peers
        })
    }

    fn record_inbox_message(&self, event: &DashboardEvent, outcome: &ProcessOutcome) {
        if !event.accepted {
            return;
        }
        let Some(parsed) = &outcome.parsed_message else {
            return;
        };
        let sender = parsed.immediate_sender().to_owned();
        let body_text = String::from_utf8_lossy(&parsed.body).into_owned();
        let body_preview = body_text.chars().take(256).collect::<String>();
        let entry = DashboardInboxMessage {
            id: event.id,
            ts: event.ts.clone(),
            sender,
            body_preview,
            body_text,
            encoded_size: parsed.encoded_len(),
            accepted: event.accepted,
            key_exchange_control: event.key_exchange_control,
            drop_reason: event.drop_reason.clone(),
            matched_count: event.matched_count,
            best_distance_raw: event.best_distance_raw,
            best_distance_normalized: event.best_distance_normalized,
            threshold_mode: event.threshold_mode.clone(),
            threshold_raw: event.threshold_raw,
            threshold_normalized: event.threshold_normalized,
            forwards: event.forwards.clone(),
        };
        if let Ok(mut inbox) = self.inbox_messages.write() {
            inbox.push_back(entry);
            while inbox.len() > INBOX_MESSAGES_CAP {
                inbox.pop_front();
            }
        }
    }

    fn update_peer_live_stats(&self, event: &DashboardEvent) {
        let Some(sender) = event.sender.clone() else {
            return;
        };
        if let Ok(mut map) = self.peer_live_stats.write() {
            let stats = map.entry(sender).or_default();
            stats.last_event_ts = Some(event.ts.clone());
            if event.best_distance_raw.is_some() || event.best_distance_normalized.is_some() {
                stats.distance_hit_count = stats.distance_hit_count.saturating_add(1);
            }
            if let Some(raw) = event.best_distance_raw {
                stats.last_distance_raw = Some(raw);
            }
            if let Some(norm) = event.best_distance_normalized {
                stats.last_distance_normalized = Some(norm);
            }
        }
    }
}

fn setup_first_send_ready(compose_transport_successes: u64) -> bool {
    compose_transport_successes > 0
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
    start_peer_with_config_path(config, None).await
}

/// Starts peer listeners and returns a runtime handle, retaining optional config path.
pub async fn start_peer_with_config_path(
    config: PeerConfig,
    config_path: Option<String>,
) -> Result<PeerRuntime, AppError> {
    let state = build_app_state(&config, config_path).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut handles = Vec::new();
    if let Some(http_cfg) = config.listen.http.clone() {
        let listener = TcpListener::bind(&http_cfg.bind).await?;
        let state = state.clone();
        let dashboard_cfg = config.dashboard.clone();
        let mut local_shutdown = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_http_listener(
                listener,
                http_cfg.path,
                dashboard_cfg,
                state,
                false,
                &mut local_shutdown,
            )
            .await
            {
                eprintln!("http listener stopped with error: {err}");
            }
        }));
    }
    if let Some(https_cfg) = config.listen.https.clone() {
        let (listener, acceptor) = bind_https_listener(&https_cfg).await?;
        let state = state.clone();
        let dashboard_cfg = config.dashboard.clone();
        let mut local_shutdown = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_https_listener(
                listener,
                acceptor,
                https_cfg.path,
                dashboard_cfg,
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
    if let Some(smtp_cfg) = config.listen.smtp.clone() {
        let listener = TcpListener::bind(&smtp_cfg.bind).await?;
        let state = state.clone();
        let mut local_shutdown = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) =
                run_smtp_listener(listener, smtp_cfg, state, &mut local_shutdown).await
            {
                eprintln!("smtp listener stopped with error: {err}");
            }
        }));
    }

    if handles.is_empty() {
        return Err(AppError::InvalidConfig(
            "at least one listener (http/https/udp/smtp) must be configured".to_owned(),
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

/// Runs peer listeners until interrupted while preserving config path for reload APIs.
pub async fn run_peer_with_config_path(
    config: PeerConfig,
    config_path: Option<String>,
) -> Result<(), AppError> {
    let runtime = start_peer_with_config_path(config, config_path).await?;
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

async fn build_app_state(
    config: &PeerConfig,
    config_path: Option<String>,
) -> Result<AppState, AppError> {
    let policy = config.effective_policy();
    let handshake_max_message_bytes = policy.content.max_message_bytes;
    let handshake_max_header_ids = policy.content.max_header_ids;
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
            handshake_max_message_bytes,
            handshake_max_header_ids,
        )
        .await?,
    );
    let (event_tx, _) = broadcast::channel(1_024);
    Ok(AppState {
        router: Arc::new(Mutex::new(router)),
        transport,
        handshake_store,
        ingest_enabled: Arc::new(AtomicBool::new(true)),
        transport_enabled: Arc::new(AtomicBool::new(true)),
        event_tx,
        event_counter: Arc::new(AtomicU64::new(0)),
        recent_events: Arc::new(RwLock::new(VecDeque::new())),
        inbox_messages: Arc::new(RwLock::new(VecDeque::new())),
        peer_live_stats: Arc::new(RwLock::new(HashMap::new())),
        peer_connect_attempts: Arc::new(AtomicU64::new(0)),
        compose_actions: Arc::new(AtomicU64::new(0)),
        compose_transport_successes: Arc::new(AtomicU64::new(0)),
        active_config: Arc::new(RwLock::new(config.clone())),
        config_path,
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
    dashboard_cfg: crate::config::DashboardConfig,
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
                let dashboard_cfg = dashboard_cfg.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        handle_http_request(
                            req,
                            path.clone(),
                            dashboard_cfg.clone(),
                            state.clone(),
                            is_https,
                            Some(remote_addr.ip()),
                        )
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
    dashboard_cfg: crate::config::DashboardConfig,
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
                let dashboard_cfg = dashboard_cfg.clone();
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
                        handle_http_request(
                            req,
                            path.clone(),
                            dashboard_cfg.clone(),
                            state.clone(),
                            true,
                            Some(remote_addr.ip()),
                        )
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

async fn run_smtp_listener(
    listener: TcpListener,
    cfg: SmtpListenConfig,
    state: AppState,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), AppError> {
    eprintln!("smtp listener active on `{}`", cfg.bind);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone();
                let max_message_bytes = cfg.max_message_bytes.max(1);
                tokio::spawn(async move {
                    if let Err(err) = handle_smtp_session(stream, state, max_message_bytes).await {
                        eprintln!("smtp session error: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_smtp_session(
    stream: TcpStream,
    state: AppState,
    max_message_bytes: usize,
) -> Result<(), AppError> {
    let (reader_half, mut writer_half) = stream.into_split();
    smtp_write_line(&mut writer_half, "220 cmr-peer ESMTP ready")
        .await
        .map_err(AppError::Io)?;

    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();
    let mut saw_mail_from = false;
    let mut saw_rcpt_to = false;

    loop {
        line.clear();
        let read = reader.read_line(&mut line).await.map_err(AppError::Io)?;
        if read == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']);
        let upper = command.to_ascii_uppercase();

        if upper.starts_with("EHLO") {
            smtp_write_line(&mut writer_half, "250-cmr-peer")
                .await
                .map_err(AppError::Io)?;
            smtp_write_line(&mut writer_half, &format!("250 SIZE {max_message_bytes}"))
                .await
                .map_err(AppError::Io)?;
            continue;
        }
        if upper.starts_with("HELO") {
            smtp_write_line(&mut writer_half, "250 cmr-peer")
                .await
                .map_err(AppError::Io)?;
            continue;
        }
        if upper.starts_with("MAIL FROM:") {
            saw_mail_from = true;
            saw_rcpt_to = false;
            smtp_write_line(&mut writer_half, "250 OK")
                .await
                .map_err(AppError::Io)?;
            continue;
        }
        if upper.starts_with("RCPT TO:") {
            if !saw_mail_from {
                smtp_write_line(&mut writer_half, "503 MAIL required")
                    .await
                    .map_err(AppError::Io)?;
                continue;
            }
            saw_rcpt_to = true;
            smtp_write_line(&mut writer_half, "250 OK")
                .await
                .map_err(AppError::Io)?;
            continue;
        }
        if upper == "RSET" {
            saw_mail_from = false;
            saw_rcpt_to = false;
            smtp_write_line(&mut writer_half, "250 OK")
                .await
                .map_err(AppError::Io)?;
            continue;
        }
        if upper == "NOOP" {
            smtp_write_line(&mut writer_half, "250 OK")
                .await
                .map_err(AppError::Io)?;
            continue;
        }
        if upper == "QUIT" {
            smtp_write_line(&mut writer_half, "221 Bye")
                .await
                .map_err(AppError::Io)?;
            break;
        }
        if upper == "DATA" {
            if !saw_mail_from || !saw_rcpt_to {
                smtp_write_line(&mut writer_half, "503 MAIL/RCPT required")
                    .await
                    .map_err(AppError::Io)?;
                continue;
            }
            smtp_write_line(&mut writer_half, "354 End data with <CR><LF>.<CR><LF>")
                .await
                .map_err(AppError::Io)?;

            let data = match read_smtp_data(&mut reader, max_message_bytes).await {
                Ok(data) => data,
                Err(err) => {
                    smtp_write_line(
                        &mut writer_half,
                        &format!(
                            "554 failed to read DATA: {}",
                            err.to_string().replace('\r', " ")
                        ),
                    )
                    .await
                    .map_err(AppError::Io)?;
                    saw_mail_from = false;
                    saw_rcpt_to = false;
                    continue;
                }
            };
            let cmr_payload = match extract_cmr_payload_from_email(&data) {
                Ok(payload) => payload,
                Err(err) => {
                    smtp_write_line(&mut writer_half, &format!("550 invalid CMR payload: {err}"))
                        .await
                        .map_err(AppError::Io)?;
                    saw_mail_from = false;
                    saw_rcpt_to = false;
                    continue;
                }
            };

            match state
                .ingest_and_forward(cmr_payload, TransportKind::Smtp)
                .await
            {
                Ok(outcome) if outcome.accepted => {
                    smtp_write_line(&mut writer_half, "250 OK")
                        .await
                        .map_err(AppError::Io)?;
                }
                Ok(outcome) => {
                    let reason = outcome
                        .drop_reason
                        .map_or_else(|| "unknown".to_owned(), |err| err.to_string());
                    smtp_write_line(
                        &mut writer_half,
                        &format!("554 message rejected by router: {reason}"),
                    )
                    .await
                    .map_err(AppError::Io)?;
                }
                Err(err) => {
                    smtp_write_line(
                        &mut writer_half,
                        &format!("554 ingest failed: {}", err.to_string().replace('\r', " ")),
                    )
                    .await
                    .map_err(AppError::Io)?;
                }
            }

            saw_mail_from = false;
            saw_rcpt_to = false;
            continue;
        }

        smtp_write_line(&mut writer_half, "502 command not implemented")
            .await
            .map_err(AppError::Io)?;
    }

    Ok(())
}

async fn smtp_write_line<W>(writer: &mut W, line: &str) -> Result<(), std::io::Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await
}

async fn read_smtp_data<R>(
    reader: &mut BufReader<R>,
    max_message_bytes: usize,
) -> Result<Vec<u8>, AppError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut data = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).await.map_err(AppError::Io)?;
        if read == 0 {
            return Err(AppError::Runtime(
                "smtp DATA terminated unexpectedly".to_owned(),
            ));
        }
        if line == ".\r\n" || line == ".\n" || line == "." {
            break;
        }
        let mut bytes = line.as_bytes().to_vec();
        if bytes.starts_with(b"..") {
            bytes.remove(0);
        }
        data.extend_from_slice(&bytes);
        if data.len() > max_message_bytes {
            return Err(AppError::Runtime(format!(
                "smtp DATA exceeds max_message_bytes ({max_message_bytes})"
            )));
        }
    }
    Ok(data)
}

fn extract_cmr_payload_from_email(email_data: &[u8]) -> Result<Vec<u8>, String> {
    let (header_bytes, body) =
        split_headers_and_body(email_data).ok_or_else(|| "missing email headers".to_owned())?;
    let headers = parse_mime_headers(header_bytes);
    let content_type = headers
        .get("content-type")
        .map_or_else(|| "text/plain".to_owned(), Clone::clone);
    let encoding = headers.get("content-transfer-encoding").map(String::as_str);

    if content_type.to_ascii_lowercase().contains("multipart/")
        && let Some(boundary) = parse_multipart_boundary(&content_type)
    {
        let parts = extract_multipart_parts(body, &boundary);
        for (part_headers, part_body) in parts {
            let part_type = part_headers
                .get("content-type")
                .map_or_else(|| "text/plain".to_owned(), Clone::clone)
                .to_ascii_lowercase();
            if !part_type.contains("application/octet-stream") && !part_type.contains("text/plain")
            {
                continue;
            }
            let part_encoding = part_headers
                .get("content-transfer-encoding")
                .map(String::as_str);
            if let Ok(decoded) = decode_mime_transfer(part_body.as_slice(), part_encoding) {
                if !decoded.is_empty() {
                    return Ok(decoded);
                }
            }
        }
        return Err("multipart message had no decodable CMR part".to_owned());
    }

    decode_mime_transfer(body, encoding)
}

fn split_headers_and_body(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(idx) = input.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((&input[..idx], &input[(idx + 4)..]));
    }
    input
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|idx| (&input[..idx], &input[(idx + 2)..]))
}

fn parse_mime_headers(raw_headers: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::<String, String>::new();
    let mut current_key: Option<String> = None;
    for line in raw_headers.split(|b| *b == b'\n') {
        let line = trim_ascii_cr(line);
        if line.is_empty() {
            continue;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some(key) = current_key.as_ref()
                && let Some(existing) = out.get_mut(key)
            {
                if !existing.is_empty() {
                    existing.push(' ');
                }
                existing.push_str(String::from_utf8_lossy(line).trim());
            }
            continue;
        }
        let text = String::from_utf8_lossy(line);
        if let Some((name, value)) = text.split_once(':') {
            let key = name.trim().to_ascii_lowercase();
            out.insert(key.clone(), value.trim().to_owned());
            current_key = Some(key);
        }
    }
    out
}

fn parse_multipart_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';').map(str::trim) {
        if part.len() >= 9 && part[..9].eq_ignore_ascii_case("boundary=") {
            let boundary = &part[9..];
            let clean = boundary.trim().trim_matches('"');
            if !clean.is_empty() {
                return Some(clean.to_owned());
            }
        }
    }
    None
}

fn extract_multipart_parts(body: &[u8], boundary: &str) -> Vec<(HashMap<String, String>, Vec<u8>)> {
    let boundary_marker = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut cursor = 0_usize;
    while let Some(found) = find_subslice(&body[cursor..], &boundary_marker) {
        let marker_idx = cursor.saturating_add(found);
        let mut part_start = marker_idx.saturating_add(boundary_marker.len());
        if body.get(part_start..part_start.saturating_add(2)) == Some(b"--") {
            break;
        }
        if body.get(part_start..part_start.saturating_add(2)) == Some(b"\r\n") {
            part_start = part_start.saturating_add(2);
        } else if body.get(part_start..part_start.saturating_add(1)) == Some(b"\n") {
            part_start = part_start.saturating_add(1);
        }

        let next_boundary_crlf = format!("\r\n--{boundary}").into_bytes();
        let next_boundary_lf = format!("\n--{boundary}").into_bytes();
        let end_rel = find_subslice(&body[part_start..], &next_boundary_crlf)
            .or_else(|| find_subslice(&body[part_start..], &next_boundary_lf))
            .unwrap_or_else(|| body.len().saturating_sub(part_start));
        let part_block = &body[part_start..part_start.saturating_add(end_rel)];
        if let Some((header_bytes, part_body)) = split_headers_and_body(part_block) {
            parts.push((parse_mime_headers(header_bytes), part_body.to_vec()));
        }
        cursor = part_start.saturating_add(end_rel).saturating_add(1);
    }
    parts
}

fn decode_mime_transfer(body: &[u8], encoding: Option<&str>) -> Result<Vec<u8>, String> {
    let encoding = encoding
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "7bit".to_owned());
    match encoding.as_str() {
        "base64" => {
            let compact = body
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
            base64::engine::general_purpose::STANDARD
                .decode(compact)
                .map_err(|err| format!("base64 decode failed: {err}"))
        }
        "7bit" | "8bit" | "binary" | "" => Ok(trim_single_trailing_newline(body.to_vec())),
        other => Err(format!("unsupported content-transfer-encoding `{other}`")),
    }
}

fn trim_single_trailing_newline(mut data: Vec<u8>) -> Vec<u8> {
    if data.ends_with(b"\r\n") {
        data.truncate(data.len().saturating_sub(2));
    } else if data.ends_with(b"\n") {
        data.truncate(data.len().saturating_sub(1));
    }
    data
}

fn trim_ascii_cr(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r") {
        &line[..line.len().saturating_sub(1)]
    } else {
        line
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn handle_http_request(
    req: Request<Incoming>,
    ingest_path: String,
    dashboard_cfg: crate::config::DashboardConfig,
    state: AppState,
    is_https: bool,
    remote_ip: Option<IpAddr>,
) -> Result<Response<PeerBody>, Infallible> {
    let transport_kind = if is_https {
        TransportKind::Https
    } else {
        TransportKind::Http
    };
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_owned();

    if dashboard_cfg.enabled {
        let base = if dashboard_cfg.path.starts_with('/') {
            dashboard_cfg.path.clone()
        } else {
            format!("/{}", dashboard_cfg.path)
        };
        if path == base || path.starts_with(&format!("{base}/")) {
            return dashboard::handle_dashboard_request(req, state, dashboard_cfg).await;
        }
    }

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
) -> Response<PeerBody> {
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
        .body(full_body(body))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

fn response(status: StatusCode, body: Bytes) -> Response<PeerBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(full_body(body))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

pub(crate) fn full_body(body: Bytes) -> PeerBody {
    Full::new(body).boxed()
}

impl EditableConfigPayload {
    #[must_use]
    pub fn from_config(cfg: &PeerConfig) -> Self {
        Self {
            local_address: cfg.local_address.clone(),
            security_level: format!("{:?}", cfg.security_level).to_ascii_lowercase(),
            prefer_http_handshake: cfg.prefer_http_handshake,
            compressor_command: cfg.compressor.command.clone(),
            compressor_args: cfg.compressor.args.clone(),
            compressor_max_frame_bytes: cfg.compressor.max_frame_bytes,
            listen_http_bind: cfg.listen.http.as_ref().map(|v| v.bind.clone()),
            listen_http_path: cfg.listen.http.as_ref().map(|v| v.path.clone()),
            listen_https_bind: cfg.listen.https.as_ref().map(|v| v.bind.clone()),
            listen_https_path: cfg.listen.https.as_ref().map(|v| v.path.clone()),
            listen_https_cert_path: cfg.listen.https.as_ref().map(|v| v.cert_path.clone()),
            listen_https_key_path: cfg.listen.https.as_ref().map(|v| v.key_path.clone()),
            listen_udp_bind: cfg.listen.udp.as_ref().map(|v| v.bind.clone()),
            listen_udp_service: cfg.listen.udp.as_ref().map(|v| v.service.clone()),
            ssh_binary: cfg.ssh.binary.clone(),
            ssh_default_remote_command: cfg.ssh.default_remote_command.clone(),
            dashboard_enabled: cfg.dashboard.enabled,
            dashboard_path: cfg.dashboard.path.clone(),
        }
    }

    pub fn apply_to(&self, cfg: &mut PeerConfig) -> Result<(), AppError> {
        cfg.local_address = self.local_address.trim().to_owned();
        cfg.security_level = parse_security_level(&self.security_level)?;
        cfg.prefer_http_handshake = self.prefer_http_handshake;
        cfg.compressor.command = self.compressor_command.trim().to_owned();
        cfg.compressor.args = self.compressor_args.clone();
        cfg.compressor.max_frame_bytes = self.compressor_max_frame_bytes.max(1024);

        cfg.listen.http =
            self.listen_http_bind
                .as_ref()
                .map(|bind| crate::config::HttpListenConfig {
                    bind: bind.trim().to_owned(),
                    path: self
                        .listen_http_path
                        .as_deref()
                        .unwrap_or("/")
                        .trim()
                        .to_owned(),
                });
        cfg.listen.https =
            self.listen_https_bind
                .as_ref()
                .map(|bind| crate::config::HttpsListenConfig {
                    bind: bind.trim().to_owned(),
                    path: self
                        .listen_https_path
                        .as_deref()
                        .unwrap_or("/")
                        .trim()
                        .to_owned(),
                    cert_path: self
                        .listen_https_cert_path
                        .clone()
                        .unwrap_or_else(|| "certs/server.crt".to_owned()),
                    key_path: self
                        .listen_https_key_path
                        .clone()
                        .unwrap_or_else(|| "certs/server.key".to_owned()),
                });
        cfg.listen.udp = self
            .listen_udp_bind
            .as_ref()
            .map(|bind| crate::config::UdpListenConfig {
                bind: bind.trim().to_owned(),
                service: self
                    .listen_udp_service
                    .as_deref()
                    .unwrap_or("cmr")
                    .trim()
                    .to_owned(),
            });

        cfg.ssh.binary = self.ssh_binary.trim().to_owned();
        cfg.ssh.default_remote_command = self.ssh_default_remote_command.trim().to_owned();
        cfg.dashboard.enabled = self.dashboard_enabled;
        cfg.dashboard.path = self.dashboard_path.trim().to_owned();

        if cfg.local_address.is_empty() {
            return Err(AppError::InvalidConfig(
                "local_address cannot be empty".to_owned(),
            ));
        }
        if cfg.compressor.command.is_empty() {
            return Err(AppError::InvalidConfig(
                "compressor_command cannot be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

fn parse_security_level(value: &str) -> Result<SecurityLevel, AppError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "strict" => Ok(SecurityLevel::Strict),
        "balanced" => Ok(SecurityLevel::Balanced),
        "trusted" => Ok(SecurityLevel::Trusted),
        _ => Err(AppError::InvalidConfig(
            "security_level must be one of: strict|balanced|trusted".to_owned(),
        )),
    }
}

fn simple_line_diff(old_text: &str, new_text: &str) -> String {
    if old_text == new_text {
        return "No changes.".to_owned();
    }
    let old_lines = old_text.lines().collect::<Vec<_>>();
    let new_lines = new_text.lines().collect::<Vec<_>>();
    let max_len = old_lines.len().max(new_lines.len());
    let mut out = String::new();
    for idx in 0..max_len {
        let old = old_lines.get(idx).copied();
        let new = new_lines.get(idx).copied();
        if old == new {
            continue;
        }
        if let Some(value) = old {
            out.push_str("- ");
            out.push_str(value);
            out.push('\n');
        }
        if let Some(value) = new {
            out.push_str("+ ");
            out.push_str(value);
            out.push('\n');
        }
    }
    out
}

fn unix_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn transport_kind_label(kind: &TransportKind) -> String {
    match kind {
        TransportKind::Http => "http".to_owned(),
        TransportKind::Https => "https".to_owned(),
        TransportKind::Smtp => "smtp".to_owned(),
        TransportKind::Udp => "udp".to_owned(),
        TransportKind::Ssh => "ssh".to_owned(),
        TransportKind::Other(v) => format!("other:{v}"),
    }
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
    use base64::Engine as _;
    use std::net::IpAddr;

    use super::{
        extract_cmr_payload_from_email, loopback_http_target, normalize_ingest_path,
        setup_first_send_ready, validate_handshake_callback_request,
    };

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

    #[test]
    fn setup_first_send_ready_requires_transport_success() {
        assert!(!setup_first_send_ready(0));
        assert!(setup_first_send_ready(1));
    }

    #[test]
    fn smtp_email_parser_extracts_plain_cmr_body() {
        let wire = b"0\r\n2029/12/31 23:59:59 http://origin\r\n\r\n5\r\nhello";
        let email = format!(
            "From: sender@example.com\r\nTo: receiver@example.com\r\nSubject: cmr\r\n\r\n{}\r\n",
            String::from_utf8_lossy(wire)
        );
        let extracted = extract_cmr_payload_from_email(email.as_bytes()).expect("extract plain");
        assert_eq!(extracted, wire);
    }

    #[test]
    fn smtp_email_parser_extracts_base64_multipart_attachment() {
        let wire = b"0\r\n2029/12/31 23:59:59 http://origin\r\n\r\n5\r\nhello";
        let encoded = base64::engine::general_purpose::STANDARD.encode(wire);
        let email = format!(
            "From: sender@example.com\r\n\
To: receiver@example.com\r\n\
Subject: cmr\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"cmr\"\r\n\
\r\n\
--cmr\r\n\
Content-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
{encoded}\r\n\
--cmr--\r\n"
        );
        let extracted =
            extract_cmr_payload_from_email(email.as_bytes()).expect("extract multipart base64");
        assert_eq!(extracted, wire);
    }
}
