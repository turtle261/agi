//! Embedded web dashboard and JSON APIs.

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::net::{SocketAddr, ToSocketAddrs};

use bytes::Bytes;
use cmr_core::policy::{RoutingPolicy, SecurityLevel};
use http::StatusCode;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Method, Request, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use url::form_urlencoded;

use crate::app::{AppError, AppState, DashboardEvent, EditableConfigPayload, PeerBody, full_body};
use crate::config::DashboardConfig;

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");

#[derive(Debug, Serialize)]
struct ApiEnvelope<T: Serialize> {
    ok: bool,
    data: Option<T>,
    error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: String,
    message: String,
    details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct StatusPayload {
    ingest_enabled: bool,
    transport_enabled: bool,
    peer_count: usize,
    known_keys: usize,
    pending_key_exchange: usize,
    cache_entries: usize,
    cache_bytes: usize,
}

#[derive(Debug, Serialize)]
struct RuntimeStatusPayload {
    ingest_enabled: bool,
    transport_enabled: bool,
    listeners: Vec<ListenerStatus>,
}

#[derive(Debug, Serialize)]
struct ListenerStatus {
    kind: String,
    bind: String,
    route: String,
}

#[derive(Debug, Serialize)]
struct CachePayload {
    stats: cmr_core::CacheStats,
    offset: usize,
    limit: usize,
    entries: Vec<cmr_core::CacheEntryView>,
}

#[derive(Debug, Serialize)]
struct ConfigPayload {
    local_address: String,
    security_level: String,
    prefer_http_handshake: bool,
    compressor_command: String,
    compressor_args: Vec<String>,
    compressor_max_frame_bytes: usize,
    listen_http_bind: Option<String>,
    listen_http_path: Option<String>,
    listen_https_bind: Option<String>,
    listen_https_path: Option<String>,
    listen_udp_bind: Option<String>,
    listen_udp_service: Option<String>,
    has_smtp: bool,
    ssh_binary: String,
    ssh_default_remote_command: String,
    dashboard_enabled: bool,
    dashboard_path: String,
}

#[derive(Debug, Serialize)]
struct DashboardPeerRow {
    peer: String,
    reputation: f64,
    inbound_messages: u64,
    inbound_bytes: u64,
    outbound_messages: u64,
    outbound_bytes: u64,
    current_window_messages: usize,
    current_window_bytes: u64,
    has_shared_key: bool,
    pending_key_exchange: bool,
    last_event_ts: Option<String>,
    last_distance_raw: Option<f64>,
    last_distance_normalized: Option<f64>,
    distance_hit_count: u64,
}

#[derive(Debug, Deserialize)]
struct PolicyUpdatePayload {
    policy: RoutingPolicy,
}

#[derive(Debug, Deserialize)]
struct SendPayload {
    destination: String,
    body_text: String,
    #[serde(default)]
    sign: bool,
}

#[derive(Debug, Deserialize)]
struct ComposePayload {
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    extra_destinations: Option<Vec<String>>,
    body_text: String,
    #[serde(default)]
    sign: bool,
}

#[derive(Debug, Deserialize)]
struct ReputationPayload {
    delta: f64,
}

#[derive(Debug, Deserialize)]
struct KeyExchangePayload {
    peer: String,
    mode: String,
    #[serde(default)]
    clear_key_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConnectPeerPayload {
    peer: String,
    mode: String,
    #[serde(default)]
    delta: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdatePayload {
    config: EditableConfigPayload,
}

#[derive(Debug, Serialize)]
struct PeerProbeResult {
    attempted: bool,
    ok: bool,
    detail: String,
}

pub(crate) async fn handle_dashboard_request(
    req: Request<Incoming>,
    state: AppState,
    cfg: DashboardConfig,
) -> Result<Response<PeerBody>, Infallible> {
    let query = parse_query(req.uri().query().unwrap_or_default());
    if !is_authorized(&req, &cfg, &query) {
        return Ok(response_api_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
            None,
        ));
    }

    let path = req.uri().path().to_owned();
    let base = normalize_base_path(&cfg.path);
    let relative = if path == base {
        "/".to_owned()
    } else {
        path.strip_prefix(&base)
            .map_or(path.clone(), |suffix| suffix.to_owned())
    };

    let method = req.method().clone();
    let response = match (method, relative.as_str()) {
        (Method::GET, "/") | (Method::GET, "/index.html") => response_html(DASHBOARD_HTML),
        (Method::GET, "/api/setup/status") => match state.setup_status() {
            Ok(status) => response_api_ok(StatusCode::OK, status),
            Err(err) => app_error_response(err),
        },
        (Method::POST, "/api/setup/complete") => match state.setup_status() {
            Ok(status) => response_api_ok(StatusCode::OK, status),
            Err(err) => app_error_response(err),
        },
        (Method::GET, "/api/runtime/status") => {
            let listeners = state
                .config_snapshot()
                .map(listener_statuses)
                .unwrap_or_default();
            response_api_ok(
                StatusCode::OK,
                RuntimeStatusPayload {
                    ingest_enabled: state.ingest_enabled(),
                    transport_enabled: state.transport_enabled(),
                    listeners,
                },
            )
        }
        (Method::POST, "/api/runtime/ingest/start") => {
            state.set_ingest_enabled(true);
            response_api_ok(StatusCode::OK, serde_json::json!({"ingest_enabled": true}))
        }
        (Method::POST, "/api/runtime/ingest/stop") => {
            state.set_ingest_enabled(false);
            response_api_ok(StatusCode::OK, serde_json::json!({"ingest_enabled": false}))
        }
        (Method::POST, "/api/runtime/transport/start") => {
            state.set_transport_enabled(true);
            response_api_ok(
                StatusCode::OK,
                serde_json::json!({"transport_enabled": true}),
            )
        }
        (Method::POST, "/api/runtime/transport/stop") => {
            state.set_transport_enabled(false);
            response_api_ok(
                StatusCode::OK,
                serde_json::json!({"transport_enabled": false}),
            )
        }
        // compatibility aliases
        (Method::POST, "/api/runtime/start") => {
            state.set_ingest_enabled(true);
            response_api_ok(StatusCode::OK, serde_json::json!({"ingest_enabled": true}))
        }
        (Method::POST, "/api/runtime/stop") => {
            state.set_ingest_enabled(false);
            response_api_ok(StatusCode::OK, serde_json::json!({"ingest_enabled": false}))
        }
        (Method::GET, "/api/status") => match api_status(&state) {
            Ok(payload) => response_api_ok(StatusCode::OK, payload),
            Err(err) => app_error_response(err),
        },
        (Method::GET, "/api/peers") => {
            let peer_rows = state
                .router_snapshot(|router| router.peer_snapshots())
                .map(|peers| {
                    let live = state.peer_live_stats();
                    peers
                        .into_iter()
                        .map(|peer| {
                            let stats = live.get(&peer.peer).cloned().unwrap_or_default();
                            DashboardPeerRow {
                                peer: peer.peer,
                                reputation: peer.reputation,
                                inbound_messages: peer.inbound_messages,
                                inbound_bytes: peer.inbound_bytes,
                                outbound_messages: peer.outbound_messages,
                                outbound_bytes: peer.outbound_bytes,
                                current_window_messages: peer.current_window_messages,
                                current_window_bytes: peer.current_window_bytes,
                                has_shared_key: peer.has_shared_key,
                                pending_key_exchange: peer.pending_key_exchange,
                                last_event_ts: stats.last_event_ts,
                                last_distance_raw: stats.last_distance_raw,
                                last_distance_normalized: stats.last_distance_normalized,
                                distance_hit_count: stats.distance_hit_count,
                            }
                        })
                        .collect::<Vec<_>>()
                });
            match peer_rows {
                Ok(payload) => response_api_ok(StatusCode::OK, payload),
                Err(err) => app_error_response(err),
            }
        }
        (Method::POST, "/api/peers/connect") => handle_peer_connect(req, &state).await,
        (Method::GET, "/api/inbox") => {
            let offset = query
                .get("offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = query
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 500);
            let sender_filter = query.get("sender").map(|v| v.trim().to_owned());
            let query_filter = query.get("q").map(|v| v.to_ascii_lowercase());
            let kind = query.get("kind").map(|v| v.to_ascii_lowercase());
            let from_ts = query.get("from").map(|v| v.trim().to_owned());
            let to_ts = query.get("to").map(|v| v.trim().to_owned());
            let mut rows = state.inbox_messages();
            rows.retain(|row| {
                if let Some(sender) = &sender_filter
                    && !sender.is_empty()
                    && row.sender != *sender
                {
                    return false;
                }
                if let Some(q) = &query_filter
                    && !q.is_empty()
                    && !row.body_text.to_ascii_lowercase().contains(q)
                    && !row.sender.to_ascii_lowercase().contains(q)
                {
                    return false;
                }
                if let Some(kind) = &kind {
                    match kind.as_str() {
                        "key_exchange" => {
                            if !row.key_exchange_control {
                                return false;
                            }
                        }
                        "message" => {
                            if row.key_exchange_control {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(from_ts) = &from_ts
                    && !from_ts.is_empty()
                    && row.ts < *from_ts
                {
                    return false;
                }
                if let Some(to_ts) = &to_ts
                    && !to_ts.is_empty()
                    && row.ts > *to_ts
                {
                    return false;
                }
                true
            });
            rows.reverse();
            let total = rows.len();
            let entries = rows
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();
            response_api_ok(
                StatusCode::OK,
                serde_json::json!({
                    "offset": offset,
                    "limit": limit,
                    "total": total,
                    "entries": entries,
                }),
            )
        }
        (Method::GET, route) if route.starts_with("/api/inbox/") => {
            let raw_id = route.trim_start_matches("/api/inbox/");
            let id = raw_id.parse::<u64>();
            match id {
                Ok(id) => match state.inbox_message(id) {
                    Some(row) => response_api_ok(StatusCode::OK, row),
                    None => response_api_error(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "inbox message not found",
                        None,
                    ),
                },
                Err(_) => response_api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "invalid inbox id",
                    None,
                ),
            }
        }
        (Method::GET, "/api/cache") => {
            let offset = query
                .get("offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = query
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .clamp(1, 2_000);
            match state.router_snapshot(|router| {
                let all_entries = router.cache_entries();
                let entries = all_entries
                    .into_iter()
                    .skip(offset)
                    .take(limit)
                    .collect::<Vec<_>>();
                CachePayload {
                    stats: router.cache_stats(),
                    offset,
                    limit,
                    entries,
                }
            }) {
                Ok(cache) => response_api_ok(StatusCode::OK, cache),
                Err(err) => app_error_response(err),
            }
        }
        (Method::GET, "/api/cache/distance") => {
            let left = query.get("left").cloned().unwrap_or_default();
            let right = query.get("right").cloned().unwrap_or_default();
            if left.is_empty() || right.is_empty() {
                response_api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "missing left/right query keys",
                    None,
                )
            } else {
                match state.router_snapshot(|router| router.cache_message_distance(&left, &right)) {
                    Ok(Ok(Some(value))) => {
                        response_api_ok(StatusCode::OK, serde_json::json!({ "distance": value }))
                    }
                    Ok(Ok(None)) => response_api_error(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "one or both cache keys not found",
                        None,
                    ),
                    Ok(Err(err)) => response_api_error(
                        StatusCode::BAD_REQUEST,
                        "runtime_error",
                        &err.to_string(),
                        None,
                    ),
                    Err(err) => app_error_response(err),
                }
            }
        }
        (Method::GET, "/api/events") => response_api_ok(StatusCode::OK, state.recent_events()),
        (Method::GET, "/api/events/stream") => response_sse(&state),
        (Method::GET, "/api/policy/preset") => {
            let level = query
                .get("level")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "strict".to_owned());
            let security_level = match level.as_str() {
                "strict" => SecurityLevel::Strict,
                "balanced" => SecurityLevel::Balanced,
                "trusted" => SecurityLevel::Trusted,
                _ => {
                    return Ok(response_api_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_input",
                        "invalid level (use strict|balanced|trusted)",
                        None,
                    ));
                }
            };
            response_api_ok(StatusCode::OK, RoutingPolicy::for_level(security_level))
        }
        (Method::GET, "/api/policy") => {
            match state.router_snapshot(|router| router.policy().clone()) {
                Ok(policy) => response_api_ok(StatusCode::OK, policy),
                Err(err) => app_error_response(err),
            }
        }
        (Method::PUT, "/api/policy") => match parse_json_body::<PolicyUpdatePayload>(req).await {
            Ok(payload) => match state.update_policy(payload.policy) {
                Ok(()) => response_api_ok(StatusCode::OK, serde_json::json!({"updated": true})),
                Err(err) => app_error_response(err),
            },
            Err(resp) => resp,
        },
        (Method::GET, "/api/config") => {
            let payload = state.config_snapshot().map(|cfg| ConfigPayload {
                local_address: cfg.local_address,
                security_level: format!("{:?}", cfg.security_level),
                prefer_http_handshake: cfg.prefer_http_handshake,
                compressor_command: cfg.compressor.command,
                compressor_args: cfg.compressor.args,
                compressor_max_frame_bytes: cfg.compressor.max_frame_bytes,
                listen_http_bind: cfg.listen.http.as_ref().map(|v| v.bind.clone()),
                listen_http_path: cfg.listen.http.as_ref().map(|v| v.path.clone()),
                listen_https_bind: cfg.listen.https.as_ref().map(|v| v.bind.clone()),
                listen_https_path: cfg.listen.https.as_ref().map(|v| v.path.clone()),
                listen_udp_bind: cfg.listen.udp.as_ref().map(|v| v.bind.clone()),
                listen_udp_service: cfg.listen.udp.as_ref().map(|v| v.service.clone()),
                has_smtp: cfg.smtp.is_some(),
                ssh_binary: cfg.ssh.binary,
                ssh_default_remote_command: cfg.ssh.default_remote_command,
                dashboard_enabled: cfg.dashboard.enabled,
                dashboard_path: cfg.dashboard.path,
            });
            response_api_ok(StatusCode::OK, payload)
        }
        (Method::GET, "/api/config/editable") => {
            response_api_ok(StatusCode::OK, state.editable_config())
        }
        (Method::POST, "/api/config/preview") => {
            match parse_json_body::<ConfigUpdatePayload>(req).await {
                Ok(payload) => match state.config_preview(payload.config) {
                    Ok(result) => response_api_ok(StatusCode::OK, result),
                    Err(err) => app_error_response(err),
                },
                Err(resp) => resp,
            }
        }
        (Method::POST, "/api/config/apply") => {
            match parse_json_body::<ConfigUpdatePayload>(req).await {
                Ok(payload) => match state.config_apply_atomic_with_backup(payload.config) {
                    Ok(result) => response_api_ok(StatusCode::OK, result),
                    Err(err) => app_error_response(err),
                },
                Err(resp) => resp,
            }
        }
        (Method::POST, "/api/runtime/reload") => match state.reload_policy_from_disk() {
            Ok(policy) => response_api_ok(StatusCode::OK, serde_json::json!({"policy": policy})),
            Err(err) => app_error_response(err),
        },
        (Method::POST, "/api/compose") => match parse_json_body::<ComposePayload>(req).await {
            Ok(payload) => {
                let destination = match payload.destination.as_deref().map(str::trim) {
                    Some("") | None => None,
                    Some(value) => match canonicalize_operator_url(value) {
                        Ok(normalized) => Some(normalized),
                        Err(err) => {
                            return Ok(response_api_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_input",
                                &err,
                                None,
                            ));
                        }
                    },
                };
                let extra_destinations = match payload.extra_destinations {
                    Some(items) => {
                        let mut normalized = Vec::new();
                        for item in items {
                            let trimmed = item.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            match canonicalize_operator_url(trimmed) {
                                Ok(value) => normalized.push(value),
                                Err(err) => {
                                    return Ok(response_api_error(
                                        StatusCode::BAD_REQUEST,
                                        "invalid_input",
                                        &format!("invalid extra destination `{trimmed}`: {err}"),
                                        None,
                                    ));
                                }
                            }
                        }
                        normalized
                    }
                    None => Vec::new(),
                };
                match state
                    .compose_and_send(
                        destination,
                        extra_destinations,
                        payload.body_text,
                        payload.sign,
                    )
                    .await
                {
                    Ok(result) => response_api_ok(StatusCode::OK, result),
                    Err(err) => app_error_response(err),
                }
            }
            Err(resp) => resp,
        },
        (Method::POST, "/api/send") => match parse_json_body::<SendPayload>(req).await {
            Ok(payload) => {
                let destination = match canonicalize_operator_url(&payload.destination) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(response_api_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_input",
                            &err,
                            None,
                        ));
                    }
                };
                let body_len = payload.body_text.len();
                match state
                    .send_message_to_destination(
                        &destination,
                        payload.body_text.into_bytes(),
                        payload.sign,
                    )
                    .await
                {
                    Ok(()) => response_api_ok(
                        StatusCode::OK,
                        serde_json::json!({
                            "destination": destination,
                            "signed": payload.sign,
                            "body_bytes": body_len,
                        }),
                    ),
                    Err(err) => app_error_response(err),
                }
            }
            Err(resp) => resp,
        },
        (Method::POST, "/api/key-exchange") => handle_key_exchange(req, &state).await,
        (Method::POST, route)
            if route.starts_with("/api/peers/") && route.ends_with("/reputation") =>
        {
            handle_reputation_update(route, req, &state).await
        }
        (Method::DELETE, route) if route.starts_with("/api/peers/") => {
            let raw = route.trim_start_matches("/api/peers/");
            let peer = match percent_decode(raw) {
                Ok(value) => value,
                Err(err) => {
                    return Ok(response_api_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_input",
                        &err,
                        None,
                    ));
                }
            };
            if peer.is_empty() {
                response_api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "missing peer",
                    None,
                )
            } else {
                match state.router_mut(|router| router.remove_peer(&peer)) {
                    Ok(removed) => {
                        response_api_ok(StatusCode::OK, serde_json::json!({"removed": removed}))
                    }
                    Err(err) => app_error_response(err),
                }
            }
        }
        _ => response_api_error(StatusCode::NOT_FOUND, "not_found", "not found", None),
    };

    Ok(response)
}

async fn handle_peer_connect(req: Request<Incoming>, state: &AppState) -> Response<PeerBody> {
    let payload = match parse_json_body::<ConnectPeerPayload>(req).await {
        Ok(payload) => payload,
        Err(resp) => return resp,
    };
    state.note_peer_connect_attempt();
    let peer = payload.peer.trim().to_owned();
    if peer.is_empty() {
        return response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "peer is required",
            None,
        );
    }

    let peer = match canonicalize_operator_url(&peer) {
        Ok(value) => value,
        Err(err) => {
            return response_api_error(StatusCode::BAD_REQUEST, "invalid_input", &err, None);
        }
    };

    match url::Url::parse(&peer) {
        Ok(url) if matches!(url.scheme(), "http" | "https" | "udp" | "ssh" | "mailto") => {}
        Ok(url) => {
            return response_api_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "unsupported peer transport scheme",
                Some(serde_json::json!({"scheme": url.scheme()})),
            );
        }
        Err(err) => {
            return response_api_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "peer must be a valid URL",
                Some(serde_json::json!({"parse_error": err.to_string()})),
            );
        }
    }
    let probe = probe_peer_connectivity(&peer).await;

    match state
        .initiate_key_exchange(&peer, &payload.mode, None)
        .await
    {
        Ok(reason) => {
            if let Some(delta) = payload.delta {
                let _ = state.router_mut(|router| {
                    router.adjust_reputation(&peer, delta);
                });
            }
            let probe_warning = if probe.attempted && !probe.ok {
                Some("probe failed but key exchange dispatch succeeded; this can happen when one resolved address is unreachable while another works".to_owned())
            } else {
                None
            };
            response_api_ok(
                StatusCode::OK,
                serde_json::json!({
                    "connected": true,
                    "peer": peer,
                    "mode": payload.mode,
                    "probe": probe,
                    "probe_warning": probe_warning,
                    "key_exchange_reason": reason,
                    "reputation_delta": payload.delta.unwrap_or(0.0),
                }),
            )
        }
        Err(err) => response_api_error(
            StatusCode::BAD_REQUEST,
            "runtime_error",
            &err.to_string(),
            Some(serde_json::json!({
                "peer": peer,
                "mode": payload.mode,
                "probe": probe,
                "hint": transport_error_hint(&err.to_string(), &peer),
            })),
        ),
    }
}

async fn probe_peer_connectivity(peer: &str) -> PeerProbeResult {
    let parsed = match url::Url::parse(peer) {
        Ok(url) => url,
        Err(err) => {
            return PeerProbeResult {
                attempted: false,
                ok: false,
                detail: format!("invalid url: {err}"),
            };
        }
    };
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme == "mailto" {
        return PeerProbeResult {
            attempted: false,
            ok: true,
            detail: "mailto transport has no direct socket probe".to_owned(),
        };
    }
    let host = if let Some(host) = parsed.host_str() {
        host.to_owned()
    } else {
        return PeerProbeResult {
            attempted: false,
            ok: false,
            detail: "missing host in peer url".to_owned(),
        };
    };
    let port = if let Some(port) = parsed.port_or_known_default() {
        port
    } else {
        return PeerProbeResult {
            attempted: false,
            ok: false,
            detail: "missing port and no default for scheme".to_owned(),
        };
    };
    let resolved = match (host.as_str(), port).to_socket_addrs() {
        Ok(addrs) => {
            let mut unique = BTreeSet::new();
            for addr in addrs {
                unique.insert(addr);
            }
            unique.into_iter().collect::<Vec<_>>()
        }
        Err(err) => {
            return PeerProbeResult {
                attempted: true,
                ok: false,
                detail: format!("dns resolve failed: {err}"),
            };
        }
    };
    if resolved.is_empty() {
        return PeerProbeResult {
            attempted: true,
            ok: false,
            detail: "dns resolve returned no addresses".to_owned(),
        };
    }

    if scheme == "udp" {
        let mut failures = Vec::with_capacity(resolved.len());
        for target in &resolved {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(sock) => sock,
                Err(err) => {
                    failures.push(format!("{target}: local udp bind failed: {err}"));
                    continue;
                }
            };
            match timeout(Duration::from_millis(1500), socket.connect(*target)).await {
                Ok(Ok(())) => {
                    return PeerProbeResult {
                        attempted: true,
                        ok: true,
                        detail: format!("udp socket connect ok ({target})"),
                    };
                }
                Ok(Err(err)) => failures.push(format!("{target}: udp connect failed: {err}")),
                Err(_) => failures.push(format!("{target}: udp connect probe timed out")),
            }
        }
        return PeerProbeResult {
            attempted: true,
            ok: false,
            detail: format_probe_failure("udp", &resolved, &failures),
        };
    }

    let mut failures = Vec::with_capacity(resolved.len());
    for target in &resolved {
        match timeout(Duration::from_millis(1500), TcpStream::connect(*target)).await {
            Ok(Ok(_)) => {
                return PeerProbeResult {
                    attempted: true,
                    ok: true,
                    detail: format!("tcp connect ok ({scheme} via {target})"),
                };
            }
            Ok(Err(err)) => failures.push(format!("{target}: tcp connect failed: {err}")),
            Err(_) => failures.push(format!("{target}: tcp connect probe timed out")),
        }
    }
    PeerProbeResult {
        attempted: true,
        ok: false,
        detail: format_probe_failure("tcp", &resolved, &failures),
    }
}

fn format_probe_failure(protocol: &str, resolved: &[SocketAddr], failures: &[String]) -> String {
    let resolved_text = resolved
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let failure_text = failures
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    if failures.len() > 3 {
        format!(
            "{protocol} probe failed for resolved targets [{resolved_text}]: {failure_text} | +{} more",
            failures.len().saturating_sub(3)
        )
    } else {
        format!("{protocol} probe failed for resolved targets [{resolved_text}]: {failure_text}")
    }
}

fn transport_error_hint(message: &str, destination: &str) -> Option<String> {
    if message.contains("upload failed with status 404") {
        return Some(
            "destination path likely does not match peer ingest path; use peer local_address exactly (including path)".to_owned(),
        );
    }
    if (message.contains("Connection refused") || message.contains("connection refused"))
        && destination.contains("localhost")
    {
        return Some(
            "localhost can resolve to IPv6 ::1; for local tests prefer 127.0.0.1 to avoid loopback family mismatch".to_owned(),
        );
    }
    None
}

async fn handle_key_exchange(req: Request<Incoming>, state: &AppState) -> Response<PeerBody> {
    let payload = match parse_json_body::<KeyExchangePayload>(req).await {
        Ok(payload) => payload,
        Err(resp) => return resp,
    };
    if payload.peer.trim().is_empty() {
        return response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "peer is required",
            None,
        );
    }
    let peer = match canonicalize_operator_url(payload.peer.trim()) {
        Ok(value) => value,
        Err(err) => {
            return response_api_error(StatusCode::BAD_REQUEST, "invalid_input", &err, None);
        }
    };
    let clear_key = if let Some(hex_key) = payload.clear_key_hex {
        match hex::decode(&hex_key) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                return response_api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "invalid clear_key_hex",
                    Some(serde_json::json!({"parse_error": err.to_string()})),
                );
            }
        }
    } else {
        None
    };
    match state
        .initiate_key_exchange(&peer, &payload.mode, clear_key)
        .await
    {
        Ok(reason) => response_api_ok(
            StatusCode::OK,
            serde_json::json!({
                "peer": peer,
                "mode": payload.mode,
                "reason": reason,
            }),
        ),
        Err(err) => app_error_response(err),
    }
}

async fn handle_reputation_update(
    route: &str,
    req: Request<Incoming>,
    state: &AppState,
) -> Response<PeerBody> {
    let raw_peer = route
        .trim_start_matches("/api/peers/")
        .trim_end_matches("/reputation");
    let peer = match percent_decode(raw_peer.trim_end_matches('/')) {
        Ok(value) => value,
        Err(err) => {
            return response_api_error(StatusCode::BAD_REQUEST, "invalid_input", &err, None);
        }
    };
    if peer.is_empty() {
        return response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "missing peer",
            None,
        );
    }

    let payload = match parse_json_body::<ReputationPayload>(req).await {
        Ok(payload) => payload,
        Err(resp) => return resp,
    };

    match state.router_mut(|router| {
        router.adjust_reputation(&peer, payload.delta);
        true
    }) {
        Ok(_) => response_api_ok(StatusCode::OK, serde_json::json!({"updated": true})),
        Err(err) => app_error_response(err),
    }
}

fn api_status(state: &AppState) -> Result<StatusPayload, AppError> {
    state.router_snapshot(|router| {
        let cache = router.cache_stats();
        StatusPayload {
            ingest_enabled: state.ingest_enabled(),
            transport_enabled: state.transport_enabled(),
            peer_count: router.peer_count(),
            known_keys: router.known_keys_count(),
            pending_key_exchange: router.pending_key_exchange_count(),
            cache_entries: cache.entry_count,
            cache_bytes: cache.total_bytes,
        }
    })
}

fn listener_statuses(cfg: crate::config::PeerConfig) -> Vec<ListenerStatus> {
    let mut out = Vec::new();
    if let Some(http) = cfg.listen.http {
        out.push(ListenerStatus {
            kind: "http".to_owned(),
            bind: http.bind,
            route: http.path,
        });
    }
    if let Some(https) = cfg.listen.https {
        out.push(ListenerStatus {
            kind: "https".to_owned(),
            bind: https.bind,
            route: https.path,
        });
    }
    if let Some(udp) = cfg.listen.udp {
        out.push(ListenerStatus {
            kind: "udp".to_owned(),
            bind: udp.bind,
            route: udp.service,
        });
    }
    if let Some(smtp) = cfg.listen.smtp {
        out.push(ListenerStatus {
            kind: "smtp".to_owned(),
            bind: smtp.bind,
            route: "smtp".to_owned(),
        });
    }
    out
}

fn response_sse(state: &AppState) -> Response<PeerBody> {
    let replay_events = state.recent_events();
    let initial = tokio_stream::iter(replay_events.into_iter().map(event_to_sse_bytes));
    let live = BroadcastStream::new(state.subscribe_events()).filter_map(|item| match item {
        Ok(event) => Some(event_to_sse_bytes(event)),
        Err(BroadcastStreamRecvError::Lagged(_)) => Some(Bytes::from_static(
            b"event: warning\ndata: {\"warning\":\"dashboard event stream lagged\"}\n\n",
        )),
    });
    let stream = initial
        .chain(live)
        .map(|chunk| Ok::<Frame<Bytes>, Infallible>(Frame::data(chunk)));

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(StreamBody::new(stream).boxed())
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

fn event_to_sse_bytes(event: DashboardEvent) -> Bytes {
    let payload = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_owned());
    Bytes::from(format!(
        "id: {}\nevent: outcome\ndata: {payload}\n\n",
        event.id
    ))
}

async fn parse_json_body<T: DeserializeOwned>(
    req: Request<Incoming>,
) -> Result<T, Response<PeerBody>> {
    let body = req.into_body().collect().await.map_err(|err| {
        response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "failed to read request body",
            Some(serde_json::json!({"io_error": err.to_string()})),
        )
    })?;
    serde_json::from_slice::<T>(&body.to_bytes()).map_err(|err| {
        response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body is not valid JSON",
            Some(serde_json::json!({"parse_error": err.to_string()})),
        )
    })
}

fn parse_query(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn normalize_base_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.trim_end_matches('/').to_owned()
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

fn canonicalize_operator_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("url is required".to_owned());
    }

    let mut parsed =
        url::Url::parse(trimmed).map_err(|err| format!("invalid url `{trimmed}`: {err}"))?;
    if let Some(host) = parsed.host_str() {
        let normalized_host = if host.eq_ignore_ascii_case("localhost") {
            "127.0.0.1".to_owned()
        } else {
            host.to_ascii_lowercase()
        };
        parsed
            .set_host(Some(&normalized_host))
            .map_err(|_| format!("invalid host in url `{trimmed}`"))?;
    }

    parsed.set_query(None);
    parsed.set_fragment(None);
    if matches!(parsed.scheme(), "http" | "https") && parsed.path().is_empty() {
        parsed.set_path("/");
    }
    Ok(parsed.to_string())
}

fn is_authorized(
    req: &Request<Incoming>,
    cfg: &DashboardConfig,
    query: &HashMap<String, String>,
) -> bool {
    let Some(expected) = cfg.auth_token.as_deref() else {
        return true;
    };
    if query.get("token").is_some_and(|value| value == expected) {
        return true;
    }
    let Some(value) = req.headers().get("authorization") else {
        return false;
    };
    let Ok(text) = value.to_str() else {
        return false;
    };
    text == format!("Bearer {expected}")
}

fn percent_decode(input: &str) -> Result<String, String> {
    let mut out = Vec::<u8>::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0_usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("invalid percent-encoding in path".to_owned());
            }
            let hi = from_hex_nibble(bytes[i + 1])
                .ok_or_else(|| "invalid percent-encoding in path".to_owned())?;
            let lo = from_hex_nibble(bytes[i + 2])
                .ok_or_else(|| "invalid percent-encoding in path".to_owned())?;
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| "path segment is not valid UTF-8".to_owned())
}

fn from_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn app_error_response(err: AppError) -> Response<PeerBody> {
    response_api_error(
        StatusCode::BAD_REQUEST,
        "runtime_error",
        &err.to_string(),
        None,
    )
}

fn response_html(html: &str) -> Response<PeerBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(full_body(Bytes::copy_from_slice(html.as_bytes())))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

fn response_api_ok<T: Serialize>(status: StatusCode, data: T) -> Response<PeerBody> {
    response_api(
        status,
        ApiEnvelope {
            ok: true,
            data: Some(data),
            error: None,
        },
    )
}

fn response_api_error(
    status: StatusCode,
    code: &str,
    message: &str,
    details: Option<serde_json::Value>,
) -> Response<PeerBody> {
    response_api(
        status,
        ApiEnvelope::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: code.to_owned(),
                message: message.to_owned(),
                details,
            }),
        },
    )
}

fn response_api<T: Serialize>(status: StatusCode, value: ApiEnvelope<T>) -> Response<PeerBody> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| {
        b"{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialize_error\",\"message\":\"failed to serialize response\",\"details\":null}}".to_vec()
    });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full_body(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_operator_url, format_probe_failure, normalize_base_path, response_api_error,
        transport_error_hint,
    };
    use http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::net::SocketAddr;

    #[test]
    fn normalize_base_path_treats_trailing_slash_consistently() {
        assert_eq!(normalize_base_path("/_cmr"), "/_cmr");
        assert_eq!(normalize_base_path("/_cmr/"), "/_cmr");
        assert_eq!(normalize_base_path("_cmr/"), "/_cmr");
        assert_eq!(normalize_base_path("/"), "/");
        assert_eq!(normalize_base_path(""), "/");
    }

    #[test]
    fn canonicalize_operator_url_normalizes_http_root_and_strips_query_fragment() {
        let left = canonicalize_operator_url("http://127.0.0.1:4001").expect("left");
        let right = canonicalize_operator_url("HTTP://127.0.0.1:4001/?x=1#frag").expect("right");
        assert_eq!(left, "http://127.0.0.1:4001/");
        assert_eq!(left, right);
    }

    #[test]
    fn canonicalize_operator_url_maps_localhost_to_ipv4_loopback() {
        let normalized = canonicalize_operator_url("http://LOCALHOST:4002").expect("normalized");
        assert_eq!(normalized, "http://127.0.0.1:4002/");
    }

    #[test]
    fn format_probe_failure_summarizes_targets_and_failures() {
        let resolved = vec![
            "127.0.0.1:4002".parse::<SocketAddr>().expect("ipv4"),
            "[::1]:4002".parse::<SocketAddr>().expect("ipv6"),
        ];
        let failures = vec![
            "127.0.0.1:4002: tcp connect failed: connection refused".to_owned(),
            "[::1]:4002: tcp connect failed: connection refused".to_owned(),
        ];
        let text = format_probe_failure("tcp", &resolved, &failures);
        assert!(text.contains("resolved targets"));
        assert!(text.contains("127.0.0.1:4002"));
        assert!(text.contains("[::1]:4002"));
    }

    #[test]
    fn transport_error_hint_for_404_points_to_ingest_path_mismatch() {
        let hint = transport_error_hint(
            "transport error: http error: upload failed with status 404 Not Found",
            "http://127.0.0.1:4002/",
        );
        assert!(hint.is_some());
        assert!(hint.unwrap_or_default().contains("ingest path"));
    }

    #[tokio::test]
    async fn api_error_response_uses_structured_envelope() {
        let response = response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "bad payload",
            None,
        );
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json.get("ok").and_then(Value::as_bool), Some(false));
        assert!(json.get("data").is_some());
        let error = json.get("error").expect("error object");
        assert_eq!(
            error.get("code").and_then(Value::as_str),
            Some("invalid_input")
        );
        assert_eq!(
            error.get("message").and_then(Value::as_str),
            Some("bad payload")
        );
    }
}
