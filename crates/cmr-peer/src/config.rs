//! Runtime configuration.

use std::io::Write;
use std::path::Path;

use cmr_core::policy::{RoutingPolicy, SecurityLevel};
use serde::Deserialize;
use thiserror::Error;

/// Top-level peer configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    /// Local peer address (must match the address advertised in CMR headers).
    pub local_address: String,
    /// Security profile preset.
    #[serde(default)]
    pub security_level: SecurityLevel,
    /// Inbound listeners.
    pub listen: ListenConfig,
    /// Compressor worker process.
    #[serde(default)]
    pub compressor: CompressorConfig,
    /// SMTP outbound client configuration.
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// SSH outbound transport config.
    #[serde(default)]
    pub ssh: SshConfig,
    /// Override full routing policy (optional).
    #[serde(default)]
    pub policy: Option<RoutingPolicy>,
    /// Lightweight policy tuning overrides.
    #[serde(default)]
    pub policy_tuning: PolicyTuningConfig,
    /// Statically configured pairwise keys.
    #[serde(default)]
    pub static_keys: Vec<StaticKeyConfig>,
    /// Enables HTTP handshake transport for HTTP/HTTPS sends.
    #[serde(default)]
    pub prefer_http_handshake: bool,
}

impl PeerConfig {
    /// Loads configuration from TOML file.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let cfg = toml::from_str::<Self>(&data).map_err(ConfigError::Toml)?;
        Ok(cfg)
    }

    /// Returns effective policy.
    #[must_use]
    pub fn effective_policy(&self) -> RoutingPolicy {
        let mut policy = self
            .policy
            .clone()
            .unwrap_or_else(|| RoutingPolicy::for_level(self.security_level));
        if let Some(value) = self.policy_tuning.max_match_distance {
            policy.spam.max_match_distance = value.max(0.0);
        }
        if let Some(value) = self.policy_tuning.max_match_distance_normalized {
            policy.spam.max_match_distance_normalized = value.clamp(0.0, 1.0);
        }
        policy
    }
}

/// Optional policy tuning knobs for experiments and controlled deployments.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PolicyTuningConfig {
    /// Optional override for raw Section 3.2 match-distance threshold.
    pub max_match_distance: Option<f64>,
    /// Optional override for normalized match-distance threshold.
    pub max_match_distance_normalized: Option<f64>,
}

/// Embedded example configuration template.
pub const EXAMPLE_CONFIG_TOML: &str = include_str!("../cmr-peer.example.toml");

/// Writes the embedded example config to `path`.
pub fn write_example_config(path: impl AsRef<Path>, overwrite: bool) -> Result<(), std::io::Error> {
    if overwrite {
        return std::fs::write(path, EXAMPLE_CONFIG_TOML);
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(EXAMPLE_CONFIG_TOML.as_bytes())
}

/// Network listeners.
#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    /// HTTP listener.
    #[serde(default)]
    pub http: Option<HttpListenConfig>,
    /// HTTPS listener.
    #[serde(default)]
    pub https: Option<HttpsListenConfig>,
    /// UDP listener.
    #[serde(default)]
    pub udp: Option<UdpListenConfig>,
}

/// HTTP listener configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct HttpListenConfig {
    /// Bind socket address.
    pub bind: String,
    /// Accept path for incoming CMR HTTP upload.
    #[serde(default = "default_http_path")]
    pub path: String,
}

/// HTTPS listener configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct HttpsListenConfig {
    /// Bind socket address.
    pub bind: String,
    /// Accept path for incoming CMR HTTPS upload.
    #[serde(default = "default_http_path")]
    pub path: String,
    /// PEM certificate file.
    pub cert_path: String,
    /// PEM private-key file.
    pub key_path: String,
}

/// UDP listener configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct UdpListenConfig {
    /// Bind socket address.
    pub bind: String,
    /// Service tag from `udp://host:port/tag`.
    #[serde(default = "default_udp_service")]
    pub service: String,
}

/// Outbound compressor worker config.
#[derive(Clone, Debug, Deserialize)]
pub struct CompressorConfig {
    /// Binary path.
    #[serde(default = "default_compressor_command")]
    pub command: String,
    /// Command-line arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Max IPC frame bytes.
    #[serde(default = "default_max_frame")]
    pub max_frame_bytes: usize,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            command: default_compressor_command(),
            args: Vec::new(),
            max_frame_bytes: default_max_frame(),
        }
    }
}

/// SMTP client settings.
#[derive(Clone, Debug, Deserialize)]
pub struct SmtpConfig {
    /// SMTP relay hostname.
    pub relay: String,
    /// SMTP port.
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// Allow plaintext SMTP (no STARTTLS/TLS). Use only on trusted local networks.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Auth username.
    #[serde(default)]
    pub username: Option<String>,
    /// Environment variable for SMTP password.
    #[serde(default)]
    pub password_env: Option<String>,
    /// Envelope sender.
    pub from: String,
}

/// SSH transport settings.
#[derive(Clone, Debug, Deserialize)]
pub struct SshConfig {
    /// SSH binary path.
    #[serde(default = "default_ssh_binary")]
    pub binary: String,
    /// Default remote command (when ssh:// URL path is empty).
    #[serde(default = "default_ssh_remote_command")]
    pub default_remote_command: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            binary: default_ssh_binary(),
            default_remote_command: default_ssh_remote_command(),
        }
    }
}

/// Static key binding.
#[derive(Clone, Debug, Deserialize)]
pub struct StaticKeyConfig {
    /// Peer address.
    pub peer: String,
    /// Lower-case hex key bytes.
    pub hex_key: String,
}

/// Configuration loading errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File read error.
    #[error("failed to read config file: {0}")]
    Io(std::io::Error),
    /// TOML parse error.
    #[error("failed to parse config toml: {0}")]
    Toml(toml::de::Error),
}

fn default_http_path() -> String {
    "/".to_owned()
}

fn default_udp_service() -> String {
    "cmr".to_owned()
}

fn default_compressor_command() -> String {
    "cmr-compressor".to_owned()
}

fn default_max_frame() -> usize {
    8 * 1024 * 1024
}

fn default_smtp_port() -> u16 {
    587
}

fn default_ssh_binary() -> String {
    "ssh".to_owned()
}

fn default_ssh_remote_command() -> String {
    "cmr-peer receive-stdin".to_owned()
}

#[cfg(test)]
mod tests {
    use super::write_example_config;

    #[test]
    fn write_example_config_honors_overwrite_flag() {
        let path = std::env::temp_dir().join(format!(
            "cmr-peer-example-config-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));

        write_example_config(&path, false).expect("write initial template");
        let first = std::fs::read_to_string(&path).expect("read first");
        assert!(first.contains("local_address"));

        let err = write_example_config(&path, false).expect_err("second create should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        write_example_config(&path, true).expect("overwrite template");
        let second = std::fs::read_to_string(&path).expect("read second");
        assert_eq!(first, second);

        let _ = std::fs::remove_file(path);
    }
}
