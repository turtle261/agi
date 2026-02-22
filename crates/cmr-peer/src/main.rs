//! CMR peer daemon and optional terminal dashboard.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use clap::{Parser, Subcommand};
use cmr_core::protocol::TransportKind;

use cmr_peer::app::{
    AppError, ingest_stdin_once, run_http_self_test, run_http_self_test_with_runtime,
    run_peer_with_config_path,
};
use cmr_peer::config::{
    ConfigError, HttpListenConfig, PeerConfig, UdpListenConfig, write_example_config,
};
#[cfg(feature = "tui")]
use cmr_peer::tui::run_tui;

/// CMR peer CLI.
#[derive(Debug, Parser)]
#[command(name = "cmr-peer")]
#[command(about = "Competitive Message Routing peer")]
struct Cli {
    /// Convenience override for local HTTP/HTTPS listener port and local address.
    /// Example: `cmr-peer --port 4002`.
    #[arg(long, global = true)]
    port: Option<u16>,
    /// Optional UDP listener port override. By default uses `--port + 1000` when `--port` is set.
    #[arg(long, global = true)]
    udp_port: Option<u16>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Debug, Default)]
struct RunOverrides {
    port: Option<u16>,
    udp_port: Option<u16>,
}

impl RunOverrides {
    #[must_use]
    fn from_cli(cli: &Cli) -> Self {
        Self {
            port: cli.port,
            udp_port: cli.udp_port,
        }
    }

    #[must_use]
    fn is_active(self) -> bool {
        self.port.is_some() || self.udp_port.is_some()
    }
}

/// CLI subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run daemon listeners.
    Run {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
    },
    /// Create an example config file.
    InitConfig {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Overwrite existing file.
        #[arg(long)]
        force: bool,
    },
    /// Execute an end-to-end local HTTP self-test.
    SelfTest {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Start the runtime, test it, then shut down.
        #[arg(long, default_value_t = true)]
        spawn_runtime: bool,
    },
    /// Receive one CMR message from stdin (for ssh forced-command flows).
    ReceiveStdin {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Inbound transport kind used for policy checks.
        #[arg(long, default_value = "ssh")]
        transport: String,
    },
    /// Open the high-level terminal dashboard (requires `--features tui`).
    #[cfg(feature = "tui")]
    Ui {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let run_overrides = RunOverrides::from_cli(&cli);
    let command = cli.command.unwrap_or_else(default_command);

    let result = match command {
        Command::Run { config } => match load_config(&config) {
            Ok((cfg, created_template)) => {
                let cfg = match apply_run_overrides(cfg, run_overrides) {
                    Ok(cfg) => cfg,
                    Err(err) => return print_error_and_exit(Some(err)),
                };
                print_startup_hints(&cfg, &config, created_template);
                if run_overrides.is_active() {
                    print_run_overrides(&cfg, run_overrides);
                }
                run_peer_with_config_path(cfg, Some(config)).await
            }
            Err(err) => Err(err),
        },
        Command::InitConfig { config, force } => {
            if let Err(err) = write_example_config(&config, force) {
                Err(AppError::Runtime(format!(
                    "failed to write config template: {err}"
                )))
            } else {
                println!("wrote example config to {config}");
                Ok(())
            }
        }
        Command::SelfTest {
            config,
            spawn_runtime,
        } => match load_config(&config) {
            Ok((cfg, created_template)) => {
                print_startup_hints(&cfg, &config, created_template);
                let report = if spawn_runtime {
                    run_http_self_test_with_runtime(cfg).await
                } else {
                    run_http_self_test(&cfg).await
                };
                match report {
                    Ok(report) => {
                        println!(
                            "self-test passed: {} bytes -> {} (status {})",
                            report.bytes_sent, report.destination, report.status
                        );
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        },
        Command::ReceiveStdin { config, transport } => match load_config(&config) {
            Ok((cfg, created_template)) => {
                print_startup_hints(&cfg, &config, created_template);
                ingest_stdin_once(cfg, parse_transport_kind(&transport)).await
            }
            Err(err) => Err(err),
        },
        #[cfg(feature = "tui")]
        Command::Ui { config } => run_tui(config).await,
    };

    print_error_and_exit(result.err());
}

fn default_command() -> Command {
    #[cfg(feature = "tui")]
    {
        Command::Ui {
            config: "cmr-peer.toml".to_owned(),
        }
    }

    #[cfg(not(feature = "tui"))]
    {
        Command::Run {
            config: "cmr-peer.toml".to_owned(),
        }
    }
}

fn load_config(path: &str) -> Result<(PeerConfig, bool), AppError> {
    match PeerConfig::from_toml_file(path) {
        Ok(cfg) => Ok((cfg, false)),
        Err(ConfigError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            write_example_config(path, false).map_err(|write_err| {
                AppError::Runtime(format!(
                    "config `{path}` was missing and template bootstrap failed: {write_err}"
                ))
            })?;
            let cfg = PeerConfig::from_toml_file(path)
                .map_err(|parse_err| AppError::Runtime(parse_err.to_string()))?;
            Ok((cfg, true))
        }
        Err(err) => Err(AppError::Runtime(err.to_string())),
    }
}

fn apply_run_overrides(
    mut cfg: PeerConfig,
    overrides: RunOverrides,
) -> Result<PeerConfig, AppError> {
    if let Some(port) = overrides.port {
        if let Some(http) = cfg.listen.http.as_mut() {
            http.bind = rewrite_bind_port(&http.bind, port);
        } else if let Some(https) = cfg.listen.https.as_mut() {
            https.bind = rewrite_bind_port(&https.bind, port);
        } else {
            cfg.listen.http = Some(HttpListenConfig {
                bind: format!("0.0.0.0:{port}"),
                path: "/".to_owned(),
            });
        }

        if cfg.listen.http.is_some() {
            cfg.local_address = format!("http://127.0.0.1:{port}/");
        } else {
            cfg.local_address = format!("https://127.0.0.1:{port}/");
        }
    }

    let effective_udp_port = overrides
        .udp_port
        .or_else(|| overrides.port.map(|port| port.saturating_add(1000)));
    if let Some(udp_port) = effective_udp_port {
        if let Some(udp) = cfg.listen.udp.as_mut() {
            udp.bind = rewrite_bind_port(&udp.bind, udp_port);
        } else if overrides.udp_port.is_some() || overrides.port.is_some() {
            cfg.listen.udp = Some(UdpListenConfig {
                bind: format!("0.0.0.0:{udp_port}"),
                service: "cmr".to_owned(),
            });
        }
    }

    if cfg.local_address.trim().is_empty() {
        return Err(AppError::InvalidConfig(
            "local_address cannot be empty after applying run overrides".to_owned(),
        ));
    }
    Ok(cfg)
}

fn rewrite_bind_port(bind: &str, port: u16) -> String {
    match bind.parse::<SocketAddr>() {
        Ok(sock) => match sock.ip() {
            IpAddr::V4(ip) => format!("{ip}:{port}"),
            IpAddr::V6(ip) => format!("[{ip}]:{port}"),
        },
        Err(_) => format!("0.0.0.0:{port}"),
    }
}

fn print_run_overrides(cfg: &PeerConfig, overrides: RunOverrides) {
    if let Some(port) = overrides.port {
        eprintln!("run override: port={port}");
    }
    if let Some(port) = overrides.udp_port {
        eprintln!("run override: udp_port={port}");
    } else if let Some(port) = overrides.port {
        eprintln!(
            "run override: udp_port={} (derived from --port + 1000)",
            port.saturating_add(1000)
        );
    }
    eprintln!("run override: local_address={}", cfg.local_address);
}

fn print_error_and_exit(err: Option<AppError>) {
    if let Some(err) = err {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn parse_transport_kind(input: &str) -> TransportKind {
    match input.to_ascii_lowercase().as_str() {
        "http" => TransportKind::Http,
        "https" => TransportKind::Https,
        "smtp" => TransportKind::Smtp,
        "udp" => TransportKind::Udp,
        "ssh" => TransportKind::Ssh,
        other => TransportKind::Other(other.to_owned()),
    }
}

fn print_startup_hints(cfg: &PeerConfig, config_path: &str, created_template: bool) {
    if created_template {
        eprintln!("created default config at `{config_path}`");
    }
    eprintln!("using config: `{config_path}`");
    if !cfg.dashboard.enabled {
        return;
    }

    let dashboard_path = normalize_path_prefix(&cfg.dashboard.path);
    if let Some(http) = &cfg.listen.http {
        if let Ok(bind) = http.bind.parse::<SocketAddr>() {
            let host = match bind.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip => ip,
            };
            let url = match host {
                IpAddr::V4(ip) => format!("http://{ip}:{}{}", bind.port(), dashboard_path),
                IpAddr::V6(ip) => format!("http://[{ip}]:{}{}", bind.port(), dashboard_path),
            };
            eprintln!("dashboard: {url}");
        }
    } else if let Some(https) = &cfg.listen.https
        && let Ok(bind) = https.bind.parse::<SocketAddr>()
    {
        let host = match bind.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        let url = match host {
            IpAddr::V4(ip) => format!("https://{ip}:{}{}", bind.port(), dashboard_path),
            IpAddr::V6(ip) => format!("https://[{ip}]:{}{}", bind.port(), dashboard_path),
        };
        eprintln!("dashboard: {url}");
    }
    if cfg.dashboard.auth_token.is_some() {
        eprintln!("dashboard auth enabled: use Authorization: Bearer <token>");
    }
}

fn normalize_path_prefix(path: &str) -> String {
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.trim_end_matches('/').to_owned()
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::{RunOverrides, apply_run_overrides, rewrite_bind_port};
    use cmr_peer::config::PeerConfig;

    #[test]
    fn rewrite_bind_port_preserves_ip_and_updates_port() {
        assert_eq!(rewrite_bind_port("0.0.0.0:8080", 4002), "0.0.0.0:4002");
        assert_eq!(rewrite_bind_port("[::1]:8080", 4002), "[::1]:4002");
    }

    #[test]
    fn apply_run_overrides_sets_http_local_and_udp_ports() {
        let mut cfg = PeerConfig::from_toml_str(cmr_peer::config::EXAMPLE_CONFIG_TOML)
            .expect("example config should parse");
        cfg.listen.udp.as_mut().expect("udp").bind = "0.0.0.0:9000".to_owned();
        let out = apply_run_overrides(
            cfg,
            RunOverrides {
                port: Some(4002),
                udp_port: None,
            },
        )
        .expect("overrides should apply");
        assert_eq!(out.local_address, "http://127.0.0.1:4002/");
        assert_eq!(out.listen.http.expect("http listener").bind, "0.0.0.0:4002");
        assert_eq!(out.listen.udp.expect("udp listener").bind, "0.0.0.0:5002");
    }
}
