use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use cmr_peer::config::{SmtpConfig, SshConfig};
use cmr_peer::transport::{HandshakeStore, TransportManager};
use rustls::crypto::ring;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct DockerContainerGuard {
    name: String,
}

impl Drop for DockerContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dockerized_smtp_preserves_binary_payload_bytes() {
    init_crypto_provider();
    if !docker_available() {
        if std::env::var_os("CMR_REQUIRE_DOCKER_SMTP").is_some() {
            panic!("dockerized SMTP test requires Docker but Docker is unavailable");
        }
        eprintln!("skipping dockerized SMTP test: docker not available");
        return;
    }

    let name = format!(
        "cmr-mailhog-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let _guard = start_mailhog_container(&name).expect("start mailhog");

    let smtp_port = docker_mapped_port(&name, 1025).expect("smtp port");
    let http_port = docker_mapped_port(&name, 8025).expect("http port");
    wait_for_mailhog(http_port).await;

    let transport = TransportManager::new(
        "http://sender.local/cmr".to_owned(),
        Some(SmtpConfig {
            relay: "127.0.0.1".to_owned(),
            port: smtp_port,
            allow_insecure: true,
            username: None,
            password_env: None,
            from: "sender@example.com".to_owned(),
        }),
        SshConfig::default(),
        false,
        Arc::new(HandshakeStore::default()),
    )
    .await
    .expect("transport init");

    // Includes non-UTF8 bytes to verify SMTP path does not corrupt opaque payload.
    let payload = vec![0x00, 0xFF, 0x41, 0x42, 0x43];
    transport
        .send_message("mailto:receiver@example.com", &payload)
        .await
        .expect("smtp send");

    let messages = wait_for_mailhog_message(http_port).await;
    let raw_data = messages["items"][0]["Raw"]["Data"]
        .as_str()
        .expect("raw MIME data");
    assert!(raw_data.contains("Content-Type: application/octet-stream"));
    assert!(raw_data.contains("Content-Transfer-Encoding: base64"));
    assert!(
        raw_data.contains("AP9BQkM="),
        "expected base64 payload not found in MIME data: {raw_data}"
    );
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn init_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        ring::default_provider()
            .install_default()
            .expect("install rustls crypto provider");
    });
}

fn start_mailhog_container(name: &str) -> Result<DockerContainerGuard, String> {
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-p",
            "127.0.0.1::1025",
            "-p",
            "127.0.0.1::8025",
            "mailhog/mailhog:v1.0.1",
        ])
        .output()
        .map_err(|e| format!("failed to launch mailhog container: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "mailhog startup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(DockerContainerGuard {
        name: name.to_owned(),
    })
}

fn docker_mapped_port(name: &str, container_port: u16) -> Result<u16, String> {
    let query = format!("{container_port}/tcp");
    let output = Command::new("docker")
        .args(["port", name, &query])
        .output()
        .map_err(|e| format!("failed to inspect mapped docker port: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker port lookup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(port_text) = text.trim().rsplit(':').next() else {
        return Err("docker port output malformed".to_owned());
    };
    port_text
        .parse::<u16>()
        .map_err(|e| format!("failed to parse mapped port `{port_text}`: {e}"))
}

async fn wait_for_mailhog(port: u16) {
    for _ in 0..60 {
        if fetch_mailhog_messages(port).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("mailhog HTTP API did not become ready");
}

async fn wait_for_mailhog_message(port: u16) -> serde_json::Value {
    for _ in 0..100 {
        if let Ok(messages) = fetch_mailhog_messages(port).await
            && messages["total"].as_u64().unwrap_or(0) > 0
        {
            return messages;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("mailhog did not receive an email in time");
}

async fn fetch_mailhog_messages(port: u16) -> Result<serde_json::Value, String> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("connect mailhog: {e}"))?;
    let request = b"GET /api/v2/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request)
        .await
        .map_err(|e| format!("send request: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read response: {e}"))?;
    let body = extract_http_body(&response)?;
    serde_json::from_slice(body).map_err(|e| format!("invalid mailhog JSON: {e}"))
}

fn extract_http_body(response: &[u8]) -> Result<&[u8], String> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| &response[(idx + 4)..])
        .ok_or_else(|| "malformed HTTP response".to_owned())
}
