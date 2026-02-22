//! Blocking compressor worker client implementing `CompressionOracle`.

use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use cmr_core::compressor_ipc::{
    CompressorRequest, CompressorResponse, DEFAULT_MAX_FRAME_BYTES, IpcError, read_frame,
    write_frame,
};
use cmr_core::router::{CompressionError, CompressionOracle};
use thiserror::Error;

/// Compressor worker client configuration.
#[derive(Clone, Debug)]
pub struct CompressorClientConfig {
    /// Worker binary.
    pub command: String,
    /// Worker args.
    pub args: Vec<String>,
    /// Max allowed frame size.
    pub max_frame_bytes: usize,
}

impl Default for CompressorClientConfig {
    fn default() -> Self {
        Self {
            command: "cmr-compressor".to_owned(),
            args: Vec::new(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

/// Errors while creating or restarting worker process.
#[derive(Debug, Error)]
pub enum CompressorClientInitError {
    /// Spawn failure.
    #[error(
        "failed to spawn compressor worker `{command}`: {source}. ensure `cmr-compressor` is in PATH or next to `cmr-peer`"
    )]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },
    /// Worker missing stdio pipes.
    #[error("worker stdio pipe missing")]
    MissingPipe,
}

struct WorkerSession {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl WorkerSession {
    fn spawn(cfg: &CompressorClientConfig) -> Result<Self, CompressorClientInitError> {
        let mut child = spawn_worker_command(&cfg.command, &cfg.args).or_else(|err| {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(CompressorClientInitError::Spawn {
                    command: cfg.command.clone(),
                    source: err,
                });
            }
            let Some(fallback) = sibling_worker_path(&cfg.command) else {
                return Err(CompressorClientInitError::Spawn {
                    command: cfg.command.clone(),
                    source: err,
                });
            };
            spawn_worker_command_path(&fallback, &cfg.args).map_err(|source| {
                CompressorClientInitError::Spawn {
                    command: fallback.display().to_string(),
                    source,
                }
            })
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or(CompressorClientInitError::MissingPipe)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(CompressorClientInitError::MissingPipe)?;
        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    fn request(
        &mut self,
        req: &CompressorRequest,
        max_frame_bytes: usize,
    ) -> Result<CompressorResponse, IpcError> {
        write_frame(&mut self.stdin, req)?;
        read_frame(&mut self.stdout, max_frame_bytes)
    }
}

fn spawn_worker_command(command: &str, args: &[String]) -> Result<Child, std::io::Error> {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    cmd.spawn()
}

fn spawn_worker_command_path(path: &PathBuf, args: &[String]) -> Result<Child, std::io::Error> {
    let mut cmd = Command::new(path);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    cmd.spawn()
}

fn sibling_worker_path(command: &str) -> Option<PathBuf> {
    if command_has_explicit_path(command) {
        return None;
    }
    let current = std::env::current_exe().ok()?;
    let parent = current.parent()?;
    let candidate = parent.join(command);
    candidate.is_file().then_some(candidate)
}

fn command_has_explicit_path(command: &str) -> bool {
    command.contains('/') || command.contains('\\')
}

impl Drop for WorkerSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Thread-safe compressor client.
pub struct CompressorClient {
    cfg: CompressorClientConfig,
    session: Mutex<WorkerSession>,
}

impl CompressorClient {
    /// Creates client and starts worker.
    pub fn new(cfg: CompressorClientConfig) -> Result<Self, CompressorClientInitError> {
        let session = WorkerSession::spawn(&cfg)?;
        Ok(Self {
            cfg,
            session: Mutex::new(session),
        })
    }

    fn request(&self, req: CompressorRequest) -> Result<CompressorResponse, CompressionError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| CompressionError::Unavailable("compressor mutex poisoned".to_owned()))?;
        match guard.request(&req, self.cfg.max_frame_bytes) {
            Ok(resp) => Ok(resp),
            Err(first_err) => {
                *guard = WorkerSession::spawn(&self.cfg)
                    .map_err(|e| CompressionError::Unavailable(e.to_string()))?;
                guard
                    .request(&req, self.cfg.max_frame_bytes)
                    .map_err(|second_err| {
                        CompressionError::Failed(format!(
                            "worker request failed after restart: first={first_err}; second={second_err}"
                        ))
                    })
            }
        }
    }
}

impl CompressionOracle for CompressorClient {
    fn compression_distance(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError> {
        match self.request(CompressorRequest::CompressionDistance {
            left: left.to_vec(),
            right: right.to_vec(),
        })? {
            CompressorResponse::CompressionDistance { value } => Ok(value),
            CompressorResponse::Error { message } => Err(CompressionError::Failed(message)),
            other => Err(CompressionError::Failed(format!(
                "unexpected compression distance response variant: {other:?}"
            ))),
        }
    }

    fn intrinsic_dependence(&self, data: &[u8], max_order: i64) -> Result<f64, CompressionError> {
        match self.request(CompressorRequest::IntrinsicDependence {
            data: data.to_vec(),
            max_order,
        })? {
            CompressorResponse::IntrinsicDependence { value } => Ok(value),
            CompressorResponse::Error { message } => Err(CompressionError::Failed(message)),
            other => Err(CompressionError::Failed(format!(
                "unexpected intrinsic dependence response variant: {other:?}"
            ))),
        }
    }

    fn batch_compression_distance(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        match self.request(CompressorRequest::BatchCompressionDistance {
            target: target.to_vec(),
            candidates: candidates.to_vec(),
        })? {
            CompressorResponse::BatchCompressionDistance { values } => Ok(values),
            CompressorResponse::Error { message } => Err(CompressionError::Failed(message)),
            other => Err(CompressionError::Failed(format!(
                "unexpected batch compression distance response variant: {other:?}"
            ))),
        }
    }
}
