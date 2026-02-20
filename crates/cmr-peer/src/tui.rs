//! Optional terminal UI for high-level peer control.

use std::collections::VecDeque;
use std::io::{Stdout, Write};
use std::path::Path;
use std::time::Duration;

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::queue;
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

use crate::app::{AppError, PeerRuntime, run_http_self_test, start_peer};
use crate::config::{PeerConfig, write_example_config};

const LOG_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeStatus {
    Stopped,
    Running,
}

struct DashboardState {
    config_path: String,
    config: Option<PeerConfig>,
    runtime: Option<PeerRuntime>,
    status: RuntimeStatus,
    logs: VecDeque<String>,
}

impl DashboardState {
    fn new(config_path: String) -> Self {
        Self {
            config_path,
            config: None,
            runtime: None,
            status: RuntimeStatus::Stopped,
            logs: VecDeque::new(),
        }
    }

    fn push_log(&mut self, message: impl Into<String>) {
        self.logs.push_back(message.into());
        while self.logs.len() > LOG_LIMIT {
            self.logs.pop_front();
        }
    }

    fn load_config(&mut self) -> Result<(), AppError> {
        let cfg = PeerConfig::from_toml_file(&self.config_path)
            .map_err(|e| AppError::Runtime(format!("failed to load config: {e}")))?;
        self.push_log(format!(
            "loaded config for {} (security={:?})",
            cfg.local_address, cfg.security_level
        ));
        self.config = Some(cfg);
        Ok(())
    }

    fn ensure_config_loaded(&mut self) -> Result<(), AppError> {
        if self.config.is_none() {
            self.load_config()?;
        }
        Ok(())
    }

    async fn start_runtime(&mut self) -> Result<(), AppError> {
        if self.runtime.is_some() {
            self.push_log("runtime already running");
            return Ok(());
        }
        self.ensure_config_loaded()?;
        let config = self
            .config
            .clone()
            .ok_or_else(|| AppError::Runtime("config unavailable".to_owned()))?;
        let runtime = start_peer(config).await?;
        self.push_log(format!(
            "runtime started with {} listener task(s)",
            runtime.listener_count()
        ));
        self.status = RuntimeStatus::Running;
        self.runtime = Some(runtime);
        Ok(())
    }

    async fn stop_runtime(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown().await;
            self.push_log("runtime stopped");
        }
        self.status = RuntimeStatus::Stopped;
    }

    async fn run_self_test(&mut self) -> Result<(), AppError> {
        if self.runtime.is_none() {
            self.push_log("start the runtime first (press s)");
            return Ok(());
        }
        self.ensure_config_loaded()?;
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| AppError::Runtime("config unavailable".to_owned()))?;
        let report = run_http_self_test(config).await?;
        self.push_log(format!(
            "self-test OK: {} bytes -> {} (status {})",
            report.bytes_sent, report.destination, report.status
        ));
        Ok(())
    }

    fn create_config_if_missing(&mut self) -> Result<(), AppError> {
        let path = Path::new(&self.config_path);
        if path.exists() {
            self.push_log(format!("config already exists at {}", self.config_path));
            return Ok(());
        }
        write_example_config(path, false)
            .map_err(|e| AppError::Runtime(format!("failed to write config template: {e}")))?;
        self.push_log(format!("created config template at {}", self.config_path));
        Ok(())
    }

    fn overwrite_config(&mut self) -> Result<(), AppError> {
        write_example_config(&self.config_path, true)
            .map_err(|e| AppError::Runtime(format!("failed to overwrite config template: {e}")))?;
        self.push_log(format!("overwrote config template at {}", self.config_path));
        Ok(())
    }
}

/// Runs the optional terminal dashboard.
pub async fn run_tui(config_path: String) -> Result<(), AppError> {
    let mut stdout = setup_terminal()?;
    let mut state = DashboardState::new(config_path);
    state.push_log("CMR peer dashboard ready");
    state.push_log(
        "keys: s=start, x=stop, t=self-test, r=reload, c=create config, C=overwrite, q=quit",
    );

    let loop_result = tui_loop(&mut stdout, &mut state).await;
    state.stop_runtime().await;
    teardown_terminal(&mut stdout)?;
    loop_result
}

async fn tui_loop(stdout: &mut Stdout, state: &mut DashboardState) -> Result<(), AppError> {
    loop {
        render_dashboard(stdout, state)?;

        if event::poll(Duration::from_millis(120))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('s') => {
                    if let Err(err) = state.start_runtime().await {
                        state.push_log(format!("start failed: {err}"));
                    }
                }
                KeyCode::Char('x') => state.stop_runtime().await,
                KeyCode::Char('t') => {
                    if let Err(err) = state.run_self_test().await {
                        state.push_log(format!("self-test failed: {err}"));
                    }
                }
                KeyCode::Char('r') => {
                    if let Err(err) = state.load_config() {
                        state.push_log(format!("reload failed: {err}"));
                    }
                }
                KeyCode::Char('c') => {
                    if let Err(err) = state.create_config_if_missing() {
                        state.push_log(format!("create failed: {err}"));
                    }
                }
                KeyCode::Char('C') => {
                    if let Err(err) = state.overwrite_config() {
                        state.push_log(format!("overwrite failed: {err}"));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn render_dashboard(stdout: &mut Stdout, state: &DashboardState) -> Result<(), AppError> {
    queue!(stdout, MoveTo(0, 0), Clear(ClearType::All))
        .map_err(|e| AppError::Runtime(format!("terminal draw failed: {e}")))?;

    writeln!(stdout, "CMR Peer Control Console")?;
    writeln!(
        stdout,
        "status: {}",
        match state.status {
            RuntimeStatus::Running => "RUNNING",
            RuntimeStatus::Stopped => "STOPPED",
        }
    )?;
    writeln!(stdout)?;
    writeln!(stdout, "Config Path: {}", state.config_path)?;

    if let Some(cfg) = &state.config {
        writeln!(stdout, "Local: {}", cfg.local_address)?;
        writeln!(stdout, "Security: {:?}", cfg.security_level)?;
        writeln!(stdout, "HTTP listener: {}", cfg.listen.http.is_some())?;
        writeln!(stdout, "HTTPS listener: {}", cfg.listen.https.is_some())?;
        writeln!(stdout, "UDP listener: {}", cfg.listen.udp.is_some())?;
        writeln!(stdout, "Compressor: {}", cfg.compressor.command)?;
    } else {
        writeln!(stdout, "Config: not loaded")?;
    }

    writeln!(stdout)?;
    writeln!(
        stdout,
        "Actions: s=start  x=stop  t=self-test  r=reload  c=create  C=overwrite  q=quit"
    )?;
    writeln!(stdout)?;
    writeln!(stdout, "Recent Events (newest first):")?;
    for line in state.logs.iter().rev().take(30) {
        writeln!(stdout, "- {line}")?;
    }

    stdout
        .flush()
        .map_err(|e| AppError::Runtime(format!("terminal flush failed: {e}")))?;
    Ok(())
}

fn setup_terminal() -> Result<Stdout, AppError> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        Hide,
        MoveTo(0, 0),
        Clear(ClearType::All)
    )?;
    Ok(stdout)
}

fn teardown_terminal(stdout: &mut Stdout) -> Result<(), AppError> {
    disable_raw_mode()?;
    execute!(stdout, Show, LeaveAlternateScreen)?;
    Ok(())
}
