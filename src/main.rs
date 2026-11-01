// shell-warden — orchestrator engine (ADR-0008 rev; decisions live in stage tools).
// Implementation plan: agent-guardrails/docs/spec/shell-warden/HANDOFF-m0.md
//
// Step 2 (HANDOFF-m0): config loader — strict validation (06 §6.2/§6.3), the
// -32001 fatal path for invalid configs (05 §5.3), last-good on reload.
// The check verdict is still INTERIM (fail-closed ask) until the stage walk
// lands in step 4. It never returns allow.

mod clock;
mod config;
// Wired into the handler in HANDOFF-m0 step 4 (walk); compiled now so the
// invoker is exercised by its own unit suite.
#[allow(dead_code)]
mod sha256;
#[allow(dead_code)]
mod stagetools;
mod wire;

use config::Config;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Instant;
use wire::{
    Capabilities, CheckParams, CheckResult, ConfigEcho, EngineInfo, EngineTelemetry, Handler,
    InitializeResult, PingResult, RpcError, CODE_CONFIG_INVALID,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_MAX_FRAME_BYTES: usize = wire::DEFAULT_MAX_FRAME_BYTES;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit = match args.first().map(String::as_str) {
        None | Some("serve") => serve(&config_path(&args)),
        Some("check") => {
            eprintln!("shell-warden v{VERSION}: check mode — implementation pending (HANDOFF-m0 step 4)");
            1
        }
        Some("--help") | Some("-h") | Some("help") => {
            println!("shell-warden v{VERSION} — orchestrator engine of the shell-warden permission system");
            println!();
            println!("USAGE:");
            println!("  shell-warden serve [--config FILE]   NDJSON loop on stdio (default mode)");
            println!("  shell-warden check --config FILE --file REQ.json   single-shot golden mode");
            println!();
            println!("Config: $XDG_CONFIG_HOME/shell-warden/config.jsonc (default: ~/.config/…), 06 §6.1");
            0
        }
        Some(other) => {
            eprintln!("unknown mode: {other}; expected: serve | check");
            2
        }
    };
    std::process::exit(exit);
}

/// `--config FILE` flag; default path per 06 §6.1/§6.8.
fn config_path(args: &[String]) -> PathBuf {
    match args.iter().position(|a| a == "--config") {
        Some(i) => args.get(i + 1).cloned().map(PathBuf::from).unwrap_or_else(config::default_path),
        None => config::default_path(),
    }
}

fn serve(path: &PathBuf) -> i32 {
    let mut handler = WardenHandler::new(path.clone());
    wire::serve(&mut handler, DEFAULT_MAX_FRAME_BYTES)
}

// ── Engine state ────────────────────────────────────────────────────────────────

/// Active config or the fail-closed fatal state (05 §5.3): invalid config at
/// startup ⇒ start anyway, every policy/check answered -32001 data.fatal:true.
enum ConfigState {
    Loaded(Box<Config>),
    Fatal { reason: String, at: String },
}

struct WardenHandler {
    path: PathBuf,
    watcher: config::ConfigWatcher,
    state: ConfigState,
    started: Instant,
    checks_processed: u64,
    last_error_at: Option<String>,
    reload_violations: u64,
}

impl WardenHandler {
    fn new(path: PathBuf) -> Self {
        let watcher = config::ConfigWatcher::new(&path);
        let state = match config::load(&path) {
            Ok(cfg) => {
                eprintln!("shell-warden v{VERSION}: config loaded: {} ({} stages)", cfg.source.display(), cfg.stages.len());
                ConfigState::Loaded(Box::new(cfg))
            }
            Err(reason) => {
                // Never fail open (05 §5.3): stay up, answer checks fatally.
                eprintln!("shell-warden v{VERSION}: {reason} — serving -32001 fatal until the config is fixed");
                ConfigState::Fatal { reason, at: clock::now_rfc3339() }
            }
        };
        WardenHandler {
            path,
            watcher,
            state,
            started: Instant::now(),
            checks_processed: 0,
            last_error_at: None,
            reload_violations: 0,
        }
    }
}

impl Handler for WardenHandler {
    fn initialize(&mut self) -> InitializeResult {
        let echo = match &self.state {
            ConfigState::Loaded(cfg) => ConfigEcho {
                source: cfg.source.display().to_string(),
                stages: cfg.stages.iter().map(|s| s.id.clone()).collect(),
                loadedAt: cfg.loaded_at.clone(),
            },
            ConfigState::Fatal { at, .. } => ConfigEcho {
                source: self.path.display().to_string(),
                stages: vec![],
                loadedAt: at.clone(),
            },
        };
        InitializeResult {
            protocolVersion: 1,
            engine: EngineInfo { name: "shell-warden".into(), version: VERSION.into() },
            capabilities: Some(Capabilities {
                // Wire schema maxItems for commands[]; the shim clamps lower locally.
                maxCommandsPerCheck: 128,
                cacheTtl: true,
                auditEvents: true,
                stages: true,
            }),
            config: Some(echo),
        }
    }

    fn check(&mut self, params: CheckParams) -> Result<CheckResult, RpcError> {
        self.checks_processed += 1;
        match &self.state {
            ConfigState::Fatal { reason, .. } => {
                self.last_error_at = Some(clock::now_rfc3339());
                Err(RpcError::fatal(CODE_CONFIG_INVALID, reason.clone()))
            }
            ConfigState::Loaded(_) => {
                // INTERIM (HANDOFF-m0 step 2): no stage walk yet — the aggregate
                // default is ask (06 §6.2), never allow (09-security I3).
                Ok(CheckResult {
                    invocationId: params.invocation.id,
                    verdict: wire::Verdict::Ask,
                    message: None,
                    commands: Some(
                        params
                            .commands
                            .iter()
                            .map(|c| wire::CheckCommandResult {
                                index: c.index,
                                verdict: wire::Verdict::Ask,
                                stage: None,
                                ruleId: None,
                                reason: None,
                                classification: None,
                                cacheTtlMs: None,
                            })
                            .collect(),
                    ),
                    engine: Some(EngineTelemetry { checkMs: 0 }),
                })
            }
        }
    }

    fn ping(&mut self) -> PingResult {
        PingResult {
            uptimeMs: self.started.elapsed().as_millis() as u64,
            checksProcessed: self.checks_processed,
            inFlight: 0, // single-threaded serve loop: never more than one
            lastErrorAt: self.last_error_at.clone(),
        }
    }

    fn tick(&mut self) {
        if !self.watcher.poll() {
            return;
        }
        match config::load(&self.path) {
            Ok(new) => {
                let changed = match &self.state {
                    ConfigState::Loaded(old) => old.as_ref() != &new,
                    ConfigState::Fatal { .. } => true,
                };
                if changed {
                    eprintln!(
                        "shell-warden: config reloaded: {} ({} stages)",
                        new.source.display(),
                        new.stages.len()
                    );
                    self.state = ConfigState::Loaded(Box::new(new));
                }
            }
            Err(reason) => {
                // Keep last-good, log, count a violation (05 §5.3).
                self.reload_violations += 1;
                eprintln!(
                    "shell-warden: config reload rejected (violation {}): {reason}",
                    self.reload_violations
                );
            }
        }
    }

    fn notification(&mut self, method: &str, _params: Option<&Value>) {
        match method {
            // 02 §2.6; derived state (budgets) arrives with the step-4 walk.
            "cache/invalidate" => eprintln!("shell-warden: cache/invalidate (no derived caches yet)"),
            "session/ended" => eprintln!("shell-warden: session/ended (no per-session state yet)"),
            "policy/observe" => {} // audit-only, never affects decisions
            other => eprintln!("shell-warden: unknown notification tolerated: {other}"),
        }
    }
}
