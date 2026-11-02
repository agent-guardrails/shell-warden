#![allow(clippy::all, unused)] // retired M0 reference implementation — lint debt accepted by ADR-0016
                               // shell-warden — orchestrator engine (ADR-0008 rev; decisions live in stage tools).
                               // Implementation plan: agent-guardrails/docs/spec/shell-warden/HANDOFF-m0.md
                               //
                               // HANDOFF-m0 steps 1–4 complete: NDJSON wire loop (02-protocol), strict config
                               // loader with the -32001 fatal path (05 §5.3), stage invoker with deadlines
                               // and ladders (06 §6.4), and the stage walk (08-request-processing). The core
                               // holds zero decision logic: it walks stages, invokes their tools and
                               // aggregates verdicts — most-restrictive-wins, the first deny stops the walk.

mod clock;
mod config;
mod sha256;
mod stagetools;
mod walk;
mod wire;

use config::Config;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Instant;
use wire::{
    AuditEvent, Capabilities, CheckParams, CheckResult, ConfigEcho, EngineInfo, EngineTelemetry,
    Handler, InitializeResult, PingResult, RpcError, CODE_CONFIG_INVALID,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_MAX_FRAME_BYTES: usize = wire::DEFAULT_MAX_FRAME_BYTES;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit = match args.first().map(String::as_str) {
        None | Some("serve") => serve(&config_path(&args)),
        Some("check") => check_mode(&args),
        Some("--help") | Some("-h") | Some("help") => {
            print_usage();
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
    str_flag(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(config::default_path)
}

fn str_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn print_usage() {
    println!("shell-warden v{VERSION} — orchestrator engine of the shell-warden permission system");
    println!();
    println!("USAGE:");
    println!("  shell-warden serve [--config FILE]                      NDJSON loop on stdio (default mode)");
    println!("  shell-warden check --config FILE --file REQ.json        single-shot golden mode (10 §10.2)");
    println!();
    println!("Config: $XDG_CONFIG_HOME/shell-warden/config.jsonc (default: ~/.config/…), 06 §6.1");
}

fn serve(path: &PathBuf) -> i32 {
    let mut handler = WardenHandler::new(path.clone());
    wire::serve(&mut handler, DEFAULT_MAX_FRAME_BYTES)
}

/// Single-shot golden mode (06 §6.8): request JSON in → result JSON out.
/// Pools are fresh; budgets start empty. Exit codes (05 §5.1): 0 answered,
/// 1 bad request, 2 config fatal.
fn check_mode(args: &[String]) -> i32 {
    let Some(config) = str_flag(args, "--config") else {
        eprintln!("check mode requires --config FILE");
        return 2;
    };
    let Some(request) = str_flag(args, "--file") else {
        eprintln!("check mode requires --file REQ.json");
        return 2;
    };
    let cfg = match config::load(Path::new(&config)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let raw = match std::fs::read_to_string(&request) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read request file: {e}");
            return 1;
        }
    };
    let params: CheckParams = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invalid request: {e}");
            return 1;
        }
    };
    if let Err(e) = wire::validate_check(&params) {
        eprintln!("invalid params: {e}");
        return 1;
    }
    let started = Instant::now();
    let mut pools = stagetools::StagePools::build(&cfg.stages, cfg.limits.max_concurrent_tools);
    let mut budgets = walk::BudgetTable::default();
    match walk::walk(
        &cfg.stages,
        &params,
        &mut pools,
        &mut budgets,
        Instant::now(),
    ) {
        Ok(outcome) => {
            let result = CheckResult {
                invocationId: params.invocation.id,
                verdict: outcome.verdict,
                message: outcome.message,
                commands: Some(outcome.commands),
                engine: Some(EngineTelemetry {
                    checkMs: started.elapsed().as_millis() as u64,
                }),
            };
            println!(
                "{}",
                serde_json::to_string(&result).expect("serialize result")
            );
            0
        }
        Err(pin) => {
            eprintln!("config invalid: {}", pin.reason);
            2
        }
    }
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
    pools: Option<stagetools::StagePools>,
    budgets: walk::BudgetTable,
    pending_audit: Option<AuditEvent>,
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
                eprintln!(
                    "shell-warden v{VERSION}: config loaded: {} ({} stages)",
                    cfg.source.display(),
                    cfg.stages.len()
                );
                ConfigState::Loaded(Box::new(cfg))
            }
            Err(reason) => {
                // Never fail open (05 §5.3): stay up, answer checks fatally.
                eprintln!("shell-warden v{VERSION}: {reason} — serving -32001 fatal until the config is fixed");
                ConfigState::Fatal {
                    reason,
                    at: clock::now_rfc3339(),
                }
            }
        };
        WardenHandler {
            path,
            watcher,
            state,
            pools: None,
            budgets: walk::BudgetTable::default(),
            pending_audit: None,
            started: Instant::now(),
            checks_processed: 0,
            last_error_at: None,
            reload_violations: 0,
        }
    }

    /// Run the stage walk for one check. The I8 pin FatalPin moves the engine
    /// to the fatal state (-32001 fatal until the config is fixed).
    fn run_walk(&mut self, params: CheckParams) -> Result<CheckResult, RpcError> {
        let started = Instant::now();
        let outcome = {
            // Disjoint field borrows: state (shared), pools (mut), budgets (mut).
            let WardenHandler {
                state,
                pools,
                budgets,
                ..
            } = self;
            let ConfigState::Loaded(cfg) = state else {
                unreachable!("the fatal branch is handled below")
            };
            if pools.is_none() {
                *pools = Some(stagetools::StagePools::build(
                    &cfg.stages,
                    cfg.limits.max_concurrent_tools,
                ));
            }
            walk::walk(
                &cfg.stages,
                &params,
                pools.as_mut().expect("built above"),
                budgets,
                Instant::now(),
            )
        };
        match outcome {
            Ok(mut o) => {
                // Defensive (I3): the lookahead branch of an empty walk is
                // always fail-closed ask — never allow from nothing.
                if !o.contributed && o.verdict == wire::Verdict::Allow {
                    o.verdict = wire::Verdict::Ask;
                }
                self.pending_audit = Some(walk::audit_decision(&params, &o, clock::now_rfc3339()));
                Ok(CheckResult {
                    invocationId: params.invocation.id,
                    verdict: o.verdict,
                    message: o.message,
                    commands: Some(o.commands),
                    engine: Some(EngineTelemetry {
                        checkMs: started.elapsed().as_millis() as u64,
                    }),
                })
            }
            Err(pin) => {
                self.last_error_at = Some(clock::now_rfc3339());
                eprintln!("shell-warden: fatal: {}", pin.reason);
                self.state = ConfigState::Fatal {
                    reason: pin.reason.clone(),
                    at: clock::now_rfc3339(),
                };
                self.pools = None; // Drop kills the spawned tools now
                Err(RpcError::fatal(CODE_CONFIG_INVALID, pin.reason))
            }
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
            engine: EngineInfo {
                name: "shell-warden".into(),
                version: VERSION.into(),
            },
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
        self.pending_audit = None; // audit rides with the next decision only
        match &self.state {
            ConfigState::Fatal { reason, .. } => {
                self.last_error_at = Some(clock::now_rfc3339());
                Err(RpcError::fatal(CODE_CONFIG_INVALID, reason.clone()))
            }
            ConfigState::Loaded(_) => self.run_walk(params),
        }
    }

    fn take_audit(&mut self) -> Option<AuditEvent> {
        self.pending_audit.take()
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
        // Config reload (05 §5.3): valid ⇒ atomic swap, invalid ⇒ last-good.
        if self.watcher.poll() {
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
                        // Stage pools restart as needed (§5.3); derived per-session
                        // state goes with them.
                        self.pools = None;
                        self.budgets.clear();
                    }
                }
                Err(reason) => {
                    self.reload_violations += 1;
                    eprintln!(
                        "shell-warden: config reload rejected (violation {}): {reason}",
                        self.reload_violations
                    );
                }
            }
        }
        // Idle maintenance of persistent tools (06 §6.4.1).
        if let Some(pools) = &mut self.pools {
            pools.tick(Instant::now());
        }
    }

    fn notification(&mut self, method: &str, params: Option<&Value>) {
        match method {
            // 02 §2.6: cache/invalidate drops derived caches; session/ended
            // drops that session's per-session budget state.
            "cache/invalidate" => {
                self.budgets.clear();
                eprintln!("shell-warden: cache/invalidate: derived state dropped");
            }
            "session/ended" => {
                let session = params
                    .and_then(|p| p.get("sessionID"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                self.budgets.drop_session(session);
                eprintln!("shell-warden: session/ended: {session}");
            }
            "policy/observe" => {} // audit-only, never affects decisions
            other => eprintln!("shell-warden: unknown notification tolerated: {other}"),
        }
    }
}
