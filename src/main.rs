// shell-warden — orchestrator engine (ADR-0008 rev; decisions live in stage tools).
// Implementation plan: agent-guardrails/docs/spec/shell-warden/HANDOFF-m0.md
//
// Step 1 (HANDOFF-m0): NDJSON wire loop — initialize + policy/check per 02-protocol.
// The check handler below is INTERIM: it answers with the fail-closed default
// verdict (ask, 06 §6.2 defaults.action) until the config loader (step 2) and the
// stage walk (step 4) replace it. It never returns allow.

mod wire;

use serde_json::Value;
use std::time::Instant;
use wire::{
    Capabilities, CheckParams, CheckResult, EngineInfo, EngineTelemetry, Handler,
    InitializeResult, PingResult, RpcError,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_MAX_FRAME_BYTES: usize = wire::DEFAULT_MAX_FRAME_BYTES;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit = match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        Some("check") => {
            eprintln!("shell-warden v{VERSION}: check mode — implementation pending (HANDOFF-m0 step 4)");
            1
        }
        Some(other) => {
            eprintln!("unknown mode: {other}; expected: serve | check");
            2
        }
    };
    std::process::exit(exit);
}

fn serve() -> i32 {
    let mut handler = InterimHandler::new();
    wire::serve(&mut handler, DEFAULT_MAX_FRAME_BYTES)
}

/// HANDOFF-m0 step 1 placeholder: answers policy/check with the fail-closed
/// aggregate default (ask). Replaced by config + walk in steps 2–4.
struct InterimHandler {
    started: Instant,
    checks_processed: u64,
    last_error_at: Option<String>,
}

impl InterimHandler {
    fn new() -> Self {
        InterimHandler { started: Instant::now(), checks_processed: 0, last_error_at: None }
    }
}

impl Handler for InterimHandler {
    fn initialize(&mut self) -> InitializeResult {
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
            // No config loader yet (HANDOFF-m0 step 2): no echo.
            config: None,
        }
    }

    fn check(&mut self, params: CheckParams) -> Result<CheckResult, RpcError> {
        self.checks_processed += 1;
        // Fail-closed interim verdict: ask, never allow (09-security I3).
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

    fn ping(&mut self) -> PingResult {
        PingResult {
            uptimeMs: self.started.elapsed().as_millis() as u64,
            checksProcessed: self.checks_processed,
            inFlight: 0, // single-threaded serve loop: never more than one
            lastErrorAt: self.last_error_at.clone(),
        }
    }

    fn notification(&mut self, method: &str, _params: Option<&Value>) {
        // 02 §2.6: cache/invalidate, session/ended, policy/observe — no derived
        // state exists yet (steps 2–4), so nothing to drop. Unknown methods are
        // tolerated per 02 §2.1.
        eprintln!("shell-warden: notification ignored (no state yet): {method}");
    }
}
