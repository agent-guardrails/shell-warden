// Stage-tool invoker tests. Process-level scenarios drive `warden-test-tool`
// (a real compiled binary — see src/bin/warden-test-tool.rs and Cargo.toml)
// instead of freshly-written shell scripts: macOS serializes scans of new
// executables, so parallel tests spawning fresh shebang files stall in dyld
// (observed 2026-11-01). Spawn tests share a mutex to keep the model close to
// the engine's serial loop anyway.

use super::*;
use crate::config::{Lifecycle, OnError, Stage, ToolSpec};
use crate::wire::{CheckCommand, Invocation};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

fn test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(PoisonError::into_inner)
}

/// Cargo puts package bins together in target/debug/; unit tests see no
/// CARGO_BIN_EXE, so the helper is derived from our own exe location.
fn tool_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().and_then(|p| p.parent()).expect("target dir");
    let helper = dir.join("warden-test-tool");
    assert!(helper.is_file(), "warden-test-tool not built at {}", helper.display());
    helper
}

fn spec(lifecycle: Lifecycle, argv: Vec<String>) -> ToolSpec {
    ToolSpec {
        argv,
        cwd: None,
        env_set: vec![],
        env_unset: vec![],
        lifecycle,
        idle_timeout_ms: None,
        timeout_ms: 2_000,
        kill_grace_ms: 50,
        max_output_bytes: 65_536,
        on_error: OnError::Ask,
        sha256: None,
        input_session_id: false,
        input_session_agent: false,
        input_mcp: false,
    }
}

fn test_tool(mode: &str, arg: Option<u64>) -> ToolSpec {
    let mut argv = vec![tool_binary().display().to_string(), mode.to_string()];
    if let Some(a) = arg {
        argv.push(a.to_string());
    }
    spec(Lifecycle::Persistent, argv)
}

fn invocation() -> Invocation {
    Invocation {
        id: "m:c".into(),
        session_id: "ses_1".into(),
        agent: Some("build".into()),
        hook: crate::wire::HookKind::PermissionEvaluate,
        project_dir: None,
        started_at: None,
    }
}

fn cmd() -> CheckCommand {
    CheckCommand { index: 0, raw: "ls -la".into(), argv: None, cwd: "/work/repo".into() }
}

fn runner(spec: ToolSpec) -> (MutexGuard<'static, ()>, StageRunner) {
    (test_lock(), StageRunner::new("t".into(), spec))
}

fn decided(out: StageOutcome) -> ToolVerdict {
    match out {
        StageOutcome::Decided(v) => v,
        StageOutcome::OnError { reason, .. } => panic!("expected Decided, got OnError: {reason}"),
    }
}

fn on_error(out: StageOutcome) -> (String, bool) {
    match out {
        StageOutcome::OnError { reason, violation } => (reason, violation),
        StageOutcome::Decided(v) => panic!("expected OnError, got Decided: {v:?}"),
    }
}

fn pid_reason(v: &ToolVerdict) -> Option<String> {
    v.reason.clone()
}

// ── Letter composition (06 §6.4.2) ──

#[test]
fn letter_has_command_and_cwd_always_and_optins_gated() {
    let tool = spec(Lifecycle::Spawn, vec!["/bin/x".into()]);
    let letter = build_letter(&tool, &cmd(), &invocation());
    assert_eq!(letter["protocolVersion"], 1);
    assert_eq!(letter["command"]["raw"], "ls -la");
    assert_eq!(letter["command"]["cwd"], "/work/repo");
    assert!(letter.get("session").is_none(), "opt-in flags off by default");
    assert!(letter.get("mcp").is_none());
}

#[test]
fn letter_includes_requested_session_and_mcp() {
    let mut tool = spec(Lifecycle::Spawn, vec!["/bin/x".into()]);
    tool.input_session_id = true;
    tool.input_session_agent = true;
    tool.input_mcp = true;
    let letter = build_letter(&tool, &cmd(), &invocation());
    assert_eq!(letter["session"]["id"], "ses_1");
    assert_eq!(letter["session"]["agent"], "build");
    assert_eq!(letter["mcp"], serde_json::json!([]));
}

#[test]
fn letter_omits_absent_agent() {
    let mut tool = spec(Lifecycle::Spawn, vec!["/bin/x".into()]);
    tool.input_session_agent = true;
    let mut inv = invocation();
    inv.agent = None;
    let letter = build_letter(&tool, &cmd(), &inv);
    assert_eq!(letter["session"], serde_json::json!({}));
}

// ── Response classification (06 §6.4.3) ──

#[test]
fn classify_accepts_the_canonical_shapes() {
    let out = classify_response(r#"{"verdict":"deny","message":"no","ruleId":"t/r","reason":"why","classification":"static","cacheTtlMs":0}"#);
    let v = decided(out);
    assert_eq!(v.verdict, Verdict::Deny);
    assert_eq!(v.message.as_deref(), Some("no"));
    assert_eq!(v.rule_id.as_deref(), Some("t/r"));
    assert_eq!(v.classification, Some(Classification::Static));
    assert_eq!(v.cache_ttl_ms, Some(0));

    // Empty strings mean "no value" (06 §6.4.3) and are normalized to None.
    let out = classify_response(r#"{"verdict":"ask","message":""}"#);
    assert!(decided(out).message.is_none());
}

#[test]
fn classify_rejects_garbage_with_violation() {
    for line in [
        "not json",
        "[1,2]",
        r#"{"message":"no verdict"}"#,
        r#"{"verdict":"permit"}"#,
        r#"{"verdict":"allow","message":1}"#,
        r#"{"verdict":"allow","classification":"vibes"}"#,
        r#"{"verdict":"allow","cacheTtlMs":-5}"#,
    ] {
        let (reason, violation) = on_error(classify_response(line));
        assert!(violation, "garbage must flag a violation: {line} ({reason})");
    }
}

#[test]
fn read_bounded_line_enforces_the_cap() {
    // Over the cap → error even without a newline.
    let mut input: &[u8] = &[b'x'; 100];
    let mut line = Vec::new();
    assert!(read_bounded_line(&mut input, 16, &mut line).is_err());
    // Line with a newline → Ok(true).
    let mut input: &[u8] = b"ok\nrest";
    let mut line = Vec::new();
    assert!(read_bounded_line(&mut input, 16, &mut line).unwrap());
    assert_eq!(line, b"ok");
    // Partial data at EOF (no newline) → Ok(false) with the partial content.
    line.clear();
    assert!(!read_bounded_line(&mut input, 16, &mut line).unwrap());
    assert_eq!(line, b"rest");
    // EOF with nothing read → Ok(false), empty.
    line.clear();
    assert!(!read_bounded_line(&mut input, 16, &mut line).unwrap());
    assert!(line.is_empty());
}

// ── Lifecycles (process-level; serialized via test_lock) ──

#[test]
fn persistent_tool_is_reused_across_calls() {
    let (_g, mut r) = runner(test_tool("loop", None));
    let now = Instant::now();
    let first = decided(r.invoke(&cmd(), &invocation(), now).unwrap());
    assert!(r.is_active(), "persistent child stays Ready between calls");
    std::thread::sleep(Duration::from_millis(30));
    let second = decided(r.invoke(&cmd(), &invocation(), now).unwrap());
    assert_eq!(pid_reason(&first), pid_reason(&second), "same child process answers both calls");
}

#[test]
fn spawn_lifecycle_runs_a_fresh_child_per_call() {
    let (_g, mut r) = runner({
        let mut s = test_tool("answer", None);
        s.lifecycle = Lifecycle::Spawn;
        s
    });
    let now = Instant::now();
    let first = decided(r.invoke(&cmd(), &invocation(), now).unwrap());
    assert!(!r.is_active(), "one-shot children do not persist");
    let second = decided(r.invoke(&cmd(), &invocation(), now).unwrap());
    assert_ne!(pid_reason(&first), pid_reason(&second), "each call spawns a new process");
}

// ── Runtime outcome classification (06 §6.4.4) ──
// Two-runner tests scope each guard: runner() takes the shared lock, so the
// first `_g` must be dropped before the second lock (self-deadlock otherwise).

#[test]
fn timeout_is_onerror_with_violation_and_the_child_dies() {
    {
        let (_g, mut r) = runner({
            let mut s = test_tool("sleep-answer", Some(5_000));
            s.timeout_ms = 300;
            s
        });
        let started = Instant::now();
        let (reason, violation) = on_error(r.invoke(&cmd(), &invocation(), started).unwrap());
        assert!(violation, "timeout counts a violation");
        assert!(reason.contains("deadline"), "{reason}");
        assert!(started.elapsed() < Duration::from_secs(3), "grace-kill must not wait out the sleep");
        assert!(!r.is_active());
    }
}

#[test]
fn exit_nonzero_is_onerror_without_violation() {
    // Spawn lifecycle: the fresh child is waited on after its answer, so the
    // exit status is observed deterministically.
    {
        let (_g, mut r) = runner({
            let mut s = test_tool("exit-code", Some(3));
            s.lifecycle = Lifecycle::Spawn;
            s
        });
        let (reason, violation) = on_error(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
        assert!(!violation, "exit != 0 is the tool's own failure, not a violation");
        assert!(reason.contains("exited"), "{reason}");
    }
}

#[test]
fn garbage_and_oversize_output_violate() {
    {
        let (_g, mut r) = runner(test_tool("garbage", None));
        let (_, violation) = on_error(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
        assert!(violation);
    }
    {
        let (_g, mut r) = runner(test_tool("oversize", Some(200_000)));
        let (_, violation) = on_error(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
        assert!(violation, "output above maxOutputBytes is a protocol violation");
    }
}

#[test]
fn foreign_pv_and_overlong_message_violate() {
    {
        let (_g, mut r) = runner(test_tool("foreign-pv", None));
        let (reason, violation) = on_error(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
        assert!(violation);
        assert!(reason.contains("protocolVersion"));
    }
    {
        let (_g, mut r) = runner(test_tool("long-message", None));
        let (_, violation) = on_error(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
        assert!(violation, "message above 512 chars is garbage (I6)");
    }
}

#[test]
fn missing_binary_is_onerror_with_violation() {
    {
        let (_g, mut r) = runner(ToolSpec {
            argv: vec!["/nonexistent/warden-tool".into()],
            ..test_tool("answer", None)
        });
        let (reason, violation) = on_error(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
        assert!(violation, "spawn failure (ENOENT) counts a violation (06 §6.4.4)");
        assert!(reason.contains("spawn"), "{reason}");
    }
}

#[test]
fn ladder_restarts_then_marks_unhealthy() {
    // Every call fails to spawn → violations at a steady cadence. Time is
    // advanced just past each expected backoff delay (250ms × 2ⁿ) so gates
    // are observed but windows (60s violations / 300s restarts) stay hot.
    let (_g, mut r) = runner(spec(Lifecycle::Spawn, vec!["/nonexistent/warden-tool".into()]));
    let mut now = Instant::now();
    let mut saw_restart_state = false;
    let mut saw_unhealthy = false;
    let mut backoff_level = 0u32;
    for _ in 0..64 {
        let (_reason, violation) = on_error(r.invoke(&cmd(), &invocation(), now).unwrap());
        match r.state_name() {
            "backoff" => {
                saw_restart_state = true;
                let delay = (250u64.saturating_mul(1 << backoff_level.min(16))).min(30_000);
                backoff_level += 1;
                now += Duration::from_millis(delay + 10);
            }
            "unhealthy" => {
                saw_unhealthy = true;
                break; // the marking call itself still carried a violation
            }
            _ => {
                assert!(violation, "each spawn failure is a violation");
                now += Duration::from_millis(10); // stay well inside the violation window
            }
        }
    }
    assert!(saw_restart_state, "3 violations ⇒ restart with backoff");
    assert!(saw_unhealthy, "restarts exceeding the window ⇒ unhealthy");
    assert_eq!(backoff_level, 3, "three backoff gates precede the unhealthy verdict");
}

#[test]
fn persistent_tool_quitting_after_answers_hits_the_ladder() {
    // "answer-linger" answers, stays alive briefly, then exits — the breach is
    // observed deterministically between calls (drain/EOF + dead child).
    let (_g, mut r) = runner(test_tool("answer-linger", Some(400)));
    assert_eq!(
        decided(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap()).verdict,
        Verdict::Allow,
        "the answer is valid; the child lingers past the liveness check"
    );
    // Violations accumulate per death: 3 ⇒ restart gate, then recovery.
    let mut saw_restart = false;
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(600)); // linger (400ms) elapses
        let outcome = r.invoke(&cmd(), &invocation(), Instant::now()).unwrap();
        match &outcome {
            StageOutcome::OnError { reason, .. } if reason.contains("restarting") => {
                assert_eq!(r.state_name(), "backoff");
                saw_restart = true;
                break;
            }
            StageOutcome::Decided(_) => {} // respawn served this call
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert!(saw_restart, "repeated persistent exits must hit the restart ladder");
    // Past the backoff the pool spawns fresh and serves again.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(decided(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap()).verdict, Verdict::Allow);
}

// ── sha256 pin (I8) ──

#[test]
fn sha256_pin_mismatch_is_fatal_and_match_passes() {
    let bytes = std::fs::read(tool_binary()).unwrap();
    let good = crate::sha256::hex_digest(&bytes);

    {
        let (_g, mut r) = runner(ToolSpec { sha256: Some("0".repeat(64)), ..test_tool("loop", None) });
        let pin = r.invoke(&cmd(), &invocation(), Instant::now()).unwrap_err();
        assert!(pin.reason.contains("sha256 mismatch"), "{}", pin.reason);
    }
    {
        let (_g, mut r) = runner(ToolSpec { sha256: Some(good), ..test_tool("loop", None) });
        assert_eq!(decided(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap()).verdict, Verdict::Allow);
    }
}

// ── Idle kill (06 §6.4.1) ──

#[test]
fn idle_persistent_child_is_killed_by_tick_and_respawns() {
    let (_g, mut r) = runner({
        let mut s = test_tool("loop", None);
        s.idle_timeout_ms = Some(100);
        s
    });
    let now = Instant::now();
    decided(r.invoke(&cmd(), &invocation(), now).unwrap());
    assert!(r.is_active());

    r.tick(now + Duration::from_millis(50));
    assert!(r.is_active(), "inside the idle window");

    r.tick(now + Duration::from_millis(150));
    assert!(!r.is_active(), "idle kill after idleTimeoutMs");

    // Next call lazily respawns.
    let v = decided(r.invoke(&cmd(), &invocation(), Instant::now()).unwrap());
    assert_eq!(v.verdict, Verdict::Allow);
    assert!(r.is_active());
}

// ── StagePools ──

fn stage(id: &str, tool: ToolSpec) -> Stage {
    Stage {
        id: id.into(),
        tool,
        message_mode: crate::config::MessageMode::Append,
        exclusive: false,
        budget: None,
        enabled: true,
    }
}

#[test]
fn pools_tick_all_runners_and_fail_independently() {
    let good = {
        let mut s = test_tool("loop", None);
        s.idle_timeout_ms = Some(100); // so tick() can idle it out
        s
    };
    let stages = vec![
        stage("s1", good.clone()),
        stage("s2", ToolSpec { argv: vec!["/nonexistent/x".into()], ..good.clone() }),
    ];
    let mut pools = StagePools::build(&stages, 16);
    let now = Instant::now();
    { let _g = test_lock();

        let out1 = pools.invoke(&stages[0], &cmd(), &invocation(), now).unwrap();
        assert!(matches!(out1, StageOutcome::Decided(_)), "healthy stage works");

        let out2 = pools.invoke(&stages[1], &cmd(), &invocation(), now).unwrap();
        assert!(matches!(out2, StageOutcome::OnError { .. }), "broken stage fails");

        // One broken tool must not disable the other (08 §8.2).
        let out1 = pools.invoke(&stages[0], &cmd(), &invocation(), now).unwrap();
        assert!(matches!(out1, StageOutcome::Decided(_)));
    }
    pools.tick(now + Duration::from_secs(3600));
    assert!(!pools.runners.values().any(|r| r.is_active()), "tick idles out children");
}

#[test]
fn max_concurrent_tools_gate_is_enforced() {
    let good = test_tool("loop", None);
    let stages: Vec<Stage> = (0..2).map(|i| stage(&format!("s{i}"), good.clone())).collect();
    let mut pools = StagePools::build(&stages, 1);
    let now = Instant::now();
    {
        let _g = test_lock();
        assert!(matches!(pools.invoke(&stages[0], &cmd(), &invocation(), now).unwrap(), StageOutcome::Decided(_)));
        let (reason, violation) = on_error(pools.invoke(&stages[1], &cmd(), &invocation(), now).unwrap());
        assert!(reason.contains("maxConcurrentTools"));
        assert!(!violation, "cap enforcement is not a tool fault");
    }
}
