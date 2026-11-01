// Stage-tool invoker — 06 §6.4, 08 §8.2.
//
// One `StageRunner` per stage; the serve loop is single-threaded, so each
// runner has exclusive access (no locks). Lifecycle per config: `persistent`
// (a long-lived child answering exactly one line per request) or `spawn` (a
// fresh child per call; stdin closed after the letter). Every invocation has
// a deadline (tool.timeoutMs); a missed deadline grace-kills the child and
// resolves to the stage's onError policy — never allow (I3), never a silent
// skip. Violations feed the restart ladder (06 §6.4.4, 02 §2.7); stages fail
// independently (08 §8.2). The optional sha256 pin is verified once before
// the first spawn; mismatch is engine-wide fatal (I8).

use crate::config::{Lifecycle, ToolSpec};
use crate::wire::{CheckCommand, Classification, Invocation, Verdict};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

// ── Outcomes ────────────────────────────────────────────────────────────────────

/// What one stage invocation contributed (08 §8.2: valid verdict or onError).
#[derive(Debug, Clone)]
pub enum StageOutcome {
    Decided(ToolVerdict),
    OnError { reason: String, violation: bool },
}

/// Verified tool response (06 §6.4.3 shape), caps enforced — over-cap or
/// ill-typed members are garbage → OnError + violation.
#[derive(Debug, Clone)]
pub struct ToolVerdict {
    pub verdict: Verdict,
    pub message: Option<String>,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub classification: Option<Classification>,
    pub cache_ttl_ms: Option<u64>,
}

/// Engine-wide fatal (I8: sha256 pin mismatch). The engine answers all checks
/// -32001 fatal until the config is fixed.
#[derive(Debug, Clone)]
pub struct FatalPin {
    pub reason: String,
}

pub type InvokeResult = Result<StageOutcome, FatalPin>;

const MESSAGE_MAX: usize = 512; // 06 §6.4.3
const DIAG_MAX: usize = 256; // 02 §2.4 audit strings
const BACKOFF_BASE_MS: u64 = 250; // 02 §2.7
const BACKOFF_MAX_MS: u64 = 30_000;
const VIOLATION_WINDOW: Duration = Duration::from_secs(60);
const RESTART_WINDOW: Duration = Duration::from_secs(300);
const MAX_VIOLATIONS: u32 = 3; // 02 §2.7 default

// ── Stdin letter (06 §6.4.2 — composition fixed by the protocol) ────────────────

pub fn build_letter(tool: &ToolSpec, cmd: &CheckCommand, invocation: &Invocation) -> serde_json::Value {
    let mut letter = serde_json::json!({
        "protocolVersion": 1,
        "command": { "raw": cmd.raw, "cwd": cmd.cwd },
    });
    if tool.input_session_id || tool.input_session_agent {
        let mut session = serde_json::Map::new();
        if tool.input_session_id {
            session.insert("id".into(), serde_json::Value::String(invocation.session_id.clone()));
        }
        if tool.input_session_agent {
            if let Some(agent) = &invocation.agent {
                session.insert("agent".into(), serde_json::Value::String(agent.clone()));
            }
        }
        letter["session"] = serde_json::Value::Object(session);
    }
    // The engine has no MCP awareness in v1; a routing tool receives an empty list.
    if tool.input_mcp {
        letter["mcp"] = serde_json::json!([]);
    }
    letter
}

// ── Response classification (06 §6.4.3/§6.4.4) ──────────────────────────────────

fn classify_response(line: &str) -> StageOutcome {
    let parsed: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return StageOutcome::OnError { reason: "unreadable output: not JSON".into(), violation: true },
    };
    let Some(obj) = parsed.as_object() else {
        return StageOutcome::OnError { reason: "unreadable output: not a JSON object".into(), violation: true };
    };
    // A foreign protocolVersion in a response is a contract breach (06 §6.4.4).
    if let Some(pv) = obj.get("protocolVersion") {
        if pv.as_u64() != Some(1) {
            return StageOutcome::OnError { reason: "foreign protocolVersion in tool response".into(), violation: true };
        }
    }
    let Some(verdict) = obj.get("verdict").and_then(|v| v.as_str()) else {
        return StageOutcome::OnError { reason: "unreadable output: missing verdict".into(), violation: true };
    };
    let verdict = match verdict {
        "allow" => Verdict::Allow,
        "ask" => Verdict::Ask,
        "deny" => Verdict::Deny,
        other => {
            return StageOutcome::OnError { reason: format!("unreadable output: unknown verdict `{other}`"), violation: true }
        }
    };
    // Caps and types (I6): over-long or wrong-typed members are garbage, not
    // truncated/coerced data.
    let bad_string = |v: &serde_json::Value, max: usize| match v {
        serde_json::Value::String(s) => s.chars().count() > max,
        serde_json::Value::Null => false,
        _ => true,
    };
    if obj.get("message").map(|m| bad_string(m, MESSAGE_MAX)).unwrap_or(false) {
        return StageOutcome::OnError { reason: format!("tool message must be a string ≤ {MESSAGE_MAX} chars"), violation: true };
    }
    for key in ["ruleId", "reason"] {
        if obj.get(key).map(|m| bad_string(m, DIAG_MAX)).unwrap_or(false) {
            return StageOutcome::OnError { reason: format!("tool {key} must be a string ≤ {DIAG_MAX} chars"), violation: true };
        }
    }
    if let Some(ttl) = obj.get("cacheTtlMs") {
        if ttl.as_u64().is_none() {
            return StageOutcome::OnError { reason: "unreadable output: cacheTtlMs must be a non-negative integer".into(), violation: true };
        }
    }
    let classification = match obj.get("classification") {
        None | Some(serde_json::Value::Null) => None,
        Some(c) => match c.as_str() {
            Some("static") => Some(Classification::Static),
            Some("opaque") => Some(Classification::Opaque),
            _ => return StageOutcome::OnError { reason: "unreadable output: classification must be static|opaque".into(), violation: true },
        },
    };
    let opt_str = |key: &str| obj.get(key).and_then(|v| v.as_str()).map(|s| s.to_string()).filter(|s| !s.is_empty());
    StageOutcome::Decided(ToolVerdict {
        verdict,
        message: opt_str("message"),
        rule_id: opt_str("ruleId"),
        reason: opt_str("reason"),
        classification,
        cache_ttl_ms: obj.get("cacheTtlMs").and_then(|v| v.as_u64()),
    })
}

// ── Violation ladder (02 §2.7 adapted to a stage pool) ──────────────────────────

#[derive(Default)]
struct Ladder {
    violations: u32,
    violations_window_start: Option<Instant>,
    restarts: Vec<Instant>,
    backoff_level: u32,
    last_ready_at: Option<Instant>,
}

enum LadderVerdict {
    Tolerated,
    Restart { delay: Duration },
    Unhealthy { until: Instant },
}

impl Ladder {
    fn violation(&mut self, now: Instant) -> LadderVerdict {
        match self.violations_window_start {
            Some(start) if now.duration_since(start) > VIOLATION_WINDOW => {
                self.violations = 1;
                self.violations_window_start = Some(now);
            }
            Some(_) => self.violations += 1,
            None => {
                self.violations = 1;
                self.violations_window_start = Some(now);
            }
        }
        if self.violations < MAX_VIOLATIONS {
            return LadderVerdict::Tolerated;
        }
        self.violations = 0;
        self.violations_window_start = None;
        self.restarts.push(now);
        self.restarts.retain(|t| now.duration_since(*t) <= RESTART_WINDOW);
        if self.restarts.len() > MAX_VIOLATIONS as usize {
            return LadderVerdict::Unhealthy { until: now + RESTART_WINDOW };
        }
        // Backoff resets after a stable period (restart.resetAfterMs).
        if let Some(ready) = self.last_ready_at {
            if now.duration_since(ready) >= RESTART_WINDOW {
                self.backoff_level = 0;
            }
        }
        let shift = self.backoff_level.min(16);
        let delay = Duration::from_millis(BACKOFF_BASE_MS.saturating_mul(1 << shift).min(BACKOFF_MAX_MS));
        self.backoff_level += 1;
        LadderVerdict::Restart { delay }
    }
}

// ── Child plumbing ──────────────────────────────────────────────────────────────

enum LineOrEof {
    Line(Vec<u8>),
    Eof,
}

/// Reader thread: owns the child's stdout, pushes bounded lines until EOF.
fn spawn_reader(stdout: std::process::ChildStdout, max_output_bytes: usize) -> Receiver<LineOrEof> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            match read_bounded_line(&mut reader, max_output_bytes, &mut line) {
                Ok(true) => {
                    if tx.send(LineOrEof::Line(line)).is_err() {
                        return; // pool moved on
                    }
                }
                _ => {
                    let _ = tx.send(LineOrEof::Eof);
                    return;
                }
            }
        }
    });
    rx
}

/// Read one `\n`-terminated line, never buffering more than `max` bytes.
/// `Ok(false)` = EOF.
fn read_bounded_line(reader: &mut impl BufRead, max: usize, line: &mut Vec<u8>) -> std::io::Result<bool> {
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(false);
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(nl) => {
                line.extend_from_slice(&available[..nl]);
                reader.consume(nl + 1);
                if line.len() > max {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "output exceeds maxOutputBytes"));
                }
                return Ok(true);
            }
            None => {
                line.extend_from_slice(available);
                let len = available.len();
                reader.consume(len);
                if line.len() > max {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "output exceeds maxOutputBytes"));
                }
            }
        }
    }
}

struct LiveChild {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<LineOrEof>,
    pid: u32,
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;

/// SIGTERM → wait grace → SIGKILL (06 §6.4.1 killGraceMs).
fn grace_kill(child: &mut Child, grace: Duration) {
    let _ = unsafe { kill(child.id() as i32, SIGTERM) };
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return,
        }
    }
}

/// Wait for exit within `remaining`; `None` on timeout.
fn wait_deadline(child: &mut Child, remaining: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + remaining;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => return None,
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return None,
        }
    }
}

/// cwd default: the engine state dir (06 §6.4.1; 05 §5.4 defines the dir).
pub fn default_tool_cwd() -> PathBuf {
    let base = match std::env::var("XDG_STATE_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => PathBuf::from(home).join(".local/state"),
            _ => std::env::temp_dir(),
        },
    };
    let dir = base.join("shell-warden");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn spawn_child(spec: &ToolSpec) -> std::io::Result<LiveChild> {
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Tool stderr is diagnostics; the engine's own stderr is a log (05 §5.1).
        .stderr(Stdio::inherit());
    match &spec.cwd {
        Some(cwd) => {
            command.current_dir(cwd);
        }
        None => {
            command.current_dir(default_tool_cwd());
        }
    }
    // Environment = engine's inherited environment + patch (06 §6.4.1).
    for (k, v) in &spec.env_set {
        command.env(k, v);
    }
    for k in &spec.env_unset {
        command.env_remove(k);
    }
    let mut child = command.spawn()?;
    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let pid = child.id();
    let lines = spawn_reader(stdout, spec.max_output_bytes);
    Ok(LiveChild { child, stdin, lines, pid })
}

fn write_letter(stdin: &mut ChildStdin, letter: &serde_json::Value) -> std::io::Result<()> {
    stdin.write_all(serde_json::to_string(letter).expect("serialize letter").as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()
}

// ── Runner ──────────────────────────────────────────────────────────────────────

enum PoolState {
    Cold,
    Ready(LiveChild),
    Backoff { until: Instant },
    Unhealthy { until: Instant },
}

pub struct StageRunner {
    stage_id: String,
    spec: ToolSpec,
    state: PoolState,
    ladder: Ladder,
    last_used: Option<Instant>,
    pin_checked: bool,
}

impl StageRunner {
    pub fn new(stage_id: String, spec: ToolSpec) -> Self {
        StageRunner {
            stage_id,
            spec,
            state: PoolState::Cold,
            ladder: Ladder::default(),
            last_used: None,
            pin_checked: false,
        }
    }

    /// True while a persistent child is alive (counts toward maxConcurrentTools).
    pub fn is_active(&self) -> bool {
        matches!(self.state, PoolState::Ready(_))
    }

    /// Diagnostics/test hook: current pool state.
    pub fn state_name(&self) -> &'static str {
        match self.state {
            PoolState::Cold => "cold",
            PoolState::Ready(_) => "ready",
            PoolState::Backoff { .. } => "backoff",
            PoolState::Unhealthy { .. } => "unhealthy",
        }
    }

    /// Idle kill for persistent tools (06 §6.4.1), evaluated by the engine's
    /// tick — no dedicated reaper thread. Unit-testable time via `now`.
    pub fn tick(&mut self, now: Instant) {
        let idle_expired = matches!(self.state, PoolState::Ready(_))
            && self
                .spec
                .idle_timeout_ms
                .map(Duration::from_millis)
                .zip(self.last_used)
                .map(|(idle, used)| now.duration_since(used) > idle)
                .unwrap_or(false);
        if idle_expired {
            let grace = Duration::from_millis(self.spec.kill_grace_ms);
            if let PoolState::Ready(mut live) = std::mem::replace(&mut self.state, PoolState::Cold) {
                eprintln!("shell-warden: stage {}: idle kill pid {}", self.stage_id, live.pid);
                drop(live.stdin);
                grace_kill(&mut live.child, grace);
            }
        }
    }

    pub fn invoke(&mut self, cmd: &CheckCommand, invocation: &Invocation, now: Instant) -> InvokeResult {
        self.last_used = Some(now);
        // Gates: unhealthy / cooling down → onError without a new violation
        // (the failure is already accounted for; 08 §8.2: the walk continues).
        match self.state {
            PoolState::Unhealthy { until } if now < until => {
                return Ok(StageOutcome::OnError { reason: "stage tool unhealthy".into(), violation: false })
            }
            PoolState::Backoff { until } if now < until => {
                return Ok(StageOutcome::OnError { reason: "stage tool restarting".into(), violation: false })
            }
            PoolState::Unhealthy { .. } | PoolState::Backoff { .. } => self.state = PoolState::Cold,
            PoolState::Cold | PoolState::Ready(_) => {}
        }

        match self.spec.lifecycle {
            Lifecycle::Spawn => self.invoke_spawn(cmd, invocation, now),
            Lifecycle::Persistent => self.invoke_persistent(cmd, invocation, now),
        }
    }

    /// One-shot: fresh child per call (06 §6.4.1 "spawn"). `spawn_child` hands
    /// over the piped stdin and the stdout reader — write the letter, close
    /// stdin (EOF), then wait for the single answer line.
    fn invoke_spawn(&mut self, cmd: &CheckCommand, invocation: &Invocation, now: Instant) -> InvokeResult {
        let LiveChild { mut child, stdin, lines, .. } = match self.ensure_spawned()? {
            Some(live) => live,
            None => return Ok(self.failure("spawn failure", true, now)),
        };
        let letter = build_letter(&self.spec, cmd, invocation);
        let deadline = Duration::from_millis(self.spec.timeout_ms);
        let started = Instant::now();

        {
            let mut stdin = stdin;
            if write_letter(&mut stdin, &letter).is_err() {
                grace_kill(&mut child, Duration::from_millis(self.spec.kill_grace_ms));
                let _ = child.wait();
                return Ok(self.failure("stage tool closed stdin", true, now));
            }
        } // stdin dropped: the one-shot tool sees EOF

        // `(outcome, grace_kill)` — the kill flag marks paths where the child
        // must be terminated rather than merely reaped.
        let outcome = match lines.recv_timeout(deadline) {
            Ok(LineOrEof::Line(line)) => {
                let mut result = (classify_response(&String::from_utf8_lossy(&line)), false);
                match wait_deadline(&mut child, deadline.saturating_sub(started.elapsed())) {
                    Some(status) => {
                        // Extra non-empty output lines are a protocol breach (06 §6.4.3).
                        if let Some(extra) = extra_nonempty_line(&lines) {
                            result.0 = StageOutcome::OnError {
                                reason: format!("protocol violation: {extra}"),
                                violation: true,
                            };
                        }
                        if !status.success() {
                            // Exit ≠ 0 is onError even with valid JSON — the tool
                            // reported its own failure; no violation (06 §6.4.4).
                            result.0 = StageOutcome::OnError { reason: format!("tool exited unsuccessfully: {status}"), violation: false };
                        }
                    }
                    None => {
                        // Answered but would not exit: protocol violation.
                        result = (StageOutcome::OnError { reason: "tool did not exit after answering".into(), violation: true }, true);
                    }
                }
                result
            }
            Ok(LineOrEof::Eof) | Err(RecvTimeoutError::Disconnected) => (
                StageOutcome::OnError { reason: "tool produced no answer".into(), violation: true },
                false,
            ),
            Err(RecvTimeoutError::Timeout) => (
                StageOutcome::OnError { reason: "deadline exceeded".into(), violation: true },
                true,
            ),
        };
        if outcome.1 {
            grace_kill(&mut child, Duration::from_millis(self.spec.kill_grace_ms));
        }
        let _ = child.wait();
        if let StageOutcome::OnError { violation: true, .. } = &outcome.0 {
            let v = self.ladder.violation(now);
            self.apply_ladder(v, now);
        }
        Ok(outcome.0)
    }

    /// Persistent: reuse the live child; exactly one line per request.
    fn invoke_persistent(&mut self, cmd: &CheckCommand, invocation: &Invocation, now: Instant) -> InvokeResult {
        // Take the child out of the state; it goes back in only on the healthy
        // path — every failure path leaves Cold/Backoff/Unhealthy behind.
        let mut live = match std::mem::replace(&mut self.state, PoolState::Cold) {
            PoolState::Ready(live) => live,
            PoolState::Cold => match self.ensure_spawned()? {
                Some(live) => {
                    self.ladder.last_ready_at = Some(now);
                    live
                }
                None => return Ok(self.failure("spawn failure", true, now)),
            },
            _ => unreachable!("backoff/unhealthy gates handled in invoke()"),
        };

        // Stale output (tool wrote without a request): drain and log; these are
        // pool hygiene, not protocol violations, in M0.
        let mut stale = 0;
        let mut died_between_calls = false;
        loop {
            match live.lines.try_recv() {
                Ok(LineOrEof::Line(line)) => {
                    stale += 1;
                    if !line.iter().all(|b| b.is_ascii_whitespace()) {
                        eprintln!("shell-warden: stage {}: dropped unsolicited output", self.stage_id);
                    }
                }
                Ok(LineOrEof::Eof) | Err(TryRecvError::Disconnected) => {
                    died_between_calls = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        if stale > 0 {
            eprintln!("shell-warden: stage {}: drained {stale} stale output line(s)", self.stage_id);
        }
        // Child died between calls: a persistent contract breach — violation
        // (06 §6.4.4) — then a lazy respawn so this call still gets an answer.
        if died_between_calls || !live_child_alive(&mut live.child) {
            let _ = live.child.wait();
            match self.ladder.violation(now) {
                LadderVerdict::Tolerated => match self.ensure_spawned()? {
                    Some(fresh) => {
                        self.ladder.last_ready_at = Some(now);
                        live = fresh;
                    }
                    None => return Ok(self.failure("spawn failure", true, now)),
                },
                LadderVerdict::Restart { delay } => {
                    drop(live.stdin);
                    grace_kill(&mut live.child, Duration::from_millis(self.spec.kill_grace_ms));
                    self.state = PoolState::Backoff { until: now + delay };
                    return Ok(StageOutcome::OnError { reason: "stage tool restarting".into(), violation: false });
                }
                LadderVerdict::Unhealthy { until } => {
                    drop(live.stdin);
                    grace_kill(&mut live.child, Duration::from_millis(self.spec.kill_grace_ms));
                    self.state = PoolState::Unhealthy { until };
                    return Ok(StageOutcome::OnError { reason: "stage tool unhealthy".into(), violation: false });
                }
            }
        }

        let letter = build_letter(&self.spec, cmd, invocation);
        if write_letter(&mut live.stdin, &letter).is_err() {
            let _ = live.child.wait();
            return Ok(self.failure("stage tool closed stdin", true, now));
        }
        match live.lines.recv_timeout(Duration::from_millis(self.spec.timeout_ms)) {
            Ok(LineOrEof::Line(line)) => {
                let outcome = classify_response(&String::from_utf8_lossy(&line));
                match live.child.try_wait() {
                    Ok(None) => {
                        // Healthy: the child goes back to Ready for the next call.
                        self.state = PoolState::Ready(live);
                        Ok(outcome)
                    }
                    Ok(Some(status)) => {
                        // A persistent tool must not exit — contract breach even
                        // with a valid answer (06 §6.4.4: crash ⇒ onError + violation).
                        let _ = live.child.wait();
                        Ok(self.failure(&format!("persistent tool exited ({status}) after answering"), true, now))
                    }
                    Err(_) => Ok(self.failure("cannot inspect tool process", true, now)),
                }
            }
            Ok(LineOrEof::Eof) | Err(RecvTimeoutError::Disconnected) => {
                let _ = live.child.wait();
                Ok(self.failure("persistent tool produced no answer", true, now))
            }
            Err(RecvTimeoutError::Timeout) => {
                let grace = Duration::from_millis(self.spec.kill_grace_ms);
                let LiveChild { mut child, stdin, .. } = live;
                drop(stdin);
                grace_kill(&mut child, grace);
                Ok(self.failure("deadline exceeded", true, now))
            }
        }
    }

    /// Register a failed invocation: ladder on violation, pool state update.
    fn failure(&mut self, reason: &str, violation: bool, now: Instant) -> StageOutcome {
        if violation {
            let v = self.ladder.violation(now);
            self.apply_ladder(v, now);
        }
        StageOutcome::OnError { reason: reason.to_string(), violation }
    }

    fn apply_ladder(&mut self, verdict: LadderVerdict, now: Instant) {
        match verdict {
            LadderVerdict::Tolerated => {
                if !matches!(self.state, PoolState::Ready(_)) {
                    self.state = PoolState::Cold;
                }
            }
            LadderVerdict::Restart { delay } => {
                self.kill_live();
                self.state = PoolState::Backoff { until: now + delay };
                eprintln!(
                    "shell-warden: stage {}: restart in {}ms (violation ladder)",
                    self.stage_id,
                    delay.as_millis()
                );
            }
            LadderVerdict::Unhealthy { until } => {
                self.kill_live();
                self.state = PoolState::Unhealthy { until };
                eprintln!(
                    "shell-warden: stage {}: unhealthy until restart window elapses ({}s)",
                    self.stage_id,
                    RESTART_WINDOW.as_secs()
                );
            }
        }
    }

    fn kill_live(&mut self) {
        if let PoolState::Ready(mut live) = std::mem::replace(&mut self.state, PoolState::Cold) {
            drop(live.stdin);
            grace_kill(&mut live.child, Duration::from_millis(self.spec.kill_grace_ms));
        }
    }

    /// Verify the sha256 pin once (I8), then spawn. `Ok(None)` = spawn failed.
    fn ensure_spawned(&mut self) -> Result<Option<LiveChild>, FatalPin> {
        if !self.pin_checked {
            self.pin_checked = true;
            if let Some(expected) = &self.spec.sha256 {
                match std::fs::read(&self.spec.argv[0]) {
                    Ok(bytes) => {
                        let actual = crate::sha256::hex_digest(&bytes);
                        if actual != *expected {
                            return Err(FatalPin {
                                reason: format!(
                                    "stage `{}` sha256 mismatch: expected {expected}, got {actual}",
                                    self.stage_id
                                ),
                            });
                        }
                    }
                    Err(e) => {
                        return Err(FatalPin {
                            reason: format!("stage `{}` binary unreadable for sha256 pin: {e}", self.stage_id),
                        });
                    }
                }
            }
        }
        match spawn_child(&self.spec) {
            Ok(live) => Ok(Some(live)),
            Err(e) => {
                eprintln!("shell-warden: stage {}: spawn failed: {e}", self.stage_id);
                Ok(None)
            }
        }
    }
}

impl Drop for StageRunner {
    fn drop(&mut self) {
        self.kill_live();
    }
}

fn live_child_alive(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(None))
}

fn extra_nonempty_line(lines: &Receiver<LineOrEof>) -> Option<String> {
    loop {
        match lines.try_recv() {
            Ok(LineOrEof::Line(line)) => {
                if !line.iter().all(|b| b.is_ascii_whitespace()) {
                    return Some(String::from_utf8_lossy(&line).chars().take(80).collect());
                }
            }
            _ => return None,
        }
    }
}

// ── Pool per config ─────────────────────────────────────────────────────────────

/// All stage runners of the active config; stages fail independently, the pool
/// is rebuilt on config swap (05 §5.3: pools restart as needed).
pub struct StagePools {
    runners: BTreeMap<String, StageRunner>,
    max_concurrent: usize,
}

impl StagePools {
    pub fn build(stages: &[crate::config::Stage], max_concurrent: usize) -> Self {
        let runners = stages
            .iter()
            .map(|s| (s.id.clone(), StageRunner::new(s.id.clone(), s.tool.clone())))
            .collect();
        StagePools { runners, max_concurrent }
    }

    pub fn invoke(&mut self, stage: &crate::config::Stage, cmd: &CheckCommand, invocation: &Invocation, now: Instant) -> InvokeResult {
        // Persistent-process cap (06 §6.2 maxConcurrentTools). Serial loop ⇒
        // at most one in-flight call, but persistent children accumulate.
        let active = self.runners.values().filter(|r| r.is_active()).count();
        let Some(runner) = self.runners.get_mut(&stage.id) else {
            return Ok(StageOutcome::OnError { reason: "stage has no runner".into(), violation: false });
        };
        if !runner.is_active() && active >= self.max_concurrent {
            return Ok(StageOutcome::OnError { reason: "maxConcurrentTools exceeded".into(), violation: false });
        }
        runner.invoke(cmd, invocation, now)
    }

    pub fn tick(&mut self, now: Instant) {
        for runner in self.runners.values_mut() {
            runner.tick(now);
        }
    }
}

#[cfg(test)]
mod tests;
