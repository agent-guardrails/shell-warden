// Wire protocol — docs/spec/shell-warden/02-protocol.md, schemas/wire.v1.schema.json.
// NDJSON on stdio: exactly one UTF-8 JSON value per \n-terminated line; the engine
// answers each request with a response carrying the same numeric id. Notifications
// (no id) are never answered; unknown methods are -32601; unparseable lines are
// -32700 with id null; every anomaly resolves fail-closed — the engine itself never
// synthesizes `allow` (09-security I3).

// Wire field names (protocolVersion, invocationId, sessionID, checkMs, …) are
// camelCase by contract and must not be renamed. The full error-code table and
// wire-shaped structs are declared up front; later HANDOFF-m0 steps consume the
// remaining members (config-fatal codes, invocation fields in the walk).
#![allow(non_snake_case)]
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 65_536; // 02 §2.1 default budget

// ── JSON-RPC error codes (02 §2.8) ─────────────────────────────────────────────

pub const CODE_PARSE: i64 = -32700;
pub const CODE_INVALID_REQUEST: i64 = -32600;
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
pub const CODE_INVALID_PARAMS: i64 = -32602;
pub const CODE_INTERNAL: i64 = -32000;
pub const CODE_CONFIG_INVALID: i64 = -32001;

const MAX_ERROR_MESSAGE: usize = 512; // wire schema: error.message maxLength

/// Error object per 02 §2.8. `fatal: true` marks config-invalid states the shim
/// treats as unhealthy-until-fixed.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<FatalData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FatalData {
    pub fatal: bool,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: truncate_chars(&message.into(), MAX_ERROR_MESSAGE),
            data: None,
        }
    }
    pub fn fatal(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: truncate_chars(&message.into(), MAX_ERROR_MESSAGE),
            data: Some(FatalData { fatal: true }),
        }
    }
    pub fn is_fatal(&self) -> bool {
        matches!(&self.data, Some(d) if d.fatal)
    }
}

/// Truncate on char boundaries — error text is capped, never wraps the protocol.
pub fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out: String = s[..end].to_string();
    out.push('…');
    out
}

// ── Protocol types (mirror of shim src/types.ts; keep in sync with the schema) ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    /// Most-restrictive-wins ranking (08 §8.3): deny > ask > allow.
    pub fn rank(self) -> u8 {
        match self {
            Verdict::Allow => 0,
            Verdict::Ask => 1,
            Verdict::Deny => 2,
        }
    }
    pub fn most_restrictive(a: Verdict, b: Verdict) -> Verdict {
        if a.rank() >= b.rank() {
            a
        } else {
            b
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u64,
    pub client: InitializeClient,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InitializeClient {
    pub name: String,
    pub version: String,
    #[serde(rename = "opencode")]
    pub opencode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitializeResult {
    pub protocolVersion: u64,
    pub engine: EngineInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigEcho>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    pub maxCommandsPerCheck: u64,
    pub cacheTtl: bool,
    pub auditEvents: bool,
    pub stages: bool,
}

/// Informational echo of the active config (05 §5.3); stage order matters only
/// to the engine, the shim just logs this.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigEcho {
    pub source: String,
    pub stages: Vec<String>,
    pub loadedAt: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckParams {
    pub invocation: Invocation,
    pub action: String,
    pub commands: Vec<CheckCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<CheckContext>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Invocation {
    pub id: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub hook: HookKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
}

/// v1 hooks per wire schema: `permission.evaluate` is the only one the shim
/// sends; `shell.create.before` is reserved.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum HookKind {
    #[serde(rename = "permission.evaluate")]
    PermissionEvaluate,
    #[serde(rename = "shell.create.before")]
    ShellCreateBefore,
}

/// One scanner-split subcommand. `raw` is untrusted payload (ADR-0014): the core
/// forwards it verbatim — normalization/classification happens inside stage tools.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckCommand {
    pub index: u64,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    pub cwd: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ContextSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContextSource {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub invocationId: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<CheckCommandResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineTelemetry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckCommandResult {
    pub index: u64,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleId: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cacheTtlMs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    Static,
    Opaque,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineTelemetry {
    pub checkMs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PingResult {
    pub uptimeMs: u64,
    pub checksProcessed: u64,
    pub inFlight: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastErrorAt: Option<String>,
}

/// Engine → shim audit notification params (02 §2.5), ≤ 16 KiB / depth ≤ 8.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub invocationId: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessionID: Option<String>,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleId: Option<String>,
    pub ts: String,
}

// ── Incoming line classification (02 §2.2, §2.8) ────────────────────────────────

pub enum Incoming {
    /// Request with a valid numeric id — MUST be answered with the same id.
    Request {
        id: u64,
        method: String,
        params: Option<Value>,
    },
    /// Notification carries no id — MUST NOT be answered (unknown ones ignored, §2.1).
    Notification {
        method: String,
        params: Option<Value>,
    },
    /// Malformed line. Answered with `id` when a valid id was present, else null.
    Malformed { id: Option<u64>, error: RpcError },
}

/// Classify one already-JSON-parsed line into request / notification / malformed.
pub fn classify(value: Value) -> Incoming {
    let obj = match value {
        Value::Object(map) => map,
        _ => {
            return Incoming::Malformed {
                id: None,
                error: RpcError::new(CODE_PARSE, "parse error: not a JSON object"),
            }
        }
    };
    // jsonrpc must be the exact version member (02 §2.2).
    match obj.get("jsonrpc") {
        Some(Value::String(s)) if s == "2.0" => {}
        _ => {
            return Incoming::Malformed {
                id: valid_id(obj.get("id")),
                error: RpcError::new(
                    CODE_INVALID_REQUEST,
                    "invalid request: jsonrpc must be \"2.0\"",
                ),
            }
        }
    }
    let id_member = obj.get("id");
    // A notification must NOT carry an id member at all (wire schema:
    // notification.not.required["id"]); `"id": null` is neither a valid request
    // id nor a notification → malformed with id null.
    let id = match id_member {
        None | Some(Value::Null) => None,
        Some(v) => match valid_id(Some(v)) {
            Some(id) => Some(id),
            None => {
                return Incoming::Malformed {
                    id: None,
                    error: RpcError::new(
                        CODE_INVALID_REQUEST,
                        "invalid request: id must be an integer >= 1",
                    ),
                }
            }
        },
    };
    let id_is_null_member = matches!(id_member, Some(Value::Null));
    match (obj.get("method"), id) {
        (Some(Value::String(method)), id_opt) => {
            let method = method.clone();
            let params = obj.get("params").cloned().filter(|p| !p.is_null());
            match id_opt {
                Some(id) => Incoming::Request { id, method, params },
                None if id_is_null_member => Incoming::Malformed {
                    id: None,
                    error: RpcError::new(
                        CODE_INVALID_REQUEST,
                        "invalid request: id must be an integer >= 1",
                    ),
                },
                None => Incoming::Notification { method, params },
            }
        }
        (Some(_), _) => Incoming::Malformed {
            id,
            error: RpcError::new(
                CODE_INVALID_REQUEST,
                "invalid request: method must be a string",
            ),
        },
        (None, _) => Incoming::Malformed {
            id,
            error: RpcError::new(CODE_INVALID_REQUEST, "invalid request: missing method"),
        },
    }
}

fn valid_id(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64().filter(|id| *id >= 1),
        _ => None,
    }
}

// ── Server contract ─────────────────────────────────────────────────────────────

/// What one request produced: an optional audit notification to emit before the
/// response (02 §2.10 shows audit before result), then the response itself.
pub struct Reply {
    pub audit: Option<AuditEvent>,
    pub body: ReplyBody,
}
pub enum ReplyBody {
    Result(Value),
    Error(RpcError),
}

impl Reply {
    pub fn result(value: Value) -> Reply {
        Reply {
            audit: None,
            body: ReplyBody::Result(value),
        }
    }
    pub fn error(err: RpcError) -> Reply {
        Reply {
            audit: None,
            body: ReplyBody::Error(err),
        }
    }
}

/// Engine behavior behind the wire loop. Transport-aware only through these
/// methods; all policy semantics live behind them (ADR-0008).
pub trait Handler {
    fn initialize(&mut self) -> InitializeResult;
    /// Fail-closed: an error reply (e.g. -32001 fatal) is always legal; an Ok
    /// reply must carry a verdict of ask/deny or a tool-verified allow.
    fn check(&mut self, params: CheckParams) -> Result<CheckResult, RpcError>;
    /// Audit notification for the last successful check (02 §2.5), if the
    /// engine emits decisions. Consumed once by the dispatch loop.
    fn take_audit(&mut self) -> Option<AuditEvent> {
        None
    }
    fn ping(&mut self) -> PingResult;
    /// Fire-and-forget shim notifications (02 §2.6). Unknown methods are
    /// tolerated (forward compatibility).
    fn notification(&mut self, method: &str, params: Option<&Value>);
    /// Called once per serve-loop iteration before reading: config reload
    /// polling, pool idle maintenance (05 §5.3 reload, 06 §6.4.1 idle kill).
    fn tick(&mut self) {}
}

/// Validate and dispatch one request. Parameter errors are -32602 per 08 §8.1
/// ("validate(request) → -32602 on schema violation").
pub fn dispatch(handler: &mut dyn Handler, method: &str, params: Option<Value>) -> Reply {
    match method {
        "initialize" => {
            let parsed: Result<InitializeParams, _> = match params {
                Some(p) => serde_json::from_value(p),
                None => Err(de::missing_field()),
            };
            match parsed {
                Ok(p) if p.protocol_version == 1 => Reply::result(
                    serde_json::to_value(handler.initialize())
                        .expect("serialize initialize result"),
                ),
                Ok(_) => Reply::error(RpcError::new(
                    CODE_INVALID_PARAMS,
                    "invalid params: protocolVersion must be 1",
                )),
                Err(e) => Reply::error(RpcError::new(
                    CODE_INVALID_PARAMS,
                    format!("invalid params: {e}"),
                )),
            }
        }
        "policy/check" => {
            let parsed: Result<CheckParams, _> = match params {
                Some(p) => serde_json::from_value(p),
                None => Err(de::missing_field()),
            };
            let params = match parsed {
                Ok(p) => p,
                Err(e) => {
                    return Reply::error(RpcError::new(
                        CODE_INVALID_PARAMS,
                        format!("invalid params: {e}"),
                    ))
                }
            };
            if let Err(e) = validate_check(&params) {
                return Reply::error(RpcError::new(
                    CODE_INVALID_PARAMS,
                    format!("invalid params: {e}"),
                ));
            }
            match handler.check(params) {
                Ok(result) => Reply {
                    audit: handler.take_audit(),
                    body: ReplyBody::Result(
                        serde_json::to_value(result).expect("serialize check result"),
                    ),
                },
                Err(e) => Reply::error(e),
            }
        }
        "ping" => {
            Reply::result(serde_json::to_value(handler.ping()).expect("serialize ping result"))
        }
        other => Reply::error(RpcError::new(
            CODE_METHOD_NOT_FOUND,
            format!("method not found: {other}"),
        )),
    }
}

mod de {
    pub fn missing_field() -> serde_json::Error {
        serde::de::Error::custom("missing field `params`")
    }
}

/// Schema limits from wire.v1.schema.json that serde types cannot express.
pub fn validate_check(p: &CheckParams) -> Result<(), String> {
    if p.invocation.id.chars().count() > 256 {
        return Err("invocation.id exceeds 256 chars".into());
    }
    if p.action.chars().count() > 64 {
        return Err("action exceeds 64 chars".into());
    }
    if p.commands.is_empty() {
        return Err("commands must contain at least 1 item".into());
    }
    if p.commands.len() > 128 {
        return Err("commands exceeds 128 items".into());
    }
    for c in &p.commands {
        // 02 §2.4: raw ≤ 8 KiB each.
        if c.raw.len() > 8192 {
            return Err(format!("commands[{}].raw exceeds 8192 bytes", c.index));
        }
    }
    if let Some(ctx) = &p.context {
        if let Some(src) = &ctx.source {
            if let Some(t) = &src.kind {
                if t != "tool" {
                    return Err("context.source.type must be \"tool\"".into());
                }
            }
        }
    }
    Ok(())
}

// ── Framing ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum FrameError {
    /// Line longer than the frame cap — protocol violation (02 §2.1).
    FrameLimit,
}

/// Read one `\n`-terminated line, enforcing the frame cap byte-wise so an
/// oversized line can never balloon memory. Returns `Ok(None)` on clean EOF.
/// A partial trailing line at EOF is tolerated (05 §5.1) and returned as a line.
pub fn read_line_capped(
    reader: &mut impl BufRead,
    cap: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut line = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(buf) if buf.is_empty() => {
                // EOF: tolerate a partial final line, otherwise end the stream.
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(line))
                };
            }
            Ok(buf) => buf,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(None), // stdin unreadable: treat as clean end
        };
        match available.iter().position(|&b| b == b'\n') {
            Some(nl) => {
                line.extend_from_slice(&available[..nl]);
                reader.consume(nl + 1);
                if line.len() > cap {
                    return Err(FrameError::FrameLimit);
                }
                return Ok(Some(line));
            }
            None => {
                line.extend_from_slice(available);
                let len = available.len();
                reader.consume(len);
                if line.len() > cap {
                    return Err(FrameError::FrameLimit);
                }
            }
        }
    }
}

fn line_to_incoming(raw: &[u8]) -> Incoming {
    // Blank lines are not valid NDJSON (02 §2.1) — parse error, same as garbage.
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(_) => {
            return Incoming::Malformed {
                id: None,
                error: RpcError::new(CODE_PARSE, "parse error: line is not UTF-8"),
            }
        }
    };
    if text.trim().is_empty() {
        return Incoming::Malformed {
            id: None,
            error: RpcError::new(CODE_PARSE, "parse error: blank line"),
        };
    }
    match serde_json::from_str::<Value>(text) {
        Ok(v) => classify(v),
        Err(_) => Incoming::Malformed {
            id: None,
            error: RpcError::new(CODE_PARSE, "parse error: line is not valid JSON"),
        },
    }
}

/// Serialize a response line; guaranteed to fit the frame cap by stripping
/// diagnostics if needed (oversized output is an engine bug, 02 §2.1).
/// `id: None` serializes as `"id": null` (wire schema rpcError.id).
pub fn encode_response(id: Option<u64>, reply: &Reply, cap: usize) -> String {
    let mut body = serde_json::json!({ "jsonrpc": "2.0", "id": id });
    match &reply.body {
        ReplyBody::Result(v) => body["result"] = v.clone(),
        ReplyBody::Error(e) => body["error"] = serde_json::to_value(e).expect("serialize error"),
    }
    let line = serde_json::to_string(&body).expect("serialize response");
    if line.len() < cap {
        return line;
    }
    // Strip to the minimal legal shape — the verdict itself is tiny and must
    // survive verbatim (fail-closed: never downgrade or drop the decision).
    let minimal = match &reply.body {
        ReplyBody::Result(v) => {
            let mut m = serde_json::Map::new();
            if let Some(iid) = v.get("invocationId") {
                m.insert("invocationId".into(), iid.clone());
            }
            if let Some(verdict) = v.get("verdict") {
                m.insert("verdict".into(), verdict.clone());
            } else {
                return encode_response(
                    id,
                    &Reply::error(RpcError::new(
                        CODE_INTERNAL,
                        "internal error: response too large",
                    )),
                    cap,
                );
            }
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": Value::Object(m) })
        }
        ReplyBody::Error(e) => {
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": e.code, "message": "internal error: response too large" } })
        }
    };
    serde_json::to_string(&minimal).expect("serialize minimal response")
}

pub fn encode_audit(event: &AuditEvent) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "audit/event",
        "params": event,
    }))
    .expect("serialize audit")
}

// ── Serve loop ──────────────────────────────────────────────────────────────────

static TERM_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_termination(_sig: i32) {
    TERM_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// SIGTERM/SIGINT → flag + watchdog: exit(0) within the shim's kill grace
/// (05 §5.1) even while blocked reading stdin.
fn install_termination_handler() {
    extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    unsafe {
        signal(SIGTERM, on_termination);
        signal(SIGINT, on_termination);
    }
    std::thread::spawn(|| loop {
        if TERM_FLAG.load(std::sync::atomic::Ordering::SeqCst) {
            std::process::exit(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    });
}

fn terminating() -> bool {
    TERM_FLAG.load(std::sync::atomic::Ordering::SeqCst)
}

/// NDJSON serve loop: one request line in → one response line out (same id).
/// Any frame-limit violation is unrecoverable per 02 §2.1 → log to stderr
/// (diagnostics only, never stdout) and crash so the shim's supervision
/// restarts the engine from a clean state.
pub fn serve(handler: &mut dyn Handler, max_frame_bytes: usize) -> i32 {
    install_termination_handler();
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    loop {
        if terminating() {
            return 0;
        }
        let raw = match read_line_capped(&mut reader, max_frame_bytes) {
            Ok(Some(line)) => line,
            Ok(None) => return 0, // EOF: clean exit (shim closed the pipe)
            Err(FrameError::FrameLimit) => {
                eprintln!(
                    "shell-warden: protocol violation: frame exceeds {max_frame_bytes} bytes"
                );
                return 1;
            }
        };
        if terminating() {
            return 0;
        }
        handler.tick();
        let mut audit_line: Option<String> = None;
        let response: Option<String> = match line_to_incoming(&raw) {
            Incoming::Notification { method, params } => {
                handler.notification(&method, params.as_ref());
                None
            }
            Incoming::Malformed { id, error } => {
                let reply = Reply::error(error);
                Some(encode_response(id, &reply, max_frame_bytes))
            }
            Incoming::Request { id, method, params } => {
                let reply = dispatch(handler, &method, params);
                if let Some(audit) = &reply.audit {
                    audit_line = Some(encode_audit(audit));
                }
                Some(encode_response(Some(id), &reply, max_frame_bytes))
            }
        };
        // stdout is wire-only (05 §5.1): audit notification first (02 §2.10),
        // then the response. A broken pipe means the shim is gone — exit.
        if let Some(audit) = audit_line {
            if write_line(&mut writer, &audit).is_err() {
                return 1;
            }
        }
        if let Some(response) = response {
            if write_line(&mut writer, &response).is_err() {
                return 1;
            }
        }
    }
}
fn write_line(writer: &mut impl Write, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── classify ──

    fn classify_str(s: &str) -> Incoming {
        classify(serde_json::from_str(s).expect("test line must be JSON"))
    }

    #[test]
    fn classify_request_with_valid_id() {
        match classify_str(r#"{"jsonrpc":"2.0","id":7,"method":"policy/check","params":{}}"#) {
            Incoming::Request { id, method, params } => {
                assert_eq!(id, 7);
                assert_eq!(method, "policy/check");
                assert_eq!(params, Some(json!({})));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn classify_notification_has_no_id_and_is_not_answered() {
        match classify_str(
            r#"{"jsonrpc":"2.0","method":"session/ended","params":{"sessionID":"s1"}}"#,
        ) {
            Incoming::Notification { method, params } => {
                assert_eq!(method, "session/ended");
                assert_eq!(params, Some(json!({"sessionID":"s1"})));
            }
            _ => panic!("expected notification"),
        }
    }

    #[test]
    fn classify_rejects_wrong_jsonrpc_version_keeping_valid_id() {
        match classify_str(r#"{"jsonrpc":"1.0","id":5,"method":"ping"}"#) {
            Incoming::Malformed { id, error } => {
                assert_eq!(id, Some(5));
                assert_eq!(error.code, CODE_INVALID_REQUEST);
            }
            _ => panic!("expected malformed"),
        }
    }

    #[test]
    fn classify_rejects_nonpositive_and_noninteger_ids() {
        for line in [
            r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":-3,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":"7","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        ] {
            match classify_str(line) {
                Incoming::Malformed { id, error } => {
                    assert_eq!(id, None, "invalid id cannot be echoed: {line}");
                    assert_eq!(error.code, CODE_INVALID_REQUEST);
                }
                _ => panic!("expected malformed for {line}"),
            }
        }
    }

    #[test]
    fn classify_rejects_missing_or_nonstring_method() {
        match classify_str(r#"{"jsonrpc":"2.0","id":3}"#) {
            Incoming::Malformed { id, error } => {
                assert_eq!(id, Some(3));
                assert_eq!(error.code, CODE_INVALID_REQUEST);
            }
            _ => panic!("expected malformed"),
        }
        match classify_str(r#"{"jsonrpc":"2.0","id":3,"method":42}"#) {
            Incoming::Malformed { error, .. } => assert_eq!(error.code, CODE_INVALID_REQUEST),
            _ => panic!("expected malformed"),
        }
    }

    // ── raw line parsing (NDJSON discipline) ──

    #[test]
    fn blank_and_garbage_lines_are_parse_errors() {
        for raw in [
            b"" as &[u8],
            b"   ",
            b"not json at all",
            b"[1,2,3]",
            b"null",
        ] {
            match line_to_incoming(raw) {
                Incoming::Malformed { id, error } => {
                    assert_eq!(id, None);
                    assert_eq!(error.code, CODE_PARSE);
                }
                _ => panic!("expected parse error for {raw:?}"),
            }
        }
    }

    #[test]
    fn oversized_line_is_a_frame_violation() {
        let mut input: &[u8] = &[b'x'; 100];
        match read_line_capped(&mut input, 16) {
            Err(FrameError::FrameLimit) => {}
            other => panic!("expected frame limit, got {other:?}"),
        }
        // Exactly at the cap is still fine.
        let mut input: &[u8] = &[b'x'; 16];
        assert!(read_line_capped(&mut input, 16).is_ok());
    }

    #[test]
    fn reads_lines_and_tolerates_partial_final_line() {
        let mut input: &[u8] = b"one\ntwo\nthree";
        assert_eq!(
            read_line_capped(&mut input, 100).unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            read_line_capped(&mut input, 100).unwrap(),
            Some(b"two".to_vec())
        );
        assert_eq!(
            read_line_capped(&mut input, 100).unwrap(),
            Some(b"three".to_vec())
        );
        assert_eq!(read_line_capped(&mut input, 100).unwrap(), None);
    }

    // ── dispatch ──

    struct FakeHandler {
        seen: Option<CheckParams>,
    }

    impl Handler for FakeHandler {
        fn initialize(&mut self) -> InitializeResult {
            InitializeResult {
                protocolVersion: 1,
                engine: EngineInfo {
                    name: "fake".into(),
                    version: "0.0.0".into(),
                },
                capabilities: None,
                config: None,
            }
        }
        fn check(&mut self, params: CheckParams) -> Result<CheckResult, RpcError> {
            self.seen = Some(params.clone());
            Ok(CheckResult {
                invocationId: params.invocation.id,
                verdict: Verdict::Deny,
                message: Some("denied by fake".into()),
                commands: None,
                engine: Some(EngineTelemetry { checkMs: 1 }),
            })
        }
        fn ping(&mut self) -> PingResult {
            PingResult {
                uptimeMs: 0,
                checksProcessed: 0,
                inFlight: 0,
                lastErrorAt: None,
            }
        }
        fn notification(&mut self, _method: &str, _params: Option<&Value>) {}
    }

    fn good_check_params() -> Value {
        json!({
            "invocation": { "id": "m:c", "sessionID": "ses_1", "hook": "permission.evaluate" },
            "action": "shell",
            "commands": [ { "index": 0, "raw": "git push origin main", "cwd": "/work/repo" } ]
        })
    }

    #[test]
    fn initialize_result_matches_wire_shape() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(
            &mut h,
            "initialize",
            Some(json!({ "protocolVersion": 1, "client": { "name": "hook", "version": "0.1.0" } })),
        );
        match reply.body {
            ReplyBody::Result(v) => assert_eq!(
                v,
                json!({ "protocolVersion": 1, "engine": { "name": "fake", "version": "0.0.0" } })
            ),
            _ => panic!("expected result"),
        }
    }

    #[test]
    fn initialize_rejects_foreign_protocol_version() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(
            &mut h,
            "initialize",
            Some(
                json!({ "protocolVersion": 99, "client": { "name": "hook", "version": "0.1.0" } }),
            ),
        );
        match reply.body {
            ReplyBody::Error(e) => assert_eq!(e.code, CODE_INVALID_PARAMS),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn initialize_requires_client_block() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(&mut h, "initialize", Some(json!({ "protocolVersion": 1 })));
        match reply.body {
            ReplyBody::Error(e) => assert_eq!(e.code, CODE_INVALID_PARAMS),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn check_request_is_delivered_to_handler_strictly() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(&mut h, "policy/check", Some(good_check_params()));
        match reply.body {
            ReplyBody::Result(v) => {
                // Same shape the shim's mock-engine emits (id echoed by serve loop).
                assert_eq!(
                    v,
                    json!({
                        "invocationId": "m:c",
                        "verdict": "deny",
                        "message": "denied by fake",
                        "engine": { "checkMs": 1 }
                    })
                );
            }
            _ => panic!("expected result"),
        }
        let seen = h.seen.expect("handler must see params");
        assert_eq!(seen.commands[0].raw, "git push origin main");
        assert_eq!(seen.commands[0].cwd, "/work/repo");
        assert_eq!(seen.invocation.session_id, "ses_1");
    }

    #[test]
    fn check_rejects_schema_violations_with_32602() {
        // serde_json::from_value reports type/enum errors without field paths;
        // derive-generated "missing field `x`" messages do carry the name.
        let cases: Vec<Value> = vec![
            json!({ "action": "shell", "commands": [] }), // no invocation
            json!({ "invocation": { "id": "x", "sessionID": "s", "hook": "permission.evaluate" }, "action": "shell", "commands": [] }),
            json!({ "invocation": { "id": "x", "sessionID": "s", "hook": "nope" }, "action": "shell", "commands": [ { "index": 0, "raw": "ls", "cwd": "/" } ] }),
            json!({ "invocation": { "id": "x", "sessionID": "s", "hook": "permission.evaluate" }, "action": "shell", "commands": [ { "index": 0, "raw": "ls" } ] }),
            json!({ "invocation": { "id": "x", "sessionID": "s", "hook": "permission.evaluate" }, "action": "shell", "commands": [ { "index": -1, "raw": "ls", "cwd": "/" } ] }),
            json!({ "invocation": { "id": "x", "sessionID": "s", "hook": "permission.evaluate" }, "action": 42, "commands": [ { "index": 0, "raw": "ls", "cwd": "/" } ] }),
        ];
        for params in cases {
            let mut h = FakeHandler { seen: None };
            let reply = dispatch(&mut h, "policy/check", Some(params));
            match reply.body {
                ReplyBody::Error(e) => assert_eq!(e.code, CODE_INVALID_PARAMS),
                _ => panic!("expected error"),
            }
        }
        // Derive messages do name missing required fields.
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(
            &mut h,
            "policy/check",
            Some(
                json!({ "invocation": { "id": "x", "sessionID": "s", "hook": "permission.evaluate" }, "action": "shell", "commands": [ { "index": 0, "raw": "ls" } ] }),
            ),
        );
        match reply.body {
            ReplyBody::Error(e) => {
                assert!(e.message.contains("missing field `cwd`"), "{}", e.message)
            }
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn check_enforces_limits_from_wire_schema() {
        let mut h = FakeHandler { seen: None };
        // raw > 8 KiB
        let big = "x".repeat(8193);
        let mut p = good_check_params();
        p["commands"][0]["raw"] = json!(big);
        match dispatch(&mut h, "policy/check", Some(p)).body {
            ReplyBody::Error(e) => assert_eq!(e.code, CODE_INVALID_PARAMS),
            _ => panic!("expected error"),
        }
        // 129 commands
        let commands: Vec<Value> = (0..129)
            .map(|i| json!({ "index": i, "raw": "ls", "cwd": "/" }))
            .collect();
        let mut p = good_check_params();
        p["commands"] = json!(commands);
        match dispatch(&mut h, "policy/check", Some(p)).body {
            ReplyBody::Error(e) => assert_eq!(e.code, CODE_INVALID_PARAMS),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn unknown_method_is_32601() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(&mut h, "config/reload", None);
        match reply.body {
            ReplyBody::Error(e) => {
                assert_eq!(e.code, CODE_METHOD_NOT_FOUND);
                assert!(e.message.contains("config/reload"));
            }
            _ => panic!("expected error"),
        }
    }

    // ── response encoding ──

    #[test]
    fn responses_echo_request_id_and_errors_carry_fatal() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(&mut h, "nope", None);
        let line = encode_response(Some(9), &reply, 65_536);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 9);
        assert_eq!(v["error"]["code"], -32601);

        let fatal = Reply::error(RpcError::fatal(CODE_CONFIG_INVALID, "config invalid"));
        let line = encode_response(Some(2), &fatal, 65_536);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["error"]["code"], -32001);
        assert_eq!(v["error"]["data"]["fatal"], true);

        // No usable id → "id": null (wire schema rpcError.id).
        let line = encode_response(None, &reply, 65_536);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert!(v["id"].is_null());
    }

    #[test]
    fn oversized_response_is_stripped_to_minimal_shape() {
        let mut h = FakeHandler { seen: None };
        let reply = dispatch(&mut h, "policy/check", Some(good_check_params()));
        let full = encode_response(Some(1), &reply, 65_536);
        assert!(full.len() > 80, "fixture must exceed the strip cap");
        let line = encode_response(Some(1), &reply, 80);
        assert!(line.len() < 80, "line must fit the cap: {line}");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["result"]["verdict"], "deny"); // decision itself survives
        assert_eq!(v["result"]["invocationId"], "m:c"); // schema-required field survives
    }

    #[test]
    fn audit_lines_are_notifications_without_id() {
        let event = AuditEvent {
            kind: "decision".into(),
            invocationId: "m:c".into(),
            sessionID: Some("ses_1".into()),
            verdict: Verdict::Deny,
            stage: Some("s1".into()),
            ruleId: None,
            ts: "2026-11-01T00:00:00Z".into(),
        };
        let line = encode_audit(&event);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("id").is_none(), "notifications carry no id");
        assert_eq!(v["method"], "audit/event");
        assert_eq!(v["params"]["type"], "decision");
    }
}
