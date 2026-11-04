// Engine configuration — docs/spec/shell-warden/06-engine-config.md (v1.1),
// schemas/shell-warden.config.v1.schema.json.
//
// Strict validation, fail-closed (06 §6.2): unknown keys, wrong types, cap
// violations ⇒ config invalid → the engine starts anyway and answers every
// policy/check with -32001 data.fatal:true (05 §5.3) — never fail-open.
// Stage tools and stages are executable policy: user-global file only (ADR-0003).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ── Resolved (validated) model ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub source: PathBuf,
    pub loaded_at: String,
    pub limits: Limits,
    /// Execution order = array position (06 §6.3).
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    pub stages: usize,
    pub config_bytes: usize,
    pub facts_bytes: usize,
    pub facts_depth: usize,
    pub max_concurrent_tools: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageMode {
    Append,
    Replace,
}

/// Tool failure policy (06 §6.4.4): never allow (I3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    Skip,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Persistent,
    Spawn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub max_rejections: u32,
    pub window_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub id: String,
    pub tool: ToolSpec,
    pub message_mode: MessageMode,
    /// A non-noop stage verdict → later stages are not invoked (06 §6.5).
    pub exclusive: bool,
    pub budget: Option<Budget>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    /// Absolute argv[0], no shell; {env:NAME} already resolved (06 §6.4.1).
    pub argv: Vec<String>,
    /// Explicit cwd, if configured (default: engine state dir at spawn time).
    pub cwd: Option<String>,
    /// Environment patch applied on top of the engine's inherited environment;
    /// `unset` removes variables (incl. the null-removal syntax).
    pub env_set: Vec<(String, String)>,
    pub env_unset: Vec<String>,
    pub lifecycle: Lifecycle,
    /// Persistent-only: kill the process after this idle time.
    pub idle_timeout_ms: Option<u64>,
    /// Deadline for a single call, 1..=30000.
    pub timeout_ms: u64,
    /// SIGTERM → SIGKILL grace.
    pub kill_grace_ms: u64,
    /// Output above this is a protocol violation (06 §6.4.1).
    pub max_output_bytes: usize,
    pub on_error: OnError,
    /// Optional binary pin; mismatch is fatal (I8). Verified at first spawn.
    pub sha256: Option<String>,
    /// What goes into the stdin letter beyond command{raw,cwd} (06 §6.4.2).
    pub input_session_id: bool,
    pub input_session_agent: bool,
    pub input_mcp: bool,
}

// ── Defaults (06 §6.2 / §6.4.1 and schema defaults) ─────────────────────────────

pub const DEFAULT_STAGES_LIMIT: usize = 64;
pub const DEFAULT_CONFIG_BYTES: usize = 262_144;
pub const DEFAULT_FACTS_BYTES: usize = 16_384;
pub const DEFAULT_FACTS_DEPTH: usize = 8;
pub const DEFAULT_MAX_CONCURRENT_TOOLS: usize = 16;
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_KILL_GRACE_MS: u64 = 250;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 65_536;

// ── Raw serde layer (schema-shaped; deny_unknown_fields everywhere) ─────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u64,
    #[serde(default)]
    defaults: Option<RawDefaults>,
    #[serde(default)]
    limits: Option<RawLimits>,
    stages: Vec<RawStage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
    #[serde(default)]
    action: Option<RawDefaultAction>,
}

/// Schema enum: only "ask" (06 §6.2 — the no-stage aggregate is fail-closed).
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawDefaultAction {
    Ask,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawLimits {
    #[serde(default)]
    stages: Option<u64>,
    #[serde(default)]
    config_bytes: Option<u64>,
    #[serde(default)]
    facts_bytes: Option<u64>,
    #[serde(default)]
    facts_depth: Option<u64>,
    #[serde(default)]
    max_concurrent_tools: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawStage {
    id: String,
    /// Schema requires the discriminator; the only tool-first kind is "tool".
    r#type: RawStageType,
    tool: RawTool,
    #[serde(default)]
    message_mode: Option<RawMessageMode>,
    #[serde(default)]
    exclusive: Option<bool>,
    #[serde(default)]
    budget: Option<RawBudget>,
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawStageType {
    Tool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawMessageMode {
    Append,
    Replace,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawBudget {
    #[serde(default)]
    max_rejections: Option<u64>,
    #[serde(default)]
    window_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawTool {
    command: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: Option<BTreeMap<String, Option<String>>>,
    #[serde(default)]
    lifecycle: Option<RawLifecycle>,
    #[serde(default)]
    idle_timeout_ms: Option<u64>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    kill_grace_ms: Option<u64>,
    #[serde(default)]
    max_output_bytes: Option<u64>,
    #[serde(default)]
    input: Option<RawInput>,
    #[serde(default)]
    on_error: Option<RawOnError>,
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawLifecycle {
    Persistent,
    Spawn,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInput {
    #[serde(default)]
    session: Option<RawSessionInput>,
    #[serde(default)]
    mcp: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSessionInput {
    #[serde(default)]
    id: Option<bool>,
    #[serde(default)]
    agent: Option<bool>,
}

/// skip | ask | deny — "allow" is not in the enum, serde rejects it (I3).
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawOnError {
    Skip,
    Ask,
    Deny,
}

// ── Loading ─────────────────────────────────────────────────────────────────────

/// Default config path (06 §6.1): `$XDG_CONFIG_HOME/shell-warden/config.jsonc`,
/// else `~/.config/shell-warden/config.jsonc`. Single file, user-global only.
pub fn default_path() -> PathBuf {
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => PathBuf::from(home).join(".config"),
            _ => return PathBuf::from("shell-warden/config.jsonc"),
        },
    };
    base.join("shell-warden").join("config.jsonc")
}

/// Load and validate a config file. `Err` carries the reason (already prefixed
/// "config invalid:"), safe for the -32001 message (truncated by the wire layer).
pub fn load(path: &Path) -> Result<Config, String> {
    let bytes = read_capped(path)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "config invalid: file is not UTF-8".to_string())?;
    parse_text(path, text)
}

fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let meta =
        std::fs::metadata(path).map_err(|e| format!("config invalid: cannot read file: {e}"))?;
    if !meta.is_file() {
        return Err("config invalid: not a regular file".into());
    }
    if meta.len() > DEFAULT_CONFIG_BYTES as u64 {
        return Err(format!(
            "config invalid: file exceeds {} bytes",
            DEFAULT_CONFIG_BYTES
        ));
    }
    std::fs::read(path).map_err(|e| format!("config invalid: cannot read file: {e}"))
}

/// Parse config text (JSONC: comments and trailing commas tolerated, per the
/// .jsonc contract in 06 §6.1). Everything else is strict.
pub fn parse_text(path: &Path, text: &str) -> Result<Config, String> {
    if text.len() > DEFAULT_CONFIG_BYTES {
        return Err(format!(
            "config invalid: file exceeds {} bytes",
            DEFAULT_CONFIG_BYTES
        ));
    }
    let stripped = strip_jsonc(text);
    let raw: RawConfig =
        serde_json::from_str(&stripped).map_err(|e| format!("config invalid: {e}"))?;
    validate(path, raw)
}

/// Remove //, /* */ comments and trailing commas outside strings. Two passes:
/// comments first, then trailing commas — a comment between a comma and the
/// closing bracket must not defeat the lookahead.
fn strip_jsonc(text: &str) -> String {
    strip_trailing_commas(&strip_comments(text))
}

/// Remove // and /* */ comments outside strings; comments become a single
/// space (line comments keep their newline for stable error positions).
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' => match chars.peek() {
                Some('/') => {
                    for n in chars.by_ref() {
                        if n == '\n' {
                            out.push(n);
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut closed = false;
                    while let Some(n) = chars.next() {
                        if n == '*' && chars.peek() == Some(&'/') {
                            chars.next();
                            closed = true;
                            break;
                        }
                    }
                    if !closed {
                        // Unterminated comment: keep the JSON error path strict.
                        out.push_str("/*");
                    }
                    out.push(' ');
                }
                _ => out.push('/'),
            },
            _ => out.push(c),
        }
    }
    out
}

/// Drop commas whose next non-whitespace char closes a block (`,]` / `,}`).
fn strip_trailing_commas(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            ',' => {
                let next = chars.clone().skip_while(|c| c.is_whitespace()).next();
                if next != Some('}') && next != Some(']') {
                    out.push(',');
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn validate(path: &Path, raw: RawConfig) -> Result<Config, String> {
    if raw.version != 1 {
        return Err(format!(
            "config invalid: version must be 1, got {}",
            raw.version
        ));
    }
    if let Some(defaults) = &raw.defaults {
        if let Some(action) = &defaults.action {
            // RawDefaultAction has only Ask; match to make future variants loud.
            match action {
                RawDefaultAction::Ask => {}
            }
        }
    }

    let limits = resolve_limits(raw.limits.as_ref())?;
    if raw.stages.len() > limits.stages {
        return Err(format!(
            "config invalid: {} stages exceed the limit {}",
            raw.stages.len(),
            limits.stages
        ));
    }
    if raw.stages.is_empty() {
        return Err("config invalid: stages must contain at least 1 item".into());
    }

    let mut stages = Vec::with_capacity(raw.stages.len());
    for (i, s) in raw.stages.into_iter().enumerate() {
        let stage = validate_stage(s).map_err(|e| format!("config invalid: stages[{i}]: {e}"))?;
        if stages.iter().any(|x: &Stage| x.id == stage.id) {
            return Err(format!(
                "config invalid: stages[{i}]: duplicate stage id `{}`",
                stage.id
            ));
        }
        stages.push(stage);
    }

    Ok(Config {
        source: path.to_path_buf(),
        loaded_at: crate::clock::now_rfc3339(),
        limits,
        stages,
    })
}

fn resolve_limits(raw: Option<&RawLimits>) -> Result<Limits, String> {
    let d = |v: Option<u64>, def: usize| -> Result<usize, String> {
        match v {
            None => Ok(def),
            Some(n) => {
                usize::try_from(n).map_err(|_| "config invalid: limits value too large".to_string())
            }
        }
    };
    let limits = Limits {
        stages: d(raw.and_then(|l| l.stages), DEFAULT_STAGES_LIMIT)?,
        config_bytes: d(raw.and_then(|l| l.config_bytes), DEFAULT_CONFIG_BYTES)?,
        facts_bytes: d(raw.and_then(|l| l.facts_bytes), DEFAULT_FACTS_BYTES)?,
        facts_depth: d(raw.and_then(|l| l.facts_depth), DEFAULT_FACTS_DEPTH)?,
        max_concurrent_tools: d(
            raw.and_then(|l| l.max_concurrent_tools),
            DEFAULT_MAX_CONCURRENT_TOOLS,
        )?,
    };
    // Schema bounds (shell-warden.config.v1.schema.json): stages 1..=64,
    // configBytes ≤ 262144. The file-size cap is enforced in parse_text too.
    if limits.stages == 0 || limits.stages > 64 {
        return Err(format!(
            "config invalid: limits.stages must be 1..=64, got {}",
            limits.stages
        ));
    }
    if limits.config_bytes > DEFAULT_CONFIG_BYTES {
        return Err(format!(
            "config invalid: limits.config_bytes must be ≤ {}",
            DEFAULT_CONFIG_BYTES
        ));
    }
    Ok(limits)
}

/// `^[a-z][a-z0-9-]{0,31}$` without a regex dependency.
fn valid_stage_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    let rest = chars.count();
    rest <= 31
        && id
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Expand `{env:NAME}` (whole-string form) from the engine's environment at
/// config load; unset ⇒ config invalid (06 §6.4.1, fail-closed).
fn expand_env(spec: &str) -> Result<String, String> {
    if let Some(name) = spec.strip_prefix("{env:").and_then(|s| s.strip_suffix('}')) {
        if name.is_empty() {
            return Err("config invalid: empty {{env:}} reference".into());
        }
        std::env::var(name).map_err(|_| {
            format!("config invalid: {{env:{name}}} is not set in the engine environment")
        })
    } else {
        Ok(spec.to_string())
    }
}

fn validate_stage(raw: RawStage) -> Result<Stage, String> {
    match raw.r#type {
        RawStageType::Tool => {}
    }
    if !valid_stage_id(&raw.id) {
        return Err(format!(
            "id `{}` must match ^[a-z][a-z0-9-]{{0,31}}$",
            raw.id
        ));
    }
    let tool = validate_tool(raw.tool)?;
    let message_mode = match raw.message_mode {
        Some(RawMessageMode::Append) | None => MessageMode::Append,
        Some(RawMessageMode::Replace) => MessageMode::Replace,
    };
    let budget = match raw.budget {
        None => None,
        Some(b) => {
            // 06 §6.6 semantics need the pair; schema leaves each optional,
            // the engine requires both together (stricter, fail-closed).
            let max_rejections = b
                .max_rejections
                .ok_or("budget.maxRejections is required together with windowMs")?;
            let window_ms = b
                .window_ms
                .ok_or("budget.windowMs is required together with maxRejections")?;
            if !(1..=10).contains(&max_rejections) {
                return Err(format!(
                    "budget.maxRejections must be 1..=10, got {max_rejections}"
                ));
            }
            if window_ms < 60_000 {
                return Err(format!("budget.windowMs must be ≥ 60000, got {window_ms}"));
            }
            Some(Budget {
                max_rejections: max_rejections as u32,
                window_ms,
            })
        }
    };
    Ok(Stage {
        id: raw.id,
        tool,
        message_mode,
        exclusive: raw.exclusive.unwrap_or(false),
        budget,
        enabled: raw.enabled.unwrap_or(true),
    })
}

fn validate_tool(raw: RawTool) -> Result<ToolSpec, String> {
    if raw.command.is_empty() {
        return Err("tool.command must contain at least 1 item".into());
    }
    let mut argv = Vec::with_capacity(raw.command.len());
    for (i, member) in raw.command.into_iter().enumerate() {
        let expanded = expand_env(&member).map_err(|e| format!("tool.command[{i}]: {e}"))?;
        if i == 0 && !expanded.starts_with('/') {
            return Err(format!(
                "tool.command[0] must be absolute after expansion, got `{expanded}`"
            ));
        }
        argv.push(expanded);
    }

    let mut env_set = Vec::new();
    let mut env_unset = Vec::new();
    if let Some(env) = raw.env {
        for (key, value) in env {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(format!("tool.env: invalid key `{key}`"));
            }
            match value {
                Some(v) => {
                    let expanded = expand_env(&v).map_err(|e| format!("tool.env.{key}: {e}"))?;
                    env_set.push((key, expanded));
                }
                None => env_unset.push(key),
            }
        }
    }

    let lifecycle = match raw.lifecycle {
        Some(RawLifecycle::Persistent) | None => Lifecycle::Persistent,
        Some(RawLifecycle::Spawn) => Lifecycle::Spawn,
    };
    if let Some(idle) = raw.idle_timeout_ms {
        // Schema minimum 30000.
        if idle < 30_000 {
            return Err(format!("tool.idleTimeoutMs must be ≥ 30000, got {idle}"));
        }
    }
    let timeout_ms = raw.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if timeout_ms == 0 || timeout_ms > 30_000 {
        return Err(format!(
            "tool.timeoutMs must be 1..=30000, got {timeout_ms}"
        ));
    }
    let kill_grace_ms = raw.kill_grace_ms.unwrap_or(DEFAULT_KILL_GRACE_MS);
    if !(50..=2_000).contains(&kill_grace_ms) {
        return Err(format!(
            "tool.killGraceMs must be 50..=2000, got {kill_grace_ms}"
        ));
    }
    let max_output_bytes = raw
        .max_output_bytes
        .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES as u64);
    if !(1_024..=1_048_576).contains(&max_output_bytes) {
        return Err(format!(
            "tool.maxOutputBytes must be 1024..=1048576, got {max_output_bytes}"
        ));
    }
    let on_error = match raw.on_error {
        Some(RawOnError::Skip) => OnError::Skip,
        Some(RawOnError::Ask) | None => OnError::Ask,
        Some(RawOnError::Deny) => OnError::Deny,
    };
    if let Some(sha) = &raw.sha256 {
        if !valid_sha256(sha) {
            return Err("tool.sha256 must be a lowercase 64-char hex string or null".into());
        }
    }

    // Stdin letter composition (06 §6.4.2): command{raw,cwd} is always sent;
    // session/mcp are opt-in via tool.input. Data minimization by default (I6/T8).
    let (input_session_id, input_session_agent, input_mcp) = match &raw.input {
        None => (false, false, false),
        Some(input) => match &input.session {
            None => (false, false, input.mcp.unwrap_or(false)),
            Some(session) => (
                session.id.unwrap_or(false),
                session.agent.unwrap_or(false),
                input.mcp.unwrap_or(false),
            ),
        },
    };

    Ok(ToolSpec {
        argv,
        cwd: raw.cwd,
        env_set,
        env_unset,
        lifecycle,
        idle_timeout_ms: raw.idle_timeout_ms,
        timeout_ms,
        kill_grace_ms,
        max_output_bytes: max_output_bytes as usize,
        on_error,
        sha256: raw.sha256.filter(|s| !s.is_empty()),
        input_session_id,
        input_session_agent,
        input_mcp,
    })
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ── Reload watcher (05 §5.3: poll, valid → atomic swap, invalid → last-good) ────

#[derive(Debug, Default)]
pub struct ConfigWatcher {
    path: PathBuf,
    last_modified: Option<SystemTime>,
    last_len: u64,
}

impl ConfigWatcher {
    pub fn new(path: &Path) -> Self {
        let mut w = ConfigWatcher {
            path: path.to_path_buf(),
            ..Default::default()
        };
        if let Ok(m) = std::fs::metadata(path) {
            w.last_modified = m.modified().ok();
            w.last_len = m.len();
        }
        w
    }

    /// True when the file changed since the last observation (mtime or size).
    /// Missing file counts as a change exactly once (watcher resets to absent).
    pub fn poll(&mut self) -> bool {
        let meta = std::fs::metadata(&self.path).ok();
        let (mod_t, len) = match &meta {
            Some(m) => (m.modified().ok(), m.len()),
            None => (None, 0),
        };
        let changed = mod_t != self.last_modified || len != self.last_len;
        self.last_modified = mod_t;
        self.last_len = len;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_config(stages: serde_json::Value) -> String {
        json!({ "version": 1, "stages": stages }).to_string()
    }

    fn stage_json() -> serde_json::Value {
        json!({
            "id": "s1",
            "type": "tool",
            "tool": { "command": ["/bin/warden-s1"], "timeoutMs": 1000 }
        })
    }

    fn parse(text: &str) -> Result<Config, String> {
        parse_text(Path::new("/cfg/config.jsonc"), text)
    }

    #[test]
    fn minimal_valid_config_parses() {
        let cfg = parse(&ok_config(json!([stage_json()]))).expect("valid");
        assert_eq!(cfg.stages.len(), 1);
        assert_eq!(cfg.stages[0].id, "s1");
        assert_eq!(cfg.stages[0].message_mode, MessageMode::Append);
        assert!(!cfg.stages[0].exclusive);
        assert!(cfg.stages[0].enabled);
        assert_eq!(cfg.stages[0].tool.on_error, OnError::Ask);
        assert_eq!(cfg.stages[0].tool.lifecycle, Lifecycle::Persistent);
        assert_eq!(cfg.stages[0].tool.timeout_ms, 1000); // fixture sets it explicitly
        // No input block → minimal letter (command/cwd only).
        assert!(!cfg.stages[0].tool.input_session_id);
        assert!(!cfg.stages[0].tool.input_mcp);
    }

    #[test]
    fn unknown_keys_are_rejected_everywhere() {
        let mut v = json!({ "version": 1, "stages": [stage_json()] });
        v["extra"] = json!(1);
        assert!(parse(&v.to_string()).is_err(), "top-level unknown key");

        let mut s = stage_json();
        s["extra"] = json!(1);
        assert!(parse(&ok_config(json!([s]))).is_err(), "stage unknown key");

        let mut s = stage_json();
        s["tool"]["extra"] = json!(1);
        assert!(parse(&ok_config(json!([s]))).is_err(), "tool unknown key");

        let mut s = stage_json();
        s["tool"]["input"] = json!({ "session": { "id": true, "nope": false } });
        assert!(parse(&ok_config(json!([s]))).is_err(), "input unknown key");

        let mut s = stage_json();
        s["budget"] = json!({ "maxRejections": 3, "nope": 1 });
        assert!(parse(&ok_config(json!([s]))).is_err(), "budget unknown key");
    }

    #[test]
    fn version_must_be_exactly_1() {
        let v = json!({ "version": 2, "stages": [stage_json()] });
        let err = parse(&v.to_string()).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn stages_cap_is_hard() {
        let mut stages = Vec::new();
        for i in 0..65 {
            let mut s = stage_json();
            s["id"] = json!(format!("s{i:02}"));
            stages.push(s);
        }
        let v = json!({ "version": 1, "stages": stages });
        let err = parse(&v.to_string()).unwrap_err();
        assert!(err.contains("exceed the limit 64"), "{err}");
    }

    #[test]
    fn stage_id_pattern_and_uniqueness_enforced() {
        let mut s = stage_json();
        s["id"] = json!("S1");
        assert!(parse(&ok_config(json!([s]))).is_err(), "uppercase rejected");
        let mut s = stage_json();
        s["id"] = json!("1s");
        assert!(
            parse(&ok_config(json!([s]))).is_err(),
            "leading digit rejected"
        );
        let mut s = stage_json();
        s["id"] = json!("tool with space");
        assert!(parse(&ok_config(json!([s]))).is_err(), "space rejected");
        let mut s2 = stage_json();
        s2["id"] = json!("s1");
        let dup = ok_config(json!([stage_json(), s2]));
        assert!(parse(&dup).is_err(), "duplicate id rejected");
        let mut s = stage_json();
        s["id"] = json!("a-9z");
        assert!(
            parse(&ok_config(json!([s]))).is_ok(),
            "lowercase/digits/dash ok"
        );
    }

    #[test]
    fn on_error_allow_is_not_in_the_enum() {
        let mut s = stage_json();
        s["tool"]["onError"] = json!("allow");
        let err = parse(&ok_config(json!([s]))).unwrap_err();
        assert!(err.contains("config invalid"), "{err}");
    }

    #[test]
    fn tool_bounds_match_schema() {
        let cases: Vec<(serde_json::Value, bool)> = vec![
            (json!({ "command": [] }), false),               // empty argv
            (json!({ "command": ["bin/relative"] }), false), // relative argv0
            (json!({ "command": ["/bin/x"], "timeoutMs": 0 }), false),
            (json!({ "command": ["/bin/x"], "timeoutMs": 30001 }), false),
            (json!({ "command": ["/bin/x"], "timeoutMs": 30000 }), true),
            (json!({ "command": ["/bin/x"], "killGraceMs": 49 }), false),
            (json!({ "command": ["/bin/x"], "killGraceMs": 2000 }), true),
            (
                json!({ "command": ["/bin/x"], "maxOutputBytes": 1024 }),
                true,
            ),
            (
                json!({ "command": ["/bin/x"], "maxOutputBytes": 1023 }),
                false,
            ),
            (
                json!({ "command": ["/bin/x"], "idleTimeoutMs": 29999 }),
                false,
            ),
            (
                json!({ "command": ["/bin/x"], "idleTimeoutMs": 30000 }),
                true,
            ),
            (json!({ "command": ["/bin/x"], "sha256": "ZZ" }), false),
            (
                json!({ "command": ["/bin/x"], "sha256": serde_json::Value::Null }),
                true,
            ),
            (
                json!({ "command": ["/bin/x"], "sha256": "a".repeat(64) }),
                true,
            ),
            (json!({ "command": ["/bin/x"], "lifecycle": "spawn" }), true),
            (
                json!({ "command": ["/bin/x"], "lifecycle": "zombie" }),
                false,
            ),
        ];
        for (tool, expect_ok) in cases {
            let mut s = stage_json();
            s["tool"] = tool;
            let res = parse(&ok_config(json!([s])));
            assert_eq!(res.is_ok(), expect_ok, "case: {res:?}");
        }
    }

    #[test]
    fn env_expansion_resolves_from_engine_environment_or_fails() {
        // Unset reference → invalid.
        let mut s = stage_json();
        s["tool"]["command"] = json!(["{env:WARDEN_TEST_UNSET_VAR_XYZ}"]);
        assert!(parse(&ok_config(json!([s]))).is_err());

        // SAFETY: test-only; no other threads are reading the environment
        unsafe { std::env::set_var("WARDEN_TEST_VAR_ABC", "/opt/tools/warden") };
        let mut s = stage_json();
        s["tool"]["command"] = json!(["{env:WARDEN_TEST_VAR_ABC}", "--flag"]);
        let cfg = parse(&ok_config(json!([s]))).expect("valid");
        assert_eq!(cfg.stages[0].tool.argv, vec!["/opt/tools/warden", "--flag"]);

        // env patch: set + expand + null removal.
        let mut s = stage_json();
        s["tool"]["env"] = json!({
            "WARDEN_MODE": "strict",
            "WARDEN_TOKEN": "{env:WARDEN_TEST_VAR_ABC}",
            "GITHUB_TOKEN": null
        });
        let cfg = parse(&ok_config(json!([s]))).expect("valid");
        let t = &cfg.stages[0].tool;
        assert!(t.env_set.contains(&("WARDEN_MODE".into(), "strict".into())));
        assert!(
            t.env_set
                .contains(&("WARDEN_TOKEN".into(), "/opt/tools/warden".into()))
        );
        assert!(t.env_unset.contains(&"GITHUB_TOKEN".to_string()));
    }

    #[test]
    fn budget_requires_the_pair_and_bounds() {
        let mut s = stage_json();
        s["budget"] = json!({ "maxRejections": 3 });
        assert!(parse(&ok_config(json!([s]))).is_err(), "windowMs missing");
        let mut s = stage_json();
        s["budget"] = json!({ "windowMs": 60_000 });
        assert!(
            parse(&ok_config(json!([s]))).is_err(),
            "maxRejections missing"
        );
        let mut s = stage_json();
        s["budget"] = json!({ "maxRejections": 11, "windowMs": 60_000 });
        assert!(parse(&ok_config(json!([s]))).is_err(), "maxRejections > 10");
        let mut s = stage_json();
        s["budget"] = json!({ "maxRejections": 3, "windowMs": 59_999 });
        assert!(parse(&ok_config(json!([s]))).is_err(), "windowMs < 60000");
        let mut s = stage_json();
        s["budget"] = json!({ "maxRejections": 3, "windowMs": 1_800_000 });
        let cfg = parse(&ok_config(json!([s]))).expect("valid budget");
        assert_eq!(
            cfg.stages[0].budget,
            Some(Budget {
                max_rejections: 3,
                window_ms: 1_800_000
            })
        );
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_are_tolerated() {
        let text = r#"{
            // user-global stages
            "version": 1, /* block comment */
            "stages": [
                { "id": "s1", "type": "tool", "tool": { "command": ["/bin/x"] } }, // trailing comma
            ],
        }"#;
        let cfg = parse(text).expect("jsonc tolerated");
        assert_eq!(cfg.stages[0].id, "s1");
    }

    #[test]
    fn jsonc_stripper_preserves_comment_like_text_inside_strings() {
        let text = r#"{ "version": 1, "stages": [ { "id": "s1", "type": "tool",
            "tool": { "command": ["/bin/x"], "env": { "NOTE": "a // b /* c */ , x" } } } ] }"#;
        let cfg = parse(text).expect("string contents untouched");
        assert_eq!(cfg.stages[0].tool.env_set[0].1, "a // b /* c */ , x");
    }

    #[test]
    fn defaults_action_only_accepts_ask() {
        let v =
            json!({ "version": 1, "defaults": { "action": "allow" }, "stages": [stage_json()] });
        assert!(parse(&v.to_string()).is_err());
        let v = json!({ "version": 1, "defaults": { "action": "ask" }, "stages": [stage_json()] });
        assert!(parse(&v.to_string()).is_ok());
    }

    #[test]
    fn stage_type_must_be_tool() {
        let mut s = stage_json();
        s["type"] = json!("rule");
        assert!(parse(&ok_config(json!([s]))).is_err());
        let mut s = stage_json();
        s.as_object_mut().unwrap().remove("type");
        assert!(
            parse(&ok_config(json!([s]))).is_err(),
            "type is required by schema"
        );
    }

    #[test]
    fn oversized_config_text_is_rejected() {
        let mut s = stage_json();
        s["tool"]["cwd"] = json!("x".repeat(300_000));
        assert!(parse(&ok_config(json!([s]))).is_err());
    }
}
