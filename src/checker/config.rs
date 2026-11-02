// Config loader (06 §6.1): strict validation, fail-closed. Invalid ⇒ error
// (bin exits 2 with the message on stderr) — never fall back to defaults.

use super::grammar::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

// re-exported for pipeline/src access

pub type ConfigResult = Result<Config, String>;

pub use super::grammar::Config;

pub struct LoadedConfig {
    pub config: Config,
    /// Absolute path after expansion (§4.2 `{env:NAME}` substitution).
    pub path: PathBuf,
}

/// Default path: `$XDG_CONFIG_HOME/shell-warden/config.jsonc`, falling back to
/// `~/.config/shell-warden/config.jsonc` (06 §6.1).
pub fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() && xdg.starts_with('/') {
            return Some(PathBuf::from(xdg).join("shell-warden").join("config.jsonc"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() && home.starts_with('/') {
            return Some(PathBuf::from(home).join(".config/shell-warden/config.jsonc"));
        }
    }
    None
}

/// `{env:NAME}` substitution in argv members (resolved from the *hook* process
/// env is the hook's duty; the checker suffers only an absolute file path).
pub fn expand_env(path: &str) -> Result<PathBuf, String> {
    let mut out = path.to_string();
    for key in extract_env_names(path) {
        match std::env::var(&key) {
            Ok(v) => out = out.replace(&format!("{{env:{key}}}"), &v),
            Err(_) => {
                return Err(format!(
                    "{{env:{key}}} unset in argv member \"{path}\" — config invalid (I2)"
                ))
            }
        }
    }
    if !out.starts_with('/') {
        return Err(format!(
            "argv member \"{path}\" must resolve to an absolute path — config invalid (I2)"
        ));
    }
    Ok(PathBuf::from(out))
}

fn extract_env_names(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if &s[i..i + 5] == "{env:" {
            if let Some(close) = s[i..].find('}') {
                out.push(s[i + 5..i + close].to_string());
                i += close + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Load + validate from a path. Returns the error string for exit-2 semantics.
pub fn load_path(path: &Path) -> ConfigResult {
    let bytes =
        std::fs::read(path).map_err(|e| format!("config unreadable: {}: {e}", path.display()))?;
    let text =
        String::from_utf8(bytes).map_err(|_| "config invalid: file is not UTF-8".to_string())?;
    load_str(&text)
}

/// Load + validate from a string (used by golden tests directly).
pub fn load_str(text: &str) -> ConfigResult {
    if text.len() > Limits::default().config_bytes as usize {
        return Err(format!(
            "config invalid: {} bytes exceeds configBytes cap {}",
            text.len(),
            Limits::default().config_bytes
        ));
    }
    let stripped =
        strip_jsonc(text).map_err(|e| format!("config invalid: JSONC syntax error: {e}"))?;
    let value: Value =
        serde_json::from_str(&stripped).map_err(|e| format!("config invalid: JSON error: {e}"))?;
    let config: Config = serde_json::from_value(value.clone())
        .map_err(|e| format!("config invalid: schema: {e}"))?;
    validate(&config).map(|_| config)
}

// ── Validation (06 §6.2–6.3; mirrors config schema bounds) ──────────────────

pub fn validate(c: &Config) -> Result<(), String> {
    if c.version != 1 {
        return Err(format!(
            "config invalid: version must be 1 (got {})",
            c.version
        ));
    }
    if c.defaults.action != VerdictKind::Ask {
        return Err("config invalid: defaults.action is always ask (never fail-open)".to_string());
    }
    if c.defaults
        .message
        .as_deref()
        .map(|m| m.len() > 512)
        .unwrap_or(false)
    {
        return Err("config invalid: defaults.message exceeds 512 chars".to_string());
    }
    // Limits are bounded by schema maxima regardless of what the file claims.
    if c.limits.stages > 64 || c.limits.rules > 512 || c.limits.config_bytes > 262_144 {
        return Err("config invalid: limits above schema maxima (stages ≤ 64, rules ≤ 512, configBytes ≤ 262144)".to_string());
    }
    if c.limits.stages == 0 || c.limits.rules == 0 {
        return Err("config invalid: limits.stages/rules must be ≥ 1".to_string());
    }
    if c.stages.is_empty() {
        return Err("config invalid: stages must not be empty".to_string());
    }
    if c.stages.len() > c.limits.stages as usize {
        return Err(format!(
            "config invalid: {} stages exceeds limits.stages {}",
            c.stages.len(),
            c.limits.stages
        ));
    }
    let total_rules = c.stages.iter().map(|s| s.rules.len()).sum::<usize>();
    if total_rules > c.limits.rules as usize {
        return Err(format!(
            "config invalid: {total_rules} rules exceeds limits.rules {}",
            c.limits.rules
        ));
    }

    let mut stage_ids = std::collections::BTreeSet::new();
    let mut rule_ids = std::collections::BTreeSet::new();
    for stage in &c.stages {
        validate_id(stage.id.as_str(), "stage id").map_err(|e| format!("config invalid: {e}"))?;
        if !stage_ids.insert(stage.id.clone()) {
            return Err(format!(
                "config invalid: duplicate stage id \"{}\"",
                stage.id
            ));
        }
        if stage.scope.any_of.is_empty() {
            return Err(format!(
                "config invalid: stage \"{}\" scope.anyOf is empty",
                stage.id
            ));
        }
        for (flag, arity) in &stage.flags {
            if !is_valid_flag_name(flag) {
                return Err(format!(
                    "config invalid: stage \"{}\" flag \"{flag}\" is not a well-formed flag name",
                    stage.id
                ));
            }
            if *arity > 4 {
                return Err(format!(
                    "config invalid: stage \"{}\" flag \"{flag}\" arity {arity} > 4",
                    stage.id
                ));
            }
        }
        for condition in &stage.scope.any_of {
            if let Some(argv) = &condition.argv {
                if argv.0.is_empty() {
                    return Err(format!(
                        "config invalid: stage \"{}\" condition argv is empty",
                        stage.id
                    ));
                }
            }
            if let Some(pattern) = &condition.pattern {
                if pattern.is_empty() {
                    return Err(format!(
                        "config invalid: stage \"{}\" condition pattern is empty",
                        stage.id
                    ));
                }
            }
        }
        for rule in &stage.rules {
            validate_rule(rule, stage).map_err(|e| format!("config invalid: {e}"))?;
            if !rule_ids.insert(rule.id.clone()) {
                return Err(format!("config invalid: duplicate rule id \"{}\"", rule.id));
            }
        }
    }
    Ok(())
}

fn validate_rule(rule: &Rule, stage: &Stage) -> Result<(), String> {
    validate_id(rule.id.as_str(), "rule id")
        .map_err(|e| e.replacen("rule id", &format!("rule id \"{}\"", rule.id), 1))?;
    if rule.action == VerdictKind::Allow {
        // Matching vocabulary: allow never originates from raw/partial evidence.
        if rule.pattern.is_some() {
            return Err(format!(
                "rule \"{}\": allow rules must not carry a pattern condition (07 §7.6)",
                rule.id
            ));
        }
        if rule.classification == Some(Classification::Opaque) {
            return Err(format!(
                "rule \"{}\": allow rules must not require classification opaque",
                rule.id
            ));
        }
        if rule.message.is_some() {
            return Err(format!(
                "rule \"{}\": allow rules carry no message",
                rule.id
            ));
        }
    }
    if rule.action != VerdictKind::Allow && rule.message.is_none() {
        // SHOULD-have; absence falls back to defaults.message. Not an error.
    }
    if let Some(argv) = &rule.argv {
        if argv.0.is_empty() {
            return Err(format!("rule \"{}\": argv condition is empty", rule.id));
        }
    }
    // `argValue` globs must be non-empty
    if let Some(globs) = &rule.arg_value {
        if globs.is_empty() {
            return Err(format!("rule \"{}\": argValue list is empty", rule.id));
        }
        for g in globs {
            if g.is_empty() {
                return Err(format!("rule \"{}\": argValue glob is empty", rule.id));
            }
        }
    }
    // Flag references must exist in the stage table, checked against arity too.
    if let Some(flags) = &rule.flag {
        for flag in flags.keys() {
            if !stage.flags.contains_key(flag) {
                return Err(format!(
                    "rule \"{}\": flag \"{flag}\" is not in stage \"{}\" flags table",
                    rule.id, stage.id
                ));
            }
        }
    }
    if let Some(flag_values) = &rule.flag_value {
        for (flag, glob) in flag_values {
            if !stage.flags.contains_key(flag) {
                return Err(format!(
                    "rule \"{}\": flagValue \"{flag}\" is not in stage \"{}\" flags table",
                    rule.id, stage.id
                ));
            }
            if glob.is_empty() {
                return Err(format!(
                    "rule \"{}\": flagValue \"{flag}\" glob is empty",
                    rule.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_id(id: &str, what: &str) -> Result<(), String> {
    let mut chars = id.chars();
    let first = chars.next();
    let ok = match first {
        Some(c) if c.is_ascii_lowercase() => chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/' || c == '.'
        }),
        _ => false,
    };
    if !ok {
        return Err(format!(
            "{what} \"{id}\" must match ^[a-z][a-z0-9/.-]{{0,63}}$"
        ));
    }
    if id.len() > 64 {
        return Err(format!("{what} \"{id}\" exceeds 63 chars"));
    }
    Ok(())
}

fn is_valid_flag_name(flag: &str) -> bool {
    // short cluster `-rf` and long `--force` / `--long=x` shells; keys of the
    // stage table are base names only (inline values are not config keys)
    if flag == "-" || flag == "--" {
        return false;
    }
    let body = if let Some(rest) = flag.strip_prefix("--") {
        rest
    } else if let Some(rest) = flag.strip_prefix('-') {
        rest
    } else {
        return false;
    };
    !body.is_empty()
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && body
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
}

// ── JSONC comment stripping (line + block), string-aware ─────────────────────

fn strip_jsonc(input: &str) -> Result<String, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            // copy the string literal verbatim
            let start = i;
            let mut j = i + 1;
            let mut escaped = false;
            while j < chars.len() {
                let ch = chars[j];
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    break;
                }
                j += 1;
            }
            if j >= chars.len() {
                return Err("unterminated string literal".to_string());
            }
            out.extend(chars[start..=j].iter());
            i = j + 1;
            continue;
        }
        if c == '/' && i + 1 < chars.len() {
            if chars[i + 1] == '/' {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if chars[i + 1] == '*' {
                match chars[i + 2..]
                    .iter()
                    .position(|ch| *ch == '*')
                    .and_then(|k| {
                        if chars.get(i + 3 + k) == Some(&'/') {
                            Some(i + 3 + k)
                        } else {
                            None
                        }
                    }) {
                    Some(end) => {
                        i = end + 1;
                        continue;
                    }
                    None => return Err("unterminated block comment".to_string()),
                }
            }
        }
        out.push(c);
        i += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_worked_sketch_from_adr() {
        // The exact config sketch of ADR-0016.
        let src = r#"{
          "version": 1,
          "defaults": { "action": "ask" },
          "stages": [
            { "id": "vcs",
              "scope":  { "anyOf": [ { "argv": ["git"] } ] },
              "flags":  { "-f": 0, "--force": 0, "-C": 1, "-m": 1 },
              "rules": [
                { "id": "vcs/no-force-push",
                  "argv": ["push"], "flag": { "--force": "present" },
                  "action": "deny", "message": "push --force is forbidden — history is protected" },
                { "id": "vcs/allow-inspection",
                  "argv": [ { "anyOf": ["status", "log", "diff"] } ],
                  "action": "allow" }
              ] },
            { "id": "docker",
              "scope":  { "anyOf": [ { "argv": ["docker"] }, { "pattern": "docker *" } ] },
              "flags":  { "-v": 1, "-d": 0 },
              "rules": [
                { "id": "docker/no-root-mount",
                  "argv": ["run"], "flagValue": { "-v": ":/:*" },
                  "action": "deny", "message": "do not mount / into the container" }
              ] },
            { "id": "catch-all",
              "scope":  { "anyOf": [ { "pattern": "*" } ] },
              "flags":  {}, "rules": [] }
          ]
        }"#;
        let cfg = load_str(src).expect("sketch must load");
        assert_eq!(cfg.stages.len(), 3);
        assert_eq!(cfg.stages[0].rules.len(), 2);
    }

    #[test]
    fn rejects_defaults_allow() {
        let err = load_str(r#"{"version":1,"defaults":{"action":"allow"},"stages":[{"id":"s","scope":{"anyOf":[{"pattern":"*"}]},"flags":{},"rules":[]}]}"#).unwrap_err();
        assert!(err.contains("always ask"), "got: {err}");
    }

    #[test]
    fn rejects_wrong_version() {
        let src = r#"{"version":2,"stages":[{"id":"s","scope":{"anyOf":[{"pattern":"*"}]},"flags":{},"rules":[]}]}"#;
        assert!(load_str(src).unwrap_err().contains("version must be 1"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let src = r#"{"version":1,"stages":[{"id":"s","scope":{"anyOf":[{"pattern":"*"}]},"flags":{},"rules":[],"tool":{"command":["/bin/x"]}}]}"#;
        let err = load_str(src).unwrap_err();
        assert!(err.contains("schema") || err.contains("tool"), "got: {err}");
    }

    #[test]
    fn rejects_flag_not_in_stage_table() {
        let src = r#"{"version":1,"stages":[{"id":"s","scope":{"anyOf":[{"pattern":"*"}]},"flags":{},"rules":[{"id":"s/r","flag":{"--f":"present"},"action":"deny","message":"m"}]}]}"#;
        let err = load_str(src).unwrap_err();
        assert!(err.contains("not in stage"), "got: {err}");
    }

    #[test]
    fn rejects_allow_with_pattern() {
        let src = r#"{"version":1,"stages":[{"id":"s","scope":{"anyOf":[{"pattern":"*"}]},"flags":{},"rules":[{"id":"s/r","pattern":"echo *","action":"allow"}]}]}"#;
        assert!(load_str(src)
            .unwrap_err()
            .contains("must not carry a pattern"));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let src = r#"{"version":1,"stages":[{"id":"s","scope":{"anyOf":[{"pattern":"*"}]},"flags":{},"rules":[{"id":"s/r","action":"ask"},{"id":"s/r","action":"ask"}]}]}"#;
        assert!(load_str(src).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn jsonc_comments_pass() {
        let src = r#"{
          // line comment
          "version": 1, /* block
             comment */
          "stages": [ { "id": "s", "scope": { "anyOf": [ { "pattern": "*" } ] }, "flags": {}, "rules": [] } ]
        }"#;
        assert!(load_str(src).is_ok());
    }

    #[test]
    fn jsonc_comment_inside_string_survives() {
        let src = r#"{
          "version": 1,
          "defaults": { "action": "ask", "message": "read http://example.com // not a comment" },
          "stages": [ { "id": "s", "scope": { "anyOf": [ { "pattern": "*" } ] }, "flags": {}, "rules": [] } ]
        }"#;
        let cfg = load_str(src).unwrap();
        assert!(cfg.defaults.message.unwrap().contains("http://example.com"));
    }

    #[test]
    fn empty_scope_anyof_rejected() {
        let src =
            r#"{"version":1,"stages":[{"id":"s","scope":{"anyOf":[]},"flags":{},"rules":[]}]}"#;
        assert!(load_str(src).unwrap_err().contains("anyOf is empty"));
    }
}
