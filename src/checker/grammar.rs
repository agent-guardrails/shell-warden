// Rules grammar v1 (06-engine-config.md, ADR-0016) — serde types mirror
// schemas/shell-warden.config.v1.schema.json exactly; `deny_unknown_fields`
// everywhere = strict validation of unknown keys at parse time.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub limits: Limits,
    pub stages: Vec<Stage>,
}

impl Config {
    pub fn version_is_current(&self) -> bool {
        self.version == 1
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "default_ask")]
    pub action: VerdictKind,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_ask() -> VerdictKind {
    VerdictKind::Ask
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            action: VerdictKind::Ask,
            message: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum VerdictKind {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "ask")]
    Ask,
    #[serde(rename = "deny")]
    Deny,
}

impl VerdictKind {
    /// Most-restrictive ordering (`deny > ask > allow`).
    pub fn rank(self) -> u8 {
        match self {
            VerdictKind::Deny => 2,
            VerdictKind::Ask => 1,
            VerdictKind::Allow => 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct Limits {
    pub config_bytes: u64,
    pub stages: u32,
    pub rules: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            config_bytes: 262_144,
            stages: 64,
            rules: 512,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub id: String,
    pub scope: ConditionGroup,
    pub flags: IndexMapLike, // stable order not needed; BTree-like semantics below
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Stage flag-arity table: flag name → number of consumed value tokens (0–4).
/// Typed as a map but validated in config loader via flag arity range.
pub type IndexMapLike = std::collections::BTreeMap<String, u8>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConditionGroup {
    /// Ordered condition list; a group matches when ANY member matches (§6.3).
    pub any_of: Vec<ScopeCondition>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCondition {
    /// Contiguous token sequence from the part's token list (§6.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<ArgvSequence>,
    /// Raw-string glob on the command text (§6.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArgvSequence(pub Vec<ArgvToken>);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged, deny_unknown_fields, rename_all_fields = "camelCase")]
pub enum ArgvToken {
    Word(String),
    AnyOf { any_of: Vec<String> },
}

impl ArgvToken {
    pub fn matches(&self, token: &str) -> bool {
        match self {
            ArgvToken::Word(s) => s == token,
            ArgvToken::AnyOf { any_of } => any_of.iter().any(|s| s == token),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub action: VerdictKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    // ── conditions (all AND together; zero conditions = match everything) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<ArgvSequence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv_at: Option<Vec<ArgvAt>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag: Option<std::collections::BTreeMap<String, FlagPresence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag_value: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<PathsCondition>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ArgvAt {
    /// 0-based argv token position.
    pub at: usize,
    /// The token that must match at that position.
    pub one: ArgvToken,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum Classification {
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "opaque")]
    Opaque,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum FlagPresence {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "absent")]
    Absent,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct PathsCondition {
    /// Every recorded path resolves inside at least one glob (`$project` allowed).
    pub within: Vec<String>,
    /// Every recorded path resolves inside none of the globs.
    #[serde(default)]
    pub not_within: Vec<String>,
}
