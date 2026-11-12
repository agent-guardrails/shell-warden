// Typed evidence layer (design/shell-warden-config-v2.md §Parsing, parts, and
// evidence states + §Closed evidence catalogs and coordinates).
//
// Every executable part carries exactly one evidence state:
//   complete — supported shell syntax, profile option parsing, analyzer
//              processing and resource limits yielded all typed evidence;
//   opaque   — runtime-dependent content whose words/values are not safely
//              known (active expansion, glob/brace/tilde…);
//   invalid  — malformed or unsupported structure, or a resource/evidence
//              limit overflow.
//
// allow may only emit from a `complete` part that passes coverage validation;
// deny/ask may still match the typed classification (e.g. facts) or raw text.

use super::grammar::Relation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState {
    Complete,
    Opaque(&'static str),
    Invalid(&'static str),
}

impl EvidenceState {
    pub fn stable_code(self) -> &'static str {
        match self {
            EvidenceState::Complete => "complete",
            EvidenceState::Opaque(reason) => reason,
            EvidenceState::Invalid(reason) => reason,
        }
    }

    pub fn can_allow(self) -> bool {
        matches!(self, EvidenceState::Complete)
    }
}

/// Stable reason codes (design §Diagnostics and verdict wire).
pub mod reason {
    pub const OPAQUE_EXPANSION: &str = "opaque-expansion";
    pub const UNKNOWN_OPTION: &str = "unknown-option";
    pub const OPTION_VALUE_MISSING: &str = "option-value-missing";
    pub const INVALID_INLINE_OPTION: &str = "invalid-inline-option";
    pub const EVIDENCE_LIMIT: &str = "evidence-limit";
    pub const UNSUPPORTED_SYNTAX: &str = "unsupported-syntax";
    pub const EMPTY_COMMAND: &str = "empty-command";
    pub const ALLOW_EVIDENCE_NOT_COMPLETE: &str = "allow-evidence-not-complete";
    pub const ALLOW_COVERAGE_MISSING: &str = "allow-coverage-missing";
    pub const REQUIRED_OPTION_MISSING: &str = "required-option-missing";
    pub const OPTION_NOT_REPEATABLE: &str = "option-not-repeatable";
    pub const OPTION_NOT_ALLOWED: &str = "option-not-allowed";
    pub const OPTION_VALUE_UNCOVERED: &str = "option-value-uncovered";
    pub const REMAINDER_UNCOVERED: &str = "remainder-uncovered";
    pub const REDIRECT_POLICY_UNCOVERED: &str = "redirect-policy-uncovered";
}

/// One positional-argument token (decoded literal; confusion-safe flags).
#[derive(Debug, Clone, PartialEq)]
pub struct ArgToken {
    pub text: String,
    /// Fully known literal value. `false` ⇒ opaque (`\$…` marker kept).
    pub resolvable: bool,
    pub span: (usize, usize),
}

/// Environment assignment evidence: literal name + literal value.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvAssign {
    pub name: String,
    pub text: String,
    pub resolvable: bool,
    pub span: (usize, usize),
    /// 1-based occurrence ordinal in source order within the part.
    pub ordinal: u32,
}

/// Redirect evidence: closed operator, source FD (None = default), typed
/// target (literal path or FD duplication), per occurrence.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectObs {
    /// None ⇒ unsupported operator form ⇒ invalid evidence (fail-closed).
    pub op: Option<super::grammar::RedirectOp>,
    pub source_fd: Option<u32>,
    pub target: String,
    pub target_resolvable: bool,
    pub is_fd_target: bool,
    pub span: (usize, usize),
    /// 1-based occurrence ordinal in source order within the part.
    pub ordinal: u32,
}

/// Analyzer fact evidence (closed catalogs; safety-relevant ones need allow
/// coverage).
#[derive(Debug, Clone, PartialEq)]
pub struct FactObs {
    pub analyzer_id: &'static str,
    pub fact_name: String,
    /// Typed (string) fact value.
    pub value: String,
    pub occurrence: u32,
    pub safety_relevant: bool,
}

/// One executable part: the complete recursive part/evidence graph node.
#[derive(Debug, Clone, PartialEq)]
pub struct Part {
    pub id: usize,
    pub parent: Option<usize>,
    pub relation: Relation,
    /// Occurrence ordinal among same-relation siblings under the parent.
    pub relation_ordinal: u32,
    pub raw: String,
    /// Environment assignments (`FOO=1 cmd` / `export FOO=…` facts), source
    /// order.
    pub assigns: Vec<EnvAssign>,
    /// Decoded argv tokens (raw argument order, pre-option parsing).
    pub argv: Vec<ArgToken>,
    pub redirects: Vec<RedirectObs>,
    /// Analyzer facts (filled by the pipeline stage after profile selection).
    pub facts: Vec<FactObs>,
    pub state: EvidenceState,
    /// `--` boundary position: option recognition ends here; every token
    /// after it is a positional argument. None = no `--` seen.
    pub dashdash: Option<usize>,
}

impl Part {
    pub fn is_complete(&self) -> bool {
        matches!(self.state, EvidenceState::Complete)
    }
}

/// Aggregate evidence for one letter command (root parts + nested graph).
#[derive(Debug, Clone)]
pub struct CommandEvidence {
    pub parts: Vec<Part>,
    /// Stable reason codes seen anywhere in the graph.
    pub reasons: Vec<&'static str>,
    /// True when the evidence-item cap blocked further collection.
    pub overflow: bool,
    /// Parts transparently unwrapped into wrapper children (the wrapper's
    /// own argv was re-evaluated as the child part); they carry no
    /// independent execution and no votes of their own.
    pub collapsed: Vec<usize>,
}

impl CommandEvidence {
    #[allow(dead_code)]
    pub fn empty(_raw: &str) -> Self {
        CommandEvidence {
            parts: Vec::new(),
            reasons: Vec::new(),
            overflow: false,
            collapsed: Vec::new(),
        }
    }
}
