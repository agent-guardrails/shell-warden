// Rules/config grammar v2 (design/shell-warden-config-v2.md): per-executable
// command profiles, typed-evidence match objects, reusable redirect policies.
// Serde types mirror schemas/shell-warden.config.v2.schema.json exactly;
// `deny_unknown_fields` everywhere = strict validation at parse time.
//
// The config-v2 wire grammar declarations live in one contiguous, marked
// region below; `agent-guardrails/docs` (PR 22) snapshots exactly that region
// and fails closed on grammar drift. Keep it contiguous and free of helpers.
//
// `option` is the umbrella term: arity 0 = flag; arity 1..=4 consumes values.
// No v1 compatibility: a v2 checker reads v2 only (design §Migration).

use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 2;
/// Highest declared option arity (design: "arity zero through four").
pub const MAX_OPTION_ARITY: u8 = 4;

// ── Verdict/action vocabulary ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerdictKind {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "ask")]
    Ask,
    #[serde(rename = "deny")]
    Deny,
}

impl VerdictKind {
    /// Monotonic lattice `allow < ask < deny` (design §Lattice reduction).
    pub fn rank(self) -> u8 {
        match self {
            VerdictKind::Allow => 0,
            VerdictKind::Ask => 1,
            VerdictKind::Deny => 2,
        }
    }
}

// ── Top-level config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawConfig {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub redirect_policies: std::collections::BTreeMap<String, RedirectPolicy>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Defaults {
    /// Fixed at `ask` (never fail-open; validated in config loader).
    #[serde(default = "default_ask")]
    pub action: VerdictKind,
    #[serde(default)]
    pub message: Option<String>,
    /// Named redirect policy effective by default for every profile and allow
    /// rule (mandatory when any allow rule exists).
    #[serde(default)]
    pub redirect_policy: Option<String>,
}

fn default_ask() -> VerdictKind {
    VerdictKind::Ask
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            action: VerdictKind::Ask,
            message: None,
            redirect_policy: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[serde(default)]
pub struct Limits {
    pub config_bytes: u64,
    pub profiles: u32,
    pub rules: u32,
    pub evidence_items: u32,
    pub diagnostics_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            config_bytes: 262_144,
            profiles: 256,
            rules: 4096,
            evidence_items: 1024,
            diagnostics_bytes: 16_384,
        }
    }
}

// ── Redirect policies and overrides ─────────────────────────────────────────

/// Named, flat, reusable redirect-policy bundle (design §Reusable redirect
/// policies): redirect structure coverage + redirect-target lexical path
/// coverage as one unit. No inheritance between bundles.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectPolicy {
    pub redirects: RedirectCoverage,
    pub paths: PathCoverage,
}

/// Redirect operator catalog (closed, design §Action-sensitive matching):
/// input, truncate output, append output, and FD duplication. `&>`, heredocs
/// and here-strings are unsupported ⇒ invalid (fail-closed).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedirectOp {
    #[serde(rename = "<")]
    In,
    #[serde(rename = ">")]
    Out,
    #[serde(rename = ">>")]
    AppendOut,
    #[serde(rename = ">&")]
    DupOut,
    #[serde(rename = "<&")]
    DupIn,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectEntry {
    /// Source FD selector: `"default"` (no explicit FD) or an explicit number.
    pub source_fd: FdSelector,
    pub operator: RedirectOp,
    /// Which redirect occurrences matching entries are selected by this entry.
    pub occurrence: Occurrence,
    /// Closed target kind: literal path or FD duplication.
    pub target: TargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FdSelector {
    /// No explicit FD digits (the operator's default FD).
    Default,
    Number(u32),
}

impl Serialize for FdSelector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            FdSelector::Default => serializer.serialize_str("default"),
            FdSelector::Number(n) => serializer.serialize_u32(*n),
        }
    }
}

impl<'de> Deserialize<'de> for FdSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = FdSelector;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("\"default\" or an FD number")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if s == "default" {
                    Ok(FdSelector::Default)
                } else {
                    Err(E::custom(format!(
                        "sourceFd must be \"default\" or a number (got \"{s}\")"
                    )))
                }
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Self::Value, E> {
                u32::try_from(n)
                    .map(FdSelector::Number)
                    .map_err(|_| E::custom("sourceFd number exceeds u32"))
            }
        }
        deserializer.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Occurrence {
    All,
    N(u32),
}

impl Occurrence {
    /// True when this occurrence selector covers occurrence number `o`
    /// (1-based ordinals; All covers every one).
    pub fn selects(&self, o: u32) -> bool {
        match self {
            Occurrence::All => true,
            Occurrence::N(n) => *n == o,
        }
    }
}

impl Serialize for Occurrence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Occurrence::All => serializer.serialize_str("all"),
            Occurrence::N(n) => serializer.serialize_u32(*n),
        }
    }
}

impl<'de> Deserialize<'de> for Occurrence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Occurrence;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("\"all\" or a 1-based occurrence number")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if s == "all" {
                    Ok(Occurrence::All)
                } else {
                    Err(E::custom(format!(
                        "occurrence must be \"all\" or a number (got \"{s}\")"
                    )))
                }
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Self::Value, E> {
                // occurrence ordinals are 1-based (design §Closed evidence
                // catalogs): a 0 selector would silently match nothing — a
                // fail-open hole for never-produced coordinates
                if n == 0 {
                    return Err(E::custom(
                        "occurrence must be \"all\" or a 1-based ordinal (0 is invalid)",
                    ));
                }
                u32::try_from(n)
                    .map(Occurrence::N)
                    .map_err(|_| E::custom("occurrence number exceeds u32"))
            }
        }
        deserializer.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetKind {
    pub kind: TargetKindKind,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum TargetKindKind {
    LiteralPath,
    Fd,
}

/// One path-coverage entry: coordinate selector + inline lexical policy
/// (design config example: `{ "coordinate": {…}, "within": "…" }`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PathEntry {
    pub coordinate: PathCoordinateSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outside: Option<String>,
}

impl PathEntry {
    pub fn policy(&self) -> PathPolicy {
        PathPolicy {
            exact: self.exact.clone(),
            within: self.within.clone(),
            outside: self.outside.clone(),
        }
    }
}

/// Lexical path policy (design §Lexical path policy): exact/within/outside;
/// trusted roots are explicit absolute lexical config values.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PathPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outside: Option<String>,
}

/// Closed path-coordinate catalog (design §Closed evidence catalogs) — one
/// selector per evidence coordinate a policy or fact may address.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PathCoordinateSelector {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument: Option<PositionalCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_value: Option<OptionValueCoordinate>,
    /// Environment-assignment coordinate (closed object form
    /// `{ "occurrence": occurrenceSelector }`, docs schema
    /// `EnvironmentCoordinate`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_fact: Option<FactCoordinate>,
}

impl PositionalCoordinate {
    pub fn is_remainder_form(&self) -> bool {
        self.remainder
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OptionValueCoordinate {
    pub option: String,
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
    /// Selected value ordinal: 1-based, bounded by the declared maximum arity.
    pub value_ordinal: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectCoordinate {
    pub operator: RedirectOp,
    pub source_fd: FdSelector,
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
}

/// Environment-assignment coordinate selector (closed, docs schema
/// `EnvironmentCoordinate`): `{ "occurrence": occurrenceSelector }`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnvironmentCoordinate {
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
}

/// Analyzer-fact coordinate selector (closed).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FactCoordinate {
    #[serde(default)]
    pub analyzer: Option<String>,
    pub name: String,
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
}

// ── Config v2 wire grammar (stable snapshot region) ─────────────────────────
//
// Every config-v2 grammar declaration consumed by the docs drift guard sits
// between the two markers, contiguously and completely; the docs repository
// (PR 22) snapshots exactly this region and fails closed on drift. No
// helper declarations inside the markers.

// shell-warden-config-v2-grammar: begin

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum RedirectCoverage {
    None { none: bool },
    All { all: Vec<RedirectEntry> },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum PathCoverage {
    None { none: bool },
    All { all: Vec<PathEntry> },
}

/// Positional coordinate source selector: one positional argument `index`
/// (0-based) plus an optional `remainder: true` flag selecting the
/// remainder arguments after the index (docs fixture
/// `PositionalCoordinate/index-and-remainder.json`).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PositionalCoordinate {
    pub index: u32,
    #[serde(default)]
    pub remainder: bool,
}

/// Positional-argument matcher. `prefix` requires an explicit `remainder`;
/// `exact` must not carry one.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArgumentsMatcher {
    #[serde(default)]
    pub exact: Option<Vec<String>>,
    #[serde(default)]
    pub prefix: Option<Vec<String>>,
    /// Remainder policy: only meaningful (and mandatory!) with `prefix`.
    pub remainder: Option<RemainderPolicy>,
    /// Existential test: any positional token matches one of these globs.
    #[serde(default)]
    pub contains_any: Option<Vec<String>>,
}

/// Cover the remaining positional arguments after `prefix`: `{none: true}` = no
/// further arguments; `{each: tokenValueSelector}` = every remaining literal
/// token must satisfy the token selector (closed vocabulary below).
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum RemainderPolicy {
    None { none: bool },
    Each { each: TokenSelector },
}

/// Selection limit in one closed selector array (design §Limits):
/// `oneOf` alternatives. Fixed at 64, not configurable.
pub const MAX_SELECTOR_ALTERNATIVES: usize = 64;
/// Regex UTF-8-byte limit for one `re2-v1` pattern (design §Limits).
pub const MAX_REGEX_BYTES: usize = 1024;
/// Lexical-path UTF-8-byte limit (design §Limits).
pub const MAX_PATH_BYTES: usize = 4096;

/// Closed string-value selector (design §Action-sensitive matching):
/// `{"any": true}`, `{"oneOf": [literal, ...]}` or `{"regex": re2-v1}`.
/// Exactly one discriminator key per selector object; no globs, no coercion.
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum StringValueSelector {
    /// Covers any complete literal token, including an empty inline value.
    Any,
    /// Covers one listed literal by exact equality. Non-empty (1..=64) and
    /// duplicate-free; `"*"` is a literal asterisk (wildcards live in `regex`).
    OneOf(Vec<String>),
    /// Whole-value `re2-v1` match; compiled when configuration loads.
    Regex(String),
}

/// Closed lexical path selector: exact / within / outside on absolute lexical
/// roots (component-boundary semantics of the lexical path policy; no I/O).
/// One key per selector object; a second key or an array is invalid.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[serde(untagged)]
pub enum PathSelector {
    Exact { exact: String },
    Within { within: String },
    Outside { outside: String },
}

/// Closed token-value selector: one string-value selector, or a lexical path
/// applied to the literal token. Both arms stay one-level on the wire:
/// `{"any": true}` / `{"oneOf": [...]}` / `{"regex": pattern}` / `{"path": …}`.
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum TokenSelector {
    Str(StringValueSelector),
    Path(PathSelector),
}

impl TokenSelector {
    /// Decode convenience: the string-value arm, if any.
    pub fn as_str_selector(&self) -> Option<&StringValueSelector> {
        match self {
            TokenSelector::Str(s) => Some(s),
            TokenSelector::Path(..) => None,
        }
    }

    pub fn as_path(&self) -> Option<&PathSelector> {
        match self {
            TokenSelector::Str(_) => None,
            TokenSelector::Path(path) => Some(path),
        }
    }
}

/// Closed option-value coverage: `{"each": tokenValueSelector}` covers every
/// value ordinal of every occurrence; `{"byPosition": [selector, ...]}` has
/// exactly one selector per fixed value ordinal (zero-based array position ⇒
/// one-based ordinal). It never expresses a variable value count.
/// Closed option-value coverage: `{"each": tokenValueSelector}` covers every
/// value ordinal of every occurrence; `{"byPosition": [selector, ...]}` has
/// exactly one selector per fixed value ordinal (zero-based array position ⇒
/// one-based ordinal). It never expresses a variable value count.
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum OptionValueCoverage {
    Each { each: TokenSelector },
    ByPosition { by_position: Vec<TokenSelector> },
}

impl OptionValueCoverage {
    /// `byPosition` is structurally bounded to the declared arity range
    /// (schema maxItems: 4); the per-option arity equality is checked against
    /// the profile declaration in config validation.
    pub fn validate_shape(&self) -> Result<(), String> {
        match self {
            OptionValueCoverage::Each { .. } => Ok(()),
            OptionValueCoverage::ByPosition { by_position } => {
                if by_position.is_empty() {
                    return Err(
                        "optionValueCoverage.byPosition must list at least one selector"
                            .to_string(),
                    );
                }
                if by_position.len() > MAX_OPTION_ARITY as usize {
                    return Err(format!(
                        "optionValueCoverage.byPosition exceeds {MAX_OPTION_ARITY} selectors"
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Zero-arity option coverage entry: presence / repetition only — no values.
/// Both directions are hand-implemented at the `OptionCoverageEntry` union
/// level (derived untagged would drop `deny_unknown_fields` under serde's
/// content buffering).
#[derive(Debug, Clone, PartialEq)]
pub struct OptionCoverage {
    pub option: String,
    pub required: bool,
    pub repeatable: bool,
}

/// Fixed option grammar declaration: canonical ID → aliases + arity +
/// inline-form permission. Fixed arity 0..=4; no variadic, minArity or
/// maxArity form exists in v2. `--alias=value` is valid only when the option
/// has arity one and declares `inline: true`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OptionSpec {
    /// Aliases exactly as they may appear in argv (`--long`, `-f`).
    pub aliases: Vec<String>,
    /// 0..=4 (validated in config loader).
    pub arity: u8,
    /// Absent or false ⇒ the inline form `--alias=value` is rejected (arity
    /// one included); `true` is only valid for a declared arity-one option.
    #[serde(default)]
    pub inline: Option<bool>,
}

/// Positive-arity option coverage entry: additionally states the value
/// selector for every consumed or inline value (required, closed form).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PositiveArityOptionCoverage {
    pub option: String,
    pub required: bool,
    pub repeatable: bool,
    pub values: OptionValueCoverage,
}

/// One allow `options.allowed` entry: references a declared canonical profile
/// option and states `required` and `repeatable`; positive arity additionally
/// carries the closed value coverage. Canonical option IDs must stay unique
/// within one list (config validation); the union rejects a zero-arity entry
/// carrying `values` and a positive-arity entry without it.
/// One allow `options.allowed` entry: references a declared canonical profile
/// option and states `required` and `repeatable`; positive arity additionally
/// carries the closed value coverage. Canonical option IDs must stay unique
/// within one list (config validation); the union rejects a zero-arity entry
/// carrying `values` and a positive-arity entry without it.
#[derive(Debug, Clone, PartialEq)]
pub enum OptionCoverageEntry {
    ZeroArity(OptionCoverage),
    PositiveArity(PositiveArityOptionCoverage),
}

impl OptionCoverageEntry {
    pub fn option(&self) -> &str {
        match self {
            OptionCoverageEntry::ZeroArity(e) => &e.option,
            OptionCoverageEntry::PositiveArity(e) => &e.option,
        }
    }

    pub fn required(&self) -> bool {
        match self {
            OptionCoverageEntry::ZeroArity(e) => e.required,
            OptionCoverageEntry::PositiveArity(e) => e.required,
        }
    }

    pub fn repeatable(&self) -> bool {
        match self {
            OptionCoverageEntry::ZeroArity(e) => e.repeatable,
            OptionCoverageEntry::PositiveArity(e) => e.repeatable,
        }
    }

    pub fn values(&self) -> Option<&OptionValueCoverage> {
        match self {
            OptionCoverageEntry::ZeroArity(_) => None,
            OptionCoverageEntry::PositiveArity(e) => Some(&e.values),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OptionsMatcher {
    #[serde(default)]
    pub present_all: Option<Vec<String>>,
    #[serde(default)]
    pub present_any: Option<Vec<String>>,
    #[serde(default)]
    pub absent_all: Option<Vec<String>>,
    /// Existential value predicate: canonical option → selector; a selected
    /// occurrence whose value satisfies the selector makes the dimension hold.
    pub values: Option<std::collections::BTreeMap<String, TokenSelector>>,
    /// Allow coverage policy ({ "none": true }); selects the allow form.
    pub none: Option<bool>,
    /// Allow coverage policy ({ "allowed": [entry, ...] }).
    pub allowed: Option<Vec<OptionCoverageEntry>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnvironmentTest {
    pub name: String,
    /// String-value selector (`any`/`oneOf`/`regex`) — optional = unconstrained.
    #[serde(default)]
    pub value: Option<StringValueSelector>,
    /// Assignment must sit in the command prefix (`FOO=1 cmd`) when true.
    #[serde(default)]
    pub prefix: Option<bool>,
    /// One-based occurrence ordinal (`"all"` = every occurrence).
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FactTest {
    /// Closed analyzer id (`generic-v1`, `sed-v1`, …); required for allow
    /// fact entries, optional for ask/deny fact tests.
    #[serde(default)]
    pub analyzer: Option<String>,
    /// Closed analyzer version ("1"); defaults to the matching analyzer
    /// when omitted in ask/deny.
    #[serde(default)]
    pub version: Option<String>,
    pub name: String,
    /// One-based occurrence ordinal ("all" = every occurrence).
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
    /// Typed value selector (None = every observed value matches).
    #[serde(default)]
    pub value: Option<TypedValueSelector>,
}

/// One nested-part selector (`NestedPartTest` in the public config-v2
/// schema): every field is optional, but at least one selector must be
/// present (schema `minProperties: 1`, enforced at config validation).
/// Execution metadata — the executable head and the analyzer origin — stays
/// internal to the evidence and is not public config.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NestedPartTest {
    /// Closed relation vocabulary (`chain`, `pipeline`, `wrapper`,
    /// `command-substitution`, `analyzer-command`).
    #[serde(default)]
    pub relation: Option<Relation>,
    /// Selected profile for the nested part: a declared profile id, or the
    /// literal `none` selecting parts with no selected profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Match only when the nested part itself is in this evidence state.
    #[serde(default)]
    pub classification: Option<EvidenceClass>,
    /// A nested part must already reduce to this verdict for the parent's
    /// nesting-coverage policy to cover it.
    #[serde(default)]
    pub verdict: Option<VerdictKind>,
    /// One-based relation-occurrence ordinal (`all` = every occurrence).
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
}

/// The literal `none` profile selector for nested parts: selects parts with
/// no selected profile (public schema `NestedPartTest.profile` is
/// `profileId | "none"`).
pub const NESTED_PROFILE_NONE: &str = "none";

// shell-warden-config-v2-grammar: end

// Canonical one-level wire forms. A derived Serde enum representation would
// externally tag the struct variants and nest both directions of the wire
// (`{"none": {"none": true}}`), the accidental nested shape the public
// contract rejects. Both directions are therefore hand-implemented: exactly
// one canonical arm, no aliases, no fallback, no migration.

impl<'de> serde::Deserialize<'de> for RemainderPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = RemainderPolicy;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a one-level remainder policy: {\"none\": true} or {\"each\": tokenSelector}",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let field = map
                    .next_key::<RemainderPolicyField>()?
                    .ok_or_else(|| serde::de::Error::custom("empty remainder policy"))?;
                let policy = match field {
                    RemainderPolicyField::None => {
                        let none: bool = map.next_value()?;
                        if !none {
                            return Err(serde::de::Error::custom(
                                "remainder none policy must be {\"none\": true}",
                            ));
                        }
                        RemainderPolicy::None { none: true }
                    }
                    RemainderPolicyField::Each => {
                        let each: TokenSelector = map.next_value()?;
                        RemainderPolicy::Each { each }
                    }
                };
                if map.next_key::<RemainderPolicyField>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "mixed remainder policy arms: use exactly one of none/each",
                    ));
                }
                Ok(policy)
            }
        }
        deserializer.deserialize_map(V)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemainderPolicyField {
    None,
    Each,
}

impl<'de> serde::Deserialize<'de> for RemainderPolicyField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = RemainderPolicyField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a remainder policy arm: `none` or `each`")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "none" => Ok(RemainderPolicyField::None),
                    "each" => Ok(RemainderPolicyField::Each),
                    other => Err(E::unknown_field(other, &["none", "each"])),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl serde::Serialize for RemainderPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            RemainderPolicy::None { none: true } => map.serialize_entry("none", &true)?,
            // Mirror the deserializer's rejection: a `none: false` value has no
            // canonical wire form, so serialization errors instead of emitting
            // a value that would parse back as invalid. Round-trip stays total.
            RemainderPolicy::None { none: false } => {
                return Err(serde::ser::Error::custom(
                    "remainder none policy requires {\"none\": true}",
                ));
            }
            RemainderPolicy::Each { each } => map.serialize_entry("each", each)?,
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for StringValueSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = StringValueSelector;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a one-level string-value selector: {\"any\": true}, \
                     {\"oneOf\": [literal, ...]} or {\"regex\": re2-v1 pattern}",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let field = map
                    .next_key::<StringValueSelectorField>()?
                    .ok_or_else(|| serde::de::Error::custom("empty string-value selector"))?;
                let selector = match field {
                    StringValueSelectorField::Any => {
                        let any: bool = map.next_value()?;
                        if !any {
                            return Err(serde::de::Error::custom(
                                "string-value selector any must be the literal boolean true",
                            ));
                        }
                        StringValueSelector::Any
                    }
                    StringValueSelectorField::OneOf => {
                        let one_of: Vec<String> = map.next_value()?;
                        if one_of.is_empty() || one_of.len() > MAX_SELECTOR_ALTERNATIVES {
                            return Err(serde::de::Error::custom(format!(
                                "oneOf must list 1..={MAX_SELECTOR_ALTERNATIVES} literals"
                            )));
                        }
                        let mut seen = std::collections::BTreeSet::new();
                        if !one_of.iter().all(|l| seen.insert(l.clone())) {
                            return Err(serde::de::Error::custom("oneOf literals must be unique"));
                        }
                        StringValueSelector::OneOf(one_of)
                    }
                    StringValueSelectorField::Regex => {
                        let regex: String = map.next_value()?;
                        if regex.len() > MAX_REGEX_BYTES {
                            return Err(serde::de::Error::custom(format!(
                                "regex pattern exceeds {MAX_REGEX_BYTES} UTF-8 bytes"
                            )));
                        }
                        StringValueSelector::Regex(regex)
                    }
                };
                if map.next_key::<StringValueSelectorField>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "mixed selector arms: use exactly one of any/oneOf/regex/path",
                    ));
                }
                Ok(selector)
            }
        }
        deserializer.deserialize_map(V)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringValueSelectorField {
    Any,
    OneOf,
    Regex,
}

impl<'de> serde::Deserialize<'de> for StringValueSelectorField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = StringValueSelectorField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string-value selector arm: `any`, `oneOf` or `regex`")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "any" => Ok(StringValueSelectorField::Any),
                    "oneOf" => Ok(StringValueSelectorField::OneOf),
                    "regex" => Ok(StringValueSelectorField::Regex),
                    other => Err(E::unknown_field(other, &["any", "oneOf", "regex"])),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl serde::Serialize for StringValueSelector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            StringValueSelector::Any => map.serialize_entry("any", &true)?,
            StringValueSelector::OneOf(one_of) => map.serialize_entry("oneOf", one_of)?,
            StringValueSelector::Regex(regex) => map.serialize_entry("regex", regex)?,
        }
        map.end()
    }
}

enum TokenSelectorField {
    Any,
    OneOf,
    Regex,
    Path,
}

impl<'de> serde::Deserialize<'de> for TokenSelectorField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = TokenSelectorField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a token selector arm: `any`, `oneOf`, `regex` or `path`")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "any" => Ok(TokenSelectorField::Any),
                    "oneOf" => Ok(TokenSelectorField::OneOf),
                    "regex" => Ok(TokenSelectorField::Regex),
                    "path" => Ok(TokenSelectorField::Path),
                    other => Err(E::unknown_field(other, &["any", "oneOf", "regex", "path"])),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl<'de> serde::Deserialize<'de> for TokenSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = TokenSelector;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a one-level token selector: {\"any\": true}, {\"oneOf\": [literal, ...]}, \
                     {\"regex\": re2-v1 pattern} or {\"path\": pathSelector}",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let field = map
                    .next_key::<TokenSelectorField>()?
                    .ok_or_else(|| serde::de::Error::custom("empty token selector"))?;
                let selector = match field {
                    TokenSelectorField::Any => {
                        let any: bool = map.next_value()?;
                        if !any {
                            return Err(serde::de::Error::custom(
                                "token selector any must be the literal boolean true",
                            ));
                        }
                        TokenSelector::Str(StringValueSelector::Any)
                    }
                    TokenSelectorField::OneOf => {
                        let one_of: Vec<String> = map.next_value()?;
                        if one_of.is_empty() || one_of.len() > MAX_SELECTOR_ALTERNATIVES {
                            return Err(serde::de::Error::custom(format!(
                                "oneOf must list 1..={MAX_SELECTOR_ALTERNATIVES} literals"
                            )));
                        }
                        let mut seen = std::collections::BTreeSet::new();
                        if !one_of.iter().all(|l| seen.insert(l.clone())) {
                            return Err(serde::de::Error::custom("oneOf literals must be unique"));
                        }
                        TokenSelector::Str(StringValueSelector::OneOf(one_of))
                    }
                    TokenSelectorField::Regex => {
                        let regex: String = map.next_value()?;
                        if regex.len() > MAX_REGEX_BYTES {
                            return Err(serde::de::Error::custom(format!(
                                "regex pattern exceeds {MAX_REGEX_BYTES} UTF-8 bytes"
                            )));
                        }
                        TokenSelector::Str(StringValueSelector::Regex(regex))
                    }
                    TokenSelectorField::Path => {
                        let path: PathSelector = map.next_value()?;
                        TokenSelector::Path(path)
                    }
                };
                if map.next_key::<TokenSelectorField>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "mixed selector arms: use exactly one of any/oneOf/regex/path",
                    ));
                }
                Ok(selector)
            }
        }
        deserializer.deserialize_map(V)
    }
}

impl serde::Serialize for TokenSelector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            TokenSelector::Str(s) => {
                // flatten the string-value selector into the same map level
                match s {
                    StringValueSelector::Any => map.serialize_entry("any", &true)?,
                    StringValueSelector::OneOf(one_of) => map.serialize_entry("oneOf", one_of)?,
                    StringValueSelector::Regex(regex) => map.serialize_entry("regex", regex)?,
                }
            }
            TokenSelector::Path(path) => map.serialize_entry("path", path)?,
        }
        map.end()
    }
}

enum OptionValueCoverageField {
    Each,
    ByPosition,
}

impl<'de> serde::Deserialize<'de> for OptionValueCoverageField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = OptionValueCoverageField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an option-value coverage arm: `each` or `byPosition`")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "each" => Ok(OptionValueCoverageField::Each),
                    "byPosition" => Ok(OptionValueCoverageField::ByPosition),
                    other => Err(E::unknown_field(other, &["each", "byPosition"])),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl<'de> serde::Deserialize<'de> for OptionValueCoverage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = OptionValueCoverage;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a one-level option-value coverage: {\"each\": tokenValueSelector} \
                     or {\"byPosition\": [tokenValueSelector, ...]}",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let field = map
                    .next_key::<OptionValueCoverageField>()?
                    .ok_or_else(|| serde::de::Error::custom("empty option-value coverage"))?;
                let coverage = match field {
                    OptionValueCoverageField::Each => {
                        let each: TokenSelector = map.next_value()?;
                        OptionValueCoverage::Each { each }
                    }
                    OptionValueCoverageField::ByPosition => {
                        let by_position: Vec<TokenSelector> = map.next_value()?;
                        OptionValueCoverage::ByPosition { by_position }
                    }
                };
                if map.next_key::<OptionValueCoverageField>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "mixed coverage arms: use exactly one of each/byPosition",
                    ));
                }
                Ok(coverage)
            }
        }
        deserializer.deserialize_map(V)
    }
}

impl serde::Serialize for OptionValueCoverage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            OptionValueCoverage::Each { each } => map.serialize_entry("each", each)?,
            OptionValueCoverage::ByPosition { by_position } => {
                map.serialize_entry("byPosition", by_position)?
            }
        }
        map.end()
    }
}

enum OptionCoverageEntryField {
    Option,
    Required,
    Repeatable,
    Values,
}

impl<'de> serde::Deserialize<'de> for OptionCoverageEntryField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = OptionCoverageEntryField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an option coverage entry field")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "option" => Ok(OptionCoverageEntryField::Option),
                    "required" => Ok(OptionCoverageEntryField::Required),
                    "repeatable" => Ok(OptionCoverageEntryField::Repeatable),
                    "values" => Ok(OptionCoverageEntryField::Values),
                    other => Err(E::unknown_field(
                        other,
                        &["option", "required", "repeatable", "values"],
                    )),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl<'de> serde::Deserialize<'de> for OptionCoverageEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = OptionCoverageEntry;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "an option coverage entry: {\"option\", \"required\", \"repeatable\"} \
                     plus \"values\" for a positive-arity option",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut option: Option<String> = None;
                let mut required: Option<bool> = None;
                let mut repeatable: Option<bool> = None;
                let mut values: Option<OptionValueCoverage> = None;
                while let Some(field) = map.next_key::<OptionCoverageEntryField>()? {
                    match field {
                        OptionCoverageEntryField::Option => option = Some(map.next_value()?),
                        OptionCoverageEntryField::Required => required = Some(map.next_value()?),
                        OptionCoverageEntryField::Repeatable => {
                            repeatable = Some(map.next_value()?)
                        }
                        OptionCoverageEntryField::Values => values = Some(map.next_value()?),
                    }
                }
                let option = option.ok_or_else(|| serde::de::Error::missing_field("option"))?;
                let required =
                    required.ok_or_else(|| serde::de::Error::missing_field("required"))?;
                let repeatable =
                    repeatable.ok_or_else(|| serde::de::Error::missing_field("repeatable"))?;
                match values {
                    None => Ok(OptionCoverageEntry::ZeroArity(OptionCoverage {
                        option,
                        required,
                        repeatable,
                    })),
                    Some(values) => Ok(OptionCoverageEntry::PositiveArity(
                        PositiveArityOptionCoverage {
                            option,
                            required,
                            repeatable,
                            values,
                        },
                    )),
                }
            }
        }
        deserializer.deserialize_map(V)
    }
}

impl serde::Serialize for OptionCoverageEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeStruct};
        match self {
            OptionCoverageEntry::ZeroArity(e) => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("option", &e.option)?;
                map.serialize_entry("required", &e.required)?;
                map.serialize_entry("repeatable", &e.repeatable)?;
                map.end()
            }
            OptionCoverageEntry::PositiveArity(e) => {
                let mut s = serializer.serialize_struct("PositiveArityOptionCoverage", 4)?;
                s.serialize_field("option", &e.option)?;
                s.serialize_field("required", &e.required)?;
                s.serialize_field("repeatable", &e.repeatable)?;
                s.serialize_field("values", &e.values)?;
                s.end()
            }
        }
    }
}

impl serde::Serialize for OptionCoverage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("OptionCoverage", 3)?;
        s.serialize_field("option", &self.option)?;
        s.serialize_field("required", &self.required)?;
        s.serialize_field("repeatable", &self.repeatable)?;
        s.end()
    }
}

// ── Typed fact-value selectors (design §Closed evidence catalogs: analyzer
// facts do not reuse token selectors implicitly; a closed typed-value selector
// first agrees with the fact type from the analyzer catalog, then applies one
// of `any`, scalar `exact`, `string`, `integer`, `number`, `boolean`, or
// `path`). One-level canonical forms only: exactly one discriminator at the
// union level, no nested Serde alias, no coercion between catalog types.

/// One scalar typed value accepted by the `exact` arm: string, finite
/// number, or boolean. Arrays, objects, and null have no scalar wire form.
#[derive(Debug, Clone, PartialEq)]
pub enum ScalarValue {
    Str(String),
    Num(serde_json::Number),
    Bool(bool),
}

impl<'de> Deserialize<'de> for ScalarValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(deserializer)?;
        match v {
            serde_json::Value::Bool(b) => Ok(ScalarValue::Bool(b)),
            serde_json::Value::Number(n) => Ok(ScalarValue::Num(n)),
            serde_json::Value::String(s) => Ok(ScalarValue::Str(s)),
            _ => Err(serde::de::Error::custom(
                "typed exact scalar must be a string, number, or boolean",
            )),
        }
    }
}

impl Serialize for ScalarValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ScalarValue::Str(s) => serializer.serialize_str(s),
            ScalarValue::Num(n) => n.serialize(serializer),
            ScalarValue::Bool(b) => serializer.serialize_bool(*b),
        }
    }
}

/// Closed inclusive integer bounds; at least one bound is required (checked
/// in config validation) and both ends are inclusive.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IntegerBounds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
}

/// Closed inclusive number bounds; at least one bound is required (checked
/// in config validation) and both ends are inclusive. Bounds are finite JSON
/// numbers.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NumberBounds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

/// Closed typed-value selector for analyzer facts: one of
/// `{"any": true}`, `{"exact": scalar}`, `{"string": stringValueSelector}`,
/// `{"integer": bounds}`, `{"number": bounds}`, `{"boolean": true|false}`, or
/// `{"path": pathSelector}`. Never coerces a typed fact to another type.
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum TypedValueSelector {
    /// Every fact value matches.
    Any,
    /// Exact scalar equality within the fact's catalog type.
    Exact(ScalarValue),
    /// String-value semantics on a string-typed fact.
    String { string: StringValueSelector },
    /// Closed inclusive integer bounds on an integer-typed fact.
    Integer { integer: IntegerBounds },
    /// Closed inclusive number bounds on a number-typed fact.
    Number { number: NumberBounds },
    /// Exact boolean equality on a boolean-typed fact.
    Boolean { boolean: bool },
    /// Lexical path semantics on a path-typed fact.
    Path { path: PathSelector },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypedValueField {
    Any,
    Exact,
    String,
    Integer,
    Number,
    Boolean,
    Path,
}

impl<'de> serde::Deserialize<'de> for TypedValueField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = TypedValueField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a typed-value selector arm: `any`, `exact`, `string`, `integer`, \
                     `number`, `boolean`, or `path`",
                )
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "any" => Ok(TypedValueField::Any),
                    "exact" => Ok(TypedValueField::Exact),
                    "string" => Ok(TypedValueField::String),
                    "integer" => Ok(TypedValueField::Integer),
                    "number" => Ok(TypedValueField::Number),
                    "boolean" => Ok(TypedValueField::Boolean),
                    "path" => Ok(TypedValueField::Path),
                    other => Err(E::unknown_field(
                        other,
                        &[
                            "any", "exact", "string", "integer", "number", "boolean", "path",
                        ],
                    )),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl<'de> serde::Deserialize<'de> for TypedValueSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = TypedValueSelector;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a one-level typed-value selector: {\"any\": true}, {\"exact\": scalar}, \
                     {\"string\": …}, {\"integer\": …}, {\"number\": …}, {\"boolean\": true|false} \
                     or {\"path\": …}",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let field = map
                    .next_key::<TypedValueField>()?
                    .ok_or_else(|| serde::de::Error::custom("empty typed-value selector"))?;
                let selector = match field {
                    TypedValueField::Any => {
                        let any: bool = map.next_value()?;
                        if !any {
                            return Err(serde::de::Error::custom(
                                "typed-value selector any requires {\"any\": true}",
                            ));
                        }
                        TypedValueSelector::Any
                    }
                    TypedValueField::Exact => TypedValueSelector::Exact(map.next_value()?),
                    TypedValueField::String => TypedValueSelector::String {
                        string: map.next_value()?,
                    },
                    TypedValueField::Integer => TypedValueSelector::Integer {
                        integer: map.next_value()?,
                    },
                    TypedValueField::Number => TypedValueSelector::Number {
                        number: map.next_value()?,
                    },
                    TypedValueField::Boolean => TypedValueSelector::Boolean {
                        boolean: map.next_value()?,
                    },
                    TypedValueField::Path => TypedValueSelector::Path {
                        path: map.next_value()?,
                    },
                };
                if map.next_key::<TypedValueField>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "mixed typed-value selector arms: use exactly one of \
                         any/exact/string/integer/number/boolean/path",
                    ));
                }
                Ok(selector)
            }
        }
        deserializer.deserialize_map(V)
    }
}

impl serde::Serialize for TypedValueSelector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            TypedValueSelector::Any => map.serialize_entry("any", &true)?,
            TypedValueSelector::Exact(exact) => map.serialize_entry("exact", exact)?,
            TypedValueSelector::String { string } => map.serialize_entry("string", string)?,
            TypedValueSelector::Integer { integer } => map.serialize_entry("integer", integer)?,
            TypedValueSelector::Number { number } => map.serialize_entry("number", number)?,
            TypedValueSelector::Boolean { boolean } => map.serialize_entry("boolean", boolean)?,
            TypedValueSelector::Path { path } => map.serialize_entry("path", path)?,
        }
        map.end()
    }
}

/// The fixed `re2-v1` regex dialect (design §Action-sensitive matching):
/// RE2-compatible UTF-8 syntax and semantics, case-sensitive, no
/// backreferences or look-around, no configurable flags. Selectors carry the
/// pattern as a plain string; patterns are compiled exactly once when the
/// configuration loads and always match the entire decoded token.
#[derive(Debug, Clone, Default)]
pub struct RegexCache {
    patterns: std::collections::BTreeMap<String, regex::Regex>,
}

impl RegexCache {
    /// Compile one whole-value `re2-v1` pattern: the user's syntax wrapped in
    /// `\A(?:…)\z` anchors so matching covers the entire value only. A
    /// backreference, look-around subexpression or inline flag group is
    /// unsupported syntax and invalidates the config (fail closed).
    pub fn compile(pattern: &str) -> Result<Self, String> {
        let re = compile_anchored_re2(pattern)?;
        Ok(RegexCache {
            patterns: std::collections::BTreeMap::from([(pattern.to_string(), re)]),
        })
    }

    /// Pre-compile `pattern` into this cache (config-load phase).
    pub fn add(&mut self, pattern: &str) -> Result<(), String> {
        if !self.patterns.contains_key(pattern) {
            let re = compile_anchored_re2(pattern)?;
            self.patterns.insert(pattern.to_string(), re);
        }
        Ok(())
    }

    /// Whole-value match against the compiled `pattern`; an uncompiled
    /// pattern cannot match (fail closed).
    pub fn whole_match(&self, pattern: &str, value: &str) -> bool {
        self.patterns
            .get(pattern)
            .map(|re| re.is_match(value))
            .unwrap_or(false)
    }
}

/// Validate the fixed `re2-v1` dialect beyond the regex crate's grammar: no
/// inline flag groups — matching is case-sensitive with no configurable
/// flags. The check walks the parsed AST (`regex-syntax`), so no hand-rolled
/// scanner can misread character classes, POSIX classes, escapes or nested
/// class sets: a `(?i)` *inside* a class is just a member, and only genuine
/// flag items (which change matching behavior globally or per-rune) are
/// rejected. Backreferences and look-around fail the regex crate's own
/// compilation.
fn compile_anchored_re2(pattern: &str) -> Result<regex::Regex, String> {
    reject_inline_flags(pattern)?;
    regex::Regex::new(&format!(r"\A(?:{pattern})\z"))
        .map_err(|e| format!("re2-v1 pattern compile failed: {e}"))
}

fn reject_inline_flags(pattern: &str) -> Result<(), String> {
    let ast = regex_syntax::ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|e| format!("re2-v1 pattern syntax: {e}"))?;
    reject_flag_items(&ast).map_err(|_| {
        "re2-v1 pattern uses an inline flag group — the dialect allows no configured \
         flags (case-sensitive whole-value matching only)"
            .to_string()
    })?;
    reject_rust_class_sets(&ast)?;
    reject_re2_ascii_mismatches(&ast)
}

/// The `re2-v1` dialect freezes RE2 semantics: in RE2 the Perl class
/// shortcuts (`\w`, `\d`, `\s`, …) and word boundaries (`\b`, `\B`) are
/// ASCII-defined, while the pinned Rust engine matches them Unicode-aware —
/// a `\w+` selector would whole-match `é` and silently widen allow
/// coverage through the regex selector. These constructs are rejected
/// (fail closed) at the top level AND inside bracketed classes
/// (`[\w]`, `[a-z\s]`, `[^\w]` — the divergence is identical there);
/// spell the class explicitly — `[0-9]`, `[0-9A-Za-z_]`, POSIX `[:word:]`
/// — or use the Unicode classes RE2 also defines (`\p{L}`), which carry
/// the intended semantics in both engines.
fn reject_re2_ascii_mismatches(ast: &regex_syntax::ast::Ast) -> Result<(), String> {
    use regex_syntax::ast::{AssertionKind, Ast, ClassPerlKind, ClassSet, ClassSetItem};
    fn perl_label(kind: &ClassPerlKind, negated: bool) -> &'static str {
        match (kind, negated) {
            (ClassPerlKind::Digit, false) => r"\d",
            (ClassPerlKind::Digit, true) => r"\D",
            (ClassPerlKind::Space, false) => r"\s",
            (ClassPerlKind::Space, true) => r"\S",
            (ClassPerlKind::Word, false) => r"\w",
            (ClassPerlKind::Word, true) => r"\W",
        }
    }
    fn reject(ast: &Ast) -> Option<&'static str> {
        match ast {
            Ast::ClassPerl(p) => Some(perl_label(&p.kind, p.negated)),
            Ast::Assertion(a) => match a.kind {
                AssertionKind::WordBoundary => Some(r"\b"),
                AssertionKind::NotWordBoundary => Some(r"\B"),
                _ => None,
            },
            _ => None,
        }
    }
    // bracketed classes carry the same divergence: any Perl shortcut member
    // (union items included, negated or plain) is RE2-mismatched
    fn walk_set(set: &ClassSet, construct: &mut Option<&'static str>) {
        if construct.is_some() {
            return;
        }
        match set {
            ClassSet::Item(item) => match item {
                ClassSetItem::Perl(p) => *construct = Some(perl_label(&p.kind, p.negated)),
                ClassSetItem::Union(u) => {
                    u.items.iter().for_each(|it| {
                        if construct.is_none()
                            && let ClassSetItem::Perl(p) = it
                        {
                            *construct = Some(perl_label(&p.kind, p.negated));
                        }
                    });
                }
                ClassSetItem::Bracketed(nested) => walk_set(&nested.kind, construct),
                ClassSetItem::Empty(_)
                | ClassSetItem::Literal(_)
                | ClassSetItem::Range(_)
                | ClassSetItem::Ascii(_)
                | ClassSetItem::Unicode(_) => {}
            },
            ClassSet::BinaryOp(op) => {
                walk_set(&op.lhs, construct);
                if construct.is_none() {
                    walk_set(&op.rhs, construct);
                }
            }
        }
    }
    let mut construct: Option<&'static str> = None;
    fn walk(ast: &regex_syntax::ast::Ast, construct: &mut Option<&'static str>) {
        if construct.is_some() {
            return;
        }
        if let Some(c) = reject(ast) {
            *construct = Some(c);
            return;
        }
        use regex_syntax::ast::Ast;
        match ast {
            Ast::ClassBracketed(b) => walk_set(&b.kind, construct),
            Ast::Alternation(x) => x.asts.iter().for_each(|a| walk(a, construct)),
            Ast::Concat(x) => x.asts.iter().for_each(|a| walk(a, construct)),
            Ast::Repetition(x) => walk(&x.ast, construct),
            Ast::Group(x) => walk(&x.ast, construct),
            _ => {}
        }
    }
    walk(ast, &mut construct);
    if let Some(c) = construct {
        return Err(format!(
            "re2-v1 pattern uses `{c}` in its engine's Unicode sense — RE2 defines \
             Perl class shortcuts and word boundaries as ASCII (top level and inside \
             bracketed classes), and a Unicode match would silently widen allow \
             coverage; spell the class explicitly ([0-9], [0-9A-Za-z_], [:word:]) or \
             use the Unicode class RE2 defines (e.g. \\p{{L}})"
        ));
    }
    Ok(())
}

/// The `re2-v1` dialect freezes the RE2 character-class subset: bracketed
/// classes contain literals, ranges, POSIX/Unicode/Perl classes — never
/// nested bracketed classes or `&&`/`--`/`~~` set operations (Rust-only
/// class-set syntax; RE2 reads those bytes as literal members, so accepting
/// them would make conforming implementations disagree).
fn reject_rust_class_sets(ast: &regex_syntax::ast::Ast) -> Result<(), String> {
    fn invalid(kind: &str) -> String {
        format!(
            "re2-v1 pattern uses a Rust-only character-class {kind} \
             (nested bracketed classes and set operators &&/--/~~ are not \
             RE2-compatible)"
        )
    }
    fn walk_class(set: &regex_syntax::ast::ClassSet) -> Result<(), String> {
        use regex_syntax::ast::{ClassSet, ClassSetItem};
        match set {
            ClassSet::Item(item) => match item {
                ClassSetItem::Bracketed(_) => Err(invalid("nested class")),
                ClassSetItem::Union(u) => u
                    .items
                    .iter()
                    .try_for_each(|it| walk_class(&ClassSet::Item(it.clone()))),
                _ => Ok(()),
            },
            ClassSet::BinaryOp(_) => Err(invalid("set operation")),
        }
    }
    fn walk(ast: &regex_syntax::ast::Ast) -> Result<(), String> {
        use regex_syntax::ast::Ast;
        match ast {
            Ast::ClassBracketed(b) => walk_class(&b.kind),
            Ast::Alternation(x) => x.asts.iter().try_for_each(walk),
            Ast::Concat(x) => x.asts.iter().try_for_each(walk),
            Ast::Repetition(x) => walk(&x.ast),
            Ast::Group(x) => walk(&x.ast),
            _ => Ok(()),
        }
    }
    walk(ast)
}

/// Depth-first AST walk: reject every inline flags item (`(?flags)` /
/// `(?flags:…)` / `(?-flags)`); named groups and `(?:…)` are Ast::Group arms
/// and stay legal.
fn reject_flag_items(ast: &regex_syntax::ast::Ast) -> Result<(), ()> {
    use regex_syntax::ast::{Ast, GroupKind};
    match ast {
        // `(?flags)` items and `(?flags:…)` groups both configure flags
        Ast::Flags(_) => Err(()),
        Ast::Group(x) if matches!(x.kind, GroupKind::NonCapturing(ref f) if !f.items.is_empty()) => {
            Err(())
        }
        Ast::Empty(_)
        | Ast::Assertion(_)
        | Ast::Dot(_)
        | Ast::Literal(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => Ok(()),
        Ast::Repetition(x) => reject_flag_items(&x.ast),
        Ast::Alternation(x) => x.asts.iter().try_for_each(reject_flag_items),
        Ast::Concat(x) => x.asts.iter().try_for_each(reject_flag_items),
        Ast::Group(x) => reject_flag_items(&x.ast),
    }
}

// ── Profiles ────────────────────────────────────────────────────────────────

/// Per-executable command profile (design §Selected architecture): owns the
/// complete lexical grammar + policy for one executable.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    /// Literal executable aliases (lexical selection; last token of the argv
    /// head-free form). Singleton always valid; multi-spelling requires an
    /// implementation-owned lexical-alias-catalog entry.
    pub executables: Vec<String>,
    /// Canonical option ID → aliases + arity (+inline form permission).
    #[serde(default)]
    pub options: std::collections::BTreeMap<String, OptionSpec>,
    /// Profiles declare which evidence coordinates may be treated as paths.
    #[serde(default)]
    pub path_sources: Vec<PathCoordinateSelector>,
    /// Effective redirect-policy override (design §Reusable redirect policies).
    #[serde(default)]
    pub redirect_policy: Option<RedirectPolicyOverride>,
    /// Optional built-in analyzer (closed catalog; never config-loaded).
    #[serde(default)]
    pub analyzer: Option<AnalyzerId>,
    pub rules: Vec<Rule>,
    /// Non-voting, profile-local messages for the bare default ask.
    #[serde(default)]
    pub fallback_hints: Vec<Hint>,
}

/// Built-in analyzer catalog (closed; versioned evidence producers, design
/// §Profiles, option grammars, and analyzers). They never emit verdicts.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum AnalyzerId {
    #[serde(rename = "generic-v1")]
    GenericV1,
    #[serde(rename = "sed-v1")]
    SedV1,
    #[serde(rename = "export-v1")]
    ExportV1,
    #[serde(rename = "xargs-v1")]
    XargsV1,
}

impl AnalyzerId {
    pub fn id(self) -> &'static str {
        match self {
            AnalyzerId::GenericV1 => "generic-v1",
            AnalyzerId::SedV1 => "sed-v1",
            AnalyzerId::ExportV1 => "export-v1",
            AnalyzerId::XargsV1 => "xargs-v1",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectPolicyOverride {
    pub mode: OverrideMode,
    /// Named policy additions (extend) or replacement set (replace).
    #[serde(default)]
    pub policies: Option<Vec<String>>,
    /// Inline bundle addition (extend) or replacement bundle (replace).
    #[serde(default)]
    pub inline: Option<RedirectPolicy>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum OverrideMode {
    #[serde(rename = "inherit")]
    Inherit,
    #[serde(rename = "extend")]
    Extend,
    #[serde(rename = "replace")]
    Replace,
}

// ── Rules ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub action: VerdictKind,
    #[serde(default)]
    pub message: Option<String>,
    /// Action-sensitive: ordinary predicate set for ask/deny; coverage proof
    /// for allow (evaluated by the matcher, not the parser).
    pub r#match: Match,
    /// Allow-only redirect-policy override.
    #[serde(default)]
    pub redirect_policy: Option<RedirectPolicyOverride>,
}

/// Non-voting hint: profile-local message for the bare default ask; only
/// considered when no rule vote and the aggregate is the default ask.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Hint {
    pub id: String,
    pub message: String,
    #[serde(default)]
    pub r#match: Option<Match>,
}

// ── Match vocabulary ─────────────────────────────────────────────────────────

/// One closed `match` object (design §Action-sensitive matching and emitted
/// votes): written once, meaning depends on the action.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Match {
    #[serde(default)]
    pub arguments: Option<ArgumentsMatcher>,
    #[serde(default)]
    pub options: Option<OptionsMatcher>,
    #[serde(default)]
    pub environment: Option<EnvironmentMatcher>,
    /// Typed redirect tests (ask/deny only; allow's redirect coverage comes
    /// from the effective redirect policy).
    #[serde(default)]
    pub redirects: Option<RedirectMatcher>,
    #[serde(default)]
    pub paths: Option<PathsMatcher>,
    #[serde(default)]
    pub facts: Option<FactsMatcher>,
    #[serde(default)]
    pub nested_parts: Option<NestedPartsMatcher>,
    #[serde(default)]
    pub classification: Option<EvidenceClass>,
    #[serde(default)]
    pub raw: Option<String>,
}

/// Ask/deny redirect predicate form (none/any/all).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectMatcher {
    #[serde(default)]
    pub none: Option<bool>,
    #[serde(default)]
    pub any: Option<Vec<RedirectTest>>,
    #[serde(default)]
    pub all: Option<Vec<RedirectTest>>,
}

/// Evidence state used in `classification` predicates (closed; design §Parsing,
/// parts, and evidence states). `invalid` never allows.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum EvidenceClass {
    #[serde(rename = "complete")]
    Complete,
    #[serde(rename = "opaque")]
    Opaque,
    #[serde(rename = "invalid")]
    Invalid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnvironmentMatcher {
    #[serde(default)]
    pub any: Option<Vec<EnvironmentTest>>,
    #[serde(default)]
    pub all: Option<Vec<EnvironmentTest>>,
    #[serde(default)]
    pub none: Option<bool>,
}

// ── Generic closed coverage form: `{"none": true}` or `{"all": [entry]}` ────

/// Generic closed coverage: `{"none": true}` or `{"all": [policy, ...]}`.
/// Used by environment/paths/facts/nestedParts in ask/deny *and* allow
/// (exactly one of none/any/all for ask-deny; none-or-all for allow).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum TypedCoverage<T> {
    None { none: bool },
    All { all: Vec<T> },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectTest {
    pub operator: Option<RedirectOp>,
    #[serde(default)]
    pub source_fd: Option<FdSelector>,
    #[serde(default)]
    pub target_kind: Option<TargetKindKind>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PathsMatcher {
    #[serde(default)]
    pub none: Option<bool>,
    #[serde(default)]
    pub any: Option<Vec<PathEntry>>,
    #[serde(default)]
    pub all: Option<Vec<PathEntry>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FactsMatcher {
    #[serde(default)]
    pub none: Option<bool>,
    #[serde(default)]
    pub any: Option<Vec<FactTest>>,
    #[serde(default)]
    pub all: Option<Vec<FactTest>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NestedPartsMatcher {
    #[serde(default)]
    pub none: Option<bool>,
    #[serde(default)]
    pub any: Option<Vec<NestedPartTest>>,
    #[serde(default)]
    pub all: Option<Vec<NestedPartTest>>,
}

/// Closed relation enum (design §Parsing, parts, and evidence states): the
/// ordinary parser emits the first four; an analyzer may emit only
/// `analyzer-command`. The wire vocabulary is the schema's hyphenated form —
/// the interim camelCase spellings are not accepted aliases.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum Relation {
    #[serde(rename = "chain")]
    Chain,
    #[serde(rename = "pipeline")]
    Pipeline,
    #[serde(rename = "wrapper")]
    Wrapper,
    #[serde(rename = "command-substitution")]
    CommandSubstitution,
    #[serde(rename = "analyzer-command")]
    AnalyzerCommand,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── RemainderPolicy ─────────────────────────────────────────────────────

    #[test]
    fn remainder_none_parses_canonical() {
        let p: RemainderPolicy = serde_json::from_value(json!({ "none": true })).unwrap();
        assert_eq!(p, RemainderPolicy::None { none: true });
    }

    #[test]
    fn remainder_each_parses_canonical_token_selectors() {
        for (wire, expected) in [
            (
                json!({ "each": { "oneOf": ["ls", "cat"] } }),
                TokenSelector::Str(StringValueSelector::OneOf(vec!["ls".into(), "cat".into()])),
            ),
            (
                json!({ "each": { "any": true } }),
                TokenSelector::Str(StringValueSelector::Any),
            ),
            (
                json!({ "each": { "regex": "[a-z]+" } }),
                TokenSelector::Str(StringValueSelector::Regex("[a-z]+".into())),
            ),
            (
                json!({ "each": { "path": { "within": "/work/project" } } }),
                TokenSelector::Path(PathSelector::Within {
                    within: "/work/project".into(),
                }),
            ),
        ] {
            let p: RemainderPolicy = serde_json::from_value(wire).unwrap();
            assert_eq!(p, RemainderPolicy::Each { each: expected });
        }
    }

    /// Externally tagged nesting (`{"none": {"none": true}}`, docs fixture
    /// `RemainderPolicy/nested-serde-none.json`) is rejected, not accepted as
    /// an alias.
    #[test]
    fn remainder_nested_none_rejected() {
        let e = serde_json::from_value::<RemainderPolicy>(json!({ "none": { "none": true } }));
        assert!(e.is_err(), "nested externally tagged none must not parse");
    }

    /// Recursively nested `each` (docs fixture
    /// `OptionValueCoverage/nested-serde-each.json`) is rejected.
    #[test]
    fn remainder_nested_each_rejected() {
        let e = serde_json::from_value::<RemainderPolicy>(
            json!({ "each": { "each": { "any": true } } }),
        );
        assert!(e.is_err(), "nested each must not parse");
    }

    #[test]
    fn remainder_mixed_arms_rejected() {
        let e = serde_json::from_value::<RemainderPolicy>(json!({
            "none": true,
            "each": { "any": true }
        }));
        assert!(e.is_err(), "mixed none+each must not parse");
    }

    #[test]
    fn remainder_empty_object_rejected() {
        assert!(serde_json::from_value::<RemainderPolicy>(json!({})).is_err());
    }

    #[test]
    fn remainder_unknown_or_false_forms_rejected() {
        // the old v0.3.0 `exact-member` and bare `within` alias forms are not
        // part of the closed contract
        assert!(
            serde_json::from_value::<RemainderPolicy>(json!({ "each": { "exact": ["ls"] } }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<RemainderPolicy>(json!({ "each": { "within": "/repo" } }))
                .is_err()
        );
        assert!(serde_json::from_value::<RemainderPolicy>(json!({ "none": false })).is_err());
    }

    /// The wire forms themselves stay canonical: serialization never emits the
    /// accidentally externally tagged nested shape.
    #[test]
    fn remainder_and_selector_serialize_canonical() {
        let p = RemainderPolicy::Each {
            each: TokenSelector::Path(PathSelector::Within {
                within: "/work/project".into(),
            }),
        };
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!({ "each": { "path": { "within": "/work/project" } } })
        );
        let p2 = RemainderPolicy::None { none: true };
        assert_eq!(serde_json::to_value(&p2).unwrap(), json!({ "none": true }));
        let t = TokenSelector::Str(StringValueSelector::OneOf(vec!["ls".into()]));
        assert_eq!(
            serde_json::to_value(&t).unwrap(),
            json!({ "oneOf": ["ls"] })
        );
    }

    /// `{"none": false}` has no canonical wire form: serialization errors
    /// instead of emitting a value the deserializer would reject, keeping
    /// round-trip symmetric.
    #[test]
    fn remainder_none_false_is_unserializable() {
        let p = RemainderPolicy::None { none: false };
        assert!(
            serde_json::to_value(&p).is_err(),
            "none=false must not serialize to a canonical value"
        );
    }

    /// A composed `arguments` rewrite carries the canonical remainder shape
    /// end-to-end through serde.
    #[test]
    fn arguments_matcher_uses_canonical_remainder_wire_form() {
        let m: ArgumentsMatcher = serde_json::from_value(json!({
            "prefix": ["git", "push"],
            "remainder": { "each": { "oneOf": ["origin", "main"] } }
        }))
        .unwrap();
        assert_eq!(
            m,
            ArgumentsMatcher {
                exact: None,
                prefix: Some(vec!["git".into(), "push".into()]),
                remainder: Some(RemainderPolicy::Each {
                    each: TokenSelector::Str(StringValueSelector::OneOf(vec![
                        "origin".into(),
                        "main".into()
                    ]))
                }),
                contains_any: None,
            }
        );
    }

    // ── StringValueSelector ─────────────────────────────────────────────────

    #[test]
    fn string_value_selector_parses_every_closed_arm() {
        let s: StringValueSelector = serde_json::from_value(json!({ "any": true })).unwrap();
        assert_eq!(s, StringValueSelector::Any);
        let s: StringValueSelector =
            serde_json::from_value(json!({ "oneOf": ["safe", "readOnly"] })).unwrap();
        assert_eq!(
            s,
            StringValueSelector::OneOf(vec!["safe".into(), "readOnly".into()])
        );
        let s: StringValueSelector = serde_json::from_value(json!({ "regex": "[a-z]+" })).unwrap();
        assert_eq!(s, StringValueSelector::Regex("[a-z]+".into()));
    }

    #[test]
    fn string_value_selector_rejects_selected_shapes() {
        // docs fixture StringValueSelector/invalid-regex.json: the pattern
        // itself is validated at config load (regex crate rejects look-around)
        let e = serde_json::from_value::<StringValueSelector>(json!({ "any": false }));
        assert!(e.is_err(), "any must be the literal boolean true");
        // oneOf must be non-empty, duplicate-free and bounded
        assert!(serde_json::from_value::<StringValueSelector>(json!({ "oneOf": [] })).is_err());
        assert!(
            serde_json::from_value::<StringValueSelector>(json!({ "oneOf": ["a", "a"] })).is_err()
        );
        let too_many = (0..65).map(|i| i.to_string()).collect::<Vec<_>>();
        assert!(
            serde_json::from_value::<StringValueSelector>(json!({ "oneOf": too_many })).is_err()
        );
        assert!(
            serde_json::from_value::<StringValueSelector>(json!({ "regex": "x".repeat(1025) }))
                .is_err()
        );
        // unknown / mixed arms
        assert!(serde_json::from_value::<StringValueSelector>(json!({ "exact": ["x"] })).is_err());
        assert!(
            serde_json::from_value::<StringValueSelector>(json!({
                "any": true, "oneOf": ["also"]
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<StringValueSelector>(json!({ "path": {} })).is_err());
    }

    // ── Typed fact-value selectors (issue #35): canonical wire forms ────────

    #[test]
    fn typed_value_selector_parses_every_arm() {
        let any: TypedValueSelector = serde_json::from_value(json!({ "any": true })).unwrap();
        assert_eq!(any, TypedValueSelector::Any);
        let exact =
            serde_json::from_value::<TypedValueSelector>(json!({ "exact": "inPlace" })).unwrap();
        assert_eq!(
            exact,
            TypedValueSelector::Exact(ScalarValue::Str("inPlace".into()))
        );
        let number_exact =
            serde_json::from_value::<TypedValueSelector>(json!({ "exact": 5 })).unwrap();
        assert_eq!(
            number_exact,
            TypedValueSelector::Exact(ScalarValue::Num(serde_json::Number::from(5)))
        );
        let boolean_exact =
            serde_json::from_value::<TypedValueSelector>(json!({ "exact": false })).unwrap();
        assert_eq!(
            boolean_exact,
            TypedValueSelector::Exact(ScalarValue::Bool(false))
        );
        let string = serde_json::from_value::<TypedValueSelector>(
            json!({ "string": { "oneOf": ["readOnly"] } }),
        )
        .unwrap();
        assert_eq!(
            string,
            TypedValueSelector::String {
                string: StringValueSelector::OneOf(vec!["readOnly".into()]),
            }
        );
        let integer = serde_json::from_value::<TypedValueSelector>(
            json!({ "integer": { "min": 1, "max": 9 } }),
        )
        .unwrap();
        assert_eq!(
            integer,
            TypedValueSelector::Integer {
                integer: IntegerBounds {
                    min: Some(1),
                    max: Some(9)
                }
            }
        );
        let number =
            serde_json::from_value::<TypedValueSelector>(json!({ "number": { "min": 0.0 } }))
                .unwrap();
        assert_eq!(
            number,
            TypedValueSelector::Number {
                number: NumberBounds {
                    min: Some(0.0),
                    max: None
                }
            }
        );
        let boolean =
            serde_json::from_value::<TypedValueSelector>(json!({ "boolean": true })).unwrap();
        assert_eq!(boolean, TypedValueSelector::Boolean { boolean: true });
        let path = serde_json::from_value::<TypedValueSelector>(
            json!({ "path": { "within": "/work/project" } }),
        )
        .unwrap();
        assert_eq!(
            path,
            TypedValueSelector::Path {
                path: PathSelector::Within {
                    within: "/work/project".into()
                }
            }
        );
    }

    #[test]
    fn typed_value_selector_wire_forms_canonical_roundtrip() {
        for (wire, selector) in [
            (json!({ "any": true }), TypedValueSelector::Any),
            (
                json!({ "exact": "inPlace" }),
                TypedValueSelector::Exact(ScalarValue::Str("inPlace".into())),
            ),
            (
                json!({ "string": { "regex": "[a-z]+" } }),
                TypedValueSelector::String {
                    string: StringValueSelector::Regex("[a-z]+".into()),
                },
            ),
            (
                json!({ "integer": { "max": 42 } }),
                TypedValueSelector::Integer {
                    integer: IntegerBounds {
                        min: None,
                        max: Some(42),
                    },
                },
            ),
            (
                json!({ "boolean": false }),
                TypedValueSelector::Boolean { boolean: false },
            ),
            (
                json!({ "path": { "outside": "/work/private" } }),
                TypedValueSelector::Path {
                    path: PathSelector::Outside {
                        outside: "/work/private".into(),
                    },
                },
            ),
        ] {
            let parsed: TypedValueSelector = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(parsed, selector);
            assert_eq!(
                serde_json::to_value(&parsed).unwrap(),
                wire,
                "serialization must stay canonical"
            );
        }
    }

    #[test]
    fn typed_value_selector_rejects_non_canonical_forms() {
        // not the closed form
        assert!(serde_json::from_value::<TypedValueSelector>(json!({ "any": false })).is_err());
        // nested externally tagged arm
        assert!(
            serde_json::from_value::<TypedValueSelector>(json!({ "any": { "any": true } }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<TypedValueSelector>(
                json!({ "string": { "each": { "any": true } } })
            )
            .is_err(),
            "string arm has no each/token union"
        );
        // mixed union arms
        assert!(
            serde_json::from_value::<TypedValueSelector>(json!({
                "any": true, "exact": "x"
            }))
            .is_err()
        );
        // exact carries no array/object/null scalar
        assert!(serde_json::from_value::<TypedValueSelector>(json!({ "exact": ["a"] })).is_err());
        assert!(serde_json::from_value::<TypedValueSelector>(json!({ "exact": null })).is_err());
        // unknown arm
        assert!(serde_json::from_value::<TypedValueSelector>(json!({ "glob": "*" })).is_err());
        // empty object
        assert!(serde_json::from_value::<TypedValueSelector>(json!({})).is_err());
    }

    #[test]
    fn string_value_selector_shapes() {
        let any: StringValueSelector = serde_json::from_value(json!({ "any": true })).unwrap();
        assert_eq!(any, StringValueSelector::Any);
        let regex =
            serde_json::from_value::<StringValueSelector>(json!({ "regex": "^[a-z]+$" })).unwrap();
        assert_eq!(regex, StringValueSelector::Regex("^[a-z]+$".into()));
        // `{"any": false}` is not the canonical form; nested and mixed arms reject
        assert!(serde_json::from_value::<StringValueSelector>(json!({ "any": false })).is_err());
        assert!(
            serde_json::from_value::<StringValueSelector>(json!({ "any": { "any": true } }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<StringValueSelector>(json!({ "oneOf": ["a"], "regex": "b" }))
                .is_err()
        );
        assert!(serde_json::from_value::<StringValueSelector>(json!({})).is_err());
    }

    #[test]
    fn token_selector_multiple_union_arms_rejected() {
        // docs fixture TokenSelector/multiple-union-arms.json
        let e = serde_json::from_value::<TokenSelector>(json!({
            "any": true, "oneOf": ["also"]
        }));
        assert!(e.is_err(), "two discriminator keys must not parse");
        // a token selector is never itself a coverage wrapper
        assert!(
            serde_json::from_value::<TokenSelector>(json!({ "each": { "any": true } })).is_err()
        );
        assert!(serde_json::from_value::<TokenSelector>(json!({})).is_err());
    }

    // ── PathSelector ────────────────────────────────────────────────────────

    #[test]
    fn path_selector_parses_every_closed_arm() {
        let p: PathSelector = serde_json::from_value(json!({ "exact": "/work/x" })).unwrap();
        assert_eq!(
            p,
            PathSelector::Exact {
                exact: "/work/x".into()
            }
        );
        let p: PathSelector =
            serde_json::from_value(json!({ "outside": "/work/project/private" })).unwrap();
        assert_eq!(
            p,
            PathSelector::Outside {
                outside: "/work/project/private".into()
            }
        );
    }

    #[test]
    fn path_selector_rejects_non_canonical_shapes() {
        // two discriminator keys in one selector object
        assert!(
            serde_json::from_value::<PathSelector>(json!({ "exact": "/a", "within": "/b" }))
                .is_err()
        );
        // nested externally tagged form
        assert!(
            serde_json::from_value::<PathSelector>(json!({ "within": { "within": "/repo" } }))
                .is_err()
        );
        // `path` is a closed token-selector arm, not a path-selector alias
        assert!(
            serde_json::from_value::<TokenSelector>(json!({ "path": { "within": "/repo" } }))
                .is_ok()
        );
        assert!(serde_json::from_value::<PathSelector>(json!({})).is_err());
    }

    #[test]
    fn path_selector_shapes() {
        let exact: PathSelector =
            serde_json::from_value(json!({ "exact": "/work/project/README.md" })).unwrap();
        assert_eq!(
            exact,
            PathSelector::Exact {
                exact: "/work/project/README.md".into()
            }
        );
        assert!(
            serde_json::from_value::<PathSelector>(json!({
                "exact": "/a", "within": "/b"
            }))
            .is_err(),
            "one selector per path entry, never two operations"
        );
        assert!(
            serde_json::from_value::<PathSelector>(json!({ "within": { "exact": "/a" } })).is_err()
        );
        assert!(serde_json::from_value::<PathSelector>(json!({})).is_err());
    }

    // ── Option grammar + coverage entries ───────────────────────────────────

    #[test]
    fn option_spec_rejects_unknown_keys() {
        let e = serde_json::from_value::<OptionSpec>(json!({
            "aliases": ["--name"], "arity": 1, "inline": true, "variadic": true
        }));
        assert!(e.is_err(), "no variadic key exists in v2");
    }

    #[test]
    fn option_coverage_entries_parse_per_fixture_family() {
        // zero-arity (docs fixture OptionCoverage/zero-arity.json)
        let e: OptionCoverageEntry = serde_json::from_value(json!({
            "option": "verbose", "required": false, "repeatable": false
        }))
        .unwrap();
        assert_eq!(e.option(), "verbose");
        assert!(e.values().is_none());
        // positive arity (docs fixture PositiveArityOptionCoverage/with-values.json)
        let e: OptionCoverageEntry = serde_json::from_value(json!({
            "option": "file", "required": false, "repeatable": true,
            "values": { "each": { "path": { "within": "/work/project" } } }
        }))
        .unwrap();
        assert!(e.values().is_some());
    }

    #[test]
    fn option_coverage_wire_carriage_of_values_selects_the_positive_arm() {
        // parse level: a `values` field selects the positive-arity shape; the
        // zero-arity semantic rejection happens against the declared profile
        // arity in config validation (see config tests)
        let e: OptionCoverageEntry = serde_json::from_value(json!({
            "option": "verbose", "required": false, "repeatable": false,
            "values": { "each": { "any": true } }
        }))
        .unwrap();
        assert!(e.values().is_some());
        // unknown keys stay rejected at parse level (no untagged buffering)
        let e = serde_json::from_value::<OptionCoverageEntry>(json!({
            "option": "verbose", "required": false, "repeatable": false,
            "variadic": true
        }));
        assert!(e.is_err(), "no variadic key exists in v2");
    }

    #[test]
    fn option_value_coverage_parses_each_and_by_position() {
        let c: OptionValueCoverage =
            serde_json::from_value(json!({ "each": { "oneOf": ["json", "yaml"] } })).unwrap();
        assert!(matches!(c, OptionValueCoverage::Each { .. }));
        let c: OptionValueCoverage = serde_json::from_value(json!({
            "byPosition": [
                { "regex": "[a-z]+" },
                { "path": { "within": "/work/project" } }
            ]
        }))
        .unwrap();
        assert!(matches!(c, OptionValueCoverage::ByPosition { .. }));
        // shape failures (docs fixtures):
        // bad-by-position-length.json — five selectors in a 0..=4 world
        let e = serde_json::from_value::<OptionValueCoverage>(json!({
            "byPosition": [
                { "any": true }, { "any": true }, { "any": true },
                { "any": true }, { "any": true }
            ]
        }))
        .unwrap();
        assert!(e.validate_shape().is_err());
        // empty byPosition list is never valid
        let e = serde_json::from_value::<OptionValueCoverage>(json!({ "byPosition": [] })).unwrap();
        assert!(e.validate_shape().is_err());
        // nested externally tagged form fails
        assert!(
            serde_json::from_value::<OptionValueCoverage>(json!({
                "each": { "each": { "any": true } }
            }))
            .is_err()
        );
    }

    // ── OptionsMatcher ──────────────────────────────────────────────────────

    #[test]
    fn options_matcher_values_carries_closed_token_selectors() {
        let m: OptionsMatcher = serde_json::from_value(json!({
            "values": { "file": { "path": { "within": "/work/project" } } }
        }))
        .unwrap();
        assert_eq!(
            m.values.unwrap()["file"],
            TokenSelector::Path(PathSelector::Within {
                within: "/work/project".into(),
            })
        );
    }

    #[test]
    fn options_coverage_none_and_allowed_parse() {
        let m: OptionsMatcher = serde_json::from_value(json!({ "none": true })).unwrap();
        assert_eq!(m.none, Some(true));
        // docs fixture OptionsCoverage/none-and-allowed.json
        let m: OptionsMatcher = serde_json::from_value(json!({
            "allowed": [
                { "option": "verbose", "required": false, "repeatable": false },
                {
                    "option": "file", "required": false, "repeatable": true,
                    "values": { "each": { "path": { "within": "/work/project" } } }
                }
            ]
        }))
        .unwrap();
        assert_eq!(m.allowed.as_ref().unwrap().len(), 2);
    }

    /// `FactTest` carries typed optional fields with canonical defaults.
    #[test]
    fn fact_test_typed_fields_parse() {
        let t: FactTest = serde_json::from_value(json!({
            "analyzer": "sed-v1", "version": "1", "name": "executionPrimitive",
            "occurrence": "all", "value": { "exact": "inPlace" }
        }))
        .unwrap();
        assert_eq!(t.analyzer.as_deref(), Some("sed-v1"));
        assert_eq!(t.version.as_deref(), Some("1"));
        assert_eq!(t.occurrence, Some(Occurrence::All));
        assert_eq!(
            t.value,
            Some(TypedValueSelector::Exact(ScalarValue::Str(
                "inPlace".into()
            )))
        );
        // `name`-only test stays valid for ask/deny
        let plain: FactTest = serde_json::from_value(json!({ "name": "programForm" })).unwrap();
        assert!(plain.analyzer.is_none() && plain.value.is_none() && plain.occurrence.is_none());
        // old bare-string value wire form is gone (no coercion, no aliases)
        assert!(
            serde_json::from_value::<FactTest>(
                json!({ "name": "programForm", "value": "inPlace" })
            )
            .is_err()
        );
    }

    /// `EnvironmentTest` parses the authoritative `EnvironmentMatcher/any`
    /// fixture shape: string-value selector plus occurrence; `name` alone
    /// stays valid for ask/deny; the bare-string value form is gone.
    #[test]
    fn environment_test_value_selector_and_occurrence_parse() {
        let t: EnvironmentTest = serde_json::from_value(json!({
            "name": "LANG",
            "value": { "oneOf": ["C", "C.UTF-8"] },
            "prefix": true,
            "occurrence": "all"
        }))
        .unwrap();
        assert_eq!(t.name, "LANG");
        assert_eq!(
            t.value,
            Some(StringValueSelector::OneOf(vec![
                "C".into(),
                "C.UTF-8".into()
            ]))
        );
        assert_eq!(t.prefix, Some(true));
        assert_eq!(t.occurrence, Some(Occurrence::All));
        // `name`-only test stays valid for ask/deny (docs EnvironmentTest def:
        // every dimension but the name is optional)
        let plain: EnvironmentTest = serde_json::from_value(json!({ "name": "LANG" })).unwrap();
        assert!(plain.value.is_none() && plain.prefix.is_none() && plain.occurrence.is_none());
        // old bare-string value wire form is gone (no coercion, no aliases)
        assert!(
            serde_json::from_value::<EnvironmentTest>(
                json!({ "name": "LANG", "value": "C.UTF-8" })
            )
            .is_err()
        );
        // unknown keys fail closed
        assert!(
            serde_json::from_value::<EnvironmentTest>(json!({ "name": "LANG", "match": "prefix" }))
                .is_err()
        );
    }

    // ── NestedPartTest + closed relation vocabulary (issue #41) ─────────────

    /// The authoritative fixture body (docs
    /// `valid/NestedPartPolicy/complete.json`) parses with the public
    /// five-field wire shape.
    #[test]
    fn nested_part_policy_complete_fixture_parses() {
        let t: NestedPartTest = serde_json::from_value(json!({
            "relation": "analyzer-command",
            "occurrence": 1,
            "profile": "rm-safe",
            "classification": "complete",
            "verdict": "ask"
        }))
        .unwrap();
        assert_eq!(t.relation, Some(Relation::AnalyzerCommand));
        assert_eq!(t.occurrence, Some(Occurrence::N(1)));
        assert_eq!(t.profile.as_deref(), Some("rm-safe"));
        assert_eq!(t.classification, Some(EvidenceClass::Complete));
        assert_eq!(t.verdict, Some(VerdictKind::Ask));
        // single-field selectors stay valid (schema minProperties: 1)
        let one: NestedPartTest = serde_json::from_value(json!({ "relation": "chain" })).unwrap();
        assert_eq!(one.relation, Some(Relation::Chain));
        assert!(one.profile.is_none() && one.occurrence.is_none());
    }

    /// The relation wire vocabulary is the schema's hyphenated closed set;
    /// the interim camelCase spellings are not accepted aliases.
    #[test]
    fn nested_part_relation_vocabulary_is_hyphenated() {
        for (wire, expected) in [
            ("chain", Relation::Chain),
            ("pipeline", Relation::Pipeline),
            ("wrapper", Relation::Wrapper),
            ("command-substitution", Relation::CommandSubstitution),
            ("analyzer-command", Relation::AnalyzerCommand),
        ] {
            let t: NestedPartTest = serde_json::from_value(json!({ "relation": wire })).unwrap();
            assert_eq!(t.relation, Some(expected));
        }
        for alias in ["commandSubstitution", "analyzerCommand"] {
            assert!(
                serde_json::from_value::<NestedPartTest>(json!({ "relation": alias })).is_err(),
                "camelCase relation alias \"{alias}\" must not parse"
            );
        }
    }

    /// The authoritative matcher fixture (docs
    /// `valid/NestedPartsMatcher/any.json`) parses as a one-level matcher.
    #[test]
    fn nested_parts_matcher_any_fixture_parses() {
        let m: NestedPartsMatcher = serde_json::from_value(json!({
            "any": [
                {
                    "relation": "analyzer-command",
                    "occurrence": 1,
                    "profile": "rm-safe",
                    "classification": "complete",
                    "verdict": "deny"
                }
            ]
        }))
        .unwrap();
        let any = m.any.unwrap();
        assert_eq!(any.len(), 1);
        assert_eq!(any[0].relation, Some(Relation::AnalyzerCommand));
        assert_eq!(any[0].verdict, Some(VerdictKind::Deny));
    }

    /// The authoritative invalid fixture (docs
    /// `invalid/NestedPartPolicy/nested-serde-form.json`) — a nested
    /// externally tagged relation — does not parse.
    #[test]
    fn nested_part_nested_serde_form_rejected() {
        assert!(
            serde_json::from_value::<NestedPartTest>(json!({
                "relation": { "analyzer-command": true },
                "occurrence": 1,
                "profile": "rm-safe",
                "classification": "complete",
                "verdict": "ask"
            }))
            .is_err()
        );
    }

    /// Execution metadata — the executable head and the analyzer origin —
    /// is internal evidence, never public config.
    #[test]
    fn nested_part_test_rejects_execution_metadata_fields() {
        assert!(
            serde_json::from_value::<NestedPartTest>(json!({ "executable": "rm" })).is_err(),
            "executable head is not public config"
        );
        assert!(
            serde_json::from_value::<NestedPartTest>(json!({ "analyzer": "xargs-v1" })).is_err(),
            "analyzer origin is not public config"
        );
        // the interim `state` spelling is not an alias for `classification`
        assert!(
            serde_json::from_value::<NestedPartTest>(json!({ "state": "complete" })).is_err(),
            "interim state field must not parse"
        );
    }

    /// Serialization emits the canonical hyphenated wire form.
    #[test]
    fn nested_part_test_serializes_canonical_wire() {
        let t: NestedPartTest = serde_json::from_value(json!({
            "relation": "command-substitution",
            "occurrence": 2,
            "profile": "rm-safe",
            "classification": "opaque",
            "verdict": "allow"
        }))
        .unwrap();
        let wire = serde_json::to_value(&t).unwrap();
        assert_eq!(
            wire,
            json!({
                "relation": "command-substitution",
                "occurrence": 2,
                "profile": "rm-safe",
                "classification": "opaque",
                "verdict": "allow"
            })
        );
    }
}
