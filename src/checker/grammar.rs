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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<Occurrence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_fact: Option<FactCoordinate>,
}

impl PositionalCoordinate {
    pub fn is_remainder_form(&self) -> bool {
        matches!(
            self,
            PositionalCoordinate::N {
                remainder: true,
                ..
            }
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OptionValueCoordinate {
    pub option: String,
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
    #[serde(default)]
    pub value_ordinal: Option<Occurrence>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RedirectCoordinate {
    pub operator: RedirectOp,
    pub source_fd: FdSelector,
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

/// `rustfmt::skip` pins the single-line `All { all: bool }` variant: the docs
/// grammar snapshot is token-identical to this source and rustfmt would
/// otherwise reformat the variant into a comma that drifts. The attribute is
/// invisible to the snapshot extractor.
#[rustfmt::skip]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum PositionalCoordinate {
    N {
        index: u32,
        #[serde(default)]
        remainder: bool,
    },
    All { all: bool },
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
/// further arguments; `{each: selector}` = every remaining literal token must
/// satisfy the token selector (design §Reusable redirect policies semantics;
/// closed vocabulary: exact-member or safe path-selector).
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum RemainderPolicy {
    None { none: bool },
    Each { each: TokenSelector },
}

/// Closed token selector for `remainder: {each}`.
#[derive(Debug, Clone, PartialEq, sw_attrs::GrammarDocAttrs)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub enum TokenSelector {
    /// Every remainder token must be one of these literal tokens.
    Exact(Vec<String>),
    /// Every remainder token must be a literal path within this lexical root.
    Within(String),
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
    /// Values map: canonical option → glob list; existential per value.
    pub values: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// Allow coverage policy ({ "none": true }); selects the allow form.
    pub none: Option<bool>,
    /// Allow coverage policy ({ "allowed": [entry, ...] }).
    pub allowed: Option<Vec<OptionCoverage>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OptionCoverage {
    pub option: String,
    pub required: bool,
    pub repeatable: bool,
    /// Closed value selector for every consumed / inline value.
    pub values: Option<ValuesCoverage>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ValuesCoverage {
    None { none: bool },
    Each { each: Vec<String> },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnvironmentTest {
    pub name: String,
    /// Literal value (exact) — optional = unconstrained.
    pub value: Option<String>,
    /// Assignment must sit in the command prefix (`FOO=1 cmd`) when true.
    pub prefix: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FactTest {
    pub analyzer: Option<String>,
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NestedPartTest {
    pub relation: Option<Relation>,
    /// Executable head of the nested part (lexical), e.g. `rm`.
    pub executable: Option<String>,
    ///// Selected profile for the nested part (config reference).
    pub profile: Option<String>,
    /// `(analyzerCommand)` parts originate from that analyzer's ID.
    pub analyzer: Option<String>,
    /// Match only when the nested part itself is in this evidence state.
    pub state: Option<EvidenceClass>,
    /// A nested part must already reduce to this verdict for the parent's
    /// nesting-coverage policy to cover it.
    pub verdict: Option<VerdictKind>,
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
}

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

impl<'de> serde::Deserialize<'de> for TokenSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = TokenSelector;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a one-level token selector: {\"exact\": [token, ...]} or {\"within\": root}",
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
                    TokenSelectorField::Exact => {
                        let exact: Vec<String> = map.next_value()?;
                        TokenSelector::Exact(exact)
                    }
                    TokenSelectorField::Within => {
                        let within: String = map.next_value()?;
                        TokenSelector::Within(within)
                    }
                };
                if map.next_key::<TokenSelectorField>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "mixed token selector arms: use exactly one of exact/within",
                    ));
                }
                Ok(selector)
            }
        }
        deserializer.deserialize_map(V)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSelectorField {
    Exact,
    Within,
}

impl<'de> serde::Deserialize<'de> for TokenSelectorField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = TokenSelectorField;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a token selector arm: `exact` or `within`")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                match s {
                    "exact" => Ok(TokenSelectorField::Exact),
                    "within" => Ok(TokenSelectorField::Within),
                    other => Err(E::unknown_field(other, &["exact", "within"])),
                }
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl serde::Serialize for TokenSelector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            TokenSelector::Exact(exact) => map.serialize_entry("exact", exact)?,
            TokenSelector::Within(within) => map.serialize_entry("within", within)?,
        }
        map.end()
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
pub struct OptionSpec {
    /// Aliases exactly as they may appear in argv (`--long`, `-f`).
    pub aliases: Vec<String>,
    /// 0..=4 (validated in config loader).
    pub arity: u8,
    /// `--long=value` valid for every positive-arity option by default;
    /// set false to refuse the inline form.
    #[serde(default)]
    pub inline: Option<bool>,
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
/// `analyzerCommand`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum Relation {
    #[serde(rename = "chain")]
    Chain,
    #[serde(rename = "pipeline")]
    Pipeline,
    #[serde(rename = "wrapper")]
    Wrapper,
    #[serde(rename = "commandSubstitution")]
    CommandSubstitution,
    #[serde(rename = "analyzerCommand")]
    AnalyzerCommand,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remainder_none_parses_canonical() {
        let p: RemainderPolicy = serde_json::from_value(json!({ "none": true })).unwrap();
        assert_eq!(p, RemainderPolicy::None { none: true });
    }

    #[test]
    fn remainder_each_parses_canonical_exact() {
        let p: RemainderPolicy =
            serde_json::from_value(json!({ "each": { "exact": ["ls", "cat"] } })).unwrap();
        assert_eq!(
            p,
            RemainderPolicy::Each {
                each: TokenSelector::Exact(vec!["ls".into(), "cat".into()])
            }
        );
    }

    #[test]
    fn remainder_each_parses_canonical_within() {
        let p: RemainderPolicy =
            serde_json::from_value(json!({ "each": { "within": "/work/project" } })).unwrap();
        assert_eq!(
            p,
            RemainderPolicy::Each {
                each: TokenSelector::Within("/work/project".into())
            }
        );
    }

    /// Externally tagged nesting (`{"none": {"none": true}}`, docs release
    /// fixture `RemainderPolicy/nested-serde-none.json`) is rejected, not
    /// accepted as an alias.
    #[test]
    fn remainder_nested_none_rejected() {
        let e = serde_json::from_value::<RemainderPolicy>(json!({ "none": { "none": true } }));
        assert!(e.is_err(), "nested externally tagged none must not parse");
    }

    #[test]
    fn remainder_nested_each_rejected() {
        let e = serde_json::from_value::<RemainderPolicy>(
            json!({ "each": { "each": { "any": true } } }),
        );
        assert!(e.is_err(), "nested each must not parse");
    }

    /// Mixed union arms (`{"none": true, "each": …}`) are invalid.
    #[test]
    fn remainder_mixed_arms_rejected() {
        let e = serde_json::from_value::<RemainderPolicy>(json!({
            "none": true,
            "each": { "exact": ["ls"] }
        }));
        assert!(e.is_err(), "mixed none+each must not parse");
    }

    #[test]
    fn remainder_empty_object_rejected() {
        assert!(serde_json::from_value::<RemainderPolicy>(json!({})).is_err());
    }

    #[test]
    fn remainder_unknown_form_rejected() {
        assert!(serde_json::from_value::<RemainderPolicy>(json!({ "any": true })).is_err());
        // `{"none": false}` is not the documented closed form (const true).
        assert!(serde_json::from_value::<RemainderPolicy>(json!({ "none": false })).is_err());
    }

    #[test]
    fn token_selector_parses_canonical() {
        let a: TokenSelector = serde_json::from_value(json!({ "exact": ["-l", "-h"] })).unwrap();
        assert_eq!(a, TokenSelector::Exact(vec!["-l".into(), "-h".into()]));
        let b: TokenSelector = serde_json::from_value(json!({ "within": "/repo" })).unwrap();
        assert_eq!(b, TokenSelector::Within("/repo".into()));
    }

    #[test]
    fn token_selector_nested_mixed_unknown_rejected() {
        // recursively nested form (docs fixture OptionValueCoverage//nested-serde-each)
        assert!(
            serde_json::from_value::<TokenSelector>(json!({ "each": { "exact": ["ls"] } }))
                .is_err()
        );
        // mixed arms
        assert!(
            serde_json::from_value::<TokenSelector>(json!({
                "exact": ["ls"], "within": "/repo"
            }))
            .is_err()
        );
        // non-documented union arms must not parse (no aliases, no rich forms)
        assert!(serde_json::from_value::<TokenSelector>(json!({ "any": true })).is_err());
        assert!(
            serde_json::from_value::<TokenSelector>(json!({ "path": { "within": "/repo" } }))
                .is_err()
        );
        assert!(serde_json::from_value::<TokenSelector>(json!({})).is_err());
    }

    /// The wire forms themselves stay canonical: serialization never emits the
    /// accidentally externally tagged nested shape.
    #[test]
    fn remainder_and_selector_serialize_canonical() {
        let p = RemainderPolicy::Each {
            each: TokenSelector::Within("/work/project".into()),
        };
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!({ "each": { "within": "/work/project" } })
        );
        let p2 = RemainderPolicy::None { none: true };
        assert_eq!(serde_json::to_value(&p2).unwrap(), json!({ "none": true }));
        let t = TokenSelector::Exact(vec!["ls".into()]);
        assert_eq!(
            serde_json::to_value(&t).unwrap(),
            json!({ "exact": ["ls"] })
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
            "remainder": { "each": { "exact": ["origin", "main"] } }
        }))
        .unwrap();
        assert_eq!(
            m,
            ArgumentsMatcher {
                exact: None,
                prefix: Some(vec!["git".into(), "push".into()]),
                remainder: Some(RemainderPolicy::Each {
                    each: TokenSelector::Exact(vec!["origin".into(), "main".into()])
                }),
                contains_any: None,
            }
        );
    }
}
