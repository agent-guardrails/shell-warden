// Config loader + semantic validation (06 §6.1–6.3 mirrored onto the v2
// design, design/shell-warden-config-v2.md §Draft closed schema outline and
// validation): strict, fail-closed. Invalid ⇒ error (bin exits 2 with the
// message on stderr) — never fall back to defaults.
//
// Semantic validation covers: version, closed catalogs (analyzers, facts,
// redirect operators, relations), unique profile/executable/option aliases,
// policy references (default + every override), action-sensitive match shape
// (allow = `complete`, no `raw`, no `redirects` matcher, explicit coverage
// for every dimension), closure of `redirectPolicy` overrides, limits.
//
// Resolution is structural, not list-ordered: config default → profile
// override → allow-rule override; `extend` = set union; `replace` = discard
// inherited permissive entries and use only named + inline additions.

use super::analyzers;
use super::grammar::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub type ConfigResult = Result<Config, String>;

/// Interned config: profiles addressable by id; redirect policies resolve
/// structurally (design §Reusable redirect policies).
#[derive(Debug, Clone)]
pub struct Config {
    pub raw: RawConfig,
    /// Effective default redirect policy id (non-empty; `no-redirects` when
    /// the config omitted one and no allow rule needs it).
    pub defaults_redirect_policy: String,
    /// Every `re2-v1` pattern compiled at configuration load; a later whole-
    /// value match consults this cache (fail closed on a missing entry).
    pub regexes: RegexCache,
}

impl Config {
    pub fn defaults(&self) -> &Defaults {
        &self.raw.defaults
    }
    pub fn limits(&self) -> &Limits {
        &self.raw.limits
    }
    pub fn profiles(&self) -> &[Profile] {
        &self.raw.profiles
    }
    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.raw.profiles.iter().find(|p| p.id == id)
    }
    pub fn redirect_policies(&self) -> &std::collections::BTreeMap<String, RedirectPolicy> {
        &self.raw.redirect_policies
    }
    pub fn defaults_message(&self) -> Option<String> {
        self.raw.defaults.message.clone()
    }
}

/// Implementation-owned, versioned lexical alias catalog (design §Selected
/// architecture): a multi-spelling `executables` list equals one complete
/// entry; the equivalence asserts identical option grammar + analyzer
/// behavior — NOT resolved binary identity. Singleton lists need no entry.
pub const LEXICAL_ALIAS_CATALOG: &[&[&str]] = &[&["node", "nodejs"], &["python", "python3"]];

// ── Path helpers (v1 carry-over) ────────────────────────────────────────────

/// Default path: `$XDG_CONFIG_HOME/shell-warden/config.jsonc`, falling back
/// to `~/.config/shell-warden/config.jsonc` (06 §6.1).
pub fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
        && xdg.starts_with('/')
    {
        return Some(PathBuf::from(xdg).join("shell-warden").join("config.jsonc"));
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
        && home.starts_with('/')
    {
        return Some(PathBuf::from(home).join(".config/shell-warden/config.jsonc"));
    }
    None
}

/// `{env:NAME}` substitution kept from v1 (06 §4.2): the checker only
/// expands toward an absolute file path.
pub fn expand_env(path: &str) -> Result<PathBuf, String> {
    let mut out = path.to_string();
    for key in extract_env_names(path) {
        match std::env::var(&key) {
            Ok(v) => out = out.replace(&format!("{{env:{key}}}"), &v),
            Err(_) => {
                return Err(format!(
                    "{{env:{key}}} unset in argv member \"{path}\" — config invalid (I2)"
                ));
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
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if &s[i..i + 5] == "{env:"
            && let Some(close) = s[i..].find('}')
        {
            out.push(s[i + 5..i + close].to_string());
            i += close + 1;
            continue;
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
///
/// `serde_json` normalizes duplicate object keys to last-wins, which silently
/// widens policies (`{"within": "/repo/safe", "within": "/"}` keeps only the
/// permissive value; a duplicated `redirectPolicies` entry can downgrade to
/// allow-or-ask at map-field level). `duplicate_free_value` rejects *any*
/// duplicate object key at any nesting depth — selectors, structs, and
/// map-valued fields alike — before a normalized value exists.
pub fn load_str(text: &str) -> ConfigResult {
    let stripped =
        strip_jsonc(text).map_err(|e| format!("config invalid: JSONC syntax error: {e}"))?;
    let value =
        duplicate_free_value(&stripped).map_err(|e| format!("config invalid: JSON error: {e}"))?;
    let limit = raw_limits_bytes(&value);
    if text.len() > limit as usize {
        return Err(format!(
            "config invalid: {} bytes exceeds configBytes cap {limit}",
            text.len()
        ));
    }
    let raw: RawConfig =
        serde_json::from_value(value).map_err(|e| format!("config invalid: schema: {e}"))?;
    let config = validate(raw).map_err(|e| format!("config invalid: {e}"))?;
    Ok(config)
}

/// Build a `Value` from raw JSON text, rejecting duplicate object keys at any
/// depth (`serde_json::from_str::<Value>` would collapse them last-wins).
/// Every alternative shape — struct fields, canonical selector arms, and
/// map-valued fields (`redirectPolicies`, `options`, `match.options.values`) —
/// therefore carries every raw key to this visitor.
fn duplicate_free_value(text: &str) -> Result<Value, serde_json::Error> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

    struct StrictValue;

    impl<'de> DeserializeSeed<'de> for StrictValue {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Value, D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }

    struct StrictVisitor;

    impl StrictVisitor {
        fn duplicate<D: serde::de::Error>(key: &str) -> D {
            D::custom(format!("duplicate object key `{key}`"))
        }
    }

    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON value free of duplicate object keys")
        }
        fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
            Ok(Value::Number(v.into()))
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
            Ok(Value::Number(v.into()))
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| E::custom("non-finite number in config"))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.to_owned()))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = access.next_element_seed(StrictValue)? {
                out.push(item);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
            let mut map = serde_json::Map::new();
            while let Some(key) = access.next_key::<String>()? {
                if map.contains_key(&key) {
                    return Err(Self::duplicate::<A::Error>(&key));
                }
                map.insert(key, access.next_value_seed(StrictValue)?);
            }
            Ok(Value::Object(map))
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValue.deserialize(&mut deserializer)?;
    // EOF Edge: a streaming deserializer returns after the first complete
    // value; everything after it (a second object, a scalar, garbage) would
    // otherwise be swallowed. `end()` fails on any trailing input.
    deserializer.end()?;
    Ok(value)
}

fn raw_limits_bytes(v: &Value) -> u64 {
    v.get("limits")
        .and_then(|l| l.get("configBytes"))
        .and_then(|x| x.as_u64())
        .unwrap_or_else(|| Limits::default().config_bytes)
}

// JSONC (JSON with comments) — v1 carry-over, unchanged semantics.
fn strip_jsonc(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            out.push(c as char);
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_string = true;
                out.push(c as char);
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            _ if (c as char).is_ascii() => {
                out.push(c as char);
                i += 1;
            }
            _ => {
                // decode multi-byte char as-is
                let ch_str = &text[i..];
                if let Some(ch) = ch_str.chars().next() {
                    out.push(ch);
                    i += ch.len_utf8();
                } else {
                    return Err("invalid utf-8".to_string());
                }
            }
        }
    }
    Ok(out)
}

// ── Validation ──────────────────────────────────────────────────────────────

const MAX_EXECUTABLES: usize = 8;
const MAX_ALIASES_PER_OPTION: usize = 16;
const MAX_PATH_SOURCES: usize = 64;
// Selector-alternative limit lives with the grammar closed unions (64); the
// option `values` map carries one closed selector per canonical id.

/// Analyzer-compatible canonical option ids (closed compatibility table,
/// design §Profiles, option grammars, and analyzers). `sed-v1` is the only
/// analyzer with a modeled option grammar; `-n` and `-E` are its recognized
/// read-only options.
fn analyzer_compatible_options(analyzer: AnalyzerId) -> &'static [&'static str] {
    match analyzer {
        AnalyzerId::SedV1 => &["inPlace", "noPrint", "extendedRegexp", "expression", "file"],
        AnalyzerId::GenericV1 | AnalyzerId::ExportV1 | AnalyzerId::XargsV1 => &[],
    }
}

fn canonical_is_compatible(analyzer: AnalyzerId, canonical: &str) -> bool {
    match analyzer {
        AnalyzerId::SedV1 => analyzer_compatible_options(analyzer).contains(&canonical),
        // non-modeled analyzers impose no canonical-id table
        _ => true,
    }
}

fn validate(raw: RawConfig) -> Result<Config, String> {
    if raw.version != CONFIG_VERSION {
        return Err(format!(
            "version must be {CONFIG_VERSION} (got {})",
            raw.version
        ));
    }
    let limits = raw.limits.clone();
    if raw.profiles.len() as u32 > limits.profiles {
        return Err(format!(
            "profiles count {} exceeds cap {}",
            raw.profiles.len(),
            limits.profiles
        ));
    }
    if raw.defaults.action != VerdictKind::Ask {
        return Err("defaults.action is always ask (never fail-open)".to_string());
    }
    if raw
        .defaults
        .message
        .as_deref()
        .map(|m| m.len() > 512)
        .unwrap_or(false)
    {
        return Err("defaults.message exceeds 512 chars".to_string());
    }

    // ── named redirect policies ──
    for (id, policy) in &raw.redirect_policies {
        if id.is_empty() || id.len() > 64 || id.contains(char::is_whitespace) {
            return Err(format!("redirect policy id \"{id}\" is not a name"));
        }
        validate_redirect_coverage(&policy.redirects)?;
        validate_redirect_path_coverage(&policy.paths)?;
    }

    // ── defaults.redirectPolicy ──
    let any_allow = raw
        .profiles
        .iter()
        .any(|p| p.rules.iter().any(|r| r.action == VerdictKind::Allow));
    let defaults_redirect = raw
        .defaults
        .redirect_policy
        .clone()
        .unwrap_or_else(|| "no-redirects".to_string());
    if defaults_redirect != "no-redirects"
        && !raw.redirect_policies.contains_key(&defaults_redirect)
    {
        return Err(format!(
            "defaults.redirectPolicy references unknown policy \"{defaults_redirect}\""
        ));
    }
    if any_allow {
        // an allow rule eventually resolves the config default: the reference
        // must exist even when omitted ("no-redirects" is built-in)
        if raw.defaults.redirect_policy.is_none() {
            return Err(
                "defaults.redirectPolicy is required when an allow rule exists".to_string(),
            );
        }
    }

    // ── profiles ──
    let mut seen_exec: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut seen_id: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for profile in &raw.profiles {
        validate_profile(
            profile,
            &raw.redirect_policies,
            &mut seen_exec,
            &mut seen_id,
            &limits,
        )?;
    }

    let total_rules: usize = raw.profiles.iter().map(|p| p.rules.len()).sum();
    if total_rules as u32 > limits.rules {
        return Err(format!(
            "rules count {total_rules} exceeds cap {}",
            limits.rules
        ));
    }

    // closed references across profiles: nestedParts.profile must name a
    // declared profile id; the literal `none` selects unprofiled parts
    for profile in &raw.profiles {
        for rule in &profile.rules {
            if let Some(np) = &rule.r#match.nested_parts {
                let lists = [&np.any, &np.all];
                for list in lists.into_iter().flatten() {
                    for e in list {
                        if let Some(pid) = &e.profile
                            && pid != NESTED_PROFILE_NONE
                            && !seen_id.contains(pid)
                        {
                            return Err(format!(
                                "nestedParts.profile references unknown profile \"{pid}\""
                            ));
                        }
                    }
                }
            }
        }
    }

    let regexes = compile_config_regexes(&raw)?;
    let cfg = Config {
        raw,
        defaults_redirect_policy: defaults_redirect,
        regexes,
    };
    // cross-check: every nestedParts profile reference resolves (already done
    // per rule against the profile set in validate_profile)
    Ok(cfg)
}

/// Validate every closed selector surface and precompile each `re2-v1`
/// pattern into the load-time cache (design §Action-sensitive matching:
/// "compiled when configuration loads"). A pattern outside the fixed dialect
/// — backreference, look-around, whitespace — invalidates the config.
fn compile_config_regexes(raw: &RawConfig) -> Result<RegexCache, String> {
    let mut regexes = RegexCache::default();
    for profile in &raw.profiles {
        for rule in &profile.rules {
            precompile_match_selectors(&rule.r#match, &mut regexes)?;
        }
        for hint in &profile.fallback_hints {
            if let Some(m) = &hint.r#match {
                precompile_match_selectors(m, &mut regexes)?;
            }
        }
    }
    Ok(regexes)
}

fn precompile_match_selectors(m: &Match, regexes: &mut RegexCache) -> Result<(), String> {
    if let Some(a) = &m.arguments
        && let Some(RemainderPolicy::Each { each }) = &a.remainder
    {
        validate_token_selector(each, regexes)?;
    }
    if let Some(o) = &m.options {
        if let Some(values) = &o.values {
            for sel in values.values() {
                validate_token_selector(sel, regexes)?;
            }
        }
        if let Some(allowed) = &o.allowed {
            for entry in allowed {
                if let Some(coverage) = entry.values() {
                    validate_option_value_coverage(coverage, regexes)?;
                }
            }
        }
    }
    if let Some(facts) = &m.facts {
        for e in facts.any.iter().chain(facts.all.iter()).flatten() {
            precompile_fact_test_selectors(e, regexes)?;
        }
    }
    if let Some(env) = &m.environment {
        for e in env.any.iter().chain(env.all.iter()).flatten() {
            // the `re2-v1` regex arm of an environment string-value selector
            // is precompiled at config load — fail closed on a bad pattern
            if let Some(StringValueSelector::Regex(pattern)) = &e.value {
                regexes.add(pattern)?;
            }
        }
    }
    Ok(())
}

/// Precompile the `re2-v1` pattern of a fact's typed string-value selector and
/// validate its path selector — the same closed dialect and lexical-path rules
/// as token and option-value selectors (fail closed at config load).
fn precompile_fact_test_selectors(e: &FactTest, regexes: &mut RegexCache) -> Result<(), String> {
    match &e.value {
        Some(TypedValueSelector::String {
            string: StringValueSelector::Regex(pattern),
        }) => regexes.add(pattern),
        Some(TypedValueSelector::Path { path }) => validate_path_selector(path),
        _ => Ok(()),
    }
}

fn validate_option_value_coverage(
    coverage: &OptionValueCoverage,
    regexes: &mut RegexCache,
) -> Result<(), String> {
    coverage.validate_shape()?;
    match coverage {
        OptionValueCoverage::Each { each } => validate_token_selector(each, regexes),
        OptionValueCoverage::ByPosition { by_position } => {
            for sel in by_position {
                validate_token_selector(sel, regexes)?;
            }
            Ok(())
        }
    }
}

/// Closed-token-selector validation beyond serde: value-ordinal and path
/// bounds (absolute lexical roots), plus regex precompilation.
fn validate_token_selector(sel: &TokenSelector, regexes: &mut RegexCache) -> Result<(), String> {
    match sel {
        TokenSelector::Str(StringValueSelector::Regex(pattern)) => regexes.add(pattern),
        TokenSelector::Str(_) => Ok(()),
        TokenSelector::Path(path) => validate_path_selector(path),
    }
}

/// Absolute lexical paths on every path-selector arm: a *normalized* absolute
/// path — no `//`, no `.` / `..` components, no trailing slash. A root like
/// `/repo/..` normalizes to `/` and would widen coverage; a root like
/// `//work` shifts component comparison — both are invalid input, not
/// implicitly normalized.
fn validate_path_selector(p: &PathSelector) -> Result<(), String> {
    let (kind, val) = match p {
        PathSelector::Exact { exact } => ("exact", exact),
        PathSelector::Within { within } => ("within", within),
        PathSelector::Outside { outside } => ("outside", outside),
    };
    if val.len() > MAX_PATH_BYTES {
        return Err(format!(
            "path selector {kind} exceeds {MAX_PATH_BYTES} UTF-8 bytes"
        ));
    }
    if !val.starts_with('/') {
        return Err(format!(
            "path selector {kind} root \"{val}\" must be an absolute lexical path"
        ));
    }
    normalized_absolute(val).ok_or_else(|| {
        format!("path selector {kind} root \"{val}\" is not a normalized absolute lexical path")
    })?;
    Ok(())
}

/// The normalized form of an absolute lexical path, or `None` when the text
/// falls outside the published pattern (`^/` with no `//`, no `.` / `..`
/// components). A single trailing slash is boundary-preserved and accepted
/// (`/repo/` — docs schema `AbsoluteLexicalPath`); `//`, an interior empty
/// component, `.` and `..` are invalid input, not implicitly normalized.
fn normalized_absolute(value: &str) -> Option<String> {
    if !value.starts_with('/') {
        return None;
    }
    if value == "/" {
        return Some("/".into());
    }
    let comps: Vec<&str> = value[1..].split('/').collect();
    for (i, comp) in comps.iter().enumerate() {
        match *comp {
            // `//` (an empty component anywhere except the single trailing
            // boundary) shifts component comparison — invalid input; a `.` or
            // `..` component is invalid outright
            "." | ".." => return None,
            "" if i + 1 == comps.len() => {}
            "" => return None,
            _ => {}
        }
    }
    Some(format!("/{}", comps[..comps.len() - 1].join("/")))
}

// ── path coordinate selectors: one closed arm + option-grammar closure ──────

/// A path coordinate selector (schema: `PathCoordinateSelector` oneOf) carries
/// **exactly one** coordinate arm; an `optionValue` arm must reference a
/// declared canonical option inside its fixed arity. A malformed selector
/// would never match runtime coordinates and could silently let a broad
/// policy win.
fn validate_path_coordinate_selector(
    sel: &PathCoordinateSelector,
    profile: Option<&Profile>,
    allow_redirect: bool,
) -> Result<(), String> {
    let set = [
        sel.argument.is_some(),
        sel.option_value.is_some(),
        sel.environment.is_some(),
        sel.redirect.is_some(),
        sel.analyzer_fact.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if set != 1 {
        return Err(
            "path coordinate selector must select exactly one coordinate \
             (argument/optionValue/environment/redirect/analyzerFact)"
                .to_string(),
        );
    }
    if !allow_redirect && sel.redirect.is_some() {
        return Err(
            "redirect coordinates come from the redirect policy, not a non-redirect path coordinate"
                .to_string(),
        );
    }
    if let Some(profile) = profile
        && let Some(ov) = &sel.option_value
    {
        validate_option_value_coordinate(profile, ov)?;
    }
    if let Some(profile) = profile
        && let Some(fc) = &sel.analyzer_fact
    {
        validate_analyzer_fact_coordinate(profile, fc)?;
    }
    Ok(())
}

/// The `analyzerFact` coordinate must name a fact in the closed catalog of the
/// profile's *declared* analyzer: a mistyped fact name would silently produce
/// no coordinate and let a path value pass a `{ "none": true }` paths policy.
fn validate_analyzer_fact_coordinate(profile: &Profile, fc: &FactCoordinate) -> Result<(), String> {
    let Some(analyzer) = profile.analyzer else {
        return Err(format!(
            "path coordinate analyzerFact \"{}\" references an analyzer, but the profile declares none",
            fc.name
        ));
    };
    if let Some(id) = &fc.analyzer
        && id != analyzer.id()
    {
        return Err(format!(
            "path coordinate analyzerFact \"{}\" references analyzer \"{}\" outside the profile analyzer {}",
            fc.name,
            id,
            analyzer.id()
        ));
    }
    if !super::analyzers::knows_fact(analyzer, &fc.name) {
        return Err(format!(
            "path coordinate analyzerFact \"{}\" is not in the {} fact catalog",
            fc.name,
            analyzer.id()
        ));
    }
    Ok(())
}

/// The `optionValue` coordinate must name a declared canonical option and stay
/// inside its fixed arity: a silent miss would let a path value slip through a
/// `{ "none": true }` paths policy.
fn validate_option_value_coordinate(
    profile: &Profile,
    ov: &OptionValueCoordinate,
) -> Result<(), String> {
    let Some(spec) = profile.options.get(&ov.option) else {
        return Err(format!(
            "path coordinate optionValue references undeclared option \"{}\"",
            ov.option
        ));
    };
    if spec.arity == 0 {
        return Err(format!(
            "path coordinate optionValue references zero-arity option \"{}\"",
            ov.option
        ));
    }
    if ov.value_ordinal == 0 || ov.value_ordinal > spec.arity as u32 {
        return Err(format!(
            "path coordinate optionValue valueOrdinal {} is outside 1..={}",
            ov.value_ordinal, spec.arity
        ));
    }
    // a `occurrence: 0` selector never matches (parse rejected), but a
    // declared occurrence must still be a plain ordinal — Occurrence::N
    // only carries positive numbers after deserialization
    Ok(())
}

fn validate_profile(
    profile: &Profile,
    policies: &std::collections::BTreeMap<String, RedirectPolicy>,
    seen_exec: &mut std::collections::BTreeMap<String, String>,
    seen_id: &mut std::collections::BTreeSet<String>,
    limits: &Limits,
) -> Result<(), String> {
    if profile.id.is_empty() || profile.id.len() > 128 {
        return Err(format!("profile id \"{}\" out of bounds", profile.id));
    }
    if !seen_id.insert(profile.id.clone()) {
        return Err(format!("duplicate profile id \"{}\"", profile.id));
    }
    if profile.executables.is_empty() || profile.executables.len() > MAX_EXECUTABLES {
        return Err(format!(
            "profile \"{}\": executables must be 1..{MAX_EXECUTABLES} aliases",
            profile.id
        ));
    }
    let mut uniq = profile.executables.clone();
    uniq.sort();
    uniq.dedup();
    if uniq.len() != profile.executables.len() {
        return Err(format!(
            "profile \"{}\": duplicate executables alias",
            profile.id
        ));
    }
    if profile.executables.len() > 1 {
        let in_catalog = LEXICAL_ALIAS_CATALOG.iter().any(|entry| {
            let mut e: Vec<&str> = entry.to_vec();
            e.sort_unstable();
            e.as_slice()
                == uniq
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .as_slice()
        });
        if !in_catalog {
            return Err(format!(
                "profile \"{}\": multi-spelling executables {:?} must equal one lexical alias catalog entry",
                profile.id, profile.executables
            ));
        }
    }
    for alias in &profile.executables {
        if alias.is_empty() {
            return Err(format!(
                "profile \"{}\": empty executable alias",
                profile.id
            ));
        }
        if let Some(other) = seen_exec.get(alias) {
            return Err(format!(
                "profile \"{}\": executable alias \"{alias}\" already owned by profile \"{other}\"",
                profile.id
            ));
        }
        seen_exec.insert(alias.clone(), profile.id.clone());
    }

    // ── options ──
    let mut seen_alias: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (canonical, spec) in &profile.options {
        if canonical.is_empty() || canonical.len() > 64 {
            return Err(format!(
                "profile \"{}\": option id out of bounds",
                profile.id
            ));
        }
        if spec.arity > MAX_OPTION_ARITY {
            return Err(format!(
                "profile \"{}\": option \"{canonical}\" arity {} exceeds {MAX_OPTION_ARITY}",
                profile.id, spec.arity
            ));
        }
        // inline form opt-in for a declared arity-one option only
        if spec.inline == Some(true) && spec.arity != 1 {
            return Err(format!(
                "profile \"{}\": option \"{canonical}\" declares inline for arity {}, \
                 but the inline form is valid only for arity one",
                profile.id, spec.arity
            ));
        }
        if spec.aliases.is_empty() || spec.aliases.len() > MAX_ALIASES_PER_OPTION {
            return Err(format!(
                "profile \"{}\": option \"{canonical}\" bad aliases list size",
                profile.id
            ));
        }
        for alias in &spec.aliases {
            if alias.is_empty() || alias.len() > 32 {
                return Err(format!(
                    "profile \"{}\": option \"{canonical}\" bad alias \"{alias}\"",
                    profile.id
                ));
            }
            // parser-visible alias grammar (design §Profiles, option
            // grammars): the option parser only treats dash-prefixed argv
            // tokens as option tokens, the bare `--` token is the terminator,
            // the bare `-` token is a positional, and inline forms split at
            // the first `=`. Anything outside that shape can load but never
            // be observed as a declared option — dead canonical policies.
            if !alias.starts_with('-') {
                return Err(format!(
                    "profile \"{}\": option \"{canonical}\" alias \"{alias}\" must begin with a dash",
                    profile.id
                ));
            }
            if alias == "-" || alias == "--" {
                return Err(format!(
                    "profile \"{}\": option \"{canonical}\" alias \"{alias}\" is a parser boundary \
                     (the bare dash is a positional, `--` is the terminator) and can never be observed",
                    profile.id
                ));
            }
            if alias.contains('=') {
                return Err(format!(
                    "profile \"{}\": option \"{canonical}\" alias \"{alias}\" contains '=': \
                     inline forms split at the first '=', so this alias can never match",
                    profile.id
                ));
            }
            if !seen_alias.insert(alias.clone()) {
                return Err(format!(
                    "profile \"{}\": duplicate option alias \"{alias}\"",
                    profile.id
                ));
            }
        }
        if let Some(analyzer) = profile.analyzer
            && !canonical_is_compatible(analyzer, canonical)
        {
            return Err(format!(
                "profile \"{}\": option \"{canonical}\" is not in the {} compatibility table",
                profile.id,
                analyzer.id()
            ));
        }
    }

    // ── analyzer + fact catalog closure ──
    if let Some(analyzer) = profile.analyzer {
        // compatibility consults the catalog: the profile must model its
        // option grammar consistently (non-model analyzers: any canonicals)
        let _ = analyzer_compatible_options(analyzer);
    }

    // ── pathSources ──
    if profile.path_sources.len() > MAX_PATH_SOURCES {
        return Err(format!(
            "profile \"{}\": pathSources exceeds {MAX_PATH_SOURCES}",
            profile.id
        ));
    }
    for sel in &profile.path_sources {
        validate_path_coordinate_selector(sel, Some(profile), false)?;
        if let Some(ov) = &sel.option_value {
            validate_option_value_coordinate(profile, ov)?;
        }
    }

    // ── profile-level redirect override ──
    if let Some(ov) = &profile.redirect_policy {
        validate_override(ov, policies)?;
    }

    // ── rules ──
    let mut seen_rule: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for rule in &profile.rules {
        if rule.id.is_empty() || rule.id.len() > 128 {
            return Err(format!("rule id \"{}\" out of bounds", rule.id));
        }
        if !seen_rule.insert(format!("{}/{}", profile.id, rule.id)) {
            return Err(format!("duplicate rule id \"{}/{}\"", profile.id, rule.id));
        }
        if rule
            .message
            .as_deref()
            .map(|m| m.len() > 512)
            .unwrap_or(false)
        {
            return Err(format!("rule \"{}\" message exceeds 512 chars", rule.id));
        }
        match rule.action {
            VerdictKind::Allow => {
                validate_allow_match(rule, profile, policies)?;
                if let Some(ov) = &rule.redirect_policy {
                    validate_override(ov, policies)?;
                }
            }
            VerdictKind::Ask | VerdictKind::Deny => validate_ask_deny_match(rule, profile)?,
        }
        if rule.redirect_policy.is_some() && rule.action != VerdictKind::Allow {
            return Err(format!(
                "rule \"{}\": redirectPolicy override is allow-only",
                rule.id
            ));
        }
    }
    let n_rules: u32 = profile.rules.len() as u32;
    if n_rules > limits.rules {
        return Err(format!(
            "rules count {n_rules} exceeds cap {}",
            limits.rules
        ));
    }

    // ── fallback hints ──
    if profile.fallback_hints.len() > 64 {
        return Err(format!(
            "profile \"{}\": fallbackHints exceeds 64",
            profile.id
        ));
    }
    let mut seen_hint: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for hint in &profile.fallback_hints {
        if hint.id.is_empty() || hint.id.len() > 128 {
            return Err(format!("hint id \"{}\" out of bounds", hint.id));
        }
        if !seen_hint.insert(hint.id.clone()) {
            return Err(format!("duplicate hint id \"{}\"", hint.id));
        }
        if let Some(m) = &hint.r#match {
            validate_ordinary_match_shape(m)?;
            // hint matches can name path coordinates: same single-arm +
            // option-grammar closure as ask/deny rules
            if let Some(paths) = &m.paths {
                let lists = [&paths.any, &paths.all];
                for list in lists.into_iter().flatten() {
                    for e in list {
                        validate_path_coordinate_selector(&e.coordinate, Some(profile), true)?;
                        validate_path_policy(&e.policy())?;
                    }
                }
            }
        }
    }
    Ok(())
}

// The empty-selector case is covered by the exactly-one-arm validation of
// `validate_path_coordinate_selector`.

fn validate_redirect_coverage(c: &RedirectCoverage) -> Result<(), String> {
    let RedirectCoverage::All { all } = c else {
        return Ok(()); // `none` shape validated by serde
    };
    if all.is_empty() {
        return Err("redirect coverage policy with zero entries".to_string());
    }
    for e in all {
        // closed pairing: input/truncate/append carry literal-path targets;
        // duplication carries FD targets
        match (e.operator, e.target.kind) {
            (RedirectOp::DupOut | RedirectOp::DupIn, TargetKindKind::Fd)
            | (
                RedirectOp::In | RedirectOp::Out | RedirectOp::AppendOut,
                TargetKindKind::LiteralPath,
            ) => {}
            _ => {
                return Err(format!(
                    "redirect entry operator {:?} mispairs target kind {:?}",
                    e.operator, e.target.kind
                ));
            }
        }
    }
    Ok(())
}

fn validate_redirect_path_coverage(c: &PathCoverage) -> Result<(), String> {
    let PathCoverage::All { all } = c else {
        return Ok(());
    };
    if all.is_empty() {
        return Err("redirect path coverage policy with zero entries".to_string());
    }
    for e in all {
        if e.coordinate.redirect.is_none() {
            return Err(
                "redirect policy path entries must select a redirect coordinate".to_string(),
            );
        }
        // single-arm selector: `redirect` + any other coordinate arm is a
        // multi-arm shape the public schema rejects
        validate_path_coordinate_selector(&e.coordinate, None, true)?;
        validate_path_policy(&e.policy())?;
    }
    Ok(())
}

/// Lexical path policy: exactly one selector; trusted roots are absolute *and*
/// normalized (no `//`, no `.`/`..` components), within the schema's
/// `AbsoluteLexicalPath` byte cap (4096) — a non-normalized root would
/// silently widen coverage.
fn validate_path_policy(p: &PathPolicy) -> Result<(), String> {
    let set = p.exact.is_some() as u8 + p.within.is_some() as u8 + p.outside.is_some() as u8;
    if set != 1 {
        return Err("path policy must select exactly one of exact/within/outside".to_string());
    }
    for root in ["exact", "within", "outside"] {
        let val = match root {
            "exact" => p.exact.as_deref().unwrap_or("/"),
            "within" => p.within.as_deref().unwrap_or("/"),
            _ => p.outside.as_deref().unwrap_or("/"),
        };
        if val.len() > MAX_PATH_BYTES {
            return Err(format!(
                "path policy {root} root exceeds {MAX_PATH_BYTES} UTF-8 bytes"
            ));
        }
        if !val.starts_with('/') {
            return Err(format!(
                "path policy {root} root \"{val}\" must be an absolute lexical path"
            ));
        }
        normalized_absolute(val).ok_or_else(|| {
            format!("path policy {root} root \"{val}\" is not a normalized absolute lexical path")
        })?;
    }
    Ok(())
}

fn validate_override(
    ov: &RedirectPolicyOverride,
    policies: &std::collections::BTreeMap<String, RedirectPolicy>,
) -> Result<(), String> {
    match ov.mode {
        OverrideMode::Inherit => {
            if ov.policies.is_some() || ov.inline.is_some() {
                return Err("inherit carries no named or inline additions".to_string());
            }
        }
        OverrideMode::Extend | OverrideMode::Replace => {
            if ov.policies.is_none() && ov.inline.is_none() {
                return Err(format!(
                    "{:?} override must carry at least one named policy or an inline bundle",
                    ov.mode
                ));
            }
            if let Some(ids) = &ov.policies {
                if ids.is_empty() {
                    return Err("empty named policy list in override".to_string());
                }
                for id in ids {
                    if !policies.contains_key(id) {
                        return Err(format!("override references unknown policy \"{id}\""));
                    }
                }
            }
        }
    }
    if let Some(inline) = &ov.inline {
        validate_redirect_coverage(&inline.redirects)?;
        validate_redirect_path_coverage(&inline.paths)?;
    }
    Ok(())
}

/// Ordinary match shape validations shared by ask/deny rules and hints.
fn validate_ordinary_match_shape(m: &Match) -> Result<(), String> {
    if let Some(a) = &m.arguments {
        if a.exact.is_some() && a.prefix.is_some() {
            return Err("arguments.exact and arguments.prefix are mutually exclusive".to_string());
        }
        if a.prefix.is_some() && a.remainder.is_some() {
            return Err("arguments.remainder is an allow-only coverage form".to_string());
        }
        if a.exact.is_some() && a.remainder.is_some() {
            return Err("arguments.exact must not carry a remainder".to_string());
        }
        if a.exact.is_none() && a.prefix.is_none() && a.contains_any.is_none() {
            return Err("empty arguments matcher".to_string());
        }
    }
    if let Some(o) = &m.options {
        if o.allowed.is_some() {
            return Err("options.allowed is an allow-only coverage form".to_string());
        }
        if o.none == Some(true) && o.allowed.is_some() {
            return Err("options none and allowed are exclusive".to_string());
        }
        if o.present_all.is_none()
            && o.present_any.is_none()
            && o.absent_all.is_none()
            && o.values.is_none()
            && o.none.is_none()
        {
            return Err("empty options matcher".to_string());
        }
    }
    validate_env_matcher(&m.environment)?;
    if let Some(r) = &m.redirects {
        match (r.none, &r.any, &r.all) {
            (Some(true), None, None) => {}
            (None | Some(false), Some(any), None) => {
                if any.is_empty() {
                    return Err("empty redirects matcher".to_string());
                }
            }
            (None | Some(false), None, Some(all)) => {
                if all.is_empty() {
                    return Err("empty redirects matcher".to_string());
                }
            }
            _ => {
                return Err("redirects matcher accepts exactly one of none/any/all".to_string());
            }
        }
    }
    if let Some(p) = &m.paths {
        match (p.none, &p.any, &p.all) {
            (Some(true), None, None) => {}
            (None, Some(any), None) => {
                if any.is_empty() {
                    return Err("empty paths matcher".to_string());
                }
                for e in any {
                    validate_path_policy(&e.policy())?;
                }
            }
            (None, None, Some(all)) => {
                if all.is_empty() {
                    return Err("empty paths matcher".to_string());
                }
                for e in all {
                    validate_path_policy(&e.policy())?;
                }
            }
            _ => return Err("paths matcher accepts exactly one of none/any/all".to_string()),
        }
    }
    if let Some(fm) = &m.facts {
        match (fm.none, &fm.any, &fm.all) {
            (Some(true), None, None) => {}
            (None | Some(false), Some(any), None) => {
                if any.is_empty() {
                    return Err("empty facts matcher".to_string());
                }
            }
            (None | Some(false), None, Some(all)) => {
                if all.is_empty() {
                    return Err("empty facts matcher".to_string());
                }
            }
            _ => return Err("facts matcher accepts exactly one of none/any/all".to_string()),
        }
    }
    if let Some(np) = &m.nested_parts {
        match (np.none, &np.any, &np.all) {
            (Some(true), None, None) => {}
            (None | Some(false), Some(any), None) => {
                if any.is_empty() {
                    return Err("empty nestedParts matcher".to_string());
                }
            }
            (None | Some(false), None, Some(all)) => {
                if all.is_empty() {
                    return Err("empty nestedParts matcher".to_string());
                }
            }
            _ => {
                return Err("nestedParts matcher accepts exactly one of none/any/all".to_string());
            }
        }
    }
    Ok(())
}

fn validate_env_matcher(e: &Option<EnvironmentMatcher>) -> Result<(), String> {
    let Some(e) = e else { return Ok(()) };
    match (e.none, &e.any, &e.all) {
        (Some(true), None, None) => {}
        (None | Some(false), Some(any), None) => {
            if any.is_empty() {
                return Err("empty environment matcher".to_string());
            }
        }
        (None | Some(false), None, Some(all)) => {
            if all.is_empty() {
                return Err("empty environment matcher".to_string());
            }
        }
        _ => return Err("environment matcher accepts exactly one of none/any/all".to_string()),
    }
    Ok(())
}

fn validate_allow_match(
    rule: &Rule,
    profile: &Profile,
    policies: &std::collections::BTreeMap<String, RedirectPolicy>,
) -> Result<(), String> {
    let m = &rule.r#match;
    if m.raw.is_some() {
        return Err("raw predicates are unavailable to allow (coverage proof only)".to_string());
    }
    if m.redirects.is_some() {
        return Err("match.redirects is invalid for allow: redirect coverage comes from the effective redirect policy".to_string());
    }
    if !matches!(m.classification, Some(EvidenceClass::Complete)) {
        return Err("allow requires classification: \"complete\"".to_string());
    }
    // arguments: exactly one of exact | (prefix && remainder), no containsAny
    let Some(args) = &m.arguments else {
        return Err("allow requires an explicit arguments policy".to_string());
    };
    if args.contains_any.is_some() {
        return Err("arguments.containsAny is unavailable to allow".to_string());
    }
    let exact = args.exact.is_some();
    let prefix = args.prefix.is_some();
    let remainder = args.remainder.is_some();
    if exact == prefix || (prefix != remainder) {
        return Err("allow arguments are exact or prefix plus an explicit remainder".to_string());
    }
    if let Some(RemainderPolicy::Each { each }) = &args.remainder {
        // path arms must carry absolute lexical roots; regex patterns are
        // precompiled (and validated) after profile validation
        let _ = each;
    }
    // options: none or allowed (entries reference profile options)
    let Some(opts) = &m.options else {
        return Err("allow requires an explicit options policy".to_string());
    };
    if opts.present_all.is_some()
        || opts.present_any.is_some()
        || opts.absent_all.is_some()
        || opts.values.is_some()
    {
        return Err(
            "allow options use the coverage form (none/allowed), not presence tests".to_string(),
        );
    }
    match (opts.none, &opts.allowed) {
        (Some(true), None) => {}
        (None | Some(false), Some(allowed)) => {
            if allowed.is_empty() {
                return Err("options.allowed must carry at least one entry".to_string());
            }
            // canonical option ids are unique within one allowed list — even
            // when the duplicate entries differ in other fields
            let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for entry in allowed {
                let canonical = entry.option();
                if !seen.insert(canonical) {
                    return Err(format!(
                        "options.allowed carries a duplicate canonical option \"{canonical}\" policy"
                    ));
                }
                let Some(spec) = profile.options.get(canonical) else {
                    return Err(format!(
                        "option coverage references undeclared option \"{canonical}\""
                    ));
                };
                let values = entry.values();
                if spec.arity > 0 {
                    let Some(coverage) = values else {
                        return Err(format!(
                            "positive-arity option \"{canonical}\" must select every consumed \
                             value (values policy)"
                        ));
                    };
                    coverage.validate_shape()?;
                    if let OptionValueCoverage::ByPosition { by_position } = coverage
                        && by_position.len() != spec.arity as usize
                    {
                        return Err(format!(
                            "option \"{canonical}\" has fixed arity {} but its byPosition \
                             coverage lists {} selectors",
                            spec.arity,
                            by_position.len()
                        ));
                    }
                } else if values.is_some() {
                    // a positive-arity entry on a declared flag: the wire
                    // carried `values`, which a zero-arity option may never
                    // have
                    return Err(format!("zero-arity option \"{canonical}\" takes no values"));
                }
            }
        }
        _ => return Err("allow options are none or allowed".to_string()),
    }
    // environment: none or all
    let Some(env) = &m.environment else {
        return Err("allow requires an explicit environment policy".to_string());
    };
    match (env.none, &env.any, &env.all) {
        (Some(true), None, None) => {}
        (None | Some(false), None, Some(all)) if !all.is_empty() => {
            for e in all {
                if e.name.is_empty() || e.name.len() > 128 {
                    return Err("environment entry name out of bounds".to_string());
                }
                // the schema mandates `prefix` and `occurrence` on allow
                // environment entries (`EnvironmentPolicy`): a missing
                // dimension is invalid config — coverage is never synthesized
                // from an omitted field
                if e.prefix.is_none() || e.occurrence.is_none() {
                    return Err(
                        "allow environment entries require prefix and occurrence".to_string()
                    );
                }
            }
        }
        _ => return Err("allow environment is none or all".to_string()),
    }
    // paths: none or all (non-redirect coordinates only)
    let Some(paths) = &m.paths else {
        return Err("allow requires an explicit paths policy".to_string());
    };
    match (paths.none, &paths.any, &paths.all) {
        (Some(true), None, None) => {}
        (None | Some(false), None, Some(all)) if !all.is_empty() => {
            for e in all {
                // redirect coordinates come from the effective redirect
                // policy; the non-redirect selector must be single-arm and
                // must reference the profile's option grammar when it names
                // an option value
                validate_path_coordinate_selector(&e.coordinate, Some(profile), false)?;
                validate_path_policy(&e.policy())?;
            }
        }
        _ => return Err("allow paths is none or all".to_string()),
    }
    // facts: none or all (closed catalog references)
    let Some(facts) = &m.facts else {
        return Err("allow requires an explicit facts policy".to_string());
    };
    match (facts.none, &facts.any, &facts.all) {
        (Some(true), None, None) => {}
        (None | Some(false), None, Some(all)) if !all.is_empty() => {
            for e in all {
                validate_fact_policy(e, profile)?;
            }
        }
        _ => return Err("allow facts is none or all".to_string()),
    }
    // nestedParts: none or all (closed relation/profile/classification/
    // verdict selectors)
    let Some(np) = &m.nested_parts else {
        return Err("allow requires an explicit nestedParts policy".to_string());
    };
    match (np.none, &np.any, &np.all) {
        (Some(true), None, None) => {}
        (None | Some(false), None, Some(all)) if !all.is_empty() => {
            for e in all {
                validate_nested_part_policy(e)?;
            }
            // profile references may resolve to any profile in the config:
            // checked later by the caller's set membership
        }
        _ => return Err("allow nestedParts is none or all".to_string()),
    }
    // a rule-level redirect override must resolve against the config
    if let Some(ov) = &rule.redirect_policy {
        validate_override(ov, policies)?;
    }
    Ok(())
}

fn validate_fact_test(e: &FactTest, profile: &Profile) -> Result<(), String> {
    if e.name.is_empty() || e.name.len() > 64 {
        return Err("fact name out of bounds".to_string());
    }
    let Some(analyzer) = profile.analyzer else {
        return Err(format!(
            "fact \"{}\" references an analyzer, but the profile declares none",
            e.name
        ));
    };
    if let Some(id) = &e.analyzer
        && id != analyzer.id()
    {
        return Err(format!(
            "fact \"{}\" references analyzer \"{id}\" outside the profile analyzer {}",
            e.name,
            analyzer.id()
        ));
    }
    if !analyzers::knows_fact(analyzer, &e.name) {
        return Err(format!(
            "fact \"{}\" is not in the {} fact catalog",
            e.name,
            analyzer.id()
        ));
    }
    // closed analyzer version: every catalogued analyzer is "v1"
    if let Some(v) = &e.version
        && analyzers::analyzer_version(analyzer.id()) != Some(v.as_str())
    {
        return Err(format!(
            "fact \"{}\" references version \"{v}\", but the closed \"{}\" catalog is version \"{VER}\"",
            e.name,
            analyzer.id(),
            VER = analyzers::ANALYZER_VERSION
        ));
    }
    // the typed value selector must agree with the catalogued fact type
    if let Some(sel) = &e.value {
        let fact_type = analyzers::fact_catalog(analyzer)
            .iter()
            .find(|f| f.name == e.name)
            .map(|f| f.value_type)
            .expect("catalog membership checked above");
        validate_typed_value_selector(sel, fact_type)?;
    }
    Ok(())
}

/// Allow fact entries (`FactPolicy` on the wire) carry every closed field:
/// analyzer, version, occurrence, and typed value selector.
fn validate_fact_policy(e: &FactTest, profile: &Profile) -> Result<(), String> {
    if e.analyzer.is_none() || e.version.is_none() || e.occurrence.is_none() || e.value.is_none() {
        return Err(
            "allow fact entries require analyzer, version, occurrence, and a typed value selector"
                .to_string(),
        );
    }
    validate_fact_test(e, profile)
}

/// A nested-part selector must name at least one closed dimension (public
/// schema `NestedPartTest` `minProperties: 1`): an empty selector would
/// match every nested part — a fail-open hole.
fn validate_nested_part_test(e: &NestedPartTest) -> Result<(), String> {
    if e.relation.is_none()
        && e.profile.is_none()
        && e.classification.is_none()
        && e.verdict.is_none()
        && e.occurrence.is_none()
    {
        return Err("nestedParts entries require at least one selector".to_string());
    }
    Ok(())
}

/// Allow coverage entries carry the public `NestedPartPolicy` shape: every
/// field is required — relation, occurrence, profile, classification, and
/// the required reduced verdict.
fn validate_nested_part_policy(e: &NestedPartTest) -> Result<(), String> {
    if e.relation.is_none()
        || e.occurrence.is_none()
        || e.profile.is_none()
        || e.classification.is_none()
        || e.verdict.is_none()
    {
        return Err(
            "allow nestedParts entries require relation, occurrence, profile, classification, and verdict"
                .to_string(),
        );
    }
    validate_nested_part_test(e)
}

/// A typed value selector first agrees with the fact type from the analyzer
/// catalog (`any` always agrees); a wrong-type arm is invalid config — no
/// coercion, no string→path fallback.
fn validate_typed_value_selector(
    sel: &TypedValueSelector,
    fact_type: analyzers::FactValueType,
) -> Result<(), String> {
    use analyzers::FactValueType as VT;
    match sel {
        TypedValueSelector::Any => Ok(()),
        TypedValueSelector::Exact(scalar) => {
            let compatible = match (fact_type, scalar) {
                (VT::Str, ScalarValue::Str(_)) | (VT::Path, ScalarValue::Str(_)) => true,
                (VT::Integer, ScalarValue::Num(n)) => n.is_i64(),
                (VT::Number, ScalarValue::Num(_)) => true,
                (VT::Boolean, ScalarValue::Bool(_)) => true,
                _ => false,
            };
            if compatible {
                Ok(())
            } else {
                Err(format!(
                    "typed fact selector `exact` does not agree with the catalogued fact type {fact_type:?}"
                ))
            }
        }
        TypedValueSelector::String { .. } => {
            if fact_type != VT::Str {
                return Err(format!(
                    "typed fact selector `string` applies only to string facts (catalog type {fact_type:?})"
                ));
            }
            // the `re2-v1` pattern compiles into the load-time cache in the
            // precompile walk (dialect-checked there, whole-value matched from
            // the cache at runtime)
            Ok(())
        }
        TypedValueSelector::Integer { integer } => {
            if fact_type != VT::Integer {
                return Err(format!(
                    "typed fact selector `integer` applies only to integer facts (catalog type {fact_type:?})"
                ));
            }
            validate_numeric_bounds(!(integer.min.is_some() || integer.max.is_some()), || {
                integer.min.zip(integer.max).is_some_and(|(lo, hi)| lo > hi)
            })
        }
        TypedValueSelector::Number { number } => {
            if fact_type != VT::Number {
                return Err(format!(
                    "typed fact selector `number` applies only to number facts (catalog type {fact_type:?})"
                ));
            }
            validate_numeric_bounds(!(number.min.is_some() || number.max.is_some()), || {
                number.min.zip(number.max).is_some_and(|(lo, hi)| lo > hi)
            })
        }
        TypedValueSelector::Boolean { .. } => {
            if fact_type != VT::Boolean {
                return Err(format!(
                    "typed fact selector `boolean` applies only to boolean facts (catalog type {fact_type:?})"
                ));
            }
            Ok(())
        }
        TypedValueSelector::Path { path } => {
            if fact_type != VT::Path {
                return Err(format!(
                    "typed fact selector `path` applies only to path facts (catalog type {fact_type:?})"
                ));
            }
            validate_path_selector(path)
        }
    }
}

/// Closed numeric bounds: at least one bound, and `min` cannot exceed `max`.
fn validate_numeric_bounds(no_bounds: bool, crossed: impl FnOnce() -> bool) -> Result<(), String> {
    if no_bounds {
        return Err("closed numeric bounds require min or max".to_string());
    }
    if crossed() {
        return Err("bound min cannot exceed bound max".to_string());
    }
    Ok(())
}

fn validate_ask_deny_match(rule: &Rule, profile: &Profile) -> Result<(), String> {
    let m = &rule.r#match;
    validate_ordinary_match_shape(m)?;
    if let Some(env) = &m.environment {
        let lists = [&env.any, &env.all];
        for list in lists.into_iter().flatten() {
            for e in list {
                if e.name.is_empty() || e.name.len() > 128 {
                    return Err("environment entry name out of bounds".to_string());
                }
            }
        }
    }
    if let Some(paths) = &m.paths {
        let lists = [&paths.any, &paths.all];
        for list in lists.into_iter().flatten() {
            for e in list {
                // ask/deny may inspect redirect coordinates, but the selector
                // is single-arm and its optionValue arm must reference the
                // profile's option grammar
                validate_path_coordinate_selector(&e.coordinate, Some(profile), true)?;
                validate_path_policy(&e.policy())?;
            }
        }
    }
    if let Some(fm) = &m.facts {
        let lists = [&fm.any, &fm.all];
        for list in lists.into_iter().flatten() {
            for e in list {
                validate_fact_test(e, profile)?;
            }
        }
    }
    if let Some(np) = &m.nested_parts {
        // relation/classification/verdict closed enums validated by serde;
        // every entry needs at least one selector (public schema
        // `NestedPartTest` minProperties: 1); profile refs are cross-checked
        // against the whole profile set in validate()
        let lists = [&np.any, &np.all];
        for list in lists.into_iter().flatten() {
            for e in list {
                validate_nested_part_test(e)?;
            }
        }
    }
    if let Some(o) = &m.options {
        if let Some(values) = &o.values {
            if values.is_empty() {
                return Err("options.values must list at least one option".to_string());
            }
            for id in values.keys() {
                if !profile.options.contains_key(id) {
                    return Err(format!(
                        "options.values references undeclared option \"{id}\""
                    ));
                }
            }
        }
        for list in [
            o.present_all.as_ref(),
            o.present_any.as_ref(),
            o.absent_all.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for id in list {
                if !profile.options.contains_key(id) {
                    return Err(format!(
                        "options condition references undeclared option \"{id}\""
                    ));
                }
            }
        }
        if o.none == Some(true)
            && (o.present_all.is_some()
                || o.present_any.is_some()
                || o.absent_all.is_some()
                || o.values.is_some())
        {
            return Err("options none excludes presence/value conditions".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Duplicated keys must never collapse to last-wins semantics: the first
    /// key restricts the remainder to /repo/safe, the second would relax it
    /// to "/". Both keys stay visible to the serde visitor and are rejected.
    #[test]
    fn duplicate_remainder_keys_never_collapse() {
        const CFG: &str = r#"{
  "version": 2,
  "defaults": { "action": "ask" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{ "id": "git", "executables": ["git"], "options": {}, "rules": [{
      "id": "a", "action": "allow", "redirectPolicy": { "mode": "replace", "policies": ["no-redirects"] },
      "match": { "classification": "complete", "arguments": { "prefix": ["push"],
        "remainder": { "each": { "within": "/repo/safe", "within": "/" } } },
        "options": { "none": true }, "environment": { "none": true }, "paths": { "none": true },
        "facts": { "none": true }, "nestedParts": { "none": true } } }] }]
}"#;
        let Err(err) = load_str(CFG) else {
            panic!("duplicate token selector keys must reject");
        };
        assert!(
            err.contains("config invalid"),
            "must fail during config parsing: {err}"
        );
    }

    #[test]
    fn duplicate_none_keys_rejected() {
        const CFG: &str = r#"{
  "version": 2,
  "defaults": { "action": "ask" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{ "id": "git", "executables": ["git"], "options": {}, "rules": [{
      "id": "a", "action": "allow", "redirectPolicy": { "mode": "replace", "policies": ["no-redirects"] },
      "match": { "classification": "complete", "arguments": { "prefix": ["push"],
        "remainder": { "none": true, "none": true } },
        "options": { "none": true }, "environment": { "none": true }, "paths": { "none": true },
        "facts": { "none": true }, "nestedParts": { "none": true } } }] }]
}"#;
        let Err(err) = load_str(CFG) else {
            panic!("duplicate none keys must reject");
        };
        assert!(err.contains("config invalid"), "{err}");
    }

    /// Duplicate keys in map-valued fields must not collapse last-wins: a
    /// permissive twin can otherwise loosen a restrictive policy. Rejected in
    /// both orders; the error names the duplicated key.
    #[test]
    fn duplicate_map_keys_rejected_in_both_orders() {
        let permissive_then_restrictive = load_str(
            r#"{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "p" },
  "redirectPolicies": {
    "p": { "redirects": { "none": true }, "paths": { "none": true } },
    "p": { "redirects": { "none": true }, "paths": { "all": [{ "coordinate": { "redirect": { "operator": ">", "sourceFd": "default", "occurrence": "all" } }, "within": "/repo/safe" }] } }
  },
  "profiles": []
}"#,
        );
        let restrictive_then_permissive = load_str(
            r#"{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "p" },
  "redirectPolicies": {
    "p": { "redirects": { "none": true }, "paths": { "all": [{ "coordinate": { "redirect": { "operator": ">", "sourceFd": "default", "occurrence": "all" } }, "within": "/repo/safe" }] } },
    "p": { "redirects": { "none": true }, "paths": { "none": true } }
  },
  "profiles": []
}"#,
        );
        for (order, result) in [
            ("permissive-then-restrictive", permissive_then_restrictive),
            ("restrictive-then-permissive", restrictive_then_permissive),
        ] {
            let Err(err) = result else {
                panic!("duplicate map key must reject ({order})");
            };
            assert!(
                err.contains("duplicate object key `p`"),
                "{order} must fail on the duplicated key: {err}"
            );
        }
    }

    #[test]
    fn duplicate_top_level_and_struct_keys_rejected() {
        let Err(dup_version) =
            load_str(r#"{ "version": 2, "version": 2, "defaults": { "action": "ask" } }"#)
        else {
            panic!("duplicate top-level key must reject");
        };
        assert!(dup_version.contains("config invalid"), "{dup_version}");
        let Err(dup_defaults) = load_str(
            r#"{ "version": 2, "defaults": { "action": "ask" }, "defaults": { "action": "ask" } }"#,
        ) else {
            panic!("duplicate struct key must reject");
        };
        assert!(dup_defaults.contains("config invalid"), "{dup_defaults}");
    }

    /// Trailing input after the first JSON value must reject immediately:
    /// the strict parser returns on the first complete value, so `end()` is
    /// what enforces EOF. On the plain text side the expectation is
    /// "config invalid" through load_str; through the public binary the
    /// contract is exit 2 with clean stdout (binary side covered in
    /// tests/pipeline_tests.rs).
    #[test]
    fn trailing_json_after_first_value_rejected() {
        const VALID: &str = r#"{ "version": 2, "defaults": { "action": "ask" } }"#;
        for (name, suffix) in [
            ("trailing second object", r#" {"x":1}"#),
            ("trailing scalar", " 42"),
            ("trailing garbage", "\n{oops"),
        ] {
            let Err(err) = load_str(&format!("{VALID}{suffix}")) else {
                panic!("trailing input must reject ({name})");
            };
            assert!(
                err.contains("config invalid"),
                "{name} must fail during config parsing: {err}"
            );
        }
        // and the pristine one-liner still loads
        assert!(load_str(VALID).is_ok());
    }

    #[test]
    fn parse_error_messages_stay_prefixed() {
        let Err(e) = load_str("{ bad") else {
            panic!("malformed JSON must reject");
        };
        assert!(e.contains("config invalid"), "{e}");
        let Err(e) = load_str(r#"{ "version": 3, "defaults": { "action": "ask" } }"#) else {
            panic!("wrong version must reject");
        };
        assert!(e.contains("version must be 2"), "{e}");
    }

    // ── Fixed option arity + option-value selectors (issue 32) ──────────────

    /// A one-profile config with an arity-one `--name` value option covered by
    /// a closed selector; `options_json` / `name_spec` / `rename_spec` are
    /// spliced in per scenario.
    fn cargo_profile(name_spec: &str, rename_spec: Option<&str>, options_json: &str) -> String {
        let rename = rename_spec
            .map(|r| format!(r#""rename": {r}, "#))
            .unwrap_or_default();
        format!(
            r#"{{
      "id": "cargo",
      "executables": ["cargo"],
      "options": {{
        {name_spec},
        {rename}
        "force": {{ "aliases": ["--force"], "arity": 0 }}
      }},
      "rules": [
        {{
          "id": "cargo/allow-init", "action": "allow",
          "match": {{
            "classification": "complete",
            "arguments": {{ "exact": ["init"] }},
            "options": {options_json},
            "environment": {{ "none": true }},
            "paths": {{ "none": true }},
            "facts": {{ "none": true }},
            "nestedParts": {{ "none": true }}
          }},
          "redirectPolicy": {{ "mode": "replace", "policies": ["no-redirects"] }}
        }}
      ]
    }}"#
        )
    }

    fn cargo_config(name_spec: &str, rename_spec: Option<&str>, options_json: &str) -> String {
        let blob = cargo_profile(name_spec, rename_spec, options_json);
        format!(
            r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{blob}]
}}"#
        )
    }

    // ── Issue #35: typed fact selectors — config-level validation ───────────

    /// Minimal sed-v1 profile whose allow rule carries the given `facts`
    /// coverage text; probe-only (never a live configuration). The entry
    /// template carries every closed `FactPolicy` field.
    fn sed_fact_entry(name: &str, value: &str) -> String {
        format!(
            r#"{{ "analyzer": "sed-v1", "version": "1", "name": "{name}", "occurrence": "all", "value": {value} }}"#
        )
    }

    fn sed_fact_config(name: &str, value: &str) -> String {
        sed_fact_config_facts(&format!(
            r#"{{ "all": [{}] }}"#,
            sed_fact_entry(name, value)
        ))
    }

    fn sed_fact_config_facts(facts: &str) -> String {
        format!(
            r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
    "id": "sed",
    "executables": ["sed"],
    "options": {{}},
    "analyzer": "sed-v1",
    "rules": [{{
      "id": "sed/allow-probe", "action": "allow",
      "match": {{
        "classification": "complete", "arguments": {{ "exact": [] }},
        "options": {{ "none": true }}, "environment": {{ "none": true }},
        "paths": {{ "none": true }},
        "facts": {facts},
        "nestedParts": {{ "none": true }}
      }}
    }}]
  }}]
}}"#
        )
    }

    fn expect_invalid(name: &str, text: &str, needle: &str) {
        let Err(err) = load_str(text) else {
            panic!("{name} config must be rejected");
        };
        assert!(
            err.contains("config invalid"),
            "{name} must fail during config parsing: {err}"
        );
        assert!(
            err.contains(needle),
            "{name} must name the violation `{needle}`: {err}"
        );
    }

    // ── Issue #41: nested-part selectors — config-level validation ──────────

    /// An echo allow probe whose `nestedParts` coverage carries `nested`
    /// verbatim, plus an `rm-safe` profile the selectors can reference.
    fn nested_probe_config(nested: &str) -> String {
        format!(
            r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
    "id": "echo",
    "executables": ["echo"],
    "options": {{}},
    "analyzer": "generic-v1",
    "rules": [{{
      "id": "echo/allow-probe", "action": "allow",
      "match": {{
        "classification": "complete", "arguments": {{ "exact": [] }},
        "options": {{ "none": true }}, "environment": {{ "none": true }},
        "paths": {{ "none": true }}, "facts": {{ "none": true }},
        "nestedParts": {nested}
      }}
    }}]
  }},
  {{
    "id": "rm-safe",
    "executables": ["rm"],
    "options": {{}},
    "analyzer": "generic-v1",
    "rules": []
  }}]
}}"#
        )
    }

    /// The authoritative allow fixture (docs
    /// `valid/NestedPartPolicy/complete.json`) loads as a coverage entry,
    /// with a declared profile reference and with the literal `none`.
    #[test]
    fn allow_nested_part_policy_fixture_loads() {
        let full = nested_probe_config(
            r#"{ "all": [{ "relation": "analyzer-command", "occurrence": 1,
                "profile": "rm-safe", "classification": "complete", "verdict": "ask" }] }"#,
        );
        assert!(
            load_str(&full).is_ok(),
            "authoritative NestedPartPolicy fixture body must load"
        );
        let none_profile = nested_probe_config(
            r#"{ "all": [{ "relation": "analyzer-command", "occurrence": "all",
                "profile": "none", "classification": "complete", "verdict": "deny" }] }"#,
        );
        assert!(
            load_str(&none_profile).is_ok(),
            "the literal none profile selector is public config"
        );
    }

    /// Allow coverage entries carry the full public `NestedPartPolicy` shape:
    /// dropping any closed field is invalid (schema `required`).
    #[test]
    fn allow_nested_part_policy_requires_every_field() {
        let fields = [
            (
                "relation",
                r#""occurrence": 1, "profile": "rm-safe", "classification": "complete", "verdict": "ask""#,
            ),
            (
                "occurrence",
                r#""relation": "analyzer-command", "profile": "rm-safe", "classification": "complete", "verdict": "ask""#,
            ),
            (
                "profile",
                r#""relation": "analyzer-command", "occurrence": 1, "classification": "complete", "verdict": "ask""#,
            ),
            (
                "classification",
                r#""relation": "analyzer-command", "occurrence": 1, "profile": "rm-safe", "verdict": "ask""#,
            ),
            (
                "verdict",
                r#""relation": "analyzer-command", "occurrence": 1, "profile": "rm-safe", "classification": "complete""#,
            ),
        ];
        for (name, body) in fields {
            expect_invalid(
                name,
                &nested_probe_config(&format!(r#"{{ "all": [{{ {body} }}] }}"#)),
                "allow nestedParts entries require",
            );
        }
    }

    /// Nested-part profile references resolve against declared profile ids;
    /// the literal `none` is the only non-reference spelling.
    #[test]
    fn nested_part_profile_references_resolve() {
        expect_invalid(
            "unknown-profile",
            &nested_probe_config(
                r#"{ "all": [{ "relation": "analyzer-command", "occurrence": 1,
                    "profile": "rm-risky", "classification": "complete", "verdict": "ask" }] }"#,
            ),
            "references unknown profile",
        );
    }

    /// An ask/deny selector naming no closed dimension is invalid (public
    /// schema `NestedPartTest` `minProperties: 1`).
    #[test]
    fn nested_part_test_requires_at_least_one_selector() {
        let ask_deny = r#"{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{
    "id": "echo",
    "executables": ["echo"],
    "options": {},
    "analyzer": "generic-v1",
    "rules": [{
      "id": "echo/deny-probe", "action": "deny",
      "match": { "nestedParts": { "any": [{}] } }
    }]
  }]
        }"#;
        expect_invalid("empty-selector", ask_deny, "at least one selector");
    }

    /// An invalid `re2-v1` pattern invalidates the config at load (docs
    /// fixture StringValueSelector/invalid-regex.json: look-around).
    #[test]
    fn invalid_regex_pattern_rejected() {
        expect_invalid(
            "invalid-regex",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "(?=unsafe)unsafe" } } }] }"#,
            ),
            "re2-v1",
        );
        // numeric backreference subexpression likewise
        expect_invalid(
            "backreference-regex",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "(a)\\1" } } }] }"#,
            ),
            "re2-v1",
        );
    }

    /// The exact `re2-v1` semantics lock (review P1): the RE2 dialect defines
    /// Perl class shortcuts and word boundaries as ASCII, but the pinned
    /// engine matches them Unicode-aware — so those constructs fail config
    /// load. Bracketed classes carry the same divergence (`[\w]`, `[a-z\s]`,
    /// negated `[^\w]`), so the config-level rejection covers both contexts.
    #[test]
    fn re2_v1_perl_class_shortcuts_rejected() {
        for (name, pattern) in [
            ("perl word class", r"\w+"),
            ("bracketed word class", r"[\w]+"),
            ("bracketed digit class", r"[\d]"),
            ("bracketed space member", r"[a-z\s]"),
            ("negated bracketed word class", r"[^\w]"),
        ] {
            expect_invalid(
                name,
                &cargo_config(
                    r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                    None,
                    &format!(
                        r#"{{ "allowed": [{{ "option": "name", "required": false, "repeatable": false,
                    "values": {{ "each": {{ "regex": {} }} }} }}] }}"#,
                        serde_json::to_string(&pattern)
                            .expect("re2 pattern json")
                            .as_str()
                    ),
                ),
                "Perl class shortcuts",
            );
        }
        // explicit spellings stay dialect-legal
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "[0-9A-Za-z_]+" } } }] }"#,
            ))
            .is_ok()
        );
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "\\p{L}" } } }] }"#,
            ))
            .is_ok()
        );
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "[:word:]" } } }] }"#,
            ))
            .is_ok()
        );
    }

    /// The fixed `re2-v1` dialect allows no flag configuration: inline flag
    /// groups would silently change case sensitivity or anchoring, so every
    /// `(?flags…)` / `(?flags:…)` / `(?-flags…)` form is invalid config —
    /// while named groups and the non-capturing core stay valid.
    #[test]
    fn inline_regex_flags_rejected() {
        for (name, pattern) in [
            ("(?i) safe", "(?i)safe"),
            ("(?i: core)", "(?i:safe)"),
            ("(?m) dot", "(?m)"),
            ("(?-u) flags", "(?-u)"),
            // every supported flag letter is configuration, including the
            // CRLF-mode `R` (historical bypass: the letter blacklist missed it)
            ("(?iR) safe", "(?iR)safe"),
            ("(?R) crlf", "(?R)"),
            ("(?x) spaced", "(?x)a b"),
        ] {
            expect_invalid(
                name,
                &cargo_config(
                    r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                    None,
                    &format!(
                        r#"{{ "allowed": [{{ "option": "name", "required": false, "repeatable": false,
                    "values": {{ "each": {{ "regex": {} }} }} }}] }}"#,
                        serde_json::to_string(&pattern)
                            .expect("re2 pattern json")
                            .as_str()
                    ),
                ),
                "flag",
            );
        }
        // named groups, bare non-capturing groups and a character class
        // carrying a `(?i)` member stay legal dialect
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "(?:ok)" } } }] }"#,
            ))
            .is_ok()
        );
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "regex": "(?P<sub>[a-z]+)" } } }] }"#,
            ))
            .is_ok()
        );
        // nested class sets and POSIX classes with a `(?i)` member: no
        // scanner ambiguity — the AST parser sees class members, not flags;
        // genuinely RE2-compatible class-literal cases only
        for (name, pattern) in [
            ("posix class", r"[[:alpha:](?i)]"),
            // a class whose first member is an escaped `]`, followed by
            // literal `(?i)` members — the AST sees class members, not flags
            ("escaped member", r"[\](?i)]"),
            // an escaped hex char followed by literal `(?i)` members
            ("escaped char then members", r"[\x41(?i)]"),
        ] {
            assert!(
                load_str(&cargo_config(
                    r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                    None,
                    &format!(
                        r#"{{ "allowed": [{{ "option": "name", "required": false, "repeatable": false,
                    "values": {{ "each": {{ "regex": {} }} }} }}] }}"#,
                        serde_json::to_string(&pattern).expect("re2 pattern json").as_str()
                    ),
                ))
                .is_ok(),
                "{name} pattern must be dialect-legal"
            );
        }
        // Rust-only class-set syntax is outside RE2 and outside the dialect
        for (name, pattern) in [
            ("nested class set", "[a&&[b](?i)]"),
            ("nested class", "[[b]]"),
            ("intersection operator", "[a&&b]"),
        ] {
            expect_invalid(
                name,
                &cargo_config(
                    r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                    None,
                    &format!(
                        r#"{{ "allowed": [{{ "option": "name", "required": false, "repeatable": false,
                    "values": {{ "each": {{ "regex": {} }} }} }}] }}"#,
                        serde_json::to_string(&pattern)
                            .expect("re2 pattern json")
                            .as_str()
                    ),
                ),
                "RE2",
            );
        }
    }

    /// Selector (and policy) roots must be normalized absolute lexical paths:
    /// `//` and `.` / `..` components shift the component-boundary semantics
    /// and would widen coverage; a single trailing slash is boundary-neutral
    /// and accepted (docs schema `AbsoluteLexicalPath`).
    #[test]
    fn non_normalized_lexical_roots_rejected() {
        for (name, root) in [
            ("double slash", "//work/project"),
            ("dot component", "/work/./project"),
            ("dot-dot component", "/work/repo/.."),
            ("interior double slash", "/work//project"),
        ] {
            expect_invalid(
                name,
                &cargo_config(
                    r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                    None,
                    &format!(
                        r#"{{ "allowed": [{{ "option": "name", "required": false, "repeatable": false,
                    "values": {{ "each": {{ "path": {{ "within": "{}" }} }} }} }}] }}"#,
                        root
                    ),
                ),
                "root",
            );
        }
        // the bare root "/" normalizes to itself and stays valid, and a
        // single trailing slash is boundary-neutral (schema-accepted)
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "path": { "within": "/" } } } }] }"#,
            ))
            .is_ok()
        );
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "path": { "within": "/work/project/" } } } }] }"#,
            ))
            .is_ok()
        );
        // `/repo//` still carries an interior empty component and rejects
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "path": { "within": "/work/" } } } }] }"#,
            ))
            .is_ok()
        );
        assert!(
            load_str(&cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "path": { "within": "/work//" } } } }] }"#,
            ))
            .is_err()
        );
        // the same rule guards redirect-policy path roots
        let Err(err) = load_str(
            r#"{ "version": 2,
  "defaults": { "action": "ask" },
  "redirectPolicies": { "p": { "redirects": { "all": [{ "sourceFd": "default", "operator": ">", "occurrence": "all", "target": { "kind": "literalPath" } }] },
    "paths": { "all": [{ "coordinate": { "redirect": { "operator": ">", "sourceFd": "default", "occurrence": "all" } }, "within": "/tmp//x" }] } } },
  "profiles": [] }"#,
        ) else {
            panic!("a redirect policy path root with // must reject");
        };
        assert!(err.contains("normalized absolute lexical path"), "{err}");
    }

    /// A pathSources `optionValue` coordinate must name a declared canonical
    /// option and stay inside its fixed arity: otherwise the coordinate
    /// would silently never be produced and a path value could pass a
    /// `{ "none": true }` paths policy.
    #[test]
    fn path_source_option_value_validates_the_option_grammar() {
        let base = |option_lines: &str, ordinal: u32| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "cargo",
      "executables": ["cargo"],
      "options": {{ {option_lines} }},
      "pathSources": [{{ "optionValue": {{ "option": "file", "valueOrdinal": {ordinal} }} }}],
      "rules": []
  }}]
}}"#
            )
        };
        // ordinal inside the declared arity-1 option is fine
        assert!(load_str(&base(r#""file": { "aliases": ["--file"], "arity": 1 }"#, 1)).is_ok());
        // undeclared canonical option
        expect_invalid(
            "undeclared option value",
            &base(r#""name": { "aliases": ["--name"], "arity": 1 }"#, 1),
            "undeclared option",
        );
        // ordinal beyond the fixed arity (declared arity 2)
        expect_invalid(
            "ordinal beyond arity",
            &base(r#""file": { "aliases": ["--rename"], "arity": 2 }"#, 3),
            "outside 1..=",
        );
        // zero-arity option can never produce a value coordinate
        expect_invalid(
            "zero-arity option value",
            &base(r#""file": { "aliases": ["-v"], "arity": 0 }"#, 1),
            "zero-arity",
        );
    }

    /// Cross-coordinate validation extends to matching path entries
    /// (ask/deny/allow + hints): a mistyped `optionValue` coordinate or a
    /// multi-arm selector in a rule's `paths` entry is invalid config instead
    /// of a dead selector a broad parallel allow can win with.
    #[test]
    fn path_rule_coordinates_validate_against_the_profile_grammar() {
        let rule_config = |coordinate: &str| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "cargo",
      "executables": ["cargo"],
      "options": {{ "file": {{ "aliases": ["--file"], "arity": 1 }} }},
      "rules": [{{
        "id": "deny-file-path", "action": "deny",
        "match": {{
          "arguments": {{ "exact": ["run"] }},
          "paths": {{ "any": [{{ "coordinate": {coordinate}, "within": "/etc" }}] }}
        }}
      }}]
  }}]
}}"#
            )
        };
        // healthy single-arm deny predicate loads
        assert!(
            load_str(&rule_config(
                r#"{ "optionValue": { "option": "file", "valueOrdinal": 1 } }"#
            ))
            .is_ok()
        );
        // mistyped option name in the deny coordinate: dead selector
        expect_invalid(
            "deny mistyped option",
            &rule_config(r#"{ "optionValue": { "option": "filee", "valueOrdinal": 1 } }"#),
            "undeclared option",
        );
        // ordinal beyond the declared arity
        expect_invalid(
            "deny unreachable ordinal",
            &rule_config(r#"{ "optionValue": { "option": "file", "valueOrdinal": 2 } }"#),
            "outside 1..=",
        );
        // multi-arm coordinate selector (schema oneOf) — including the
        // closed object form `{ "occurrence": … }` for the environment arm
        expect_invalid(
            "multi-arm coordinate",
            &rule_config(
                r#"{ "optionValue": { "option": "file", "valueOrdinal": 1 }, "environment": { "occurrence": "all" } }"#,
            ),
            "exactly one coordinate",
        );
        // the same closure applies to an allow rule's paths entries
        let allow_config = format!(
            r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "cargo",
      "executables": ["cargo"],
      "options": {{ "file": {{ "aliases": ["--file"], "arity": 1 }} }},
      "pathSources": [{{ "optionValue": {{ "option": "file", "valueOrdinal": 1 }} }}],
      "rules": [{{
        "id": "allow-init", "action": "allow",
        "match": {{
          "classification": "complete",
          "arguments": {{ "exact": ["init"] }},
          "options": {{ "none": true }},
          "environment": {{ "none": true }},
          "paths": {{ "all": [{{ "coordinate": {coordinate}, "within": "/etc" }}] }},
          "facts": {{ "none": true }},
          "nestedParts": {{ "none": true }}
        }},
        "redirectPolicy": {{ "mode": "replace", "policies": ["no-redirects"] }}
      }}]
  }}]
}}
"#,
            coordinate = r#"{ "optionValue": { "option": "filee", "valueOrdinal": 1 } }"#
        );
        expect_invalid(
            "allow mistyped coordinate",
            &allow_config,
            "undeclared option",
        );
    }

    /// Occurrence selectors are 1-based: `occurrence: 0` would silently match
    /// no runtime coordinate (fail-open hole for never-produced coordinates).
    #[test]
    fn zero_occurrence_selector_rejected() {
        // ...in a pathSources optionValue coordinate
        let bad_source = r#"{ "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{ "id": "cargo", "executables": ["cargo"],
    "options": { "file": { "aliases": ["--file"], "arity": 1 } },
    "pathSources": [{ "optionValue": { "option": "file", "valueOrdinal": 1, "occurrence": 0 } }],
    "rules": [], "analyzer": "generic-v1" }] }"#;
        expect_invalid("optionValue occurrence 0", bad_source, "1-based");
        // ...in a redirect policy entry's occurrence (the untagged redirect
        // coverage arm reports a generic union failure, still fail-closed)
        let bad_redirect = r#"{ "version": 2,
  "defaults": { "action": "ask" },
  "redirectPolicies": { "p": { "redirects": { "all": [{ "sourceFd": "default", "operator": ">", "occurrence": 0, "target": { "kind": "literalPath" } }] },
    "paths": { "all": [{ "coordinate": { "redirect": { "operator": ">", "sourceFd": "default", "occurrence": "all" } }, "within": "/tmp" }] } } },
  "profiles": [] }"#;
        expect_invalid(
            "redirect entry occurrence 0",
            bad_redirect,
            "config invalid",
        );
        // ...in an ask/deny RedirectTest's occurrence (match.redirects arm,
        // the same fail-closed parse rejection as every other occurrence arm)
        let bad_test = r#"{ "version": 2,
  "defaults": { "action": "ask" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{ "id": "git", "executables": ["git"], "rules": [
    { "id": "r", "action": "ask", "message": "redirects",
      "match": { "redirects": { "any": [{ "operator": ">", "sourceFd": "default", "targetKind": "literalPath", "occurrence": 0 }] } } }
  ] }] }"#;
        expect_invalid("redirect test occurrence 0", bad_test, "config invalid");
    }

    /// `RedirectTest.occurrence` — the schema-supported occurrence selector —
    /// parses in both documented forms (docs fixtures RedirectMatcher/all.json
    /// and RedirectMatcher/any.json) and applies to `any` and `all` alike.
    #[test]
    fn redirect_matcher_occurrence_selector_wire_shapes() {
        let rule = |occurrence: &str| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{ "id": "git", "executables": ["git"], "rules": [
    {{ "id": "r", "action": "ask", "message": "redirects",
      "match": {{ "redirects": {{ "all": [{{ "operator": ">&", "sourceFd": 2, "targetKind": "fd", "occurrence": {occurrence} }}] }} }} }}
  ] }}]
}}"#
            )
        };
        // battery-fixture forms: one-based ordinal and `"all"`
        assert!(load_str(&rule("1")).is_ok(), "occurrence 1 must load");
        assert!(
            load_str(&rule(r#""all""#)).is_ok(),
            "occurrence \"all\" must load"
        );
        // other invalid occurrence forms stay rejected
        expect_invalid(
            "redirect test occurrence word",
            &rule(r#""every""#),
            "config invalid",
        );
    }

    /// A pathSources `analyzerFact` coordinate must name a fact in the closed
    /// catalog of the profile's declared analyzer: otherwise the coordinate
    /// is never produced and a `{ "none": true }` paths policy silently
    /// covers emitted path-valued evidence.
    #[test]
    fn analyzer_fact_coordinate_validates_the_fact_catalog() {
        let fact_config = |analyzer: Option<&str>, fact: &str, fact_analyzer: &str| {
            let analyzer_field = analyzer
                .map(|a| format!(r#""analyzer": "{a}", "#))
                .unwrap_or_default();
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "sed", "executables": ["sed"],
      "options": {{ "expression": {{ "aliases": ["-e"], "arity": 1 }} }},
      {analyzer_field}
      "pathSources": [{{ "analyzerFact": {{ "name": "{fact}", "analyzer": "{fact_analyzer}" }} }}],
      "rules": []
  }}]
}}"#
            )
        };
        for (name, text, needle) in [
            (
                "mistyped fact",
                fact_config(Some("sed-v1"), "inPlacee", "sed-v1"),
                "fact catalog",
            ),
            (
                "profile declares no analyzer",
                fact_config(None, "executionPrimitive", "sed-v1"),
                "profile declares none",
            ),
            (
                "fact analyzer mismatch",
                fact_config(Some("sed-v1"), "executionPrimitive", "export-v1"),
                "outside the profile analyzer",
            ),
        ] {
            expect_invalid(name, &text, needle);
        }
        // the correct catalog entry is accepted
        assert!(load_str(&fact_config(Some("sed-v1"), "executionPrimitive", "sed-v1")).is_ok());
    }

    /// The analyzer-fact coordinate validator runs at every call site —
    /// pathSources, ask/deny rule paths entries, allow rule paths entries and
    /// fallback hints — so one missed call site cannot restore the
    /// dead-coordinate fail-open.
    #[test]
    fn analyzer_fact_coordinates_validate_at_every_call_site() {
        let path_entries = |list_kind: &str, fact: &str| {
            format!(
                r#""{list_kind}": [{{ "coordinate": {{ "analyzerFact": {{ "name": "{fact}", "analyzer": "sed-v1" }} }}, "within": "/work" }}]"#
            )
        };
        let site_config = |site: &str, fact: &str| {
            let rule_block = match site {
                "deny" => format!(
                    r#""rules": [{{ "id": "d", "action": "deny", "message": "m",
                      "match": {{ "arguments": {{ "prefix": [] }},
                      "paths": {{ {} }} }} }}]"#,
                    path_entries("any", fact)
                ),
                "allow" => format!(
                    r#""rules": [{{ "id": "a", "action": "allow",
                      "match": {{
                        "classification": "complete", "arguments": {{ "exact": [] }},
                        "options": {{ "none": true }}, "environment": {{ "none": true }},
                        "paths": {{ {} }},
                        "facts": {{ "none": true }}, "nestedParts": {{ "none": true }}
                      }},
                      "redirectPolicy": {{ "mode": "replace", "policies": ["no-redirects"] }} }}]"#,
                    path_entries("all", fact)
                ),
                _ => format!(
                    r#""rules": [], "fallbackHints": [{{ "id": "h", "message": "m",
                      "match": {{ "arguments": {{ "prefix": [] }},
                      "paths": {{ {} }} }} }}]"#,
                    path_entries("any", fact)
                ),
            };
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "sed", "executables": ["sed"],
      "options": {{ "expression": {{ "aliases": ["-e"], "arity": 1 }} }},
      "analyzer": "sed-v1",
      {rule_block}
  }}]
}}"#
            )
        };
        // the valid control at every site is accepted
        for site in ["deny", "allow", "hint"] {
            let text = site_config(site, "executionPrimitive");
            let loaded = load_str(&text);
            assert!(
                loaded.is_ok(),
                "valid analyzerFact at the {} site must load: {}",
                site,
                loaded.err().unwrap_or_default()
            );
        }
        // a mistyped catalog name is rejected at every site
        for site in ["deny", "allow", "hint"] {
            expect_invalid(
                &format!("{site} site mistyped fact"),
                &site_config(site, "inPlacee"),
                "fact catalog",
            );
        }
    }

    /// The environment path coordinate must be the closed object form
    /// `{ "occurrence": occurrenceSelector }` (docs schema
    /// `EnvironmentCoordinate`).
    #[test]
    fn environment_coordinate_object_form() {
        let source_config = |env_coordinate: &str| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "echo", "executables": ["echo"],
      "options": {{}},
      "pathSources": [{{ "environment": {env_coordinate} }}],
      "rules": []
  }}]
}}"#
            )
        };
        // healthy object form (with and without an occurrence selector)
        assert!(load_str(&source_config(r#"{ "occurrence": "all" }"#)).is_ok());
        assert!(
            load_str(&source_config(r"{ }")).is_ok(),
            "an occurrence-less environment coordinate selects every assignment"
        );
        // the bare scalar form is schema-rejected and never parses
        expect_invalid(
            "scalar environment coordinate",
            &source_config(r#""all""#),
            "EnvironmentCoordinate",
        );
    }

    /// The option parser only observes dash-prefixed argv tokens, treats the
    /// bare `--` token as the terminator (a bare `-` as a positional) and
    /// splits inline forms at the first `=`. Aliases outside that grammar
    /// would load but never be observed — dead canonical-option policies.
    #[test]
    fn option_aliases_must_be_parser_visible() {
        let alias_config = |alias_literal: &str| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "cargo", "executables": ["cargo"],
      "options": {{ "name": {{ "aliases": ["--name"], "arity": 1 }},
        "flag": {{ "aliases": [{alias_literal}], "arity": 0 }} }},
      "rules": []
  }}]
}}"#
            )
        };
        for (name, alias_literal, needle) in [
            (
                "bare alias without dash",
                r#""name""#,
                "must begin with a dash",
            ),
            ("the terminator token", r#""--""#, "never be observed"),
            ("inline-shaped alias", r#""--name=x""#, "can never match"),
            ("bare dash", r#""-""#, "never be observed"),
        ] {
            expect_invalid(name, &alias_config(alias_literal), needle);
        }
        // dash-prefixed parse-visible aliases stay legal
        assert!(
            load_str(&alias_config(r#""--flag""#)).is_ok(),
            "long alias must load"
        );
        assert!(
            load_str(&alias_config(r#""-f""#)).is_ok(),
            "short alias must load"
        );
        assert!(
            load_str(&alias_config(r#""-rf""#)).is_ok(),
            "multi-char short alias is exact-match visible"
        );
    }

    /// Fixed arity boundary: arity 4 is valid (four consumed values), arity 5
    /// is invalid — the 0..=4 bound is exact.
    #[test]
    fn option_arity_four_is_upper_bound() {
        let arity_config = |arity: u32| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "cargo", "executables": ["cargo"],
      "options": {{ "quad": {{ "aliases": ["--quad"], "arity": {arity} }} }},
      "rules": []
  }}]
}}"#
            )
        };
        assert!(load_str(&arity_config(4)).is_ok(), "arity 4 is valid");
        expect_invalid("arity 5", &arity_config(5), "exceeds 4");
    }

    /// `PathPolicy` roots use the schema's `AbsoluteLexicalPath` limit (4096
    /// UTF-8 bytes) across every arm: 4096 bytes accepted, 4097 rejected.
    #[test]
    fn path_policy_root_byte_limit() {
        for (name, arm) in [
            ("exact", "exact"),
            ("within", "within"),
            ("outside", "outside"),
        ] {
            // '/' + 4095 'x' = exactly the 4096-byte cap → accepted
            let ok = path_policy_config(arm, &format!("/{}", "x".repeat(4095)));
            assert!(
                load_str(&ok).is_ok(),
                "{name} at exactly 4096 bytes must be accepted"
            );
            // '/' + 4096 'x' = 4097 bytes → rejected
            let bad = path_policy_config(arm, &format!("/{}", "x".repeat(4096)));
            expect_invalid(&format!("{name} 4097 bytes"), &bad, "4096");
        }
    }

    fn path_policy_config(arm: &str, root: &str) -> String {
        format!(
            r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
      "id": "cargo", "executables": ["cargo"],
      "options": {{}},
      "pathSources": [{{ "argument": {{ "index": 0 }} }}],
      "rules": [{{
        "id": "allow", "action": "allow",
        "match": {{
          "classification": "complete", "arguments": {{ "exact": ["init"] }},
          "options": {{ "none": true }}, "environment": {{ "none": true }},
          "paths": {{ "all": [{{ "coordinate": {{ "argument": {{ "index": 0 }} }}, "{arm}": "{root}" }}] }},
          "facts": {{ "none": true }}, "nestedParts": {{ "none": true }}
        }},
        "redirectPolicy": {{ "mode": "replace", "policies": ["no-redirects"] }}
      }}]
  }}]
}}"#
        )
    }

    /// A selector arm with the payload of the wrong type is a parse error
    /// (schema "type mismatch"), never silently coerced.
    #[test]
    fn selector_type_mismatch_rejected() {
        expect_invalid(
            "one-of-string",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "oneOf": "x" } } }] }"#,
            ),
            "config invalid",
        );
    }

    /// Nested selector input (`{"each": {"each": …}}`) is rejected — no
    /// nested proxy.
    #[test]
    fn nested_selector_input_rejected() {
        expect_invalid(
            "nested-each",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false,
                    "values": { "each": { "path": { "each": { "any": true } } } } }] }"#,
            ),
            "config invalid",
        );
    }

    /// A positive-arity option coverage without `values` is invalid (docs
    /// fixture PositiveArityOptionCoverage/missing-values-policy.json).
    #[test]
    fn positive_arity_option_requires_values_policy() {
        expect_invalid(
            "missing-values-policy",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                None,
                r#"{ "allowed": [{ "option": "name", "required": false, "repeatable": false }] }"#,
            ),
            "positive-arity option",
        );
    }

    /// A coverage entry carrying `values` on a declared zero-arity option is
    /// invalid.
    #[test]
    fn zero_arity_option_prohibits_values() {
        expect_invalid(
            "zero-arity-values",
            &cargo_config(
                r#""verbose": { "aliases": ["-v"], "arity": 0 }"#,
                None,
                r#"{ "allowed": [{ "option": "verbose", "required": false, "repeatable": false,
                    "values": { "each": { "any": true } } }] }"#,
            ),
            "zero-arity option",
        );
    }

    /// `byPosition` must have exactly the declared fixed arity of selectors.
    #[test]
    fn by_position_length_must_equal_declared_arity() {
        expect_invalid(
            "bad-by-position-length",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                Some(r#"{ "aliases": ["--rename"], "arity": 2 }"#),
                r#"{ "allowed": [
                    { "option": "name", "required": false, "repeatable": false,
                      "values": { "each": { "any": true } } },
                    { "option": "rename", "required": false, "repeatable": false,
                      "values": { "byPosition": [ { "any": true }, { "any": true }, { "any": true } ] } }
                ] }"#,
            ),
            "byPosition",
        );
    }

    /// `inline: true` is only valid for a declared arity-one option (docs
    /// fixture OptionSpec/inline-arity-greater-than-one.json).
    #[test]
    fn inline_opt_in_is_arity_one_only() {
        expect_invalid(
            "inline-arity-two",
            &cargo_config(
                r#""name": { "aliases": ["--name"], "arity": 1 }"#,
                Some(r#"{ "aliases": ["--rename"], "arity": 2, "inline": true }"#),
                r#"{ "none": true }"#,
            ),
            "inline",
        );
    }

    /// Canonical duplicate option policies in one `allowed` list invalidate
    /// the config (docs fixture
    /// OptionsCoverage/duplicate-canonical-option-policies.json).
    #[test]
    fn duplicate_canonical_option_policies_rejected() {
        expect_invalid(
            "duplicate-option-policies",
            &cargo_config(
                r#""verbose": { "aliases": ["-v"], "arity": 0 }"#,
                None,
                r#"{ "allowed": [
                    { "option": "verbose", "required": false, "repeatable": false },
                    { "option": "verbose", "required": false, "repeatable": true }
                ] }"#,
            ),
            "duplicate canonical option",
        );
    }

    /// A string-typed fact cannot be selected through path semantics: no
    /// string→path coercion, no path selector on a string catalog type.
    #[test]
    fn string_selector_used_as_path_selector_rejected() {
        expect_invalid(
            "path selector on a string fact",
            &sed_fact_config("executionPrimitive", r#"{ "path": { "within": "/work" } }"#),
            "typed",
        );
    }

    /// Numeric bounds must be closed: at least one of min/max is required,
    /// and `min` cannot exceed `max`. No built-in analyzer emits
    /// integer/number facts yet, so the closed-bounds checks are exercised
    /// directly against the typed-selector validator.
    #[test]
    fn numeric_bounds_validator_rejects_open_and_crossed_bounds() {
        use analyzers::FactValueType as VT;
        let sel = |text: &str| serde_json::from_str::<TypedValueSelector>(text).unwrap();
        let open_integer = sel(r#"{ "integer": {} }"#);
        let open_number = sel(r#"{ "number": {} }"#);
        let crossed_integer = sel(r#"{ "integer": { "min": 9, "max": 5 } }"#);
        let crossed_number = sel(r#"{ "number": { "min": 9.5, "max": 5.5 } }"#);
        for (name, s, t) in [
            ("integer-open", &open_integer, VT::Integer),
            ("number-open", &open_number, VT::Number),
            ("integer-crossed", &crossed_integer, VT::Integer),
            ("number-crossed", &crossed_number, VT::Number),
        ] {
            let err = validate_typed_value_selector(s, t)
                .err()
                .unwrap_or_else(|| panic!("{name} bounds must reject"));
            assert!(
                err.contains("bound"),
                "{name} must name the open/crossed bound cause: {err}"
            );
        }
        // closed inclusive bounds validate on the matching fact types
        assert!(
            validate_typed_value_selector(&sel(r#"{ "integer": { "min": 1 } }"#), VT::Integer)
                .is_ok()
        );
        assert!(
            validate_typed_value_selector(
                &sel(r#"{ "number": { "min": 0.0, "max": 9.5 } }"#),
                VT::Number
            )
            .is_ok()
        );
    }

    /// The oneOf string selector is a non-empty, duplicate-free list.
    #[test]
    fn string_one_of_shape_rejected() {
        for (name, sel) in [
            ("one-of-empty", r#"{ "string": { "oneOf": [] } }"#),
            (
                "one-of-duplicate",
                r#"{ "string": { "oneOf": ["readOnly", "readOnly"] } }"#,
            ),
        ] {
            let Err(err) = load_str(&sed_fact_config("executionPrimitive", sel)) else {
                panic!("{name} selector must reject the config");
            };
            assert!(err.contains("config invalid"), "{name}: {err}");
            assert!(
                err.contains("oneOf"),
                "{name} must name the oneOf cause: {err}"
            );
        }
    }

    /// Regex selectors compile at load time (re2-v1 dialect): lookaround and
    /// other unsupported syntax reject the config.
    #[test]
    fn regex_unsupported_syntax_rejected() {
        expect_invalid(
            "regex lookaround",
            &sed_fact_config("programForm", r#"{ "string": { "regex": "(?=inPlace)" } }"#),
            "regex",
        );
    }

    /// Boolean selectors only apply to boolean-typed facts.
    #[test]
    fn boolean_selector_on_string_fact_rejected() {
        expect_invalid(
            "boolean selector on a string fact",
            &sed_fact_config("executionPrimitive", r#"{ "boolean": true }"#),
            "typed",
        );
    }

    /// The closed analyzer version: fact selectors reference "1".
    #[test]
    fn fact_version_outside_catalog_rejected() {
        expect_invalid(
            "unknown fact version",
            &sed_fact_config_facts(
                r#"{ "all": [{ "analyzer": "sed-v1", "version": "2", "name": "executionPrimitive", "occurrence": "all", "value": { "any": true } }] }"#,
            ),
            "version",
        );
    }

    /// Allow fact entries reference the profile analyzer explicitly and a
    /// closed typed selector: omissions fail closed.
    #[test]
    fn allow_fact_entry_missing_fields_rejected() {
        for (name, entry) in [
            (
                "missing-analyzer",
                r#"{ "name": "executionPrimitive", "occurrence": "all", "value": { "any": true } }"#,
            ),
            (
                "missing-version",
                r#"{ "analyzer": "sed-v1", "name": "executionPrimitive", "occurrence": "all", "value": { "any": true } }"#,
            ),
            (
                "missing-occurrence",
                r#"{ "analyzer": "sed-v1", "version": "1", "name": "executionPrimitive", "value": { "any": true } }"#,
            ),
            (
                "missing-value",
                r#"{ "analyzer": "sed-v1", "version": "1", "name": "executionPrimitive", "occurrence": "all" }"#,
            ),
        ] {
            let facts = format!(r#"{{ "all": [{entry}] }}"#);
            expect_invalid(name, &sed_fact_config_facts(&facts), "allow fact");
        }
    }

    /// Sed-v1's closed compatibility table: undeclared canonical ids are
    /// invalid; the read-only table entries are recognized.
    #[test]
    fn sed_compatibility_table_rejects_unknown_option() {
        let bad = r#"{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{
    "id": "sed",
    "executables": ["sed"],
    "options": { "printScript": { "aliases": ["-y"], "arity": 0 } },
    "analyzer": "sed-v1",
    "rules": []
  }]
}"#;
        expect_invalid("non-modeled sed option", bad, "compatibility table");
        // the read-only table entries themselves are recognized canonical ids
        let good = r#"{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [{
    "id": "sed",
    "executables": ["sed"],
    "options": {
      "noPrint": { "aliases": ["-n"], "arity": 0 },
      "extendedRegexp": { "aliases": ["-E"], "arity": 0 }
    },
    "analyzer": "sed-v1",
    "rules": []
  }]
}"#;
        assert!(
            load_str(good).is_ok(),
            "sed-v1 read-only option table must load"
        );
    }

    // ── Issue #40: environment selectors — config-level validation ──────────

    /// Minimal sed-v1 profile whose allow rule carries the given `environment`
    /// coverage text; probe-only (never a live configuration).
    fn sed_fact_config_environment(env: &str) -> String {
        format!(
            r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
    "id": "sed",
    "executables": ["sed"],
    "options": {{}},
    "analyzer": "sed-v1",
    "rules": [{{
      "id": "sed/allow-probe", "action": "allow",
      "match": {{
        "classification": "complete", "arguments": {{ "exact": [] }},
        "options": {{ "none": true }}, "environment": {env},
        "paths": {{ "none": true }}, "facts": {{ "none": true }},
        "nestedParts": {{ "none": true }}
      }}
    }}]
  }}]
}}"#
        )
    }

    /// The authoritative `EnvironmentPolicy/complete` fixture shape parses and
    /// validates: required `prefix` + `occurrence`, optional string-value
    /// selector (`AllowMatch/complete-coverage` carries the one-of form).
    #[test]
    fn allow_environment_complete_policy_accepted() {
        assert!(
            load_str(&sed_fact_config_environment(
                r#"{ "all": [{ "name": "LANG", "prefix": true, "occurrence": "all" }] }"#,
            ))
            .is_ok(),
            "name + prefix + occurrence (no value selector) is the complete EnvironmentPolicy form"
        );
        assert!(
            load_str(&sed_fact_config_environment(
                r#"{ "all": [{ "name": "LANG", "value": { "oneOf": ["C", "C.UTF-8"] }, "prefix": true, "occurrence": "all" }] }"#,
            ))
            .is_ok(),
            "the one-of string-value selector parses on allow entries"
        );
    }

    /// The authoritative `EnvironmentPolicy/missing-occurrence` fixture is
    /// invalid: schema-mandated allow dimensions are never synthesized.
    #[test]
    fn allow_environment_missing_occurrence_rejected() {
        expect_invalid(
            "missing-occurrence",
            &sed_fact_config_environment(r#"{ "all": [{ "name": "LANG", "prefix": true }] }"#),
            "allow environment entries require prefix and occurrence",
        );
    }

    /// `prefix` is the other schema-mandated allow dimension.
    #[test]
    fn allow_environment_missing_prefix_rejected() {
        expect_invalid(
            "missing-prefix",
            &sed_fact_config_environment(r#"{ "all": [{ "name": "LANG", "occurrence": "all" }] }"#),
            "allow environment entries require prefix and occurrence",
        );
    }

    /// An invalid `re2-v1` arm in an environment value selector fails config
    /// load — the pattern is precompiled at load (fail closed).
    #[test]
    fn allow_environment_invalid_value_regex_rejected() {
        expect_invalid(
            "invalid-env-value-regex",
            &sed_fact_config_environment(
                r#"{ "all": [{ "name": "LANG", "value": { "regex": "(?=safe)safe" }, "prefix": true, "occurrence": "all" }] }"#,
            ),
            "re2-v1",
        );
    }

    /// Ordinary ask/deny environment tests accept the string-value selector
    /// plus occurrence while `name` alone stays valid.
    #[test]
    fn ordinary_environment_selector_fields_validate() {
        let deny_config = |env: &str| {
            format!(
                r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [{{
    "id": "sed",
    "executables": ["sed"],
    "options": {{}},
    "rules": [{{
      "id": "sed/deny-env", "action": "deny", "message": "denied environment",
      "match": {{ "classification": "complete", "environment": {env} }}
    }}]
  }}]
}}"#
            )
        };
        // `any` form with the full selector set (EnvironmentMatcher/any.json)
        assert!(
            load_str(&deny_config(
                r#"{ "any": [{ "name": "LANG", "value": { "oneOf": ["C", "C.UTF-8"] }, "prefix": true, "occurrence": "all" }] }"#,
            ))
            .is_ok()
        );
        // name-only tests stay valid for ask/deny
        assert!(load_str(&deny_config(r#"{ "all": [{ "name": "LANG" }] }"#)).is_ok());
    }
}
