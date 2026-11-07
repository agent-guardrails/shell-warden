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
const MAX_MATCH_GLOBS: usize = 64;

/// Analyzer-compatible canonical option ids (closed compatibility table,
/// design §Profiles, option grammars, and analyzers). `sed-v1` is the only
/// analyzer with a modeled option grammar.
fn analyzer_compatible_options(analyzer: AnalyzerId) -> &'static [&'static str] {
    match analyzer {
        AnalyzerId::SedV1 => &["inPlace", "expression", "file"],
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
    // declared profile id
    for profile in &raw.profiles {
        for rule in &profile.rules {
            if let Some(np) = &rule.r#match.nested_parts {
                let lists = [&np.any, &np.all];
                for list in lists.into_iter().flatten() {
                    for e in list {
                        if let Some(pid) = &e.profile
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

    let cfg = Config {
        raw,
        defaults_redirect_policy: defaults_redirect,
    };
    // cross-check: every nestedParts profile reference resolves (already done
    // per rule against the profile set in validate_profile)
    Ok(cfg)
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
        if is_empty_selector(sel) {
            return Err(format!(
                "profile \"{}\": empty path source selector",
                profile.id
            ));
        }
        if sel.redirect.is_some() {
            return Err(format!(
                "profile \"{}\": redirect targets come from the redirect policy, not pathSources",
                profile.id
            ));
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
        }
    }
    Ok(())
}

fn is_empty_selector(sel: &PathCoordinateSelector) -> bool {
    sel.argument.is_none()
        && sel.option_value.is_none()
        && sel.environment.is_none()
        && sel.redirect.is_none()
        && sel.analyzer_fact.is_none()
}

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
        validate_path_policy(&e.policy())?;
    }
    Ok(())
}

/// Lexical path policy: exactly one selector; trusted roots are absolute.
fn validate_path_policy(p: &PathPolicy) -> Result<(), String> {
    let set = p.exact.is_some() as u8 + p.within.is_some() as u8 + p.outside.is_some() as u8;
    if set != 1 {
        return Err("path policy must select exactly one of exact/within/outside".to_string());
    }
    for root in ["within", "outside"] {
        let val = match root {
            "within" => p.within.as_deref().unwrap_or("/"),
            _ => p.outside.as_deref().unwrap_or("/"),
        };
        if !val.starts_with('/') {
            return Err(format!(
                "path policy {root} root \"{val}\" must be an absolute lexical path"
            ));
        }
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
        match each {
            TokenSelector::Within(root) => {
                if !root.starts_with('/') {
                    return Err(
                        "remainder within root must be an absolute lexical path".to_string()
                    );
                }
            }
            TokenSelector::Exact(_) => {}
        }
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
            for entry in allowed {
                let Some(spec) = profile.options.get(&entry.option) else {
                    return Err(format!(
                        "option coverage references undeclared option \"{}\"",
                        entry.option
                    ));
                };
                if spec.arity > 0 {
                    match &entry.values {
                        Some(ValuesCoverage::Each { each }) => {
                            if each.is_empty() {
                                return Err(format!(
                                    "option \"{}\" values.each must not be empty",
                                    entry.option
                                ));
                            }
                        }
                        _ => {
                            return Err(format!(
                                "positive-arity option \"{}\" must select every consumed value (values.each)",
                                entry.option
                            ));
                        }
                    }
                } else if entry.values.is_some() {
                    return Err(format!(
                        "zero-arity option \"{}\" takes no values",
                        entry.option
                    ));
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
                if (e.coordinate.redirect.is_some() || e.coordinate.option_value.is_some())
                    && e.coordinate.redirect.is_some()
                {
                    return Err(
                        "redirect coordinates are covered by the redirect policy, not match.paths"
                            .to_string(),
                    );
                }
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
                validate_fact_test(e, profile)?;
            }
        }
        _ => return Err("allow facts is none or all".to_string()),
    }
    // nestedParts: none or all (closed relation/profile/state/verdict refs)
    let Some(np) = &m.nested_parts else {
        return Err("allow requires an explicit nestedParts policy".to_string());
    };
    match (np.none, &np.any, &np.all) {
        (Some(true), None, None) => {}
        (None | Some(false), None, Some(all)) if !all.is_empty() => {
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
    match profile.analyzer {
        None => {
            return Err(format!(
                "fact \"{}\" references an analyzer, but the profile declares none",
                e.name
            ));
        }
        Some(analyzer) => {
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
        }
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
        // relation/verdict closed enums validated by serde; profile refs are
        // cross-checked against the whole profile set in validate()
        let _ = (&np.any, &np.all);
    }
    if let Some(o) = &m.options {
        if let Some(values) = &o.values {
            for (id, globs) in values {
                if !profile.options.contains_key(id) {
                    return Err(format!(
                        "options.values references undeclared option \"{id}\""
                    ));
                }
                if globs.is_empty() || globs.len() > MAX_MATCH_GLOBS {
                    return Err(format!("options.values \"{id}\" bad glob list"));
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
}
