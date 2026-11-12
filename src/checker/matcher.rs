// Action-sensitive matching (design/shell-warden-config-v2.md §Action-sensitive
// matching and emitted votes + §Lattice reduction):
//
//   ask/deny — `match` asks whether its supplied predicates hold; predicates
//              may be existential or conjunctive and need not account for
//              unrelated evidence (e.g. a deny for force push matches a
//              `force` option without describing every argument);
//   allow    — `match` is both the shape constraint and the total coverage
//              proof: every observed security-relevant item must be
//              universally covered; a rejected allow emits no vote and
//              records its coverage failure.
//
// Internal phases stay separate even though config has one selector object:
// predicate satisfaction, allow coverage validation, then vote emission.

use super::evidence::reason;
use super::evidence::{ArgToken, EnvAssign, EvidenceState, FactObs, Part, RedirectObs};
use super::grammar::{
    self, EnvironmentTest, EvidenceClass, FactTest, OptionCoverage, PathCoordinateSelector,
    PathPolicy, RedirectTest, RemainderPolicy, TokenSelector, ValuesCoverage, VerdictKind,
};

// ── Raw-text glob (07 §7.5, OpenCode-compatible) ─────────────────────────────
// `*` = zero+ chars incl. spaces; `?` = one char; trailing `" *"` also matches
// the bare command.

pub fn glob(raw: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.len() > 2 && pattern.ends_with(" *") {
        let bare = &pattern[..pattern.len() - 2];
        if raw == bare {
            return true;
        }
    }
    glob_inner(raw.chars().peekable(), pattern.chars().peekable())
}

fn glob_inner(
    mut s: std::iter::Peekable<std::str::Chars<'_>>,
    mut p: std::iter::Peekable<std::str::Chars<'_>>,
) -> bool {
    while let Some(pc) = p.peek().copied() {
        match pc {
            '*' => {
                p.next();
                if p.peek().is_none() {
                    return true;
                }
                while s.peek().is_some() {
                    if glob_inner(s.clone(), p.clone()) {
                        return true;
                    }
                    s.next();
                }
                return false;
            }
            '?' => {
                p.next();
                if s.next().is_none() {
                    return false;
                }
            }
            _ => {
                p.next();
                if s.next() != Some(pc) {
                    return false;
                }
            }
        }
    }
    s.peek().is_none()
}

// ── Evidence view supplied by the pipeline ──────────────────────────────────

/// One runtime path coordinate produced from profile `pathSources`.
#[derive(Debug, Clone, PartialEq)]
pub struct PathCoordinateObs {
    pub source: PathSourceTag,
    pub path: String,
    pub resolvable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PathSourceTag {
    Argument {
        index: u32,
    },
    OptionValue {
        canonical: String,
        occurrence: u32,
        value_ordinal: u32,
    },
    Environment {
        occurrence: u32,
    },
    AnalyzerFact {
        analyzer: &'static str,
        name: String,
        occurrence: u32,
    },
}

/// Reduced result of one nested (child) part.
#[derive(Debug, Clone)]
pub struct NestedResult {
    pub part_id: usize,
    pub relation: grammar::Relation,
    pub relation_ordinal: u32,
    pub executable: Option<String>,
    pub profile_id: Option<String>,
    pub analyzer: Option<&'static str>,
    pub state: EvidenceState,
    pub verdict: VerdictKind,
}

/// One option occurrence as seen by the matcher.
#[derive(Debug, Clone, PartialEq)]
pub struct OptionOccurrenceView {
    pub ordinal: u32,
    pub values: Vec<(String, bool)>, // (decoded text, resolvable)
}

/// Everything a predicate or coverage check may consult about one part.
pub struct PartFacts<'a> {
    pub part: &'a Part,
    pub profile_id: Option<&'a str>,
    /// Positional arguments after option parsing.
    pub positionals: &'a [ArgToken],
    /// Canonical option ID → occurrences (source order).
    pub canonical: std::collections::BTreeMap<String, Vec<OptionOccurrenceView>>,
    pub path_coords: &'a [PathCoordinateObs],
    pub nested: &'a [NestedResult],
}

// ── Lexical path comparison (design §Lexical path policy) ───────────────────

pub fn lexical_components(path: &str, cwd: &str) -> Vec<String> {
    let joined = if path.starts_with('/') {
        path.to_string()
    } else if cwd.is_empty() {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    };
    let mut out: Vec<String> = Vec::new();
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other.to_string()),
        }
    }
    out
}

/// `/work/repo2` is NOT within `/work/repo` (component-wise).
pub fn path_within(path: &str, root: &str, cwd: &str) -> bool {
    let p = lexical_components(path, cwd);
    let r = lexical_components(root, "");
    r.len() <= p.len() && p[..r.len()] == r[..]
}

pub fn path_matches_policy(text_path: &str, policy: &PathPolicy, cwd: &str) -> bool {
    if let Some(exact) = &policy.exact {
        return exact.as_str() == text_path;
    }
    if let Some(within_root) = &policy.within {
        return path_within(text_path, within_root, cwd);
    }
    if let Some(outside_root) = &policy.outside {
        return !path_within(text_path, outside_root, cwd);
    }
    false
}

// ── Ordinary predicate satisfaction (ask/deny) ──────────────────────────────

fn state_class(state: EvidenceState) -> EvidenceClass {
    match state {
        EvidenceState::Complete => EvidenceClass::Complete,
        EvidenceState::Opaque(_) => EvidenceClass::Opaque,
        EvidenceState::Invalid(_) => EvidenceClass::Invalid,
    }
}

pub fn predicate_holds(m: &grammar::Match, f: &PartFacts) -> bool {
    let classification = m.classification;
    let raw = m.raw.as_ref();
    let arguments = m.arguments.as_ref();
    let options = m.options.as_ref();
    let environment = m.environment.as_ref();
    let redirects = m.redirects.as_ref();
    let paths = m.paths.as_ref();
    let facts = m.facts.as_ref();
    let nested_parts = m.nested_parts.as_ref();

    if let Some(cls) = classification
        && cls != state_class(f.part.state)
    {
        return false;
    }
    if let Some(pattern) = raw
        && !glob(&f.part.raw, pattern)
    {
        return false;
    }
    if let Some(a) = arguments
        && !arguments_holds(a, f.positionals)
    {
        return false;
    }
    if let Some(o) = options
        && !options_holds(o, f)
    {
        return false;
    }
    if let Some(e) = environment
        && !environment_holds(e, &f.part.assigns)
    {
        return false;
    }
    if let Some(r) = redirects
        && !redirects_holds(r, &f.part.redirects)
    {
        return false;
    }
    if let Some(p) = paths
        && !paths_matcher_holds(p, f.path_coords)
    {
        return false;
    }
    if let Some(fm) = facts
        && !facts_matcher_holds(fm, &f.part.facts)
    {
        return false;
    }
    if let Some(np) = nested_parts
        && !nested_matcher_holds(np, f.nested)
    {
        return false;
    }
    true
}

/// Design's argument predicates (ordinary ask/deny): `exact` = anchored
/// positional-token sequence (the listed tokens match positionally from 0,
/// unrelated trailing evidence is absent from the predicate — denies need
/// not describe every argument); `prefix` = same anchored semantics kept
/// for vocabulary symmetry; `containsAny` = ∃ token × ∃ glob.
/// For allow, `exact` means total coverage of the positional list (see
/// allow_covers) — the action-sensitive meaning of one selector object.
fn arguments_holds(a: &grammar::ArgumentsMatcher, positionals: &[ArgToken]) -> bool {
    if a.exact.is_some() && (a.prefix.is_some() || a.remainder.is_some()) {
        return false;
    }
    if let Some(exact) = &a.exact {
        if positionals.len() < exact.len() {
            return false;
        }
        if positionals[..exact.len()]
            .iter()
            .map(|t| t.text.as_str())
            .ne(exact.iter().map(|s| s.as_str()))
        {
            return false;
        }
    }
    if let Some(prefix) = &a.prefix
        && (positionals.len() < prefix.len()
            || positionals[..prefix.len()]
                .iter()
                .map(|t| t.text.as_str())
                .ne(prefix.iter().map(|s| s.as_str())))
    {
        return false;
    }
    if let Some(globs) = &a.contains_any
        && !globs
            .iter()
            .any(|g| positionals.iter().any(|t| glob(&t.text, g)))
    {
        return false;
    }
    true
}

fn options_holds(o: &grammar::OptionsMatcher, f: &PartFacts) -> bool {
    if let Some(none) = o.none
        && none
        && !f.canonical.is_empty()
    {
        return false;
    }
    if let Some(present_all) = &o.present_all
        && !present_all.iter().all(|id| f.canonical.contains_key(id))
    {
        return false;
    }
    if let Some(present_any) = &o.present_any
        && !present_any.iter().any(|id| f.canonical.contains_key(id))
    {
        return false;
    }
    if let Some(absent_all) = &o.absent_all
        && absent_all.iter().any(|id| f.canonical.contains_key(id))
    {
        return false;
    }
    if let Some(values) = &o.values
        && !values.iter().all(|(id, globs)| {
            f.canonical.get(id).map(|occs| {
                occs.iter().any(|occ| {
                    occ.values
                        .iter()
                        .any(|(v, _)| globs.iter().any(|g| glob(v, g)))
                })
            }) == Some(true)
        })
    {
        return false;
    }
    // positional `containsAny` in the design maps to arguments, and an
    // `allowed` policy never participates in ordinary matching
    true
}

fn env_value_text(a: &EnvAssign) -> &str {
    match a.text.split_once('=') {
        Some((_, v)) => v,
        None => "",
    }
}

fn env_test_matches(test: &EnvironmentTest, a: &EnvAssign) -> bool {
    if test.name != a.name {
        return false;
    }
    if let Some(v) = &test.value
        && !glob(env_value_text(a), v)
    {
        return false;
    }
    if let Some(true) = test.prefix {
        // every recorded assignment is a command-prefix assignment
    }
    true
}

fn environment_holds(e: &grammar::EnvironmentMatcher, assigns: &[EnvAssign]) -> bool {
    stress_none_env(e, assigns) && existentials(e, assigns) && universals(e, assigns)
}

fn stress_none_env(e: &grammar::EnvironmentMatcher, assigns: &[EnvAssign]) -> bool {
    if let Some(true) = e.none
        && !assigns.is_empty()
    {
        return false;
    }
    true
}

fn existentials(e: &grammar::EnvironmentMatcher, assigns: &[EnvAssign]) -> bool {
    let Some(any) = &e.any else { return true };
    if !any
        .iter()
        .any(|test| assigns.iter().any(|a| env_test_matches(test, a)))
    {
        return false;
    }
    true
}

fn universals(e: &grammar::EnvironmentMatcher, assigns: &[EnvAssign]) -> bool {
    let Some(all) = &e.all else { return true };
    all.iter()
        .all(|test| assigns.iter().any(|a| env_test_matches(test, a)))
}

/// `any`/`all`/`none` semantics: none = zero items; any = ∃ item × ∃ entry;
/// all = ∀ item ∃ entry.
fn redirects_holds(r: &grammar::RedirectMatcher, redirects: &[RedirectObs]) -> bool {
    if let Some(true) = r.none
        && !redirects.is_empty()
    {
        return false;
    }
    if let Some(any) = &r.any
        && !redirects
            .iter()
            .any(|o| any.iter().any(|test| redirect_test_holds(test, o)))
    {
        return false;
    }
    if let Some(all) = &r.all
        && !redirects
            .iter()
            .all(|o| any_of(all, |test| redirect_test_holds(test, o)))
    {
        return false;
    }
    true
}

fn redirect_test_holds(test: &RedirectTest, o: &RedirectObs) -> bool {
    let op_ok = match test.operator {
        Some(op) => Some(op) == o.op,
        None => true,
    };
    let fd_ok = match test.source_fd {
        Some(sel) => {
            let want = match sel {
                grammar::FdSelector::Default => None,
                grammar::FdSelector::Number(n) => Some(n),
            };
            want == o.source_fd
        }
        None => true,
    };
    let kind_ok = match test.target_kind {
        Some(grammar::TargetKindKind::LiteralPath) => !o.is_fd_target,
        Some(grammar::TargetKindKind::Fd) => o.is_fd_target,
        None => true,
    };
    op_ok && fd_ok && kind_ok
}

/// Coordinate selector (static, from config) vs one runtime coordinate tag.
pub fn coordinate_matches(sel: &PathCoordinateSelector, tag: &PathSourceTag) -> bool {
    match tag {
        PathSourceTag::Argument { index } => match &sel.argument {
            Some(pc) => match pc {
                grammar::PositionalCoordinate::N {
                    index: n,
                    remainder,
                } => *n == *index || *remainder,
                grammar::PositionalCoordinate::All { all: true } => true,
                grammar::PositionalCoordinate::All { all: false } => false,
            },
            None => false,
        },
        PathSourceTag::OptionValue {
            canonical,
            occurrence,
            value_ordinal,
        } => match &sel.option_value {
            Some(oc) => {
                oc.option.as_str() == canonical.as_str()
                    && oc
                        .occurrence
                        .map(|o| o.selects(*occurrence))
                        .unwrap_or(true)
                    && oc
                        .value_ordinal
                        .map(|o| o.selects(*value_ordinal))
                        .unwrap_or(true)
            }
            None => false,
        },
        PathSourceTag::Environment { occurrence } => match &sel.environment {
            Some(o) => o.selects(*occurrence),
            None => false,
        },
        PathSourceTag::AnalyzerFact {
            analyzer,
            name,
            occurrence,
        } => match &sel.analyzer_fact {
            Some(fc) => {
                fc.name.as_str() == *name
                    && fc
                        .occurrence
                        .map(|o| o.selects(*occurrence))
                        .unwrap_or(true)
                    && fc
                        .analyzer
                        .as_deref()
                        .map(|a| a == *analyzer)
                        .unwrap_or(true)
            }
            None => false,
        },
    }
}

/// Ask/deny path predicates over the runtime coordinates they may select.
pub fn paths_matcher_holds(p: &grammar::PathsMatcher, coords: &[PathCoordinateObs]) -> bool {
    if let Some(true) = p.none
        && !coords.is_empty()
    {
        return false;
    }
    if let Some(any) = &p.any {
        if !any.is_empty()
            && !any.iter().any(|entry| {
                coords
                    .iter()
                    .any(|c| coordinate_matches(&entry.coordinate, &c.source))
            })
        {
            return false;
        }
        if any.is_empty() {
            return false;
        }
    }
    if let Some(all) = &p.all {
        if all.is_empty() {
            return false;
        }
        if !coords.is_empty()
            && !coords.iter().all(|c| {
                all.iter()
                    .any(|entry| coordinate_matches(&entry.coordinate, &c.source))
            })
        {
            return false;
        }
    }
    true
}

pub fn facts_matcher_holds(fm: &grammar::FactsMatcher, facts: &[FactObs]) -> bool {
    let matches_entry = |e: &FactTest, fact: &FactObs| -> bool {
        e.name == fact.fact_name
            && e.analyzer
                .as_ref()
                .map(|a| a.as_str() == fact.analyzer_id)
                .unwrap_or(true)
            && e.value
                .as_ref()
                .map(|v| glob(&fact.value, v))
                .unwrap_or(true)
    };
    if let Some(true) = fm.none
        && !facts.is_empty()
    {
        return false;
    }
    if let Some(any) = &fm.any
        && !any
            .iter()
            .any(|e| facts.iter().any(|f| matches_entry(e, f)))
    {
        return false;
    }
    if let Some(all) = &fm.all {
        if all.is_empty() {
            return false;
        }
        if !facts.iter().all(|f| any_of(all, |e| matches_entry(e, f))) {
            return false;
        }
    }
    true
}

fn nested_test(e: &grammar::NestedPartTest, n: &NestedResult) -> bool {
    if let Some(relation) = e.relation
        && relation != n.relation
    {
        return false;
    }
    if let Some(exec) = &e.executable
        && n.executable.as_deref() != Some(exec.as_str())
    {
        return false;
    }
    if let Some(profile) = &e.profile
        && n.profile_id.as_deref() != Some(profile.as_str())
    {
        return false;
    }
    if let Some(analyzer) = &e.analyzer
        && n.analyzer.map(|a| a != analyzer.as_str()).unwrap_or(true)
    {
        return false;
    }
    if let Some(state) = e.state
        && state_class(n.state) != state
    {
        return false;
    }
    if let Some(verdict) = e.verdict
        && verdict != n.verdict
    {
        return false;
    }
    if let Some(occ) = e.occurrence
        && !occ.selects(n.relation_ordinal)
    {
        return false;
    }
    true
}

pub fn nested_matcher_holds(np: &grammar::NestedPartsMatcher, nested: &[NestedResult]) -> bool {
    if let Some(true) = np.none
        && !nested.is_empty()
    {
        return false;
    }
    if let Some(any) = &np.any
        && !any.iter().any(|e| nested.iter().any(|n| nested_test(e, n)))
    {
        return false;
    }
    if let Some(all) = &np.all {
        if all.is_empty() {
            return false;
        }
        if !nested.iter().all(|n| any_of(all, |e| nested_test(e, n))) {
            return false;
        }
    }
    true
}

fn any_of<T, F: Fn(&T) -> bool>(entries: &[T], f: F) -> bool {
    !entries.is_empty() && entries.iter().any(f)
}

// ── Allow coverage validation (only reached for action = allow) ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageCode {
    AllowEvidenceNotComplete,
    AllowCoverageMissing,
    UnknownOption,
    RequiredOptionMissing,
    OptionNotRepeatable,
    OptionNotAllowed,
    OptionValuesUncovered,
    RemainderUncovered,
    RedirectPolicyUncovered,
}

impl CoverageCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            CoverageCode::AllowEvidenceNotComplete => reason::ALLOW_EVIDENCE_NOT_COMPLETE,
            CoverageCode::AllowCoverageMissing => reason::ALLOW_COVERAGE_MISSING,
            CoverageCode::UnknownOption => reason::UNKNOWN_OPTION,
            CoverageCode::RequiredOptionMissing => reason::REQUIRED_OPTION_MISSING,
            CoverageCode::OptionNotRepeatable => reason::OPTION_NOT_REPEATABLE,
            CoverageCode::OptionNotAllowed => reason::OPTION_NOT_ALLOWED,
            CoverageCode::OptionValuesUncovered => reason::OPTION_VALUE_UNCOVERED,
            CoverageCode::RemainderUncovered => reason::REMAINDER_UNCOVERED,
            CoverageCode::RedirectPolicyUncovered => reason::REDIRECT_POLICY_UNCOVERED,
        }
    }
}

/// Validate the total coverage proof of an allow `match`.
///
/// Statically validated preconditions: `classification: "complete"`, no `raw`
/// predicate, no `redirects` matcher, explicit policy for every other
/// dimension, `prefix` always has an explicit `remainder`, `exact` has none.
///
/// `effective_redirect` is the resolved policy bundle (config default →
/// profile override → allow-rule override); `cwd` is the letter command cwd.
#[allow(clippy::too_many_lines)]
pub fn allow_covers(
    m: &grammar::Match,
    ctx: &PartFacts,
    effective_redirect: &grammar::RedirectPolicy,
    cwd: &str,
) -> Result<(), Vec<CoverageCode>> {
    let mut failures: Vec<CoverageCode> = Vec::new();

    if !ctx.part.state.can_allow() {
        failures.push(CoverageCode::AllowEvidenceNotComplete);
        return Err(failures);
    }
    if !matches!(m.classification, Some(EvidenceClass::Complete)) {
        failures.push(CoverageCode::AllowEvidenceNotComplete);
        return Err(failures);
    }

    // ── arguments ──
    match &m.arguments {
        Some(a) if a.exact.is_some() => {
            match exact_covers_args(a.exact.as_ref().unwrap(), ctx.positionals) {
                Ok(()) => {}
                Err(code) => failures.push(code),
            }
        }
        Some(a) if a.prefix.is_some() && a.remainder.is_some() => {
            let prefix = a.prefix.as_ref().unwrap();
            let prefix_ok = ctx.prefix_matches_literal(prefix);
            match prefix_ok {
                Ok(()) => {
                    let rest = &ctx.positionals[prefix.len()..];
                    match &a.remainder.as_ref().unwrap() {
                        RemainderPolicy::None { none: true } => {
                            if !rest.is_empty() {
                                failures.push(CoverageCode::RemainderUncovered);
                            }
                        }
                        RemainderPolicy::None { none: false } => {
                            failures.push(CoverageCode::AllowCoverageMissing);
                        }
                        RemainderPolicy::Each { each } => {
                            if rest.iter().any(|t| !remainder_fits(each, t, cwd)) {
                                failures.push(CoverageCode::RemainderUncovered);
                            }
                        }
                    }
                }
                Err(code) => failures.push(code),
            }
        }
        _ => failures.push(CoverageCode::AllowCoverageMissing),
    }

    // ── options ──
    match &m.options {
        Some(o) if o.none == Some(true) && o.allowed.is_none() => {
            if !ctx.canonical.is_empty() {
                failures.push(CoverageCode::OptionNotAllowed);
            }
        }
        Some(o) if o.allowed.is_some() => {
            let allowed = o.allowed.as_ref().unwrap();
            // every observed occurrence satisfied by exactly one entry shape
            for (canonical, occs) in &ctx.canonical {
                match allowed
                    .iter()
                    .find(|c| c.option.as_str() == canonical.as_str())
                {
                    None => failures.push(CoverageCode::OptionNotAllowed),
                    Some(entry) => {
                        if occs.len() > 1 && !entry.repeatable {
                            failures.push(CoverageCode::OptionNotRepeatable);
                        }
                        if !option_values_covers(entry, occs) {
                            failures.push(CoverageCode::OptionValuesUncovered);
                        }
                    }
                }
            }
            // required entries must actually occur
            for entry in allowed {
                let seen = ctx
                    .canonical
                    .get(&entry.option)
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                if entry.required && !seen {
                    failures.push(CoverageCode::RequiredOptionMissing);
                }
            }
        }
        _ => failures.push(CoverageCode::AllowCoverageMissing),
    }

    // ── environment ──
    match &m.environment {
        Some(e) if e.none == Some(true) && e.any.is_none() && e.all.is_none() => {
            if !ctx.part.assigns.is_empty() {
                failures.push(CoverageCode::AllowCoverageMissing);
            }
        }
        Some(e) if e.all.is_some() => {
            let entries = e.all.as_ref().unwrap();
            for assign in &ctx.part.assigns {
                let covered = assign.resolvable
                    && entries.iter().any(|test: &EnvironmentTest| {
                        test.name == assign.name
                            && test
                                .value
                                .as_ref()
                                .map(|v| v.as_str() == env_value_text(assign))
                                .unwrap_or(true)
                            && test.prefix.unwrap_or(true)
                    });
                if !covered {
                    failures.push(CoverageCode::AllowCoverageMissing);
                    break;
                }
            }
        }
        _ => failures.push(CoverageCode::AllowCoverageMissing),
    }

    // ── redirects: resolved effective policy covers every occurrence ──
    if let Err(code) = redirect_policy_covers(&effective_redirect.redirects, &ctx.part.redirects) {
        failures.push(code);
    }
    if let Err(code) = redirect_paths_covers(&effective_redirect.paths, &ctx.part.redirects, cwd) {
        failures.push(code);
    }

    // ── non-redirect paths ──
    match &m.paths {
        Some(p) if p.none == Some(true) && p.any.is_none() && p.all.is_none() => {
            if !ctx.path_coords.is_empty() {
                failures.push(CoverageCode::AllowCoverageMissing);
            }
        }
        Some(p) if p.all.is_some() => {
            let entries = p.all.as_ref().unwrap();
            for coord in ctx.path_coords {
                let covered = coord.resolvable
                    && entries.iter().any(|entry: &grammar::PathEntry| {
                        coordinate_matches(&entry.coordinate, &coord.source)
                            && path_matches_policy(&coord.path, &entry.policy(), cwd)
                    });
                if !covered {
                    failures.push(CoverageCode::AllowCoverageMissing);
                    break;
                }
            }
        }
        _ => failures.push(CoverageCode::AllowCoverageMissing),
    }

    // ── facts ──
    match &m.facts {
        Some(fm) if fm.none == Some(true) && fm.any.is_none() && fm.all.is_none() => {
            if !ctx.part.facts.is_empty() {
                failures.push(CoverageCode::AllowCoverageMissing);
            }
        }
        Some(fm) if fm.all.is_some() => {
            let entries = fm.all.as_ref().unwrap();
            for fact in &ctx.part.facts {
                let covered = entries.iter().any(|e: &FactTest| {
                    e.name == fact.fact_name
                        && e.analyzer
                            .as_ref()
                            .map(|a| a.as_str() == fact.analyzer_id)
                            .unwrap_or(true)
                        && e.value
                            .as_ref()
                            .map(|v| v.as_str() == fact.value)
                            .unwrap_or(true)
                });
                if !covered {
                    failures.push(CoverageCode::AllowCoverageMissing);
                    break;
                }
            }
        }
        _ => failures.push(CoverageCode::AllowCoverageMissing),
    }

    // ── nested parts ──
    match &m.nested_parts {
        Some(np) if np.none == Some(true) && np.any.is_none() && np.all.is_none() => {
            if !ctx.nested.is_empty() {
                failures.push(CoverageCode::AllowCoverageMissing);
            }
        }
        Some(np) if np.all.is_some() => {
            let entries = np.all.as_ref().unwrap();
            for n in ctx.nested {
                if !entries
                    .iter()
                    .any(|e: &grammar::NestedPartTest| nested_test(e, n))
                {
                    failures.push(CoverageCode::AllowCoverageMissing);
                    break;
                }
            }
        }
        _ => failures.push(CoverageCode::AllowCoverageMissing),
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(dedupe(failures))
    }
}

fn dedupe(v: Vec<CoverageCode>) -> Vec<CoverageCode> {
    let mut out: Vec<CoverageCode> = Vec::new();
    for c in v {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

impl<'a> PartFacts<'a> {
    fn prefix_matches_literal(&self, prefix: &[String]) -> Result<(), CoverageCode> {
        if self.positionals.len() < prefix.len()
            || self.positionals[..prefix.len()]
                .iter()
                .zip(prefix.iter())
                .any(|(t, e)| t.text != e.as_str() || !t.resolvable)
        {
            return Err(CoverageCode::AllowCoverageMissing);
        }
        Ok(())
    }
}

fn exact_covers_args(exact: &[String], positionals: &[ArgToken]) -> Result<(), CoverageCode> {
    if positionals.len() != exact.len()
        || positionals
            .iter()
            .zip(exact.iter())
            .any(|(t, e)| t.text != e.as_str() || !t.resolvable)
    {
        return Err(CoverageCode::AllowCoverageMissing);
    }
    Ok(())
}

fn option_values_covers(entry: &OptionCoverage, occs: &[OptionOccurrenceView]) -> bool {
    let Some(coverage) = &entry.values else {
        // consumed/inline values must be selected when any exist
        return !occs.iter().any(|o| !o.values.is_empty());
    };
    match coverage {
        ValuesCoverage::Each { each } => occs.iter().all(|o| {
            o.values
                .iter()
                .all(|(v, resolvable)| *resolvable && each.iter().any(|want| want == v))
        }),
        ValuesCoverage::None { none: true } => occs.iter().all(|o| o.values.is_empty()),
        ValuesCoverage::None { none: false } => false,
    }
}

fn remainder_fits(selector: &TokenSelector, token: &ArgToken, cwd: &str) -> bool {
    match selector {
        TokenSelector::Exact(list) => {
            token.resolvable && list.iter().any(|t| t.as_str() == token.text)
        }
        TokenSelector::Within(root) => token.resolvable && path_within(&token.text, root, cwd),
    }
}

/// Every redirect occurrence is covered by some redirect entry (structure).
fn redirect_policy_covers(
    coverage: &grammar::RedirectCoverage,
    redirects: &[RedirectObs],
) -> Result<(), CoverageCode> {
    let entries = match coverage {
        grammar::RedirectCoverage::None { none: true } => {
            return if redirects.is_empty() {
                Ok(())
            } else {
                Err(CoverageCode::RedirectPolicyUncovered)
            };
        }
        grammar::RedirectCoverage::None { none: false } => {
            return Err(CoverageCode::RedirectPolicyUncovered);
        }
        grammar::RedirectCoverage::All { all } => all,
    };
    for o in redirects {
        // unsupported operator form or dynamic target can never allow
        if o.op.is_none() || !o.target_resolvable {
            return Err(CoverageCode::RedirectPolicyUncovered);
        }
        let op = o.op.unwrap();
        if !any_of(entries, |e: &grammar::RedirectEntry| {
            e.operator == op
                && e.occurrence.selects(o.ordinal)
                && fd_matches(&e.source_fd, o.source_fd)
                && target_kind_matches(e.target.kind, o)
        }) {
            return Err(CoverageCode::RedirectPolicyUncovered);
        }
    }
    Ok(())
}

fn fd_matches(selector: &grammar::FdSelector, observed: Option<u32>) -> bool {
    match selector {
        grammar::FdSelector::Default => observed.is_none(),
        grammar::FdSelector::Number(n) => observed == Some(*n),
    }
}

fn target_kind_matches(kind: grammar::TargetKindKind, o: &RedirectObs) -> bool {
    if o.op.is_none() || !o.target_resolvable {
        return false;
    }
    match kind {
        grammar::TargetKindKind::LiteralPath => !o.is_fd_target,
        grammar::TargetKindKind::Fd => o.is_fd_target,
    }
}

/// Every literal redirect target satisfies the policy's redirect-path entries.
fn redirect_paths_covers(
    coverage: &grammar::PathCoverage,
    redirects: &[RedirectObs],
    cwd: &str,
) -> Result<(), CoverageCode> {
    let entries = match coverage {
        grammar::PathCoverage::None { none: true } => {
            return if redirects
                .iter()
                .all(|o| o.is_fd_target || !o.target_resolvable || o.op.is_none())
            {
                Ok(())
            } else {
                Err(CoverageCode::RedirectPolicyUncovered)
            };
        }
        grammar::PathCoverage::None { none: false } => {
            return Err(CoverageCode::RedirectPolicyUncovered);
        }
        grammar::PathCoverage::All { all } => all,
    };
    for o in redirects {
        if o.op.is_none() || !o.target_resolvable || o.is_fd_target {
            continue; // fd targets and dynamic targets are structural (above)
        }
        let op = o.op.unwrap();
        if !any_of(entries, |e: &grammar::PathEntry| {
            redirect_coordinate_matches(&e.coordinate, op, o.source_fd, o.ordinal)
                && path_matches_policy(&o.target, &e.policy(), cwd)
        }) {
            return Err(CoverageCode::RedirectPolicyUncovered);
        }
    }
    Ok(())
}

fn redirect_coordinate_matches(
    sel: &PathCoordinateSelector,
    op: grammar::RedirectOp,
    fd: Option<u32>,
    ordinal: u32,
) -> bool {
    sel.redirect
        .as_ref()
        .map(|rc| {
            rc.operator == op
                && fd_matches(&rc.source_fd, fd)
                && rc.occurrence.map(|o| o.selects(ordinal)).unwrap_or(true)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob("git status", "git status *"));
        assert!(glob("git status -v", "git status *"));
        assert!(glob("docker push foo", "docker *"));
        assert!(!glob("cat docker", "docker *"));
        assert!(glob("ab", "a?"));
        assert!(!glob("b", "a?"));
        assert!(glob("git status", "*"));
    }

    #[test]
    fn componeent_prefix_semantics() {
        assert!(path_within("/work/repo", "/work/repo", "/"));
        assert!(path_within("/work/repo/x", "/work/repo", "/"));
        assert!(!path_within("/work/repo2", "/work/repo", "/"));
        assert!(path_within("reports/a.txt", "/tmp", "/tmp/work"));
        assert!(!path_within("reports/a.txt", "/var", "/tmp/work"));
    }
}
