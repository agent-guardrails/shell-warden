// Decision pipeline v2 (design/shell-warden-config-v2.md §Lattice reduction
// and fallback hints + §Action-sensitive matching and emitted votes):
//
//   raw shell text
//     → shell parse + recursive executable-part extraction (split.rs)
//     → per-part profile selection (lexical, unique by config validation)
//     → profile option parsing, analyzer facts, analyzer-command parts
//     → complete part & evidence graph
//     → policy resolution → predicate satisfaction → allow coverage
//     → emitted votes reduce by the fixed lattice `allow < ask < deny`
//     → per-command aggregate → letter aggregate + message composition
//
// Monotonic: every matching rule is evaluated and emits its vote; there is no
// numeric priority, no first/last match, no refinement phase, and no
// configuration-order meaning. Adding a matching allow never lowers a result.
// No emitted vote yields ask. Messages never decide a verdict: at the
// winning action the message comes from the lexicographically smallest rule
// ID; fallback hints fire only on the bare default ask.

use super::config::Config;
use super::evidence::{ArgToken, EvidenceState, Part, reason};

use super::grammar::{
    AnalyzerId, OverrideMode, PathCoverage, Profile, RedirectCoverage, RedirectEntry,
    RedirectPolicy, RedirectPolicyOverride, Relation, Rule, VerdictKind,
};
use super::letter::{Command, Letter};
use super::matcher::{
    NestedResult, OptionOccurrenceView, PartFacts, PathCoordinateObs, PathSourceTag, allow_covers,
    predicate_holds,
};
use super::options::{ParsedOptions, parse_options};
use super::verdict::{
    CommandVerdict, Diagnostics, EvidenceClass, FullDiagnostics, RejectedAllow,
    TruncatedDiagnostics, Verdict, is_invalid_cause, select_truncated_reasons, sorted_unique,
};

const DENY_FALLBACK_MESSAGE: &str = "denied by shell-warden policy";

pub fn evaluate(config: &Config, letter: &Letter) -> Verdict {
    let mut commands = Vec::new();
    let mut outcome: Vec<(VerdictKind, Option<String>)> = Vec::new();
    for cmd in &letter.commands {
        let (v, msg) = command_verdict(config, cmd);
        outcome.push((v.verdict, msg));
        commands.push(v);
    }

    // Letter aggregate: most restrictive across commands; message from the
    // most restrictive deciding command (first explicit message), else
    // defaults.message — never on allow.
    let aggregate = commands
        .iter()
        .map(|c| c.verdict)
        .max_by_key(|v| v.rank())
        .unwrap_or(VerdictKind::Ask);
    let message = if aggregate == VerdictKind::Allow {
        None
    } else {
        outcome
            .iter()
            .filter(|(v, _)| *v == aggregate)
            .find_map(|(_, m)| m.clone())
            .or_else(|| config.defaults_message())
            .or_else(|| (aggregate == VerdictKind::Deny).then(|| DENY_FALLBACK_MESSAGE.to_string()))
    };

    Verdict {
        invocation_id: letter.invocation.id.clone(),
        verdict: aggregate,
        message,
        commands,
    }
}

// ── Per-command evaluation ──────────────────────────────────────────────────

impl PartOutcome {
    fn default_ask() -> Self {
        PartOutcome {
            verdict: VerdictKind::Ask,
            rule_id: None,
            message: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PartOutcome {
    verdict: VerdictKind,
    rule_id: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Default)]
struct CmdDiag {
    reasons: Vec<String>,
    selected_profiles: Vec<String>,
    matched: Vec<String>,
    qualified: Vec<String>,
    rejected: Vec<(String, Vec<String>)>,
    votes: Vec<String>,
}

pub(super) fn command_verdict(config: &Config, cmd: &Command) -> (CommandVerdict, Option<String>) {
    let cwd = cmd.cwd.clone();
    let mut graph = super::split::extract(&cmd.raw);
    graph.overflow |= graph.parts.len() > config.limits().evidence_items as usize;
    if graph.overflow {
        graph.reasons.push(reason::EVIDENCE_LIMIT);
    }

    relabel_xargs_children(config, &mut graph);

    // profile selection per part (lexical, unique by validation)
    let selections: Vec<Option<usize>> = (0..graph.parts.len())
        .map(|i| select_profile_index(config, &graph.parts[i]))
        .collect();

    let mut diag = CmdDiag::default();

    // analyzer facts (only for parts selecting a profile with an analyzer)
    if !graph.overflow {
        for (part, pi) in graph.parts.iter_mut().zip(selections.iter()) {
            if graph.collapsed.contains(&part.id) {
                continue;
            }
            let Some(pi) = *pi else { continue };
            let prof = &config.profiles()[pi];
            let Some(analyzer) = prof.analyzer else {
                continue;
            };
            let head = part
                .argv
                .first()
                .map(|t| t.text.clone())
                .unwrap_or_default();
            // the executable head is evidence of profile selection, not a
            // positional argument: rules match arguments after it
            let pos: Vec<ArgToken> = part.argv.clone();
            let parsed = parse_options(argv_for_options(&pos), &prof.options);
            let canonical = occurred_canonicals(&parsed);
            part.facts =
                super::analyzers::analyze(analyzer, &head, &parsed.positionals, &canonical);
        }
    }

    // children reduce first (their ids are strictly greater than the parent's)
    let mut reduced: std::collections::BTreeMap<usize, (VerdictKind, EvidenceState)> =
        std::collections::BTreeMap::new();
    let mut outcomes: Vec<(usize, PartOutcome)> = Vec::new();

    if graph.overflow {
        // evidence-items cap: no rule runs, no allow ever wins; everything
        // reduces to ask on non-complete evidence (fail-closed)
        for i in 0..graph.parts.len() {
            if dead_part(&graph.parts[i]) || graph.collapsed.contains(&i) {
                continue;
            }
            reduced.insert(
                i,
                (
                    VerdictKind::Ask,
                    EvidenceState::Invalid(reason::EVIDENCE_LIMIT),
                ),
            );
            outcomes.push((i, PartOutcome::default_ask()));
        }
    } else {
        for (part, pi) in graph.parts.iter().zip(selections.iter()) {
            if graph.collapsed.contains(&part.id) {
                continue;
            }
            if let Some(pi) = *pi {
                diag.selected_profiles
                    .push(config.profiles()[pi].id.clone());
            }
        }
        for i in (0..graph.parts.len()).rev() {
            let part = &graph.parts[i];
            if dead_part(part) || graph.collapsed.contains(&i) {
                continue;
            }
            let Some(pi) = selections[i] else {
                // No selected profile ⇒ no rule may run; the part's own state
                // still contributes to the aggregate and classification.
                let _ = !part.is_complete();
                reduced.insert(i, (VerdictKind::Ask, part.state));
                outcomes.push((i, PartOutcome::default_ask()));
                continue;
            };
            let prof = &config.profiles()[pi];
            let pos: Vec<ArgToken> = part.argv.clone();
            let parsed = parse_options(argv_for_options(&pos), &prof.options);
            let state = if parsed.invalid_reasons.is_empty() {
                part.state
            } else {
                EvidenceState::Invalid(parsed.invalid_reasons[0])
            };
            // annotate the graph part so evidence/reason diagnostics carry
            // the per-profile parse failure (unknown-option, missing values)
            graph.parts[i].state = state;
            for r in parsed.invalid_reasons.iter().copied() {
                if !diag.reasons.iter().any(|x| x == r) {
                    diag.reasons.push(r.to_string());
                }
            }

            let nested = nested_results(&graph, i, &selections, &reduced, config);
            let outcome = evaluate_part_rules(
                config,
                &graph.parts[i],
                prof,
                &parsed,
                state,
                nested,
                cwd.as_str(),
                &mut diag,
            );
            reduced.insert(i, (outcome.verdict, state));
            outcomes.push((i, outcome));
        }
    }

    // per-command aggregate: deny > ask > allow across every part
    let verdict = outcomes
        .iter()
        .map(|(_, o)| o.verdict)
        .max_by_key(|v| v.rank())
        .unwrap_or(VerdictKind::Ask);

    // message: lexico-smallest rule id among deciding parts at the winning
    // action; fallback hints already covered the bare default ask per part
    let mut deciding: Vec<&PartOutcome> = Vec::new();
    for (_, o) in outcomes.iter().filter(|(_, o)| o.verdict == verdict) {
        if o.rule_id.is_some() {
            deciding.push(o);
        }
    }
    deciding.sort_by(|a, b| {
        a.rule_id
            .as_deref()
            .unwrap_or("")
            .cmp(b.rule_id.as_deref().unwrap_or(""))
    });
    let mut rule_id_out: Option<String> = None;
    let mut message_out: Option<String> = None;
    if let Some(winner) = deciding.first() {
        rule_id_out = winner.rule_id.clone();
        message_out = winner.message.clone();
    }

    // evidence + wire classification (02 §2.7): complete → static/argv,
    // opaque → opaque/raw, invalid → invalid/raw. Invalid dominates opaque,
    // which dominates complete (08 §8.6). A graph with no participating part
    // but recorded graph reasons (e.g. the empty-command cause) is invalid.
    let participating = |i: usize| !graph.collapsed.contains(&i) && !dead_part(&graph.parts[i]);
    let has_invalid = graph.overflow
        || graph
            .parts
            .iter()
            .enumerate()
            .any(|(i, p)| participating(i) && matches!(p.state, EvidenceState::Invalid(_)))
        || (graph
            .reasons
            .iter()
            .any(|r| super::verdict::is_invalid_cause(r))
            && !graph
                .parts
                .iter()
                .enumerate()
                .any(|(i, _)| participating(i)));
    let has_opaque = graph
        .parts
        .iter()
        .enumerate()
        .any(|(i, p)| participating(i) && matches!(p.state, EvidenceState::Opaque(_)));
    let evidence = if has_invalid {
        EvidenceClass::Invalid
    } else if has_opaque {
        EvidenceClass::Opaque
    } else {
        EvidenceClass::Complete
    };

    // reasons are the stable codes seen in the graph (08 §8.7), aligned with
    // each participating part's evidence STATE: complete parts anchor
    // `complete`, opaque parts anchor `opaque-expansion` (their own reason
    // word, e.g. the depth-limit marker, is informational and never an
    // invalid-cause entry — 02 §2.8 forbids invalid causes under opaque
    // evidence), invalid parts contribute their invalid-cause code. Graph-level
    // causes (e.g. the empty-command marker) are merged verbatim; option parse
    // failures were already collected above.
    // Graph-level causes merge only when they can stay coherent with the
    // command evidence (02 §2.8): invalid-cause codes are meaningful only
    // under invalid evidence — markers attached to non-participating parts
    // (e.g. the split depth limit on a dead substitution part) must not turn
    // an opaque command's reasons incoherent.
    for reason in graph.reasons.iter() {
        if is_invalid_cause(reason) && evidence != EvidenceClass::Invalid {
            continue;
        }
        if !diag.reasons.iter().any(|x| x == reason) {
            diag.reasons.push((*reason).to_string());
        }
    }
    for (i, part) in graph.parts.iter().enumerate() {
        if !participating(i) {
            continue;
        }
        let code = match part.state {
            EvidenceState::Complete => "complete",
            EvidenceState::Opaque(_) => "opaque-expansion",
            EvidenceState::Invalid(code) => code,
        };
        if !diag.reasons.iter().any(|x| x == code) {
            diag.reasons.push(code.to_string());
        }
    }

    let facts = build_facts(config, &diag, evidence);
    (
        CommandVerdict {
            index: cmd.index,
            verdict,
            rule_id: rule_id_out,
            classification: evidence.classification(),
            r#match: evidence.r#match(),
            facts: Some(facts),
        },
        message_out,
    )
}

// ── Per-part rule evaluation ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn evaluate_part_rules(
    config: &Config,
    part: &Part,
    prof: &Profile,
    parsed: &ParsedOptions,
    state: EvidenceState,
    nested: Vec<NestedResult>,
    cwd: &str,
    diag: &mut CmdDiag,
) -> PartOutcome {
    let canonical = canonical_view(parsed);
    let positionals: Vec<ArgToken> = parsed.positionals.clone();
    let path_coords = path_coordinates(prof, parsed, part, state);
    let ctx = PartFacts {
        part,
        profile_id: Some(prof.id.as_str()),
        positionals: &positionals,
        canonical,
        path_coords: &path_coords,
        nested: &nested,
        cwd,
        regexes: &config.regexes,
    };

    // every matching rule is evaluated and emits its vote (monotonicity)
    let mut votes: Vec<(&Rule, VerdictKind)> = Vec::new();
    for rule in &prof.rules {
        match rule.action {
            VerdictKind::Ask | VerdictKind::Deny => {
                if predicate_holds(&rule.r#match, &ctx) {
                    push_unique(&mut diag.matched, rule.id.clone());
                    diag.votes
                        .push(format!("{}:{}", vote_word(rule.action), rule.id));
                    votes.push((rule, rule.action));
                }
            }
            VerdictKind::Allow => {
                push_unique(&mut diag.matched, rule.id.clone());
                let effective =
                    effective_redirect(config, Some(prof), rule.redirect_policy.as_ref());
                match allow_covers(&rule.r#match, &ctx, &effective, cwd) {
                    Ok(()) => {
                        push_unique(&mut diag.qualified, rule.id.clone());
                        diag.votes
                            .push(format!("{}:{}", vote_word(rule.action), rule.id));
                        votes.push((rule, rule.action));
                    }
                    Err(codes) => {
                        diag.rejected.push((
                            rule.id.clone(),
                            codes.iter().map(|c| c.stable_code().to_string()).collect(),
                        ));
                    }
                }
            }
        }
    }

    // reduction: deny > ask > allow over emitted votes; none ⇒ ask
    let winning = votes
        .iter()
        .map(|(_, a)| *a)
        .max_by_key(|a| a.rank())
        .unwrap_or(VerdictKind::Ask);
    if let Some(rule) = votes
        .iter()
        .filter(|(_, a)| *a == winning)
        .map(|(r, _)| *r)
        .min_by(|a, b| a.id.cmp(&b.id))
    {
        return PartOutcome {
            verdict: winning,
            rule_id: Some(rule.id.clone()),
            message: rule.message.clone(),
        };
    }

    // no vote: default ask with fallback hints (lexico-smallest matching id)
    let mut hints: Vec<&super::grammar::Hint> = prof
        .fallback_hints
        .iter()
        .filter(|h| match &h.r#match {
            None => true,
            Some(m) => predicate_holds(m, &ctx),
        })
        .collect();
    hints.sort_by(|a, b| a.id.cmp(&b.id));
    PartOutcome {
        verdict: VerdictKind::Ask,
        rule_id: None,
        message: hints.first().map(|h| h.message.clone()),
    }
}

fn vote_word(v: VerdictKind) -> &'static str {
    match v {
        VerdictKind::Allow => "allow",
        VerdictKind::Ask => "ask",
        VerdictKind::Deny => "deny",
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

// ── Views ───────────────────────────────────────────────────────────────────

fn canonical_view(
    parsed: &ParsedOptions,
) -> std::collections::BTreeMap<String, Vec<OptionOccurrenceView>> {
    let mut map: std::collections::BTreeMap<String, Vec<OptionOccurrenceView>> =
        std::collections::BTreeMap::new();
    for occ in &parsed.occurrences {
        map.entry(occ.canonical.clone())
            .or_default()
            .push(OptionOccurrenceView {
                ordinal: occ.ordinal,
                values: occ
                    .values
                    .iter()
                    .map(|v| (v.text.clone(), v.resolvable))
                    .collect(),
            });
    }
    map
}

/// Produce actual per-occurrence path coordinates from the profile's
/// `pathSources` declarations (design §Closed evidence catalogs): redirect
/// coordinates never appear here — the redirect policy covers those.
fn path_coordinates(
    prof: &Profile,
    parsed: &ParsedOptions,
    part: &Part,
    _state: EvidenceState,
) -> Vec<PathCoordinateObs> {
    let mut out: Vec<PathCoordinateObs> = Vec::new();
    let push =
        |tag: PathSourceTag, path: String, resolvable: bool, out: &mut Vec<PathCoordinateObs>| {
            let obs = PathCoordinateObs {
                source: tag,
                path,
                resolvable,
            };
            if !out.contains(&obs) {
                out.push(obs);
            }
        };
    for sel in &prof.path_sources {
        if let Some(pc) = &sel.argument {
            // `{index}` selects that one positional; `{index, remainder: true}`
            // selects the positionals from the index onwards (inclusive).
            let (start, remainder) = (pc.index, pc.remainder);
            let positionals: Vec<(u32, &ArgToken)> = if remainder {
                parsed
                    .positionals
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| *k as u32 >= start)
                    .map(|(k, t)| (k as u32, t))
                    .collect()
            } else if (start as usize) < parsed.positionals.len() {
                vec![(start, &parsed.positionals[start as usize])]
            } else {
                Vec::new()
            };
            for (k, tok) in positionals {
                push(
                    PathSourceTag::Argument { index: k },
                    tok.text.clone(),
                    tok.resolvable,
                    &mut out,
                );
            }
        }
        if let Some(ov) = &sel.option_value {
            for occ in &parsed.occurrences {
                if occ.canonical != ov.option {
                    continue;
                }
                if let Some(osel) = &ov.occurrence
                    && !osel.selects(occ.ordinal)
                {
                    continue;
                }
                // `valueOrdinal` selects exactly that 1-based value ordinal
                for (k, v) in occ.values.iter().enumerate() {
                    if ov.value_ordinal != k as u32 + 1 {
                        continue;
                    }
                    push(
                        PathSourceTag::OptionValue {
                            canonical: occ.canonical.clone(),
                            occurrence: occ.ordinal,
                            value_ordinal: k as u32 + 1,
                        },
                        v.text.clone(),
                        v.resolvable,
                        &mut out,
                    );
                }
            }
        }
        // the environment coordinate selects only the occurrences it names
        // (1-based assignment ordinals), not every assignment
        if let Some(env) = &sel.environment {
            for (k, a) in part.assigns.iter().enumerate() {
                if let Some(osel) = &env.occurrence
                    && !osel.selects(k as u32 + 1)
                {
                    continue;
                }
                let value = match a.text.split_once('=') {
                    Some((_, v)) => v.to_string(),
                    None => String::new(),
                };
                push(
                    PathSourceTag::Environment {
                        occurrence: k as u32 + 1,
                    },
                    value,
                    a.resolvable,
                    &mut out,
                );
            }
        }
        if let Some(fc) = &sel.analyzer_fact {
            for f in &part.facts {
                if f.fact_name != fc.name {
                    continue;
                }
                if let Some(osel) = &fc.occurrence
                    && !osel.selects(f.occurrence)
                {
                    continue;
                }
                push(
                    PathSourceTag::AnalyzerFact {
                        analyzer: f.analyzer_id,
                        name: f.fact_name.clone(),
                        occurrence: f.occurrence,
                    },
                    f.value.clone(),
                    !f.value.is_empty() && !f.value.contains('\u{fffd}'),
                    &mut out,
                );
            }
        }
    }
    out
}

fn occurred_canonicals(parsed: &ParsedOptions) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for occ in &parsed.occurrences {
        if !out.contains(&occ.canonical) {
            out.push(occ.canonical.clone());
        }
    }
    out
}

// ── Graph helpers ───────────────────────────────────────────────────────────

/// Option parsing starts after the executable head token. Empty argv keeps
/// the (empty) whole list.
fn argv_for_options(argv: &[ArgToken]) -> &[ArgToken] {
    if argv.is_empty() { argv } else { &argv[1..] }
}

fn select_profile_index(config: &Config, part: &Part) -> Option<usize> {
    let head = part.argv.first()?;
    if !head.resolvable {
        return None;
    }
    config
        .profiles()
        .iter()
        .position(|p| p.executables.iter().any(|e| e == &head.text))
}

fn dead_part(part: &Part) -> bool {
    part.argv.is_empty() && part.redirects.is_empty()
}

/// xargs-v1: the operand child of an `xargs` part becomes an
/// `analyzerCommand` part when the selected profile runs that analyzer.
fn relabel_xargs_children(config: &Config, graph: &mut CommandGraph) {
    let mut targets: Vec<usize> = Vec::new();
    for (i, part) in graph.parts.iter().enumerate() {
        let Some(pi) = select_profile_index(config, part) else {
            continue;
        };
        let prof = &config.profiles()[pi];
        if prof.analyzer != Some(AnalyzerId::XargsV1) {
            continue;
        }
        if part
            .argv
            .first()
            .map(|t| t.text.as_str() == "xargs" && t.resolvable)
            .unwrap_or(false)
        {
            targets.push(i);
        }
    }
    for i in targets {
        for c in graph.parts.iter_mut() {
            if c.parent == Some(i) {
                c.relation = Relation::AnalyzerCommand;
            }
        }
    }
}

type CommandGraph = super::evidence::CommandEvidence;

/// Reduced results of the direct children (nested parts) of parent `i`.
fn nested_results(
    graph: &CommandGraph,
    i: usize,
    selections: &[Option<usize>],
    reduced: &std::collections::BTreeMap<usize, (VerdictKind, EvidenceState)>,
    config: &Config,
) -> Vec<NestedResult> {
    graph
        .parts
        .iter()
        .filter(|c| c.parent == Some(i))
        .filter(|c| !dead_part(c) && !graph.collapsed.contains(&c.id))
        .map(|c| {
            let profile_id = selections
                .get(c.id)
                .and_then(|s| *s)
                .map(|pi| config.profiles()[pi].id.clone());
            NestedResult {
                part_id: c.id,
                relation: c.relation,
                relation_ordinal: c.relation_ordinal,
                executable: c
                    .argv
                    .first()
                    .and_then(|t| t.resolvable.then(|| t.text.clone())),
                profile_id,
                analyzer: if c.relation == Relation::AnalyzerCommand {
                    Some(AnalyzerId::XargsV1.id())
                } else {
                    None
                },
                state: reduced.get(&c.id).map(|r| r.1).unwrap_or(c.state),
                verdict: reduced.get(&c.id).map(|r| r.0).unwrap_or(VerdictKind::Ask),
            }
        })
        .collect()
}

// ── Redirect policy resolution (structural, order-free) ─────────────────────

type Bundle = (Vec<RedirectEntry>, Vec<super::grammar::PathEntry>);

/// Config default → profile override → allow-rule override. `extend` =
/// set union; `replace` = discard inherited permissive entries; `inherit`
/// keeps the current effective policy. Reordering never changes meaning.
pub(super) fn effective_redirect(
    config: &Config,
    profile: Option<&Profile>,
    rule_override: Option<&RedirectPolicyOverride>,
) -> RedirectPolicy {
    let base_name: &str = &config.defaults_redirect_policy;
    let mut bundle = named_entries(config, base_name);
    for ov in [
        profile.and_then(|p| p.redirect_policy.as_ref()),
        rule_override,
    ]
    .into_iter()
    .flatten()
    {
        let additions = addition_entries(config, ov);
        match ov.mode {
            OverrideMode::Inherit => {}
            OverrideMode::Extend => {
                bundle.0.extend(additions.0);
                bundle.1.extend(additions.1);
                normalize(&mut bundle.0, &mut bundle.1);
            }
            OverrideMode::Replace => {
                bundle = additions;
                normalize(&mut bundle.0, &mut bundle.1);
            }
        }
    }
    RedirectPolicy {
        redirects: to_redirect_coverage(&bundle.0),
        paths: to_path_coverage(&bundle.1),
    }
}

fn named_entries(config: &Config, id: &str) -> Bundle {
    match config.redirect_policies().get(id) {
        Some(p) => bundle_of(p),
        None => (Vec::new(), Vec::new()),
    }
}

fn bundle_of(p: &RedirectPolicy) -> Bundle {
    let redirects = match &p.redirects {
        RedirectCoverage::All { all } => all.clone(),
        RedirectCoverage::None { .. } => Vec::new(),
    };
    let paths = match &p.paths {
        PathCoverage::All { all } => all.clone(),
        PathCoverage::None { .. } => Vec::new(),
    };
    (redirects, paths)
}

fn addition_entries(config: &Config, ov: &RedirectPolicyOverride) -> Bundle {
    let mut out = (Vec::new(), Vec::new());
    if let Some(ids) = &ov.policies {
        for id in ids {
            let b = named_entries(config, id);
            out.0.extend(b.0);
            out.1.extend(b.1);
        }
    }
    if let Some(inline) = &ov.inline {
        let b = bundle_of(inline);
        out.0.extend(b.0);
        out.1.extend(b.1);
    }
    out
}

fn normalize(redirects: &mut Vec<RedirectEntry>, paths: &mut Vec<super::grammar::PathEntry>) {
    redirects.sort_by_key(redir_sort_key);
    redirects.dedup();
    paths.sort_by_key(path_sort_key);
    paths.dedup();
}

fn redir_sort_key(e: &RedirectEntry) -> Vec<u8> {
    format!(
        "{:?}|{:?}|{:?}|{:?}",
        e.source_fd, e.operator, e.occurrence, e.target.kind
    )
    .into_bytes()
}

fn path_sort_key(e: &super::grammar::PathEntry) -> Vec<u8> {
    format!("{:?}|{:?}", e.coordinate, e.policy()).into_bytes()
}

fn to_redirect_coverage(entries: &[RedirectEntry]) -> RedirectCoverage {
    if entries.is_empty() {
        RedirectCoverage::None { none: true }
    } else {
        RedirectCoverage::All {
            all: entries.to_vec(),
        }
    }
}

fn to_path_coverage(entries: &[super::grammar::PathEntry]) -> PathCoverage {
    if entries.is_empty() {
        PathCoverage::None { none: true }
    } else {
        PathCoverage::All {
            all: entries.to_vec(),
        }
    }
}

// ── Diagnostics (bounded only after the decision is computed) ────────────────

/// Canonical diagnostics per 08 §8.7: reasons sorted and deduplicated with the
/// required evidence anchor, matched/qualified sorted and deduplicated,
/// rejected grouped into one entry per rule ID with sorted coverage reasons,
/// votes in evaluation order. Truncation only after the full shape misses the
/// `diagnosticsBytes` cap, keeping the deterministic evidence anchor.
fn build_facts(config: &Config, diag: &CmdDiag, evidence: EvidenceClass) -> Diagnostics {
    let mut reasons = diag.reasons.clone();
    let anchor = evidence.reason_anchor();
    if !anchor.is_empty() && !reasons.iter().any(|r| r == anchor) {
        reasons.push(anchor.to_string());
    }
    let reasons = sorted_unique(&reasons);
    let full = FullDiagnostics {
        evidence: evidence.as_str(),
        reasons: reasons.clone(),
        selected_profiles: diag.selected_profiles.clone(),
        matched: sorted_unique(&diag.matched),
        qualified: sorted_unique(&diag.qualified),
        rejected: canonical_rejected(&diag.rejected),
        votes: diag.votes.clone(),
    };
    let cap = config.limits().diagnostics_bytes as usize;
    if serde_json::to_vec(&full)
        .map(|b| b.len())
        .unwrap_or(usize::MAX)
        <= cap
    {
        return Diagnostics::Full(full);
    }
    Diagnostics::Truncated(TruncatedDiagnostics {
        evidence: evidence.as_str(),
        reasons: select_truncated_reasons(evidence, &reasons)
            .unwrap_or_else(|_| reasons.into_iter().take(8).collect()),
        diagnostics: super::verdict::TRUNCATED_MARKER,
    })
}

/// One canonical entry per rejected allow rule ID (08 §8.7): group findings by
/// rule, deduplicate and sort each entry's coverage reasons by UTF-8 bytes.
fn canonical_rejected(rejected: &[(String, Vec<String>)]) -> Vec<RejectedAllow> {
    let mut by_rule: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (rule_id, codes) in rejected {
        by_rule
            .entry(rule_id.clone())
            .or_default()
            .extend(codes.iter().cloned());
    }
    by_rule
        .into_iter()
        .map(|(rule_id, codes)| RejectedAllow {
            rule_id,
            reasons: sorted_unique(&codes),
        })
        .collect()
}
