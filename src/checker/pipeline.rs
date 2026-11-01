// Decision pipeline (08-request-processing.md): scope entry → rule vote →
// refinement (08 §8.3, per part and stage) → reduction (first deny final;
// else most-restrictive with the first surviving ask in config order →
// per-command aggregate → letter aggregate + message composition (§8.5).

use super::config::Config;
use super::grammar::{Classification, Rule, VerdictKind};
use super::letter::{Command, Letter};
use super::refine::refines;
use super::split::Part;
use super::verdict::{CommandVerdict, MatchKind, Verdict};

pub fn evaluate(config: &Config, letter: &Letter) -> Verdict {
    // per-command verdicts + the letter-level decision messages in one pass
    let mut commands = Vec::new();
    let mut outcome_messages: Vec<(VerdictKind, Option<String>)> = Vec::new();
    for cmd in &letter.commands {
        let (v, msg) = command_verdict(config, cmd, letter);
        outcome_messages.push((v.verdict, msg));
        commands.push(v);
    }

    // Letter aggregate (08 §8.4–8.5): most-restrictive across commands; message
    // from the most-restrictive deciding command — the first explicit rule
    // message among them, else defaults.message.
    let aggregate = commands
        .iter()
        .map(|c| c.verdict)
        .max_by_key(|v| v.rank())
        .unwrap_or(VerdictKind::Ask);
    let explicit = outcome_messages
        .iter()
        .filter(|(v, _)| *v == aggregate)
        .map(|(_, m)| m.clone())
        .find(|m| m.is_some())
        .flatten();
    let message = explicit.or_else(|| {
        (aggregate != VerdictKind::Allow)
            .then(|| config.defaults.message.clone())
            .flatten()
    });

    Verdict {
        invocation_id: letter.invocation.id.clone(),
        verdict: aggregate,
        message: message.filter(|_| aggregate != VerdictKind::Allow),
        commands,
    }
}

struct CommandOutcome {
    /// message for the letter-level aggregate (not serialized per command).
    message_for_aggregate: Option<String>,
    verdict: VerdictKind,
    rule_id: Option<String>,
    match_kind: MatchKind,
    static_command: bool,
    facts: Option<serde_json::Value>,
}

fn command_verdict(
    config: &Config,
    cmd: &Command,
    letter: &Letter,
) -> (CommandVerdict, Option<String>) {
    let parts = super::split::split(&cmd.raw, 0);
    let outcome = reduce_parts(config, &parts, cmd, letter);
    let class = if outcome.static_command {
        Classification::Static
    } else {
        Classification::Opaque
    };
    (
        CommandVerdict {
            index: cmd.index,
            verdict: outcome.verdict,
            rule_id: outcome.rule_id,
            classification: class,
            r#match: outcome.match_kind,
            facts: outcome.facts,
        },
        outcome.message_for_aggregate,
    )
}

fn reduce_parts(config: &Config, parts: &[Part], cmd: &Command, letter: &Letter) -> CommandOutcome {
    let mut static_all = true;
    let mut best: Option<PartDecision> = None;
    for part in parts {
        let d = part_decision(config, part, cmd, letter);
        static_all &= d.static_part;
        // strictly more restrictive replaces the incumbent (ties: scan order)
        if best
            .as_ref()
            .map(|b| d.verdict.rank() > b.verdict.rank())
            .unwrap_or(true)
        {
            best = Some(d);
        }
    }
    if cmd_is_empty(parts) {
        return CommandOutcome {
            verdict: VerdictKind::Ask,
            rule_id: None,
            message_for_aggregate: config.defaults.message.clone(),
            match_kind: MatchKind::Argv,
            static_command: static_all,
            facts: None,
        };
    }
    best.map(|d| CommandOutcome {
        verdict: d.verdict,
        rule_id: Some(d.rule_id.clone()),
        message_for_aggregate: d.message.clone(),
        match_kind: d.kind_of(),
        static_command: static_all,
        facts: Some(d.facts),
    })
    .unwrap_or(CommandOutcome {
        verdict: VerdictKind::Ask,
        rule_id: None,
        message_for_aggregate: config.defaults.message.clone(),
        match_kind: MatchKind::Argv,
        static_command: static_all,
        facts: None,
    })
}

fn cmd_is_empty(parts: &[Part]) -> bool {
    parts.len() == 1 && parts[0].argv.is_empty() && parts[0].opaque_reason.is_some()
}

/// Per-part pipeline (08 §8.1–8.4).
fn part_decision(config: &Config, part: &Part, cmd: &Command, letter: &Letter) -> PartDecision {
    let static_part = part.classification_static();
    let mut votes: Vec<(usize, &Rule)> = Vec::new(); // (stage index, rule)

    for (idx, stage) in config.stages.iter().enumerate() {
        let flags = super::matcher::flags_of(&part.argv, &stage.flags);
        // scope entry with anchor: rules match the stage tail (post-scope argv)
        let anchor = super::matcher::stage_anchor(stage, &flags.cleaned_argv, &part.raw);
        if anchor == usize::MAX {
            continue;
        }
        let tail: Vec<String> = flags.cleaned_argv[anchor.min(flags.cleaned_argv.len())..].to_vec();
        let ctx = super::matcher::MatchCtx {
            cleaned_argv: &tail,
            raw: &part.raw,
            fully_parsed: flags.fully_parsed,
            static_part,
            flags: &flags,
            paths_evidence: &part.paths,
            project_dir: letter.invocation.project_dir.as_deref(),
            cwd: &cmd.cwd,
        };
        for rule in &stage.rules {
            if rule.action == VerdictKind::Allow && !static_part {
                continue; // opaque ⇒ allow inert (I10)
            }
            if rule.action == VerdictKind::Allow && !flags.fully_parsed {
                continue; // unknown flag ⇒ not fully parsed ⇒ no allow (08 §8.2)
            }
            if super::matcher::rule_matches(rule, &ctx) {
                votes.push((idx, rule));
                if rule.action == VerdictKind::Deny {
                    break; // the first deny is final (08 §8.2)
                }
            }
        }
        if votes.iter().any(|(_, r)| r.action == VerdictKind::Deny) {
            break;
        }
    }

    // Refinement prune (08 §8.3): absent denies; within each stage group.
    let survivors: Vec<(usize, &Rule)> = if votes.iter().any(|(_, r)| r.action == VerdictKind::Deny)
    {
        votes
    } else {
        prune(votes)
    };

    if let Some((_, r)) = survivors
        .iter()
        .find(|(_, r)| r.action == VerdictKind::Deny)
    {
        return decided(r, static_part, part);
    }
    if let Some((_, r)) = survivors.iter().find(|(_, r)| r.action == VerdictKind::Ask) {
        return decided(r, static_part, part);
    }
    if let Some((_, r)) = survivors
        .iter()
        .find(|(_, r)| r.action == VerdictKind::Allow)
    {
        return decided(r, static_part, part);
    }
    // nothing decided: defaults action (always ask, 06 §6.2); match kind
    // follows the evidence actually available (raw when opaque)
    PartDecision {
        verdict: VerdictKind::Ask,
        rule_id: "no-rule".into(),
        message: config.defaults.message.clone(),
        evidence_argv: static_part,
        facts: part_facts(part, static_part),
        static_part,
    }
}

/// Keep matched rules not strictly refined by any other matched rule of the
/// same stage (same stage index only, 08 §8.3).
fn prune(votes: Vec<(usize, &Rule)>) -> Vec<(usize, &Rule)> {
    votes
        .iter()
        .filter(|(si, r)| {
            !votes
                .iter()
                .any(|(sj, rj)| sj == si && rj.id != r.id && refines(rj, r))
        })
        .cloned()
        .collect()
}

fn decided(rule: &Rule, static_part: bool, part: &Part) -> PartDecision {
    let argv_match = rule.pattern.is_none() && static_part;
    PartDecision {
        verdict: rule.action,
        rule_id: rule.id.clone(),
        message: rule.message.clone(),
        evidence_argv: argv_match,
        facts: part_facts(part, argv_match),
        static_part,
    }
}

fn part_facts(part: &Part, argv_match: bool) -> serde_json::Value {
    let mut facts = serde_json::json!({ "argv": part.argv });
    if !argv_match {
        facts["match"] = serde_json::json!("raw");
    }
    if !part.unknown_texts.is_empty() {
        facts["unresolvable"] = serde_json::json!(part.unknown_texts);
    }
    if !part.assigns.is_empty() {
        facts["envPrefix"] = serde_json::json!(part.assigns);
    }
    if !part.paths.is_empty() {
        facts["paths"] = serde_json::json!(part.paths);
    }
    facts
}

struct PartDecision {
    verdict: VerdictKind,
    rule_id: String,
    message: Option<String>,
    /// decided on fully parsed (argv) evidence rather than raw pattern.
    evidence_argv: bool,
    facts: serde_json::Value,
    static_part: bool,
}

impl PartDecision {
    fn kind_of(&self) -> MatchKind {
        if self.evidence_argv {
            MatchKind::Argv
        } else {
            MatchKind::Raw
        }
    }
}
