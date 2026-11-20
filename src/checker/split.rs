// Recursive executable-part extraction (07 §7.2 + design/shell-warden-config-
// v2.md §Parsing). The checker's own split — never trusts the harness: each
// letter command is always scanned from its raw string. Every part retains
// raw text, span/class evidence, parent ID, relation and relation ordinal.
//
// The closed relation enum (grammar::Relation):
//   chain — operator-bounded executable segments;
//   pipeline — segment following `|`;
//   wrapper — transparent interpreter unwrap (bash/sh -c, sudo, nohup, nice,
//             timeout, env);
//   commandSubstitution — inner text of `$(…)`, backticks and process
//             substitution, split recursively;
//   analyzerCommand — parts emitted by an analyzer (xargs-v1 operand).

use super::evidence::{
    ArgToken, CommandEvidence, EnvAssign, EvidenceState, Part, RedirectObs, reason,
};
use super::grammar::Relation;
use super::parse::{self, Operator, RawRedirOp, TokKind};

pub const MAX_SPLIT_DEPTH: usize = 32;

/// Extract the complete part/evidence graph for one raw command.
pub fn extract(raw: &str) -> CommandEvidence {
    if raw.trim().is_empty() {
        return CommandEvidence {
            parts: Vec::new(),
            reasons: vec![reason::EMPTY_COMMAND],
            overflow: false,
            collapsed: Vec::new(),
        };
    }
    let mut graph = CommandEvidence {
        parts: Vec::new(),
        reasons: Vec::new(),
        overflow: false,
        collapsed: Vec::new(),
    };
    extract_raw(raw, 0, Relation::Chain, 0, None, &mut graph);
    graph
}

fn extract_raw(
    raw: &str,
    depth: usize,
    relation: Relation,
    _ordinal: u32,
    parent: Option<usize>,
    graph: &mut CommandEvidence,
) {
    if depth > MAX_SPLIT_DEPTH {
        // 07 §7.2: retain current-level evidence so invalid ask/deny rules
        // can still identify the executable, but never recurse past the cap.
        let scanned = parse::scan(raw);
        for seg in &scanned.segments {
            let (assigns, mut argv, redirects, _) = segment_observations(seg);
            retain_overflow_marker(seg, &mut argv, &redirects);
            let part_relation = if scanned.malformed || seg.heredoc {
                relation
            } else {
                segment_relation(seg, relation)
            };
            let ordinal = next_ordinal(graph, part_relation, parent);
            push_part(
                seg.raw.trim().to_string(),
                part_relation,
                ordinal,
                parent,
                assigns,
                argv,
                redirects,
                EvidenceState::Invalid(reason::EVIDENCE_LIMIT),
                None,
                graph,
            );
        }
        return;
    }
    let scanned = parse::scan(raw);
    for seg in &scanned.segments {
        if scanned.malformed || seg.heredoc {
            split_heredoc_like(
                seg,
                relation,
                next_ordinal(graph, relation, parent),
                parent,
                depth,
                graph,
            );
            continue;
        }
        let seg_relation = segment_relation(seg, relation);
        let (assigns, argv, redirects, _) = segment_observations(seg);
        let state = observations_state(&assigns, &argv, &redirects);
        let ordinal = next_ordinal(graph, seg_relation, parent);
        // Record the owner first so every executable child has a real parent
        // and a larger ID. Reverse-ID evaluation still reduces children first.
        let (part_id, _) = push_part(
            seg.raw.trim().to_string(),
            seg_relation,
            ordinal,
            parent,
            assigns,
            argv,
            redirects,
            state,
            None,
            graph,
        );
        for (inner, _span) in seg
            .items
            .iter()
            .filter_map(|it| match it {
                parse::Item::Tok(t) if !t.subtexts.is_empty() => Some(t.subtexts.clone()),
                _ => None,
            })
            .flatten()
            .chain(
                seg.redirects
                    .iter()
                    .flat_map(|redirect| redirect.target.subtexts.clone()),
            )
        {
            extract_raw(
                inner.trim(),
                depth + 1,
                Relation::CommandSubstitution,
                next_ordinal(graph, Relation::CommandSubstitution, Some(part_id)),
                Some(part_id),
                graph,
            );
        }

        // wrapper unwrap turns transparent interpreters into child parts
        let part = graph.parts[part_id].clone();
        unwrap_wrapper(part, part_id, depth, graph);
    }
}

fn segment_relation(seg: &parse::Segment, inherited: Relation) -> Relation {
    if inherited != Relation::Chain {
        return inherited;
    }
    match seg.sep {
        Some(Operator::Pipe) => Relation::Pipeline,
        _ => Relation::Chain,
    }
}

fn segment_observations(
    seg: &parse::Segment,
) -> (Vec<EnvAssign>, Vec<ArgToken>, Vec<RedirectObs>, bool) {
    let mut assigns: Vec<EnvAssign> = Vec::new();
    let mut argv: Vec<ArgToken> = Vec::new();
    let mut unresolvable = false;
    let mut declaration_head = false;
    for tok in seg.items.iter().filter_map(|it| match it {
        parse::Item::Tok(t) if t.kind == TokKind::Word => Some(t),
        _ => None,
    }) {
        if !tok.resolvable {
            unresolvable = true;
        }
        let destination = tok
            .source
            .split_once('=')
            .map(|(name, _)| name)
            .filter(|name| super::parameter::is_name(name))
            .or_else(|| {
                (declaration_head && argv.len() == 1 && tok.resolvable)
                    .then(|| tok.text.split_once('=').map(|(name, _)| name))
                    .flatten()
                    .filter(|name| super::parameter::is_name(name))
            });
        let prefix = argv.is_empty();
        let declaration = argv.len() == 1 && declaration_head;
        if (prefix || declaration) && destination.is_some_and(super::parameter::is_name) {
            let name = destination.unwrap().to_string();
            assigns.push(EnvAssign {
                name,
                parameter: tok.assignment_parameter().map(|(_, value)| value),
                prefix,
                text: tok.text.clone(),
                resolvable: tok.resolvable,
                span: tok.span,
                ordinal: (assigns.len() + 1) as u32,
            });
            continue;
        }
        if argv.is_empty() {
            declaration_head = tok.source == "export";
        }
        argv.push(ArgToken {
            text: tok.text.clone(),
            parameter: tok.parameter(),
            resolvable: tok.resolvable,
            span: tok.span,
        });
    }

    let redirects: Vec<RedirectObs> = seg
        .redirects
        .iter()
        .enumerate()
        .map(|(index, redirect)| RedirectObs {
            op: match redirect.op {
                RawRedirOp::Supported(op) => Some(op),
                RawRedirOp::Unsupported => None,
            },
            source_fd: redirect.source_fd,
            target: redirect.target.text.clone(),
            parameter: match redirect.op {
                RawRedirOp::Supported(
                    super::grammar::RedirectOp::Out | super::grammar::RedirectOp::AppendOut,
                ) => redirect.target.parameter(),
                _ => None,
            },
            target_resolvable: redirect.target.resolvable,
            is_fd_target: matches!(
                redirect.op,
                RawRedirOp::Supported(
                    super::grammar::RedirectOp::DupOut | super::grammar::RedirectOp::DupIn
                )
            ) && redirect.target.is_fd_operand(),
            span: redirect.span,
            ordinal: index as u32 + 1,
        })
        .collect();
    unresolvable |= redirects.iter().any(|redirect| !redirect.target_resolvable);

    (assigns, argv, redirects, unresolvable)
}

fn observations_state(
    assigns: &[EnvAssign],
    argv: &[ArgToken],
    redirects: &[RedirectObs],
) -> EvidenceState {
    if redirects.iter().any(|r| r.op.is_none()) {
        return EvidenceState::Invalid(reason::UNSUPPORTED_SYNTAX);
    }
    let opaque = argv.iter().any(|a| !a.resolvable && a.parameter.is_none())
        || assigns
            .iter()
            .any(|a| !a.resolvable && a.parameter.is_none())
        || redirects
            .iter()
            .any(|r| !r.target_resolvable && r.parameter.is_none())
        || argv.first().is_some_and(|a| !a.resolvable);
    let parameter = argv.iter().any(|a| a.parameter.is_some())
        || assigns.iter().any(|a| a.parameter.is_some())
        || redirects.iter().any(|r| r.parameter.is_some());
    // Unknown wrapper/interpreter operands are not ordinary positional values.
    // Basenames only broaden this blocking check, not transparent unwrapping.
    let wrapper = parameter
        && argv
            .first()
            .is_some_and(|a| match a.text.rsplit('/').next().unwrap_or(&a.text) {
                "bash" | "sh" => argv.iter().skip(1).any(|a| !a.resolvable),
                "sudo" | "nohup" | "nice" | "timeout" | "env" | "xargs" => true,
                _ => false,
            });
    let dynamic_code_or_destination = argv.first().is_some_and(|head| {
        let name = head.text.rsplit('/').next().unwrap_or(&head.text);
        matches!(
            name,
            "export"
                | "eval"
                | "exec"
                | "command"
                | "builtin"
                | "source"
                | "."
                | "bash"
                | "sh"
                | "node"
                | "nodejs"
                | "python"
                | "python2"
                | "python3"
                | "perl"
                | "awk"
                | "ruby"
                | "php"
                | "lua"
                | "Rscript"
                | "deno"
                | "bun"
        ) && argv.iter().skip(1).any(|a| !a.resolvable)
    });
    if opaque || wrapper || dynamic_code_or_destination {
        EvidenceState::Opaque(reason::OPAQUE_EXPANSION)
    } else if parameter {
        EvidenceState::Parameter
    } else {
        EvidenceState::Complete
    }
}

fn retain_overflow_marker(
    seg: &parse::Segment,
    argv: &mut Vec<ArgToken>,
    redirects: &[RedirectObs],
) {
    if argv.is_empty() && redirects.is_empty() {
        argv.push(ArgToken {
            parameter: None,
            text: seg.raw.trim().to_string(),
            resolvable: false,
            span: seg.span,
        });
    }
}

fn state_at_depth(depth: usize, state: EvidenceState) -> EvidenceState {
    if depth > MAX_SPLIT_DEPTH {
        EvidenceState::Invalid(reason::EVIDENCE_LIMIT)
    } else {
        state
    }
}

fn split_heredoc_like(
    seg: &parse::Segment,
    relation: Relation,
    ordinal: u32,
    parent: Option<usize>,
    depth: usize,
    graph: &mut CommandEvidence,
) {
    // heredoc/here-string and malformed structure: invalid, but keep argv so
    // deny/ask still match the typed classification / raw text.
    let mut assigns: Vec<EnvAssign> = Vec::new();
    let mut argv: Vec<ArgToken> = Vec::new();
    let mut unresolvable = false;
    for tok in seg.items.iter().filter_map(|it| match it {
        parse::Item::Tok(t) if t.kind == TokKind::Word => Some(t),
        _ => None,
    }) {
        if !tok.resolvable {
            unresolvable = true;
        }
        if argv.is_empty() && assigns.is_empty() && is_assignment(&tok.text) {
            let name = tok.text[..tok.text.find('=').unwrap_or(0)].to_string();
            assigns.push(EnvAssign {
                name,
                parameter: None,
                prefix: true,
                text: tok.text.clone(),
                resolvable: tok.resolvable,
                span: tok.span,
                ordinal: (assigns.len() + 1) as u32,
            });
            continue;
        }
        argv.push(ArgToken {
            text: tok.text.clone(),
            parameter: None,
            resolvable: tok.resolvable,
            span: tok.span,
        });
    }
    let state = EvidenceState::Invalid(reason::UNSUPPORTED_SYNTAX);
    let _ = unresolvable;
    let (part_id, _) = push_part(
        seg.raw.trim().to_string(),
        relation,
        ordinal,
        parent,
        assigns,
        argv,
        Vec::new(),
        state,
        None,
        graph,
    );
    let part = graph.parts[part_id].clone();
    unwrap_wrapper(part, part_id, depth, graph);
}

#[allow(clippy::too_many_arguments)]
fn push_part(
    raw: String,
    relation: Relation,
    ordinal: u32,
    parent: Option<usize>,
    assigns: Vec<EnvAssign>,
    argv: Vec<ArgToken>,
    redirects: Vec<RedirectObs>,
    state: EvidenceState,
    dashdash: Option<usize>,
    graph: &mut CommandEvidence,
) -> (usize, bool) {
    let id = graph.parts.len();
    let truncated = graph.overflow;
    graph.parts.push(Part {
        id,
        parent,
        relation,
        relation_ordinal: ordinal,
        raw,
        assigns,
        argv: if truncated { Vec::new() } else { argv },
        redirects: if truncated { Vec::new() } else { redirects },
        facts: Vec::new(),
        state,
        dashdash,
    });
    if !truncated && state.stable_code() != reason::OPAQUE_EXPANSION {
        graph.reasons.push(state.stable_code());
    }
    (id, truncated)
}

/// One-based per-relation occurrence ordinal (design §Selector semantics:
/// occurrence ordinals are one-based): the first part emitted with this
/// (relation, parent) pair carries ordinal 1.
fn next_ordinal(graph: &CommandEvidence, relation: Relation, parent: Option<usize>) -> u32 {
    graph
        .parts
        .iter()
        .filter(|p| p.relation == relation && p.parent == parent)
        .count() as u32
        + 1
}

fn is_assignment(w: &str) -> bool {
    match w.find('=') {
        None => false,
        Some(0) => false,
        Some(eq) => {
            let name = &w[..eq];
            name.chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

// ── Wrapper unwrapping (07 §7.2 step 2) ─────────────────────────────────────

/// Wrapper interpretations unwrap into child parts (relation `wrapper`).
/// `xargs` keeps its operand as an opaque child (stdiн-appended args are
/// unconstrained); the xargs-v1 analyzer re-exposes it as analyzerCommand.
fn unwrap_wrapper(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let head = part
        .argv
        .first()
        .filter(|a| a.resolvable)
        .map(|a| a.text.clone());
    if matches!(head.as_deref(), Some("bash" | "sh"))
        && !matches!(part.state, EvidenceState::Invalid(_))
    {
        unwrap_bash(part, part_id, depth, graph);
        return;
    }
    if !matches!(part.state, EvidenceState::Invalid(_)) {
        match head.as_deref() {
            Some("sudo") => unwrap_transparent(
                part,
                part_id,
                depth,
                graph,
                reason::OPAQUE_EXPANSION,
                "sudo without command",
            ),
            Some("nohup") => unwrap_transparent(
                part,
                part_id,
                depth,
                graph,
                reason::OPAQUE_EXPANSION,
                "nohup without command",
            ),
            Some("nice") => unwrap_nice(part, part_id, depth, graph),
            Some("timeout") => unwrap_timeout(part, part_id, depth, graph),
            Some("env") => unwrap_env(part, part_id, depth, graph),
            Some("xargs") => unwrap_xargs(part, part_id, depth, graph),
            _ => {}
        }
    }
}

fn emit_wrapped(
    part: &Part,
    part_id: usize,
    rest: Vec<ArgToken>,
    transparent: bool,
    depth: usize,
    graph: &mut CommandEvidence,
) {
    if rest
        .first()
        .is_none_or(|head| !head.resolvable || head.text.starts_with('-'))
    {
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
        return;
    }
    let child_depth = depth + 1;
    let state = observations_state(&part.assigns, &rest, &part.redirects);
    let child_id = emit_child(
        part_id,
        part.raw.clone(),
        part.assigns.clone(),
        rest,
        part.redirects.clone(),
        state_at_depth(child_depth, state),
        graph,
    );
    if transparent && part.state == EvidenceState::Complete {
        collapse(part_id, graph);
    } else {
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
    }
    if child_depth <= MAX_SPLIT_DEPTH {
        let child = graph.parts[child_id].clone();
        unwrap_wrapper(child, child_id, child_depth, graph);
    }
}

/// Children of a wrapper part: fresh parts under the wrapper's ID with the
/// wrapper relation and their own occurrence ordinals.
fn emit_child(
    wrapper_id: usize,
    raw: String,
    assigns: Vec<EnvAssign>,
    argv: Vec<ArgToken>,
    redirects: Vec<RedirectObs>,
    state: EvidenceState,
    graph: &mut CommandEvidence,
) -> usize {
    let relation = Relation::Wrapper;
    let ordinal = next_ordinal(graph, relation, Some(wrapper_id));
    push_part(
        raw,
        relation,
        ordinal,
        Some(wrapper_id),
        assigns,
        argv,
        redirects,
        state,
        None,
        graph,
    )
    .0
}

fn unwrap_bash(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let pos = match part
        .argv
        .iter()
        .position(|w| w.resolvable && w.text == "-c")
    {
        Some(p) => p,
        None => {
            graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
            return;
        }
    };
    let Some(operand) = part.argv.get(pos + 1) else {
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
        return;
    };
    if !operand.resolvable {
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
        return;
    }
    // Only the fixed `shell -c literal-script` form is transparent. Other
    // operands are not inner argv: in particular $0/$1 extras must never
    // manufacture a required option (e.g. --dry-run) in a child command.
    let transparent = pos == 1 && part.argv.len() == 3 && part.state.can_allow();
    let operand = operand.text.clone();
    if transparent {
        collapse(part_id, graph);
    } else {
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
    }
    let start = graph.parts.len();
    extract_raw(
        &operand,
        depth + 1,
        Relation::Wrapper,
        1,
        Some(part_id),
        graph,
    );
    if graph.parts.len() == start {
        graph.collapsed.retain(|id| *id != part_id);
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
    }
    // Outer assignments and redirects affect every executable descendant.
    // Keep them as coverage obligations instead of losing them on collapse.
    for child in &mut graph.parts[start..] {
        let mut assigns = part.assigns.clone();
        assigns.append(&mut child.assigns);
        for (i, assignment) in assigns.iter_mut().enumerate() {
            assignment.ordinal = i as u32 + 1;
        }
        child.assigns = assigns;
        let mut redirects = part.redirects.clone();
        redirects.append(&mut child.redirects);
        for (i, redirect) in redirects.iter_mut().enumerate() {
            redirect.ordinal = i as u32 + 1;
        }
        child.redirects = redirects;
        if child.state.can_allow() {
            child.state = observations_state(&child.assigns, &child.argv, &child.redirects);
        }
    }
}

fn unwrap_transparent(
    part: Part,
    part_id: usize,
    depth: usize,
    graph: &mut CommandEvidence,
    opt_reason: &'static str,
    empty_reason: &'static str,
) {
    let rest: Vec<ArgToken> = part.argv[1..].to_vec();
    if rest.is_empty() {
        graph.parts[part_id].state = EvidenceState::Opaque(empty_reason);
        return;
    }
    if rest[0].text.starts_with('-') {
        graph.parts[part_id].state = EvidenceState::Opaque(opt_reason);
        return;
    }
    emit_wrapped(&part, part_id, rest, true, depth, graph);
}

fn unwrap_nice(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let mut rest: Vec<ArgToken> = part.argv[1..].to_vec();
    if rest.first().map(|w| w.text.as_str()) == Some("-n") {
        if rest
            .get(1)
            .is_none_or(|priority| !priority.resolvable || priority.text.parse::<i64>().is_err())
        {
            graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
            return;
        }
        rest.drain(..2.min(rest.len()));
    } else if rest
        .first()
        .map(|w| w.text.starts_with('-'))
        .unwrap_or(false)
    {
        graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
        return;
    }
    if rest.is_empty() {
        graph.parts[part_id].state = EvidenceState::Opaque("nice without command");
        return;
    }
    emit_wrapped(&part, part_id, rest, true, depth, graph);
}

fn unwrap_timeout(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let mut rest: Vec<ArgToken> = part.argv[1..].to_vec();
    match rest
        .first()
        .filter(|w| w.resolvable)
        .map(|w| w.text.clone())
    {
        None => graph.parts[part_id].state = EvidenceState::Opaque("timeout without duration"),
        Some(w) if w.starts_with("--") => {
            graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION)
        }
        Some(w) => {
            if !is_duration(&w) {
                graph.parts[part_id].state = EvidenceState::Opaque("timeout without duration");
                return;
            }
            rest.drain(0..1);
            if matches!(rest.first(), Some(f) if f.text.starts_with('-') && f.text.len() > 1) {
                graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
                return;
            }
            if rest.is_empty() {
                graph.parts[part_id].state = EvidenceState::Opaque("timeout without command");
                return;
            }
            emit_wrapped(&part, part_id, rest, true, depth, graph);
        }
    }
}

fn unwrap_env(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let mut rest: Vec<ArgToken> = Vec::new();
    let mut idx = 1usize;
    let mut opaque: Option<&'static str> = None;
    while idx < part.argv.len() {
        let w = &part.argv[idx];
        if !w.resolvable {
            graph.parts[part_id].state = EvidenceState::Opaque(reason::OPAQUE_EXPANSION);
            return;
        }
        if is_assignment(&w.text) {
            idx += 1;
            continue;
        }
        if w.text.starts_with('-') {
            opaque = Some(reason::OPAQUE_EXPANSION);
            break;
        }
        rest = part.argv[idx..].to_vec();
        break;
    }
    if let Some(reason) = opaque {
        graph.parts[part_id].state = EvidenceState::Opaque(reason);
        return;
    }
    if rest.is_empty() {
        graph.parts[part_id].state = EvidenceState::Opaque("env without command");
        return;
    }
    // Utility assignment operands are not direct prefix-assignment evidence.
    // Keep that unsupported wrapper visible instead of dropping destinations.
    emit_wrapped(&part, part_id, rest, idx == 1, depth, graph);
}

fn unwrap_xargs(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    // Executed command = operand + stdin-appended args (unconstrained) ⇒ the
    // whole thing can never allow; the operand still parses as an opaque
    // child so deny rules can see its typed shape.
    let operand: Vec<ArgToken> = part.argv[1..]
        .iter()
        .filter(|w| !w.text.starts_with('-'))
        .cloned()
        .collect();
    if !operand.is_empty() {
        let child_depth = depth + 1;
        emit_child(
            part_id,
            part.raw.clone(),
            Vec::new(),
            operand,
            Vec::new(),
            state_at_depth(
                child_depth,
                EvidenceState::Opaque("xargs operand executed with stdin-appended args"),
            ),
            graph,
        );
    }
    graph.parts[part_id].state = EvidenceState::Opaque("xargs executes from stdin");
}

/// Mark a wrapper part as unwrapped into its children: it keeps no votes of
/// its own (the child parts carry the execution semantics).
fn collapse(part_id: usize, graph: &mut CommandEvidence) {
    if !graph.collapsed.contains(&part_id) {
        graph.collapsed.push(part_id);
    }
}

fn is_duration(w: &str) -> bool {
    let base: String = w
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if base.is_empty() {
        return false;
    }
    matches!(&w[base.len()..], "" | "s" | "m" | "h" | "d") && base.parse::<f64>().is_ok()
}

// re-exported: split() alias for callers that think of the whole graph alike.
#[allow(dead_code)]
pub fn parts_of(raw: &str) -> Vec<Part> {
    extract(raw).parts
}

const _: () = {
    // silence: Quoting is re-exported for callers with match arms on quoting
    // classes only; the evidence layer keeps the flag set at ArgToken level.
};

#[allow(unused_imports)]
use crate::checker::parse::Quoting as _;
