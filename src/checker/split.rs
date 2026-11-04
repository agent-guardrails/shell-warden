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

pub const MAX_SPLIT_DEPTH: usize = 8;

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
    ordinal: u32,
    parent: Option<usize>,
    graph: &mut CommandEvidence,
) {
    if depth > MAX_SPLIT_DEPTH {
        // deeper nesting is opaque, not invalid (07 §11.3 Q8 direction)
        let (id, parent_note) = push_part(
            raw.to_string(),
            relation,
            ordinal,
            parent,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            EvidenceState::Opaque(reason::EVIDENCE_LIMIT),
            None,
            graph,
        );
        let _ = parent_note;
        let _ = id;
        return;
    }
    let scanned = parse::scan(raw);
    for seg in &scanned.segments {
        if scanned.malformed || seg.heredoc {
            split_heredoc_like(seg, relation, ordinal, parent, graph);
            continue;
        }
        let seg_relation = match seg.sep {
            Some(Operator::Pipe) => Relation::Pipeline,
            _ => Relation::Chain,
        };
        // recursion for captured inner texts (command substitution), BEFORE
        // the ordinary part: substitution order matches shell evaluation.
        for (inner, _span) in seg
            .items
            .iter()
            .filter_map(|it| match it {
                parse::Item::Tok(t) if !t.subtexts.is_empty() => Some(t.subtexts.clone()),
                _ => None,
            })
            .flatten()
        {
            extract_raw(
                inner.trim(),
                depth + 1,
                Relation::CommandSubstitution,
                next_ordinal(graph, Relation::CommandSubstitution, parent),
                parent,
                graph,
            );
        }

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
            if tok.text.is_empty() {
                continue;
            }
            if argv.is_empty() && assigns.is_empty() && is_assignment(&tok.text) {
                let name = tok.text[..tok.text.find('=').unwrap_or(0)].to_string();
                assigns.push(EnvAssign {
                    name,
                    text: tok.text.clone(),
                    resolvable: tok.resolvable,
                    span: tok.span,
                });
                continue;
            }
            argv.push(ArgToken {
                text: tok.text.clone(),
                resolvable: tok.resolvable,
                span: tok.span,
            });
        }

        let redirects: Vec<RedirectObs> = seg
            .redirects
            .iter()
            .enumerate()
            .map(|(k, r)| RedirectObs {
                op: match r.op {
                    RawRedirOp::Supported(op) => Some(op),
                    RawRedirOp::Unsupported => None,
                },
                source_fd: r.source_fd,
                target: r.target.text.clone(),
                target_resolvable: r.target.resolvable,
                is_fd_target: r.target.text.chars().all(|c| c.is_ascii_digit()),
                span: r.span,
                ordinal: k as u32 + 1,
            })
            .collect();

        let state = if unresolvable {
            EvidenceState::Opaque(reason::OPAQUE_EXPANSION)
        } else {
            EvidenceState::Complete
        };

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

        // wrapper unwrap turns transparent interpreters into child parts
        let part = graph.parts[part_id].clone();
        unwrap_wrapper(part, part_id, depth + 1, graph);
    }
}

fn split_heredoc_like(
    seg: &parse::Segment,
    relation: Relation,
    ordinal: u32,
    parent: Option<usize>,
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
                text: tok.text.clone(),
                resolvable: tok.resolvable,
                span: tok.span,
            });
            continue;
        }
        argv.push(ArgToken {
            text: tok.text.clone(),
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
    unwrap_wrapper(part, part_id, MAX_SPLIT_DEPTH, graph);
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

fn next_ordinal(graph: &CommandEvidence, relation: Relation, parent: Option<usize>) -> u32 {
    graph
        .parts
        .iter()
        .filter(|p| p.relation == relation && p.parent == parent)
        .count() as u32
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
    let head = part.argv.first().map(|a| a.text.clone());
    if part.state == EvidenceState::Complete {
        match head.as_deref() {
            Some("bash") | Some("sh") => unwrap_bash(part, part_id, depth, graph),
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
        return;
    }
    if let Some("xargs") = head.as_deref() {
        unwrap_xargs(part, part_id, depth, graph)
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
    let pos = match part.argv.iter().position(|w| w.text == "-c") {
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
    // The operand is evaluated wholly; extra words after it are $0/$1 args —
    // appended to the last child argv (they only ADD stricter matches).
    let extras: Vec<String> = part.argv[pos + 2..]
        .iter()
        .map(|a| a.text.clone())
        .collect();
    let operand = operand.text.clone();
    drop(part);
    collapse(part_id, graph);
    emit_sh_children(part_id, &operand, &extras, depth, graph);
}

fn emit_sh_children(
    part_id: usize,
    operand: &str,
    extras: &[String],
    depth: usize,
    graph: &mut CommandEvidence,
) {
    let children_scanned = parse::scan(operand.trim());
    // emit each segment of the operand as a wrapper child, mirroring shell
    for seg in &children_scanned.segments {
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
                    text: tok.text.clone(),
                    resolvable: tok.resolvable,
                    span: tok.span,
                });
                continue;
            }
            argv.push(ArgToken {
                text: tok.text.clone(),
                resolvable: tok.resolvable,
                span: tok.span,
            });
        }
        for extra in extras {
            argv.push(ArgToken {
                text: extra.clone(),
                resolvable: true,
                span: (0, 0),
            });
        }
        for (inner, _span) in seg
            .items
            .iter()
            .filter_map(|it| match it {
                parse::Item::Tok(t) if !t.subtexts.is_empty() => Some(t.subtexts.clone()),
                _ => None,
            })
            .flatten()
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
        let redirects: Vec<RedirectObs> = seg
            .redirects
            .iter()
            .enumerate()
            .map(|(k, r)| RedirectObs {
                op: match r.op {
                    RawRedirOp::Supported(op) => Some(op),
                    RawRedirOp::Unsupported => None,
                },
                source_fd: r.source_fd,
                target: r.target.text.clone(),
                target_resolvable: r.target.resolvable,
                is_fd_target: r.target.text.chars().all(|c| c.is_ascii_digit()),
                span: r.span,
                ordinal: k as u32 + 1,
            })
            .collect();
        let state = if children_scanned.malformed || seg.heredoc {
            EvidenceState::Invalid(reason::UNSUPPORTED_SYNTAX)
        } else if unresolvable {
            EvidenceState::Opaque(reason::OPAQUE_EXPANSION)
        } else {
            EvidenceState::Complete
        };
        let child_id = emit_child(
            part_id,
            seg.raw.trim().to_string(),
            assigns,
            argv,
            redirects,
            state,
            graph,
        );
        let child = graph.parts[child_id].clone();
        unwrap_wrapper(child, child_id, depth, graph);
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
    let ids = emit_child(
        part_id,
        part.raw.clone(),
        part.assigns.clone(),
        rest,
        Vec::new(),
        EvidenceState::Complete,
        graph,
    );
    collapse(part_id, graph);
    let child = graph.parts[ids].clone();
    unwrap_wrapper(child, ids, depth, graph);
}

fn unwrap_nice(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let mut rest: Vec<ArgToken> = part.argv[1..].to_vec();
    if rest.first().map(|w| w.text.as_str()) == Some("-n") {
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
    let child_id = emit_child(
        part_id,
        part.raw.clone(),
        part.assigns.clone(),
        rest,
        Vec::new(),
        EvidenceState::Complete,
        graph,
    );
    collapse(part_id, graph);
    let child = graph.parts[child_id].clone();
    unwrap_wrapper(child, child_id, depth, graph);
}

fn unwrap_timeout(part: Part, part_id: usize, _depth: usize, graph: &mut CommandEvidence) {
    let mut rest: Vec<ArgToken> = part.argv[1..].to_vec();
    match rest.first().map(|w| w.text.clone()) {
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
            let child_id = emit_child(
                part_id,
                part.raw.clone(),
                part.assigns.clone(),
                rest,
                Vec::new(),
                EvidenceState::Complete,
                graph,
            );
            collapse(part_id, graph);
            let child = graph.parts[child_id].clone();
            unwrap_wrapper(child, child_id, MAX_SPLIT_DEPTH, graph);
        }
    }
}

fn unwrap_env(part: Part, part_id: usize, depth: usize, graph: &mut CommandEvidence) {
    let mut rest: Vec<ArgToken> = Vec::new();
    let mut idx = 1usize;
    let mut opaque: Option<&'static str> = None;
    while idx < part.argv.len() {
        let w = &part.argv[idx];
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
    // env assignments are transparent prefixes — argv untouched
    let child_id = emit_child(
        part_id,
        part.raw.clone(),
        part.assigns.clone(),
        rest,
        Vec::new(),
        EvidenceState::Complete,
        graph,
    );
    collapse(part_id, graph);
    let child = graph.parts[child_id].clone();
    unwrap_wrapper(child, child_id, depth, graph);
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
        emit_child(
            part_id,
            part.raw.clone(),
            Vec::new(),
            operand,
            Vec::new(),
            EvidenceState::Opaque("xargs operand executed with stdin-appended args"),
            graph,
        );
    }
    graph.parts[part_id].state = EvidenceState::Opaque("xargs executes from stdin");
    let _ = depth;
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
