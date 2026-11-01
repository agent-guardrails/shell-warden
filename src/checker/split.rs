// Recursive chain splitting (07 §7.2): segments become parts; wrapper
// interpreters unwrap into their operand parts; substitution inner texts are
// scanned recursively as their own parts. Splitting is the checker's own and
// complete — the letter's command split is never trusted (0014): each letter
// command is always scanned from its raw string.

use super::parse::{self, Item, Segment};

pub const MAX_SPLIT_DEPTH: usize = 8; // §11.3 Q8: deeper nesting ⇒ opaque

#[derive(Debug, Clone)]
pub struct Part {
    /// Raw text covered by this part (for `pattern` matching).
    pub raw: String,
    /// Resolvable argv tokens (quotes decoded, assignments excluded).
    pub argv: Vec<String>,
    /// Env-prefix assignments (`FOO=1 cmd`), recorded, excluded from argv.
    pub assigns: Vec<String>,
    /// Path evidence (§7.4 step 7): pathlike argv words + redirect targets.
    pub paths: Vec<String>,
    /// Unresolvable token textual forms (diagnostics).
    pub unknown_texts: Vec<String>,
    /// None ⇒ static; Some(reason) ⇒ opaque (07 §7.3).
    pub opaque_reason: Option<&'static str>,
}

impl Part {
    pub fn classification_static(&self) -> bool {
        self.opaque_reason.is_none()
    }
}

/// Split one raw command text into evaluated parts (order: scan order).
pub fn split(raw: &str, depth: usize) -> Vec<Part> {
    if raw.trim().is_empty() {
        return vec![Part {
            raw: raw.to_string(),
            argv: vec![],
            assigns: vec![],
            paths: vec![],
            unknown_texts: vec![],
            opaque_reason: Some("empty command"),
        }];
    }
    if depth > MAX_SPLIT_DEPTH {
        return vec![Part {
            raw: raw.to_string(),
            argv: vec![],
            assigns: vec![],
            paths: vec![],
            unknown_texts: vec![],
            opaque_reason: Some("split depth exceeded (Q8)"),
        }];
    }
    let scanned = parse::scan(raw);
    let mut parts = Vec::new();
    let mut pending_subs: Vec<String> = Vec::new();
    for seg in &scanned.segments {
        if scanned.salvage_failed {
            parts.push(whole_opaque(seg));
            continue;
        }
        pending_subs.extend(segment_subtexts(seg));
        parts.extend(assemble(seg, depth));
    }
    for sub in pending_subs {
        for p in split(sub.trim(), depth + 1) {
            parts.push(p);
        }
    }
    parts
}

fn whole_opaque(seg: &Segment) -> Part {
    Part {
        raw: seg.raw.clone(),
        argv: vec![],
        assigns: vec![],
        paths: vec![],
        unknown_texts: vec![seg.raw.clone()],
        opaque_reason: Some("salvage failed (heredoc)"),
    }
}

fn segment_subtexts(seg: &Segment) -> Vec<String> {
    seg.items
        .iter()
        .filter_map(|it| match it {
            Item::Tok(t) if !t.subtexts.is_empty() => Some(t.subtexts.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Assemble a segment into a part, then unwrap wrappers.
fn assemble(seg: &Segment, depth: usize) -> Vec<Part> {
    let st = parse::summarize(seg);

    // leading `NAME=…` words are env-prefix assignments (07 §7.4 step 5)
    let mut assigns = Vec::new();
    let mut start = 0usize;
    for w in &st.words {
        if is_assignment(w) {
            assigns.push(w.clone());
            start += 1;
        } else {
            break;
        }
    }
    let argv: Vec<String> = st
        .words
        .iter()
        .skip(start)
        .filter(|(_, r)| *r)
        .map(|(t, _)| t.clone())
        .collect();
    let unknown: Vec<String> = st
        .words
        .iter()
        .enumerate()
        .skip(start)
        .filter(|(_, r)| !*r)
        .map(|(i, _)| st.words[i].0.clone())
        .collect();

    let mut part = Part {
        raw: seg.raw.clone(),
        argv,
        assigns,
        paths: st.pathlike_words.clone().into_iter().chain(st.pathlike_targets.iter().cloned()).collect(),
        unknown_texts: unknown,
        opaque_reason: if st.resolvable_all {
            None
        } else {
            Some("unresolvable token (expansion / bad quoting)")
        },
    };
    let mut out = Vec::new();
    unwrap_wrapper(&mut part, depth, &mut out);
    out
}

fn is_assignment(w: &str) -> bool {
    match w.find('=') {
        None => false,
        Some(eq) if eq == 0 => false,
        Some(eq) => {
            let name = &w[..eq];
            name.chars().next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

/// Wrapper unwrapping (§7.2 step 2): transparent heads drop; `-c` operators
/// recurse into their operand; `xargs` (stdin-appended args) stays opaque with
/// a visible opaque operand part (raw-deny matched on outer raw).
fn unwrap_wrapper(part: &Part, depth: usize, out: &mut Vec<Part>) {
    if part.opaque_reason.is_none() {
        if let Some(head) = part.argv.first().map(String::as_str) {
            match head {
                "bash" | "sh" => unwrap_bash(part, depth, out),
                "sudo" => unwrap_transparent(part, out, "sudo options", "sudo without command"),
                "nohup" => unwrap_transparent(part, out, "nohup options", "nohup without command"),
                "nice" => unwrap_nice(part, depth, out),
                "timeout" => unwrap_timeout(part, depth, out),
                "env" => unwrap_env(part, depth, out),
                "xargs" => unwrap_xargs(part, out),
                _ => out.push(part.clone()),
            }
        } else {
            out.push(part.clone());
        }
        return;
    }
    match part.argv.first().map(String::as_str) {
        Some("xargs") => unwrap_xargs(part, out),
        _ => out.push(part.clone()),
    }
}

fn unwrap_bash(part: &Part, depth: usize, out: &mut Vec<Part>) {
    let Some(pos) = part.argv.iter().position(|w| w == "-c") else {
        out.push(opaque_like(part, "interpreter without -c"));
        return;
    };
    let Some(operand) = part.argv.get(pos + 1) else {
        out.push(opaque_like(part, "bash/sh -c without operand"));
        return;
    };
    // The operand is evaluated wholly; any extra words after it are $0/$1-name
    // args — appended to the last child argv (conservative direction: extra
    // tokens only ADD stricter potential matches).
    let extras: Vec<String> = part.argv[pos + 2..].to_vec();
    let mut children = split(operand.trim(), depth + 1);
    if let Some(last) = children.last_mut() {
        // extras attach to the last command of the operand chain
        last.argv.extend(extras.iter().cloned());
    }
    out.extend(children);
}

fn unwrap_transparent(part: &Part, out: &mut Vec<Part>, opt_reason: &str, empty_reason: &'static str) {
    let rest: Vec<&String> = part.argv[1..].iter().collect();
    if rest.is_empty() {
        out.push(opaque_like(part, empty_reason));
        return;
    }
    if rest[0].starts_with('-') {
        // sudo -u …, nohup --help …: unknown head behavior
        out.push(opaque_like(part, opt_reason));
        return;
    }
    let mut child = part.clone();
    child.argv = vec![rest[0].clone()];
    child.argv.extend(rest[1..].iter().cloned());
    unwrap_wrapper(&child, depth, out);
}

fn unwrap_nice(part: &Part, depth: usize, out: &mut Vec<Part>) {
    let mut rest: Vec<String> = part.argv[1..].to_vec();
    if rest.first().is_some_and(|w| w == "-n") {
        rest.drain(..2.min(rest.len()));
    } else if rest.first().is_some_and(|w| w.starts_with('-')) {
        out.push(opaque_like(part, "nice options"));
        return;
    }
    if rest.is_empty() {
        out.push(opaque_like(part, "nice without command"));
        return;
    }
    let child = part_with_argv(part, rest);
    unwrap_wrapper(&child, depth, out);
}

fn unwrap_timeout(part: &Part, _depth: usize, out: &mut Vec<Part>) {
    let mut rest: Vec<String> = part.argv[1..].to_vec();
    match rest.first() {
        None => out.push(opaque_like(part, "timeout without duration")),
        Some(w) if w.starts_with("--") => out.push(opaque_like(part, "timeout options")),
        Some(w) => {
            if !is_duration(w) {
                out.push(opaque_like(part, "timeout without duration"));
                return;
            }
            rest.drain(0..1);
            // optional priority/signal flags after duration
            while matches!(rest.first(), Some(f) if f.starts_with('-') && f.len() > 1) {
                out.push(opaque_like(part, "timeout options"));
                return;
            }
            if rest.is_empty() {
                out.push(opaque_like(part, "timeout without command"));
                return;
            }
            let child = part_with_argv(part, rest);
            unwrap_wrapper(&child, MAX_SPLIT_DEPTH, out);
        }
    }
}

fn unwrap_env(part: &Part, depth: usize, out: &mut Vec<Part>) {
    let mut rest: Vec<String> = Vec::new();
    let mut it = part.argv[1..].iter();
    let mut opaque: Option<&'static str> = None;
    for w in it.by_ref() {
        if is_assignment(w) {
            continue;
        }
        if w.starts_with('-') {
            opaque = Some("env options");
            break;
        }
        rest.push(w.clone());
        rest.extend(it.cloned());
        break;
    }
    if let Some(reason) = opaque {
        out.push(opaque_like(part, reason));
        return;
    }
    if rest.is_empty() {
        out.push(opaque_like(part, "env without command"));
        return;
    }
    // env assignments are transparent prefixes — argv untouched
    let child = part_with_argv(part, rest);
    unwrap_wrapper(&child, depth, out);
}

fn unwrap_xargs(part: &Part, out: &mut Vec<Part>) {
    // executed command = operand + pipe-appended args (unconstrained) ⇒ the
    // whole thing is unresolvable for `allow`; the operand still parses as an
    // opaque child so raw deny rules can see it.
    let operand: Vec<String> = part.argv[1..].iter().filter(|w| !w.starts_with('-')).cloned().collect();
    if !operand.is_empty() {
        out.push(Part {
            argv: operand,
            opaque_reason: Some("xargs operand executed with stdin-appended args"),
            ..part.clone()
        });
    }
    out.push(opaque_like(part, "xargs executes from stdin"));
}

fn part_with_argv(part: &Part, argv: Vec<String>) -> Part {
    Part { argv, ..part.clone() }
}

fn opaque_like(part: &Part, reason: &'static str) -> Part {
    Part { opaque_reason: Some(reason), ..part.clone() }
}

fn is_duration(w: &str) -> bool {
    let base: String = w.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    if base.is_empty() {
        return false;
    }
    matches!(&w[base.len()..], "" | "s" | "m" | "h" | "d") && base.parse::<f64>().is_ok()
}
