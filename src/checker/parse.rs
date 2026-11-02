// Parsing: tokenizer, classification and normalization (07 §§7.2–7.4).
//
// One scanner turns a raw command into segments per operator; segments carry
// resolved tokens plus captured substitution texts for the recursive splitter
// (split.rs). Anything unresolvable (expansions, brace/process substitution,
// heredocs, malformed quoting, residual unknown operators) marks the affected
// tokens non-resolvable ⇒ the part is `opaque` (07 §7.3). `allow` never
// originates from opaque parts (I10).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokKind {
    /// Normal argv word.
    Word,
    /// Redirect target (excluded from argv; joins path evidence when pathlike).
    RedirectTarget,
}

#[derive(Debug, Clone)]
pub struct Tok {
    pub kind: TokKind,
    /// Decoded text (quotes resolved). Unresolvable tokens keep the raw textual
    /// form for diagnostics/raw matching; decision logic must consult
    /// `resolvable` first.
    pub text: String,
    pub resolvable: bool,
    /// Inner texts of executions found inside this token: `$(…)`, backticks,
    /// process substitution, `-c` operands (split recursively).
    pub subtexts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Pipe,
    Or,
    And,
    Semi,
    Amp,
    Redirect,
}

#[derive(Debug, Clone)]
pub enum Item {
    Op(Operator),
    Tok(Tok),
}

#[derive(Debug, Clone)]
pub struct Segment {
    /// Raw slice this segment covers (for `pattern` matching).
    pub raw: String,
    pub items: Vec<Item>,
}

#[derive(Debug)]
pub struct ScanResult {
    pub segments: Vec<Segment>,
    /// Constructs even segment recovery refused (heredocs): whole input turns
    /// opaque and raw-pattern matching only (§7.4 step 4 posture).
    pub salvage_failed: bool,
}

// The scanner maintains a defensive state machine: some assignments are
// overwritten before read on early-exit paths; clippy cannot see the loop
// structure. Accepted at this function level.
#[allow(unused_assignments)]
pub fn scan(raw: &str) -> ScanResult {
    let chars: Vec<char> = raw.chars().collect();
    let n = chars.len();
    let mut segments: Vec<Segment> = Vec::new();
    let mut items: Vec<Item> = Vec::new();
    let mut salvage_failed = false;

    let mut seg_start = 0usize;
    let mut cur_text = String::new();
    let mut cur_resolvable = true;
    let mut cur_sub: Vec<String> = Vec::new();

    macro_rules! new_segment {
        ($op:expr, $upto:expr) => {{
            items.push(Item::Op($op));
            let raw = chars[seg_start..$upto].iter().collect();
            segments.push(Segment {
                raw,
                items: std::mem::take(&mut items),
            });
            seg_start = $upto;
        }};
    }

    macro_rules! finish_token_impl {
        ($kind:expr) => {
            if !cur_text.is_empty() {
                items.push(Item::Tok(Tok {
                    kind: $kind,
                    text: std::mem::take(&mut cur_text),
                    resolvable: cur_resolvable, // note: take() would reset bool to false
                    subtexts: std::mem::take(&mut cur_sub),
                }));
                cur_resolvable = true;
            }
        };
    }

    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' => {
                finish_token_impl!(TokKind::Word);
                i += 1;
            }
            '\n' => {
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::Semi, i);
                i += 1;
            }
            '#' if cur_text.is_empty() => {
                // comment: the rest of the segment is decoration
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::Semi, i);
                i = n; // discard the comment tail
                break;
            }
            '\'' => match (i + 1..n).find(|&j| chars[j] == '\'') {
                Some(end) => {
                    cur_text.extend(chars[i + 1..end].iter());
                    i = end + 1;
                }
                None => {
                    cur_resolvable = false;
                    cur_text.extend(chars[i..].iter());
                    i = n;
                }
            },
            '"' => {
                let mut j = i + 1;
                let mut tail = String::new();
                let mut escaped = false;
                let mut ok = false;
                while j < n {
                    let ch = chars[j];
                    if escaped {
                        tail.push(unescape(ch));
                        escaped = false;
                        j += 1;
                        continue;
                    }
                    if ch == '\\' {
                        escaped = true;
                        j += 1;
                        continue;
                    }
                    if ch == '"' {
                        ok = true;
                        break;
                    }
                    if ch == '$' || ch == '`' {
                        // Expansions inside double quotes: unresolvable, inner
                        // text captured for the recursive splitter.
                        cur_resolvable = false;
                        cur_text.push_str(&tail);
                        tail.clear();
                        let (inner, next) = capture_expand(&chars, j, &cur_text, &mut cur_sub);
                        let _ = inner;
                        cur_text.push('\u{fffd}'); // placeholder: the substitution site
                        cur_resolvable = false;
                        j = next;
                        continue;
                    }
                    tail.push(ch);
                    j += 1;
                }
                if ok {
                    cur_text.push_str(&tail);
                    i = j + 1;
                } else {
                    cur_resolvable = false;
                    cur_text.extend(chars[i..].iter());
                    i = n;
                }
            }
            '\\' if i + 1 < n => {
                cur_text.push(unescape(chars[i + 1]));
                i += 2;
            }
            '\\' => {
                // dangling escape
                cur_resolvable = false;
                cur_text.push('\\');
                i = n;
            }
            '$' => {
                cur_resolvable = false;
                let (inner, next) = capture_expand(&chars, i, &cur_text, &mut cur_sub);
                let _ = inner;
                cur_text.push('\u{fffd}');
                i = next;
            }
            '`' => match (i + 1..n).find(|&j| chars[j] == '`') {
                Some(end) => {
                    cur_resolvable = false;
                    let _ = &cur_text;
                    cur_sub.push(chars[i + 1..end].iter().collect());
                    cur_text.push('\u{fffd}');
                    i = end + 1;
                }
                None => {
                    cur_resolvable = false;
                    cur_text.extend(chars[i..].iter());
                    i = n;
                }
            },
            '<' if i + 1 < n && chars[i + 1] == '(' => {
                // process substitution <( … )
                cur_resolvable = false;
                let close = find_balanced(&chars, i + 1, '(', ')');
                cur_sub.push(chars[i + 2..close].iter().collect());
                cur_text.push('\u{fffd}');
                i = close + 1;
            }
            '>' if i + 1 < n && chars[i + 1] == '(' => {
                // process substitution >( … )
                cur_resolvable = false;
                let close = find_balanced(&chars, i + 1, '(', ')');
                cur_sub.push(chars[i + 2..close].iter().collect());
                cur_text.push('\u{fffd}');
                i = close + 1;
            }
            '{' if is_brace_expand(&chars, i) => {
                cur_resolvable = false;
                cur_text.push('{');
                i += 1;
            }
            '|' if i + 1 < n && chars[i + 1] == '|' => {
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::Or, i + 2);
                i += 2;
            }
            '|' => {
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::Pipe, i + 1);
                i += 1;
            }
            ';' => {
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::Semi, i + 1);
                i += 1;
            }
            '&' if i + 1 < n && chars[i + 1] == '&' => {
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::And, i + 2);
                i += 2;
            }
            '&' if i + 1 < n && chars[i + 1] == '>' => {
                finish_token_impl!(TokKind::Word);
                i = skip_after_amp_redirect(&chars, i + 2);
                // &> / &>>: redirect; target follows
                let (tok, next) =
                    read_target(&chars, i, &mut cur_text, &mut cur_resolvable, &mut cur_sub);
                items.push(Item::Tok(tok));
                i = next;
            }
            '&' => {
                finish_token_impl!(TokKind::Word);
                new_segment!(Operator::Amp, i + 1);
                i += 1;
            }
            '>' | '<' => {
                // fd-prefixed redirections (`2>`, `1<`): a pure-digit pending token
                // belongs to the operator, not argv.
                if !cur_text.is_empty() && cur_text.chars().all(|ch| ch.is_ascii_digit()) {
                    cur_text.clear();
                    cur_resolvable = true;
                    cur_sub.clear();
                }
                finish_token_impl!(TokKind::Word);
                i = skip_redir(&chars, i);
                if i < n && chars[i] == '<' {
                    // heredoc: unresolvable rest of the segment (fail-closed)
                    salvage_failed = true;
                    cur_resolvable = false;
                    cur_text.extend(chars[i..].iter());
                    finish_token_impl!(TokKind::RedirectTarget);
                    let raw = chars[seg_start..n].iter().collect();
                    segments.push(Segment {
                        raw,
                        items: std::mem::take(&mut items),
                    });
                    return ScanResult {
                        segments,
                        salvage_failed: true,
                    };
                }
                let (tok, next) =
                    read_target(&chars, i, &mut cur_text, &mut cur_resolvable, &mut cur_sub);
                items.push(Item::Tok(tok));
                i = next;
            }
            _ => {
                cur_text.push(c);
                i += 1;
            }
        }
    }
    finish_token_impl!(TokKind::Word);
    if !items.is_empty() {
        let raw = chars[seg_start..].iter().collect();
        segments.push(Segment { raw, items });
    }
    ScanResult {
        segments,
        salvage_failed,
    }
}

fn unescape(c: char) -> char {
    match c {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        other => other,
    }
}

/// Capture `$…` at position `start`: records the inner text into `subtexts`
/// and returns the next index after the construct. Handles `$(`, `$((`,
/// `${}`, `$NAME`, bare `$` and backticks.
fn capture_expand(
    chars: &[char],
    start: usize,
    _ctx: &str,
    subtexts: &mut Vec<String>,
) -> (Option<String>, usize) {
    let n = chars.len();
    let first = *chars.get(start + 1).unwrap_or(&'\0');
    if first == '(' {
        if chars.get(start + 2) == Some(&'(') {
            let close = find_balanced(chars, start + 1, '(', ')');
            subtexts.push(
                chars[start + 3..close.max(start + 3).saturating_sub(1)]
                    .iter()
                    .collect(),
            );
            subtexts.pop();
            subtexts.push(chars[start..=close].iter().collect());
            let _ = 0; // arithmetic: whole $(…) form is unresolvable
            return (Some(chars[start..=close].iter().collect()), close + 1);
        }
        let close = find_balanced(chars, start + 1, '(', ')');
        subtexts.push(chars[start + 2..close].iter().collect());
        return (
            Some(format!(
                "$({})",
                chars[start + 2..close].iter().collect::<String>()
            )),
            close + 1,
        );
    }
    if first == '{' {
        match (start + 1..n).find(|&j| chars[j] == '}') {
            Some(end) => {
                subtexts.push(chars[start..=end].iter().collect());
                return (Some(chars[start..=end].iter().collect()), end + 1);
            }
            None => return (None, n),
        }
    }
    if first.is_ascii_alphabetic() || first == '_' {
        let mut end = start + 1;
        while end < n && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        subtexts.push(chars[start..end].iter().collect());
        return (Some(chars[start..end].iter().collect()), end);
    }
    // bare $: unresolvable noise
    (Some("$".to_string()), start + 2)
}

fn find_balanced(chars: &[char], open_at: usize, open: char, close: char) -> usize {
    let mut depth = 0usize;
    let mut i = open_at;
    while i < chars.len() {
        let c = chars[i];
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        } else if c == '\'' || c == '"' {
            if let Some(e) = (i + 1..chars.len()).find(|&j| chars[j] == c) {
                i = e;
            } else {
                return chars.len() - 1;
            }
        }
        i += 1;
    }
    chars.len() - 1
}

fn is_brace_expand(chars: &[char], i: usize) -> bool {
    match (i..chars.len()).find(|&j| chars[j] == '}') {
        Some(end) if end > i => {
            let inner: String = chars[i + 1..end].iter().collect();
            let has_space = inner.chars().any(|c| c == ' ');
            (!has_space && inner.contains(',')) || inner.contains("..")
        }
        _ => false,
    }
}

/// After `<` / `>`: skip `>`, `<`, `>>`, `<<`, `&>`-like and fd digits (`2>`).
fn skip_redir(chars: &[char], mut i: usize) -> usize {
    let n = chars.len();
    while i < n && (chars[i] == '<' || chars[i] == '>') {
        if chars[i] == '<' && is_heredoc(chars, i) {
            return i;
        }
        // fd prefix (2>, 2>>): count digits immediately left? they are already consumed by caller
        i += 1;
    }
    i
}

fn is_heredoc(chars: &[char], i: usize) -> bool {
    chars.get(i) == Some(&'<')
}

fn skip_after_amp_redirect(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && chars[i] == '>' {
        i += 1;
    }
    i
}

/// Read the redirect target starting at `i`: quote-aware until top-level
/// whitespace or an operator. Targets that are fd numbers (`2>&1` form: `&1`)
/// still yield a token; matcher treats pure `&N` as no path evidence.
fn read_target(
    chars: &[char],
    i: usize,
    _cur: &mut String,
    _res: &mut bool,
    _sub: &mut Vec<String>,
) -> (Tok, usize) {
    let n = chars.len();
    let mut j = i;
    let mut text = String::new();
    let mut resolvable = true;
    let mut subtexts = Vec::new();
    while j < n {
        let c = chars[j];
        if c == ' '
            || c == '\t'
            || c == '\n'
            || c == ';'
            || c == '|'
            || c == '&'
            || c == '<'
            || c == '>'
            || c == '('
            || c == ')'
        {
            break;
        }
        if c == '\\' && j + 1 < n {
            text.push(unescape(chars[j + 1]));
            j += 2;
            continue;
        }
        if c == '\'' || c == '"' {
            match (j + 1..n).find(|&k| chars[k] == c) {
                Some(end) => {
                    text.extend(chars[j + 1..end].iter());
                    j = end + 1;
                    continue;
                }
                None => {
                    resolvable = false;
                    text.extend(chars[j..].iter());
                    j = n;
                    break;
                }
            }
        }
        if c == '$' || c == '`' {
            resolvable = false;
            let (inner, next) = capture_expand(chars, j, &text, &mut subtexts);
            let _ = inner;
            text.push('\u{fffd}');
            j = next;
            continue;
        }
        if c == '<' && chars.get(j + 1) == Some(&'(') {
            // process substitution inside the target
            resolvable = false;
            let close = find_balanced(chars, j + 1, '(', ')');
            subtexts.push(chars[j + 2..close].iter().collect());
            text.push('\u{fffd}');
            j = close + 1;
            continue;
        }
        text.push(c);
        j += 1;
    }
    let _ = i;
    (
        Tok {
            kind: TokKind::RedirectTarget,
            text,
            resolvable,
            subtexts,
        },
        j,
    )
}

// ── Segment summary (consumed by split.rs) ───────────────────────────────────

pub struct SegTokens {
    /// Word tokens in order: (decoded text, resolvable).
    pub words: Vec<(String, bool)>,
    /// Redirect targets in order: (decoded text, resolvable).
    pub targets: Vec<(String, bool)>,
    /// True iff every token in the segment is resolvable.
    pub resolvable_all: bool,
}

pub fn summarize(seg: &Segment) -> SegTokens {
    let mut words = Vec::new();
    let mut targets = Vec::new();
    let mut resolvable_all = true;
    for it in &seg.items {
        if let Item::Tok(t) = it {
            match t.kind {
                TokKind::Word => words.push((t.text.clone(), t.resolvable)),
                TokKind::RedirectTarget => targets.push((t.text.clone(), t.resolvable)),
            }
            if !t.resolvable {
                resolvable_all = false;
            }
        }
    }
    SegTokens {
        words,
        targets,
        resolvable_all,
    }
}
