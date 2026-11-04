// Parsing: tokenizer and classification (07 §§7.2–7.4 + design/shell-warden-
// config-v2.md §Parsing, parts, and evidence states).
//
// One scanner turns raw command text into segments per operator. Segments
// carry decoded literal tokens, redirect records (operator + source FD +
// target), and captured substitution texts for the recursive splitter.
//
// Literal-vs-active word classes (design §Parsing): single quotes are literal;
// escaped metacharacters are literal; double quotes stay literal without an
// active expansion; active `$VAR`/`${…}`/`$(…)`/backticks/arith/process
// substitution, unquoted glob syntax, unquoted brace expansion, and any tilde
// a shell would expand are opaque (⇒ the affected token is not resolvable).
// A literal regex `$` inside quotes, or `\$`, is literal.

use super::grammar::RedirectOp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokKind {
    /// Normal argv word.
    Word,
    /// Redirect target (excluded from argv; joins redirect path evidence).
    RedirectTarget,
}

/// Token span in the raw source (byte offsets).
pub type Span = (usize, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quoting {
    None,
    Single,
    Double,
    Escaped,
}

#[derive(Debug, Clone)]
pub struct Tok {
    pub kind: TokKind,
    /// Decoded text (quotes resolved). Unresolvable tokens keep the raw
    /// textual form for diagnostics; decision logic must consult `resolvable`.
    pub text: String,
    /// Fully known literal value (no active expansion / glob / brace / tilde /
    /// broken quoting).
    pub resolvable: bool,
    pub quoting: Quoting,
    /// Inner texts of active executions/expansions found inside this token
    /// (`$(…)`, backticks, process substitution) — split recursively.
    pub subtexts: Vec<(String, Span)>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Pipe,
    Or,
    And,
    Semi,
    Amp,
}

#[derive(Debug, Clone)]
pub enum Item {
    Tok(Tok),
}

/// Catalog-exact redirect operator plus raw unsupported markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawRedirOp {
    Supported(RedirectOp),
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct RedirectRecord {
    pub op: RawRedirOp,
    /// Explicit source FD digits (`2>`), None = default FD.
    pub source_fd: Option<u32>,
    pub target: Tok,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Segment {
    /// Raw slice including the leading separator (for pattern matching).
    pub raw: String,
    pub span: Span,
    /// Operator directly before this segment (None = first segment).
    pub sep: Option<Operator>,
    pub items: Vec<Item>,
    /// Redirects found in this segment, source order.
    pub redirects: Vec<RedirectRecord>,
    /// Heredoc / here-string encountered: the part is invalid (closed until a
    /// later design adds typed support — design §Action-sensitive matching).
    pub heredoc: bool,
}

#[derive(Debug)]
pub struct ScanResult {
    pub segments: Vec<Segment>,
    /// True when a supported structure cannot be established for the whole
    /// input (heredoc/body): every part ⇒ invalid (fail-closed).
    pub malformed: bool,
}

pub fn scan(raw: &str) -> ScanResult {
    let chars: Vec<char> = raw.chars().collect();
    match scan_chars(raw, &chars) {
        Some(result) => result,
        None => ScanResult {
            segments: vec![Segment {
                raw: raw.to_string(),
                span: (0, raw.len()),
                sep: None,
                items: Vec::new(),
                redirects: Vec::new(),
                heredoc: true,
            }],
            malformed: true,
        },
    }
}

#[allow(unused_assignments)]
fn scan_chars(_raw: &str, chars: &[char]) -> Option<ScanResult> {
    let n = chars.len();
    let mut segments: Vec<Segment> = Vec::new();
    let _items: Vec<Item> = Vec::new();
    let mut redirects: Vec<RedirectRecord> = Vec::new();
    let mut malformed = false;

    let mut seg_start = 0usize; // byte offset
    let mut seg_items: Vec<Item> = Vec::new();
    let mut pending_sep: Option<Operator> = None;

    let mut cur_text = String::new();
    let mut cur_start: Option<usize> = None;
    let mut cur_resolvable = true;
    let mut cur_quoting = Quoting::None;
    let mut cur_sub: Vec<(String, Span)> = Vec::new();
    let mut trailing_empty = false; // last op chain saw a redirect target

    macro_rules! finish_token {
        ($kind:expr) => {
            if !cur_text.is_empty() {
                // Spans are diagnostic bookkeeping only: end = decode length
                // from the token start (never security-relevant).
                let end = cur_start.unwrap_or(0) + cur_text.len().max(1);
                seg_items.push(Item::Tok(Tok {
                    kind: $kind,
                    text: std::mem::take(&mut cur_text),
                    resolvable: cur_resolvable,
                    quoting: cur_quoting,
                    subtexts: std::mem::take(&mut cur_sub),
                    span: (cur_start.unwrap_or(0), end),
                }));
                cur_resolvable = true;
                cur_quoting = Quoting::None;
                cur_start = None;
            }
        };
    }

    macro_rules! new_segment {
        ($upto:expr) => {{
            let rawslice: String = chars[seg_start..$upto].iter().collect();
            segments.push(Segment {
                raw: rawslice,
                span: (seg_start, $upto),
                sep: pending_sep.take(),
                items: std::mem::take(&mut seg_items),
                redirects: std::mem::take(&mut redirects),
                heredoc: false,
            });
            seg_start = $upto;
        }};
    }

    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' => {
                finish_token!(TokKind::Word);
                i += 1;
            }
            '\n' => {
                finish_token!(TokKind::Word);
                trailing_empty = false;
                new_segment!(i);
                pending_sep = Some(Operator::Semi);
                i += 1;
            }
            '#' if cur_text.is_empty() => {
                // comment: the rest of the input is decoration
                finish_token!(TokKind::Word);
                new_segment!(i);
                i = n;
                break;
            }
            '\'' => {
                cur_quoting = Quoting::Single;
                cur_start.get_or_insert(i);
                match (i + 1..n).find(|&j| chars[j] == '\'') {
                    Some(end) => {
                        // single quotes are literal and fully resolved
                        cur_text.extend(chars[i + 1..end].iter());
                        cur_quoting = Quoting::None;
                        cur_start = None;
                        i = end + 1;
                    }
                    None => {
                        // unterminated single quote: glued literal fragment
                        cur_text.extend(chars[i..].iter());
                        cur_resolvable = false;
                        i = n;
                    }
                }
            }
            '"' => {
                cur_quoting = Quoting::Double;
                cur_start.get_or_insert(i);
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
                        // Active expansion inside double quotes: opaque; inner
                        // text captured for the recursive splitter.
                        cur_resolvable = false;
                        cur_text.push_str(&tail);
                        tail.clear();
                        let site_start = tail.len();
                        let _ = site_start;
                        let (inner, next) = capture_expand(chars, j, &mut cur_sub, i);
                        let _ = inner;
                        cur_text.push('\u{fffd}'); // §[replacement] site marker
                        j = next;
                        continue;
                    }
                    tail.push(ch);
                    j += 1;
                }
                if ok {
                    cur_text.push_str(&tail);
                    cur_quoting = Quoting::None;
                    cur_start = None;
                    i = j + 1;
                } else {
                    cur_text.extend(chars[i..].iter());
                    cur_resolvable = false;
                    cur_quoting = Quoting::None;
                    cur_start = None;
                    i = n;
                }
            }
            '\\' if i + 1 < n => {
                cur_start.get_or_insert(i);
                cur_quoting = Quoting::Escaped;
                cur_text.push(unescape(chars[i + 1]));
                i += 2;
            }
            '\\' => {
                // dangling escape
                cur_start.get_or_insert(i);
                cur_text.push('\\');
                cur_resolvable = false;
                i = n;
            }
            '$' => {
                cur_start.get_or_insert(i);
                cur_resolvable = false;
                let (inner, next) = capture_expand(chars, i, &mut cur_sub, i);
                let _ = inner;
                cur_text.push('\u{fffd}');
                i = next;
            }
            '`' => match (i + 1..n).find(|&j| chars[j] == '`') {
                Some(end) => {
                    cur_start.get_or_insert(i);
                    cur_resolvable = false;
                    cur_sub.push((chars[i + 1..end].iter().collect::<String>(), (i, end + 1)));
                    cur_text.push('\u{fffd}');
                    i = end + 1;
                }
                None => {
                    cur_start.get_or_insert(i);
                    cur_resolvable = false;
                    cur_text.extend(chars[i..].iter());
                    i = n;
                }
            },
            '<' if i + 1 < n && chars[i + 1] == '(' => {
                // process substitution <( … )
                cur_start.get_or_insert(i);
                cur_resolvable = false;
                let close = find_balanced(chars, i + 1, '(', ')');
                cur_sub.push((
                    chars[i + 2..close].iter().collect::<String>(),
                    (i, close + 1),
                ));
                cur_text.push('\u{fffd}');
                i = close + 1;
            }
            '>' if i + 1 < n && chars[i + 1] == '(' => {
                // process substitution >( … )
                cur_start.get_or_insert(i);
                cur_resolvable = false;
                let close = find_balanced(chars, i + 1, '(', ')');
                cur_sub.push((
                    chars[i + 2..close].iter().collect::<String>(),
                    (i, close + 1),
                ));
                cur_text.push('\u{fffd}');
                i = close + 1;
            }
            '{' if is_brace_expand(chars, i) => {
                cur_start.get_or_insert(i);
                cur_resolvable = false;
                cur_text.push('{');
                i += 1;
            }
            '*' | '?' | '[' | '~' => {
                // unquoted glob metachar / tilde expansion: opaque
                cur_start.get_or_insert(i);
                cur_resolvable = false;
                cur_text.push(c);
                i += 1;
            }
            '|' if i + 1 < n && chars[i + 1] == '|' => {
                finish_token!(TokKind::Word);
                new_segment!(i + 2);
                pending_sep = Some(Operator::Or);
                i += 2;
            }
            '|' => {
                finish_token!(TokKind::Word);
                new_segment!(i + 1);
                pending_sep = Some(Operator::Pipe);
                i += 1;
            }
            ';' => {
                finish_token!(TokKind::Word);
                new_segment!(i + 1);
                pending_sep = Some(Operator::Semi);
                i += 1;
            }
            '&' if i + 1 < n && chars[i + 1] == '&' => {
                finish_token!(TokKind::Word);
                new_segment!(i + 2);
                pending_sep = Some(Operator::And);
                i += 2;
            }
            '&' => {
                // `&` (async) or `&>` / `&>>` redirects
                finish_token!(TokKind::Word);
                let mut j = i + 1;
                let mut ngt = 0usize;
                while j < n && chars[j] == '>' {
                    ngt += 1;
                    j += 1;
                }
                if ngt >= 1 {
                    // &> / &>> are unsupported redirect operators in v2
                    redirects.push(RedirectRecord {
                        op: RawRedirOp::Unsupported,
                        source_fd: None,
                        target: dummy_target(chars.len()),
                        span: (i, j),
                    });
                    let (tok, next) = read_target(chars, j);
                    if let Some(t) = tok {
                        redirects.last_mut().unwrap().target = t;
                    }
                    i = next;
                    continue;
                }
                new_segment!(i + 1);
                pending_sep = Some(Operator::Amp);
                i += 1;
            }
            '>' | '<' => {
                // possibly FD-prefixed redirect (`2>`, `2>>`, `1<`): a pure
                // digit pending token belongs to the operator, not argv.
                let mut source_fd: Option<u32> = None;
                if !cur_text.is_empty() && cur_text.chars().all(|ch| ch.is_ascii_digit()) {
                    source_fd = cur_text.parse::<u32>().ok();
                    cur_text.clear();
                    cur_resolvable = true;
                    cur_sub.clear();
                    cur_start = None;
                    cur_quoting = Quoting::None;
                }
                finish_token!(TokKind::Word);
                let op_start = i;
                let mut nlt = 0usize;
                let mut ngt = 0usize;
                while i < n && (chars[i] == '<' || chars[i] == '>') {
                    if chars[i] == '<' {
                        nlt += 1;
                    } else {
                        ngt += 1;
                    }
                    i += 1;
                }
                let (op, span_end) = match (nlt, ngt) {
                    (0, 1) => (Some(RedirectOp::Out), i),
                    (0, 2) => (Some(RedirectOp::AppendOut), i),
                    (1, 0) => (Some(RedirectOp::In), i),
                    _ => {
                        // heredoc / here-string / `<>`: unsupported in v2
                        malformed = true;
                        return None;
                    }
                };
                let op = op.unwrap();
                {
                    // duplication form: `<&N` / `>&N` (+ `&-` close)
                    match chars.get(i) {
                        Some('&') => {
                            i += 1;
                            let dup = match op {
                                RedirectOp::Out => RedirectOp::DupOut,
                                RedirectOp::In => RedirectOp::DupIn,
                                other => other,
                            };
                            let (tok, next) = read_target(chars, i);
                            let digits = tok.as_ref().map(|t| t.text.parse::<i32>().is_ok());
                            match (dup, digits) {
                                (RedirectOp::DupOut | RedirectOp::DupIn, Some(true)) => {
                                    let t = tok.unwrap();
                                    redirects.push(RedirectRecord {
                                        op: RawRedirOp::Supported(dup),
                                        source_fd,
                                        target: t,
                                        span: (op_start, i),
                                    });
                                    i = next;
                                }
                                _ => {
                                    // `<&-` (FD close) and non-numeric dup targets
                                    redirects.push(RedirectRecord {
                                        op: RawRedirOp::Unsupported,
                                        source_fd,
                                        target: tok.unwrap_or_else(|| dummy_target(next)),
                                        span: (op_start, i),
                                    });
                                    i = next;
                                }
                            }
                        }
                        _ => {
                            let op = if matches!(chars.get(i), Some(':') | Some(',') | Some('?')) {
                                None
                            } else {
                                Some(op)
                            };
                            let (tok, next) = read_target(chars, i);
                            redirects.push(RedirectRecord {
                                op: RawRedirOp::Supported(op.unwrap()),
                                source_fd,
                                target: tok.unwrap_or_else(|| dummy_target(next)),
                                span: (op_start, span_end.max(i)),
                            });
                            i = next;
                        }
                    }
                }
                trailing_empty = true;
            }
            _ => {
                cur_start.get_or_insert(i);
                cur_text.push(c);
                i += 1;
            }
        }
    }
    finish_token!(TokKind::Word);
    if trailing_empty || !seg_items.is_empty() || !redirects.is_empty() {
        let rawslice: String = chars[seg_start..].iter().collect();
        segments.push(Segment {
            raw: rawslice,
            span: (seg_start, n),
            sep: pending_sep,
            items: seg_items,
            redirects,
            heredoc: false,
        });
    }
    Some(ScanResult {
        segments,
        malformed,
    })
}

fn dummy_target(n: usize) -> Tok {
    Tok {
        kind: TokKind::RedirectTarget,
        text: String::new(),
        resolvable: false,
        quoting: Quoting::None,
        subtexts: Vec::new(),
        span: (n, n),
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
/// `${}`, `$NAME`, bare `$` (and callers use the same for backticks).
#[allow(clippy::too_many_arguments)]
fn capture_expand(
    chars: &[char],
    start: usize,
    subtexts: &mut Vec<(String, Span)>,
    _quote_start: usize,
) -> (Option<String>, usize) {
    let n = chars.len();
    let first = *chars.get(start + 1).unwrap_or(&'\0');
    if first == '(' {
        if chars.get(start + 2) == Some(&'(') {
            let close = find_balanced(chars, start + 1, '(', ')');
            return (
                Some(chars[start..=close].iter().collect::<String>()),
                close + 1,
            );
        }
        let close = find_balanced(chars, start + 1, '(', ')');
        subtexts.push((
            chars[start + 2..close].iter().collect::<String>(),
            (start, close + 1),
        ));
        return (
            Some(chars[start..=close].iter().collect::<String>()),
            close + 1,
        );
    }
    if first == '{' {
        match (start + 1..n).find(|&j| chars[j] == '}') {
            Some(end) => {
                subtexts.push((
                    chars[start..=end].iter().collect::<String>(),
                    (start, end + 1),
                ));
                return (Some(chars[start..=end].iter().collect::<String>()), end + 1);
            }
            None => return (None, n),
        }
    }
    if first.is_ascii_alphabetic() || first == '_' {
        let mut end = start + 1;
        while end < n && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        subtexts.push((chars[start..end].iter().collect::<String>(), (start, end)));
        return (Some(chars[start..end].iter().collect::<String>()), end);
    }
    // bare $: opaque noise
    (Some("$".to_string()), (start + 2).min(n))
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
            let _ = chars[i];
            let inner: String = chars[i + 1..end].iter().collect();
            let _ = inner.clone();
            (!inner.contains(' ') && inner.contains(',')) || inner.contains("..")
        }
        _ => false,
    }
}

/// Read the redirect target starting at `i`: quote-aware until a top-level
/// delimiter or operator. Mildest failure: opaque (expansion), invalid stays
/// with the redirect operator decision.
fn read_target(chars: &[char], i: usize) -> (Option<Tok>, usize) {
    let n = chars.len();
    let mut j = i;
    // optional blanks between the operator and its target (`cmd > file`)
    while j < n && (chars[j] == ' ' || chars[j] == '\t' || chars[j] == '\n') {
        j += 1;
    }
    let text_start = j;
    let mut text = String::new();
    let mut resolvable = true;
    let mut quoting = Quoting::None;
    let mut subtexts: Vec<(String, Span)> = Vec::new();
    let mut sub_believable = false;
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
            quoting = Quoting::Escaped;
            j += 2;
            continue;
        }
        if c == '\'' || c == '"' {
            match (j + 1..n).find(|&k| chars[k] == c) {
                Some(end) => {
                    text.extend(chars[j + 1..end].iter());
                    if !matches!(quoting, Quoting::Escaped) {
                        quoting = if c == '\'' {
                            Quoting::Single
                        } else {
                            Quoting::Double
                        };
                    }
                    sub_believable = false;
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
            let (_inner, next) = capture_expand(chars, j, &mut subtexts, j);
            text.push('\u{fffd}');
            sub_believable = true;
            j = next;
            continue;
        }
        if c == '<' && chars.get(j + 1) == Some(&'(') {
            resolvable = false;
            let close = find_balanced(chars, j + 1, '(', ')');
            subtexts.push((
                chars[j + 2..close.min(n.saturating_sub(1))]
                    .iter()
                    .collect::<String>(),
                (j, close + 1),
            ));
            let _ = sub_believable;
            text.push('\u{fffd}');
            j = close + 1;
            continue;
        }
        if matches!(c, '*' | '?' | '[' | '~' | '{') {
            resolvable = false;
        }
        text.push(c);
        j += 1;
    }
    if text.is_empty() {
        (None, j)
    } else {
        (
            Some(Tok {
                kind: TokKind::RedirectTarget,
                text,
                resolvable,
                quoting,
                subtexts,
                span: (text_start, j),
            }),
            j,
        )
    }
}
