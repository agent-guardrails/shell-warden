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
use super::parameter::{self, ParameterForm, ParameterWord};

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
    /// Exact word syntax before quote removal or expansion replacement.
    /// Parameter recognition must never reconstruct this from decoded text.
    pub source: String,
    /// Decoded text (quotes resolved). Unresolvable tokens keep the raw
    /// textual form for diagnostics; decision logic must consult `resolvable`.
    pub text: String,
    /// Fully known literal value (no active expansion / glob / brace / tilde /
    /// broken quoting).
    pub resolvable: bool,
    pub quoting: Quoting,
    /// Inner texts of active executions found inside this token (`$(…)`,
    /// backticks, process substitution) — split recursively.
    pub subtexts: Vec<(String, Span)>,
    pub span: Span,
}

impl Tok {
    /// Supported FD operands are literal unsigned decimal descriptors. Bash
    /// `>&` can interpret signed numbers as filenames instead. Preserve the
    /// existing numeric range; closing/moving descriptors remain unsupported.
    pub fn is_fd_operand(&self) -> bool {
        self.resolvable
            && self.text.bytes().all(|byte| byte.is_ascii_digit())
            && self.text.parse::<i32>().is_ok()
    }

    /// A supported argument/redirect candidate. This is syntactic evidence,
    /// not an allow permission; the effective value is still unknown.
    pub fn parameter(&self) -> Option<ParameterWord> {
        let parameter = parameter::parse(&self.source)?;
        (parameter.form == ParameterForm::DoubleQuoted).then_some(parameter)
    }

    /// A syntactically literal destination and supported value expression.
    /// The caller must separately establish prefix/declaration assignment
    /// semantics; an ordinary argument containing '=' is not an assignment.
    pub fn assignment_parameter(&self) -> Option<(&str, ParameterWord)> {
        let (name, value) = self.source.split_once('=')?;
        parameter::is_name(name).then_some(())?;
        Some((name, parameter::parse(value)?))
    }
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
    let mut cur_source_start: Option<usize> = None;
    let mut cur_quoted = false;
    let mut cur_resolvable = true;
    let mut cur_quoting = Quoting::None;
    let mut cur_sub: Vec<(String, Span)> = Vec::new();
    let mut trailing_empty = false; // last op chain saw a redirect target
    let mut i = 0usize;

    macro_rules! finish_token {
        ($kind:expr) => {
            if !cur_text.is_empty() || cur_quoted {
                // Spans are diagnostic bookkeeping only: end = decode length
                // from the token start (never security-relevant).
                let end = cur_start.unwrap_or(0) + cur_text.len().max(1);
                seg_items.push(Item::Tok(Tok {
                    kind: $kind,
                    source: chars[cur_source_start.unwrap_or(0)..i.min(n)]
                        .iter()
                        .collect(),
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
            cur_source_start = None;
            cur_quoted = false;
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

    while i < n {
        let c = chars[i];
        if cur_source_start.is_none() && !c.is_whitespace() {
            cur_source_start = Some(i);
        }
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
            '#' if cur_text.is_empty() && !cur_quoted => {
                // comment: the rest of the input is decoration
                finish_token!(TokKind::Word);
                trailing_empty = false;
                new_segment!(i);
                i = n;
                break;
            }
            '\'' => {
                cur_quoted = true;
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
                cur_quoted = true;
                cur_quoting = Quoting::Double;
                cur_start.get_or_insert(i);
                let mut j = i + 1;
                let mut tail = String::new();
                let mut escaped = false;
                let mut ok = false;
                while j < n {
                    let ch = chars[j];
                    if escaped {
                        if ch != '\n' {
                            if !matches!(ch, '$' | '`' | '"' | '\\') {
                                tail.push('\\');
                            }
                            tail.push(ch);
                        }
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
                        let (inner, next) = capture_expand(chars, j, &mut cur_sub);
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
                if chars[i + 1] != '\n' {
                    cur_text.push(chars[i + 1]);
                }
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
                let (inner, next) = capture_expand(chars, i, &mut cur_sub);
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
                    chars
                        .get(i + 2..close)
                        .unwrap_or_default()
                        .iter()
                        .collect::<String>(),
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
                    chars
                        .get(i + 2..close)
                        .unwrap_or_default()
                        .iter()
                        .collect::<String>(),
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
                if !cur_text.is_empty()
                    && chars[cur_source_start.unwrap_or(i)..i]
                        .iter()
                        .collect::<String>()
                        .replace("\\\n", "")
                        .chars()
                        .all(|ch| ch.is_ascii_digit())
                {
                    source_fd = cur_text.parse::<u32>().ok();
                    cur_text.clear();
                    cur_source_start = None;
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
                            let digits = tok.as_ref().map(Tok::is_fd_operand);
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
        source: String::new(),
        text: String::new(),
        resolvable: false,
        quoting: Quoting::None,
        subtexts: Vec::new(),
        span: (n, n),
    }
}

/// Capture an active expansion at `start`, recording only executable inner
/// texts and returning the next index after the construct.
fn capture_expand(
    chars: &[char],
    start: usize,
    subtexts: &mut Vec<(String, Span)>,
) -> (Option<String>, usize) {
    let n = chars.len();
    if chars.get(start) == Some(&'`') {
        return match (start + 1..n).find(|&index| chars[index] == '`') {
            Some(end) => {
                subtexts.push((
                    chars[start + 1..end].iter().collect::<String>(),
                    (start, end + 1),
                ));
                (Some(chars[start..=end].iter().collect::<String>()), end + 1)
            }
            None => (None, n),
        };
    }
    let first = *chars.get(start + 1).unwrap_or(&'\0');
    if first == '(' {
        if chars.get(start + 2) == Some(&'(') {
            let close = find_balanced(chars, start + 1, '(', ')');
            capture_executable_subtexts(chars, (start + 3, close), subtexts);
            return (
                Some(chars[start..=close].iter().collect::<String>()),
                close + 1,
            );
        }
        let close = find_balanced(chars, start + 1, '(', ')');
        subtexts.push((
            chars
                .get(start + 2..close)
                .unwrap_or_default()
                .iter()
                .collect::<String>(),
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
                capture_executable_subtexts(chars, (start + 2, end), subtexts);
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
        return (Some(chars[start..end].iter().collect::<String>()), end);
    }
    // Positional/special parameters consume their next character. A literal
    // dollar must not swallow a closing quote or command delimiter.
    let next = if first.is_ascii_digit() || matches!(first, '?' | '$' | '#' | '@' | '*' | '-' | '!')
    {
        start + 2
    } else {
        start + 1
    };
    (Some("$".to_string()), next.min(n))
}

fn capture_executable_subtexts(chars: &[char], range: Span, subtexts: &mut Vec<(String, Span)>) {
    let (start, end) = range;
    let mut index = start;
    while index < end {
        match chars[index] {
            '\\' => index = (index + 2).min(end),
            '$' | '`' => {
                let (_, next) = capture_expand(chars, index, subtexts);
                index = next.min(end);
            }
            '<' | '>' if chars.get(index + 1) == Some(&'(') => {
                let close = find_balanced(chars, index + 1, '(', ')');
                subtexts.push((
                    chars
                        .get(index + 2..close)
                        .unwrap_or_default()
                        .iter()
                        .collect::<String>(),
                    (index, close + 1),
                ));
                index = (close + 1).min(end);
            }
            '\'' => {
                index = (index + 1..end)
                    .find(|&candidate| chars[candidate] == '\'')
                    .map_or(end, |close| close + 1);
            }
            '"' => {
                let close = (index + 1..end)
                    .find(|&candidate| chars[candidate] == '"')
                    .unwrap_or(end);
                capture_executable_subtexts(chars, (index + 1, close), subtexts);
                index = (close + 1).min(end);
            }
            _ => index += 1,
        }
    }
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
    // Find the source boundary, then use the ordinary word scanner. Maintaining
    // a second quote/expansion decoder here loses escaped quotes and can turn
    // a double-quoted expansion into an apparently literal redirect path.
    while j < n {
        let c = chars[j];
        match c {
            '\\' => j = (j + 2).min(n),
            '\'' => {
                j = (j + 1..n)
                    .find(|&k| chars[k] == '\'')
                    .map_or(n, |end| end + 1);
            }
            '"' => {
                j += 1;
                while j < n {
                    match chars[j] {
                        '\\' => j = (j + 2).min(n),
                        '"' => {
                            j += 1;
                            break;
                        }
                        '$' | '`' => {
                            let (_, next) = capture_expand(chars, j, &mut Vec::new());
                            j = next.min(n);
                        }
                        _ => j += 1,
                    }
                }
            }
            '$' | '`' => {
                let (_, next) = capture_expand(chars, j, &mut Vec::new());
                j = next.min(n);
            }
            '<' | '>' if chars.get(j + 1) == Some(&'(') => {
                j = (find_balanced(chars, j + 1, '(', ')') + 1).min(n);
            }
            ' ' | '\t' | '\r' | '\n' | ';' | '|' | '&' | '<' | '>' | '(' | ')' => break,
            _ => j += 1,
        }
    }
    let source: String = chars[text_start..j].iter().collect();
    let token = scan_chars(&source, &chars[text_start..j]).and_then(|mut result| {
        if result.malformed || result.segments.len() != 1 {
            return None;
        }
        let mut segment = result.segments.pop()?;
        if !segment.redirects.is_empty() || segment.items.len() != 1 {
            return None;
        }
        match segment.items.pop()? {
            Item::Tok(mut token) => {
                token.kind = TokKind::RedirectTarget;
                token.span = (text_start, j);
                for (_, span) in &mut token.subtexts {
                    span.0 += text_start;
                    span.1 += text_start;
                }
                Some(token)
            }
        }
    });
    (token, j)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(raw: &str) -> Tok {
        let result = scan(raw);
        assert!(!result.malformed, "{raw}");
        assert_eq!(result.segments.len(), 1, "{raw}");
        assert_eq!(result.segments[0].items.len(), 1, "{raw}");
        match &result.segments[0].items[0] {
            Item::Tok(token) => token.clone(),
        }
    }

    #[test]
    fn literal_dollar_does_not_consume_a_quote_or_delimiter() {
        for source in ["$\"", "$;", "$ ", "$\n", "$>"] {
            let chars: Vec<_> = source.chars().collect();
            let (_, next) = capture_expand(&chars, 0, &mut Vec::new());
            assert_eq!(next, 1, "{source}");
        }
        for source in ["$?", "$$", "$1", "$@", "$#", "$*", "$-", "$!"] {
            let chars: Vec<_> = source.chars().collect();
            let (_, next) = capture_expand(&chars, 0, &mut Vec::new());
            assert_eq!(next, 2, "{source}");
        }
    }

    #[test]
    fn parameter_candidates_use_original_word_syntax() {
        for source in [
            "\"$HOME\"",
            "\"${HOME}/cache\"",
            "\"$HOME/space here\"",
            "\"$HOME/../*\"",
            r#""$HOME/\$USER""#,
            "\"$HOME/日本語\"",
        ] {
            let token = word(source);
            assert_eq!(token.source, source);
            assert!(token.parameter().is_some(), "{source}");
            // Recognition is not permission and does not invent literal argv.
            assert!(!token.resolvable, "{source}");
        }
    }

    #[test]
    fn literal_escapes_use_shell_not_c_string_semantics() {
        for (source, expected) in [
            (r#""\n\t\r\q""#, r"\n\t\r\q"),
            (r"\n\t\r", "ntr"),
            (r#""\$HOME""#, "$HOME"),
            ("\"a\\\nb\"", "ab"),
            ("a\\\nb", "ab"),
        ] {
            let token = word(source);
            assert_eq!(token.text, expected, "{source}");
            assert!(token.resolvable, "{source}");
            assert_eq!(token.parameter(), None, "{source}");
        }
        assert!(scan("\\\n").segments.is_empty());
        let result = scan("echo 2\\\n>out");
        assert_eq!(result.segments[0].items.len(), 1);
        assert_eq!(result.segments[0].redirects[0].source_fd, Some(2));
    }

    #[test]
    fn incomplete_substitutions_never_panic_or_qualify_as_parameters() {
        for raw in ["$(", "<(", ">(", "\"$HOME/$(", "\"$HOME/<("] {
            let result = scan(raw);
            for segment in result.segments {
                for item in segment.items {
                    let Item::Tok(token) = item;
                    assert_eq!(token.parameter(), None, "{raw}");
                    assert!(!token.resolvable, "{raw}");
                }
            }
        }
    }

    #[test]
    fn literal_or_unsupported_words_do_not_acquire_parameter_evidence() {
        for source in [
            "'$HOME/cache'",
            r#""\$HOME/cache""#,
            "$HOME/cache",
            "\"$HOME/$USER\"",
            "\"$HOME/$(touch marker)\"",
            "\"${HOME:-/tmp}\"",
            "\"$HOME\"\"/cache\"",
            "prefix\"$HOME\"",
        ] {
            let token = word(source);
            assert_eq!(token.source, source);
            assert_eq!(token.parameter(), None, "{source}");
        }
    }

    #[test]
    fn assignment_candidates_keep_the_literal_destination_separate() {
        for source in ["CACHE=$HOME/cache", "CACHE=\"${HOME}/cache\""] {
            let token = word(source);
            assert_eq!(token.source, source);
            assert_eq!(token.parameter(), None);
            let (destination, value) = token.assignment_parameter().unwrap();
            assert_eq!(destination, "CACHE");
            assert_eq!(value.name, "HOME");
            assert_eq!(value.suffix, "/cache");
            assert!(!token.resolvable);
        }
        for source in [
            "'CACHE'=\"$HOME/cache\"",
            "CACHE\\=\"$HOME/cache\"",
            "2CACHE=$HOME/cache",
            "CACHE=\"$HOME/$USER\"",
        ] {
            assert_eq!(word(source).assignment_parameter(), None, "{source}");
        }
    }

    #[test]
    fn word_source_is_preserved_across_quotes_unicode_and_separators() {
        let result = scan("echo 日本語 \"$HOME/a b\";echo '${HOME}' > \"${HOME}/out\"");
        let sources: Vec<_> = result
            .segments
            .iter()
            .flat_map(|segment| &segment.items)
            .map(|item| match item {
                Item::Tok(token) => token.source.as_str(),
            })
            .collect();
        assert_eq!(
            sources,
            ["echo", "日本語", "\"$HOME/a b\"", "echo", "'${HOME}'"]
        );
        assert_eq!(
            result.segments[1].redirects[0].target.source,
            "\"${HOME}/out\""
        );
    }

    #[test]
    fn redirect_targets_share_argument_quote_and_expansion_scanning() {
        for source in [
            "\"$HOME/out\"",
            "\"$HOME/a b\"",
            r#""$HOME/\"quoted\"""#,
            r#""$HOME/\$USER""#,
            "\"${HOME}/日本語\"",
        ] {
            let result = scan(&format!("echo > {source}"));
            let target = &result.segments[0].redirects[0].target;
            assert_eq!(target.source, source);
            assert!(target.parameter().is_some(), "{source}");
            assert!(!target.resolvable, "{source}");
        }
        for source in ["'$HOME/out'", r#""\$HOME/out""#] {
            let result = scan(&format!("echo > {source}"));
            let target = &result.segments[0].redirects[0].target;
            assert_eq!(target.source, source);
            assert_eq!(target.parameter(), None);
            assert!(target.resolvable, "{source}");
        }
    }

    #[test]
    fn empty_literal_words_remain_observed_tokens() {
        for source in ["\"\"", "''"] {
            let token = word(source);
            assert_eq!(token.source, source);
            assert_eq!(token.text, "");
            assert!(token.resolvable);
            assert_eq!(token.parameter(), None);
        }
        let result = scan("echo 2>out");
        assert_eq!(result.segments[0].items.len(), 1);
        assert_eq!(result.segments[0].redirects[0].source_fd, Some(2));
        for source in ["echo \"2\">out", "echo '2'>out", "echo \\2>out"] {
            let result = scan(source);
            assert_eq!(result.segments[0].items.len(), 2, "{source}");
            assert_eq!(result.segments[0].redirects[0].source_fd, None, "{source}");
        }
    }

    #[test]
    fn redirect_substitutions_are_captured_not_hidden_by_a_parameter_prefix() {
        for source in [
            "\"$HOME/$(touch marker)\"",
            "\"${HOME:-$(touch marker)}\"",
            "\"$HOME/`touch marker`\"",
            "\"$HOME/$((1 + $(touch marker)))\"",
        ] {
            let result = scan(&format!("echo > {source}"));
            let target = &result.segments[0].redirects[0].target;
            assert_eq!(target.source, source);
            assert_eq!(target.parameter(), None);
            assert!(!target.resolvable);
            assert_eq!(target.subtexts.len(), 1, "{source}");
            assert_eq!(target.subtexts[0].0, "touch marker", "{source}");
        }
    }

    fn executable_subtexts(raw: &str) -> Vec<String> {
        scan(raw)
            .segments
            .into_iter()
            .flat_map(|segment| segment.items)
            .flat_map(|item| match item {
                Item::Tok(token) => token.subtexts,
            })
            .map(|(text, _)| text)
            .collect()
    }

    #[test]
    fn variable_braced_and_arithmetic_expansions_are_not_executable_subtexts() {
        // Given / When / Then
        for raw in ["echo $VAR", "echo ${NAME}", "echo $((1 + 2))"] {
            assert_eq!(executable_subtexts(raw), Vec::<String>::new(), "{raw}");
        }
    }

    #[test]
    fn shell_execution_forms_are_executable_subtexts() {
        // Given / When / Then
        for raw in [
            "echo $(denied-command)",
            "echo `denied-command`",
            "cat <(denied-command)",
            "cat >(denied-command)",
        ] {
            assert_eq!(
                executable_subtexts(raw),
                vec!["denied-command".to_string()],
                "{raw}"
            );
        }
    }

    #[test]
    fn command_substitution_inside_braced_expansion_is_executable_subtext() {
        // Given / When / Then
        assert_eq!(
            executable_subtexts("echo ${X:-$(denied-command)}"),
            vec!["denied-command".to_string()]
        );
    }

    #[test]
    fn escaped_command_substitution_inside_braced_expansion_is_literal() {
        // Given / When / Then
        assert_eq!(
            executable_subtexts(r"echo ${X:-\$(denied-command)}"),
            Vec::<String>::new()
        );
    }
}
