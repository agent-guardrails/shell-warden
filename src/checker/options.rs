// Per-profile option parsing (design §Profiles, option grammars): aliases,
// arity 0..=4, `--long=value` inline (positive arity, arity 1, inline not
// refused), `--` boundary, safe short clusters, per-occurrence values.
// Unknown options, missing values and invalid inline forms are `invalid`
// evidence (design §Parsing, parts, and evidence states). Values consume the
// following argv tokens regardless of their shape (v1 06 §6.4 semantics).

use super::evidence::{ArgToken, reason};
use super::grammar::OptionSpec;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct OptionOccurrence {
    pub canonical: String,
    /// Alias exactly as present in argv.
    pub alias_used: String,
    /// 1-based ordinal among occurrences of this canonical ID (source order).
    pub ordinal: u32,
    /// Consumed (separate) or inline values, in order.
    pub values: Vec<ArgToken>,
    pub inline: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedOptions {
    /// Positional arguments: option tokens and every consumed value token are
    /// excluded; everything after the `--` boundary is positional.
    pub positionals: Vec<ArgToken>,
    pub occurrences: Vec<OptionOccurrence>,
    /// Stable reason codes; non-empty ⇒ invalid evidence for this profile.
    pub invalid_reasons: Vec<&'static str>,
    /// Token index of the `--` boundary (None = absent).
    pub dashdash: Option<usize>,
}

pub fn parse_options(argv: &[ArgToken], options: &BTreeMap<String, OptionSpec>) -> ParsedOptions {
    let mut aliases: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lookup: Vec<(&String, &OptionSpec)> = Vec::new();
    for (idx, (canonical, spec)) in options.iter().enumerate() {
        lookup.push((canonical, spec));
        for alias in &spec.aliases {
            // loader validation keeps aliases unique inside a profile
            aliases.insert(alias.as_str(), idx);
        }
    }

    let mut out = ParsedOptions::default();
    let mut counts: BTreeMap<usize, u32> = BTreeMap::new();
    let mut i = 0usize;
    let mut terminated = false;

    while i < argv.len() {
        let tok = &argv[i];
        if terminated {
            out.positionals.push(tok.clone());
            i += 1;
            continue;
        }
        if tok.text == "--" {
            terminated = true;
            out.dashdash = Some(i);
            i += 1;
            continue;
        }
        let opt_token = tok.text.len() > 1 && tok.text.starts_with('-');
        if !opt_token {
            out.positionals.push(tok.clone());
            i += 1;
            continue;
        }

        // inline form `alias=value`
        if let Some(eq) = tok.text.find('=')
            && eq > 1
        {
            let alias_part = &tok.text[..eq];
            if let Some(&idx) = aliases.get(alias_part) {
                let spec = lookup[idx].1;
                if spec.arity == 0 || spec.arity > 1 || spec.inline == Some(false) {
                    out.invalid_reasons.push(reason::INVALID_INLINE_OPTION);
                    out.positionals.push(tok.clone());
                    i += 1;
                    continue;
                }
                let value = tok.text[eq + 1..].to_string();
                consume(
                    idx,
                    alias_part.to_string(),
                    lookup[idx].0.clone(),
                    counts.entry(idx),
                    vec![ArgToken {
                        text: value,
                        resolvable: is_plain_literal(&tok.text[eq + 1..]),
                        span: tok.span,
                    }],
                    true,
                    &mut out,
                );
                i += 1;
                continue;
            }
        }

        // exact alias match
        if let Some(&idx) = aliases.get(tok.text.as_str()) {
            let spec = lookup[idx].1;
            let mut values: Vec<ArgToken> = Vec::new();
            for k in 1..=usize::from(spec.arity) {
                match argv.get(i + k) {
                    Some(v) => values.push(v.clone()),
                    None => {
                        out.invalid_reasons.push(reason::OPTION_VALUE_MISSING);
                        break;
                    }
                }
            }
            consume(
                idx,
                tok.text.clone(),
                lookup[idx].0.clone(),
                counts.entry(idx),
                values,
                false,
                &mut out,
            );
            i += 1 + usize::from(spec.arity);
            continue;
        }

        // safe short cluster: `-rf.`-like bodies where EVERY char is a
        // declared alias; only the last char may have positive arity
        let body = &tok.text[1..];
        let cluster_ok = !tok.text.starts_with("--")
            && body.len() >= 2
            && body.chars().enumerate().all(|(k, ch)| {
                let spec = aliases
                    .get(&*format!("-{ch}"))
                    .copied()
                    .map(|idx| lookup[idx].1);
                match spec {
                    Some(s) => s.arity == 0 || k + 1 == body.chars().count(),
                    None => false,
                }
            });
        if cluster_ok {
            let mut j = i;
            for ch in body.chars() {
                let alias = format!("-{ch}");
                let idx = aliases[&*alias];
                let spec = lookup[idx].1;
                let mut values: Vec<ArgToken> = Vec::new();
                let mut consumed = 0usize;
                if spec.arity > 0 {
                    for k in 1..=usize::from(spec.arity) {
                        match argv.get(j + k) {
                            Some(v) => values.push(v.clone()),
                            None => {
                                out.invalid_reasons.push(reason::OPTION_VALUE_MISSING);
                                break;
                            }
                        }
                    }
                    consumed = usize::from(spec.arity);
                }
                consume(
                    idx,
                    alias,
                    lookup[idx].0.clone(),
                    counts.entry(idx),
                    values,
                    false,
                    &mut out,
                );
                j += 1 + consumed;
            }
            i = j;
            continue;
        }

        out.invalid_reasons.push(reason::UNKNOWN_OPTION);
        // keep the token visible as a positional for diagnostics/raw rules
        out.positionals.push(tok.clone());
        i += 1;
    }
    out
}

#[allow(clippy::type_complexity)]
fn consume(
    idx: usize,
    alias_used: String,
    canonical: String,
    count: std::collections::btree_map::Entry<usize, u32>,
    values: Vec<ArgToken>,
    inline: bool,
    out: &mut ParsedOptions,
) {
    let ord = {
        let c = count.or_insert(0);
        *c += 1;
        *c
    };
    let _ = idx;
    out.occurrences.push(OptionOccurrence {
        canonical,
        alias_used,
        ordinal: ord,
        values,
        inline,
    });
}

fn is_plain_literal(s: &str) -> bool {
    // active expansions left the replacement marker in the decoded text
    !s.contains('\u{fffd}')
}
