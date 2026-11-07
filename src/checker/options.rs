// Per-profile option parsing (design §Profiles, option grammars): fixed
// arity 0..=4, `--long=value` inline (arity 1 only, declared `inline: true`),
// `--` boundary, safe short clusters, per-occurrence values. Unknown options,
// missing values and invalid inline forms are `invalid` evidence (design
// §Parsing, parts, and evidence states). Values consume the fixed number of
// following argv tokens regardless of their shape; no variadic reading exists.

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
                // Inline values are valid only for a declared arity-one option
                // that explicitly accepts the inline form: everything else is
                // invalid evidence (fixed arity; no variadic reading).
                if spec.arity != 1 || spec.inline != Some(true) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::evidence::reason;

    fn tok(text: &str) -> ArgToken {
        ArgToken {
            text: text.to_string(),
            resolvable: is_plain_literal(text),
            span: (0, 0),
        }
    }

    fn spec(aliases: &[&str], arity: u8, inline: Option<bool>) -> (String, OptionSpec) {
        (
            aliases[0].trim_start_matches('-').to_string(),
            OptionSpec {
                aliases: aliases.iter().map(|a| a.to_string()).collect(),
                arity,
                inline,
            },
        )
    }

    fn opts(specs: Vec<(String, OptionSpec)>) -> BTreeMap<String, OptionSpec> {
        specs.into_iter().collect()
    }

    /// Fixed arity: an arity-two option consumes exactly two following tokens
    /// (issue 32 red test: "a fixed arity-two rename option").
    #[test]
    fn arity_two_option_consumes_exactly_two_values() {
        let mut map = opts(vec![spec(&["--rename"], 2, None)]);
        map.insert(
            "rename".to_string(),
            OptionSpec {
                aliases: vec!["--rename".into()],
                arity: 2,
                inline: None,
            },
        );
        let parsed = parse_options(&[tok("--rename"), tok("old"), tok("new")], &map);
        assert!(parsed.invalid_reasons.is_empty());
        assert_eq!(parsed.occurrences.len(), 1);
        assert_eq!(parsed.occurrences[0].values.len(), 2);
        assert_eq!(parsed.occurrences[0].values[0].text, "old");
        assert_eq!(parsed.occurrences[0].values[1].text, "new");
        // no leftover positional from the consumed values
        assert!(parsed.positionals.is_empty());
    }

    /// Fixed arity is never variable: a missing second value is invalid
    /// evidence (`option-value-missing`), it does not consume a positional or
    /// fall back to arity one.
    #[test]
    fn arity_two_option_with_one_value_is_invalid() {
        let map = opts(vec![spec(&["--rename"], 2, None)]);
        let parsed = parse_options(&[tok("--rename"), tok("old")], &map);
        assert_eq!(parsed.invalid_reasons, vec![reason::OPTION_VALUE_MISSING]);
    }

    /// The inline form is valid only for a declared arity-one option with
    /// `inline: true` (issue 32: "inline values for arity above one", and the
    /// arity-one default rejection).
    #[test]
    fn inline_form_requires_declared_inline_arity_one() {
        // arity one + inline: true → value ordinal one
        let map = opts(vec![spec(&["--name"], 1, Some(true))]);
        let parsed = parse_options(&[tok("--name=one")], &map);
        assert!(parsed.invalid_reasons.is_empty(), "{:?}", parsed);
        assert_eq!(parsed.occurrences.len(), 1);
        assert!(parsed.occurrences[0].inline);
        assert_eq!(parsed.occurrences[0].values[0].text, "one");

        // arity one without the inline opt-in is rejected (fail closed)
        let map = opts(vec![spec(&["--name"], 1, None)]);
        let parsed = parse_options(&[tok("--name=one")], &map);
        assert_eq!(parsed.invalid_reasons, vec![reason::INVALID_INLINE_OPTION]);

        // inline value for arity two is rejected — never a slicing reading
        let mut map = opts(vec![spec(&["--name"], 1, Some(true))]);
        map.insert(
            "rename".to_string(),
            OptionSpec {
                aliases: vec!["--rename".into()],
                arity: 2,
                inline: Some(true),
            },
        );
        let parsed = parse_options(&[tok("--rename=x")], &map);
        assert_eq!(parsed.invalid_reasons, vec![reason::INVALID_INLINE_OPTION]);

        // arity zero rejects the inline form like before
        let map = opts(vec![spec(&["--force"], 0, None)]);
        let parsed = parse_options(&[tok("--force=1")], &map);
        assert_eq!(parsed.invalid_reasons, vec![reason::INVALID_INLINE_OPTION]);
    }

    /// Repeated occurrences of one arity-one option each record their values
    /// separately (red test: "repeated `--file`") — occurrences are never
    /// collapsed to first or last.
    #[test]
    fn repeated_occurrences_keep_separate_values() {
        let map = opts(vec![spec(&["--file"], 1, None)]);
        let parsed = parse_options(&[tok("--file"), tok("a"), tok("--file"), tok("b")], &map);
        assert!(parsed.invalid_reasons.is_empty());
        assert_eq!(parsed.occurrences.len(), 2);
        assert_eq!(parsed.occurrences[0].ordinal, 1);
        assert_eq!(parsed.occurrences[0].values[0].text, "a");
        assert_eq!(parsed.occurrences[1].ordinal, 2);
        assert_eq!(parsed.occurrences[1].values[0].text, "b");
    }
}
