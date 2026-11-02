// Matching primitives (07 §7.5, 06 §6.4) and stage-aware flag extraction.

use super::grammar::{ArgvSequence, ArgvToken, IndexMapLike};

#[derive(Debug, Clone, Default)]
pub struct Flags {
    /// base flag → consumed value tokens in argv order (empty for arity 0).
    pub present: std::collections::BTreeMap<String, Vec<String>>,
    /// flag bases not declared in a stage's table (unknown flag ⇒ not fully
    /// parsed ⇒ allow blocked, 08 §8.2).
    pub unrecognized: Vec<String>,
    /// argv with flag tokens and their consumed value tokens removed.
    pub cleaned_argv: Vec<String>,
    pub fully_parsed: bool,
}

/// Per-stage flag parse (06 §6.4): base-flag identity, `--long=value` inline,
/// arity N consumes next N tokens, `--` terminates flags; values parse raw.
pub fn flags_of(argv: &[String], arity: &IndexMapLike) -> Flags {
    if argv.is_empty() {
        return Flags {
            cleaned_argv: Vec::new(),
            fully_parsed: true,
            ..Default::default()
        };
    }
    let mut present = std::collections::BTreeMap::new();
    let mut unrecognized = Vec::new();
    let mut cleaned: Vec<String> = vec![argv[0].clone()];
    let mut i = 1usize;
    let mut terminated = false;
    while i < argv.len() {
        if terminated {
            cleaned.push(argv[i].clone());
            i += 1;
            continue;
        }
        let tok = &argv[i];
        if tok == "--" {
            terminated = true;
            i += 1;
            continue;
        }
        match split_flag_token(tok) {
            Some((base, inline)) => match arity.get(&base) {
                Some(a) => {
                    let mut values = Vec::new();
                    let mut consumed = 0usize;
                    if let Some(v) = inline {
                        if *a == 0 {
                            values.push(v); // `--long=value` with declared arity 0
                        } else {
                            // inline form supplies the whole value set
                            values.push(v);
                        }
                    } else {
                        while consumed < *a as usize {
                            match argv.get(i + 1 + consumed) {
                                Some(v) => values.push(v.clone()),
                                None => break, // under-supplied arity ends the scan
                            }
                            consumed += 1;
                        }
                    }
                    present.insert(base, values);
                    i += 1 + consumed;
                    continue;
                }
                None => {
                    unrecognized.push(base);
                    cleaned.push(tok.clone()); // stays visible as a positional
                    i += 1;
                }
            },
            None => {
                cleaned.push(argv[i].clone());
                i += 1;
            }
        }
    }
    let fully_parsed = unrecognized.is_empty();
    Flags {
        present,
        unrecognized,
        cleaned_argv: cleaned,
        fully_parsed,
    }
}

fn split_flag_token(tok: &str) -> Option<(String, Option<String>)> {
    if !tok.starts_with('-') || tok == "-" || tok == "--" {
        return None;
    }
    // inline form `--long=value` / `-f=x`: base up to '='
    if let Some(eq) = tok.find('=') {
        if eq > 1 {
            return Some((tok[..eq].to_string(), Some(tok[eq + 1..].to_string())));
        }
    }
    // short forms `-a` and combined clusters `-rf` (the table resolves them),
    // long forms `--any-thing`
    Some((tok.to_string(), None))
}

// ── Condition matching ──────────────────────────────────────────────────────

/// Ordered equality on the first N tokens (06 §6.4): strings compare
/// literally, `{anyOf}` matches one alternative; contiguous from position 0.
pub fn matches_argv(seq: &[ArgvToken], argv: &[String]) -> bool {
    if seq.len() > argv.len() {
        return false;
    }
    seq.iter().zip(argv.iter()).all(|(t, s)| t.matches(s))
}

/// Raw-string glob, OpenCode-compatible (07 §7.5): `*` = zero+ chars incl.
/// spaces; `?` = one char; trailing `" *"` also matches the bare command.
pub fn glob(raw: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // trailing " *" also matches the bare command (07 §7.5); the standard
    // glob covers the suffixed forms on its own
    if pattern.len() > 2 && pattern.ends_with(" *") {
        let bare = &pattern[..pattern.len() - 2];
        if raw == bare {
            return true;
        }
    }
    glob_inner(raw.chars().peekable(), pattern.chars().peekable())
}

fn glob_inner(
    mut s: std::iter::Peekable<std::str::Chars<'_>>,
    mut p: std::iter::Peekable<std::str::Chars<'_>>,
) -> bool {
    while let Some(pc) = p.peek().copied() {
        match pc {
            '*' => {
                p.next();
                // `*` matches everything when it is the last pattern char;
                // otherwise every candidate prefix position is tried
                if p.peek().is_none() {
                    return true;
                }
                while s.peek().is_some() {
                    if glob_inner(s.clone(), p.clone()) {
                        return true;
                    }
                    s.next();
                }
                return false;
            }
            '?' => {
                p.next();
                if s.next().is_none() {
                    return false;
                }
            }
            _ => {
                p.next();
                if s.next() != Some(pc) {
                    return false;
                }
            }
        }
    }
    s.peek().is_none()
}

/// Scope entry (06 §6.3): returns the anchor length — how many cleaned argv
/// tokens the matched `argv` condition consumed (pattern conditions anchor at
/// 0). Rules then match against the stage tail `cleaned_argv[anchor..]`.
pub fn stage_anchor(stage: &super::grammar::Stage, cleaned: &[String], raw: &str) -> usize {
    stage
        .scope
        .any_of
        .iter()
        .filter_map(|cond| {
            if let Some(seq) = &cond.argv {
                matches_argv(&seq.0, cleaned).then_some(seq.0.len())
            } else if let Some(pattern) = &cond.pattern {
                glob(raw, pattern).then_some(0_usize)
            } else {
                None
            }
        })
        .max()
        .filter(|_| true)
        .unwrap_or_else(|| usize::MAX.saturating_sub(0)) // sentinel: no entry ⇒ no match
}

/// Sequence-condition matching against a part (legacy single-condition form).
pub fn matches_scope(argv_seq: &ArgvSequence, cleaned: &[String]) -> bool {
    matches_argv(&argv_seq.0, cleaned)
}

// ── Rule-condition evaluation on a part ──────────────────────────────────────

/// Evaluation context of one (part × stage) cell.
pub struct MatchCtx<'a> {
    /// Stage-cleaned argv (flags + consumed values removed).
    pub cleaned_argv: &'a [String],
    /// The part's raw text.
    pub raw: &'a str,
    /// True when the part is fully parsed (all tokens resolvable, no unknown
    /// flags against this stage — 08 §8.2).
    pub fully_parsed: bool,
    pub static_part: bool,
    /// Stage-flag facts.
    pub flags: &'a Flags,
}

pub fn rule_matches(rule: &super::grammar::Rule, ctx: &MatchCtx) -> bool {
    use super::grammar::FlagPresence::Present;

    if let Some(seq) = &rule.argv {
        if !matches_argv(&seq.0, ctx.cleaned_argv) {
            return false;
        }
    }
    if let Some(globs) = &rule.arg_value {
        // `argValue` (06 §6.5): ∃ positional token × ∃ glob — the positional
        // mirror of `flagValue`
        let holds = globs
            .iter()
            .any(|g| ctx.cleaned_argv.iter().any(|t| glob(t, g)));
        if !holds {
            return false;
        }
    }
    if let Some(pattern) = &rule.pattern {
        if !glob(ctx.raw, pattern) {
            return false;
        }
    }
    if let Some(class) = rule.classification {
        let is_static = super::grammar::Classification::Static == class;
        if ctx.static_part != is_static {
            return false;
        }
    }
    if let Some(flags) = &rule.flag {
        for (name, presence) in flags {
            let found = ctx.flags.present.contains_key(name);
            let holds = match presence {
                Present => found,
                super::grammar::FlagPresence::Absent => !found,
            };
            if !holds {
                return false;
            }
        }
    }
    if let Some(flag_values) = &rule.flag_value {
        // `flagValue` keys are anyOf across their map: each entry checks that
        // the named flag (whichever alias carried it) has A value matching the
        // glob — the same predicate expressed through alias spellings.
        let holds = flag_values.iter().any(|(name, value_glob)| {
            ctx.flags
                .present
                .get(name)
                .map(|values| values.iter().any(|v| glob(v, value_glob)))
                .unwrap_or(false)
        });
        if !holds {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_with_arity_values() {
        let arity: IndexMapLike = [
            ("-C".to_string(), 1),
            ("--force".to_string(), 0),
            ("-m".to_string(), 1),
        ]
        .into_iter()
        .collect();
        let f = flags_of(
            &argv(&["git", "-C", "/repo", "push", "--force", "origin", "main"]),
            &arity,
        );
        assert!(f.present.contains_key("-C"));
        assert_eq!(f.present.get("-C").unwrap().len(), 1);
        assert_eq!(f.present.get("-C").unwrap()[0], "/repo");
        assert!(f.present.contains_key("--force"));
        // cleaned: flag tokens + consumed values removed
        assert_eq!(f.cleaned_argv, argv(&["git", "push", "origin", "main"]));
        assert!(f.fully_parsed);
    }

    #[test]
    fn unknown_flag_blocks_fully_parsed() {
        let arity: IndexMapLike = [("--force".to_string(), 0)].into_iter().collect();
        let f = flags_of(&argv(&["git", "push", "--stealth-x"]), &arity);
        assert_eq!(f.unrecognized, vec!["--stealth-x".to_string()]);
        assert!(!f.fully_parsed);
    }

    #[test]
    fn combined_shorts_are_unknown() {
        let arity: IndexMapLike = [("-f".to_string(), 0)].into_iter().collect();
        let f = flags_of(&argv(&["echo", "-abc"]), &arity);
        assert_eq!(f.unrecognized, vec!["-abc".to_string()]);
    }

    #[test]
    fn dash_dash_terminates() {
        let arity: IndexMapLike = [("-f".to_string(), 0)].into_iter().collect();
        let f = flags_of(&argv(&["cmd", "--", "-f"]), &arity);
        assert!(f.present.is_empty());
        assert_eq!(f.cleaned_argv, argv(&["cmd", "-f"]));
        assert!(f.fully_parsed);
    }

    #[test]
    fn inline_value_form() {
        let arity: IndexMapLike = [("--long".to_string(), 0)].into_iter().collect();
        let f = flags_of(&argv(&["cmd", "--long=x"]), &arity);
        assert_eq!(f.present.get("--long").unwrap(), &vec!["x".to_string()]);
    }

    #[test]
    fn glob_basics() {
        assert!(glob("git status", "git status *")); // trailing " *" bare-form
        assert!(glob("git status -v", "git status *"));
        assert!(glob("docker push foo", "docker *"));
        assert!(!glob("cat docker", "docker *"));
        assert!(glob("ab", "a?"));
        assert!(!glob("b", "a?"));
        assert!(glob("git status", "*"));
    }

    #[test]
    fn argv_sequence_prefix() {
        let seq = ArgvSequence(vec![
            ArgvToken::Word("git".into()),
            ArgvToken::AnyOf {
                any_of: vec!["push".into(), "pull".into()],
            },
        ]);
        assert!(matches_argv(&seq.0, &argv(&["git", "push", "origin"])));
        assert!(!matches_argv(&seq.0, &argv(&["git", "commit"])));
        assert!(!matches_argv(&seq.0, &argv(&["git"])));
        assert!(matches_argv(&seq.0, &argv(&["git", "push"])));
    }
}
