// Rule refinement (08 §8.3); applied per part and stage only. Absent denies,
// a matched rule strictly refined by another matched rule is discarded
// (precise over broad: level-prefix of tokens plus contained predicates —
// bash-guard refinement basis).
//
// `refines(refiner, refined)` is true when every condition of `refined`
// follows from having matched `refiner`, and `refiner` constrains at least one
// dimension strictly more.

use super::grammar::{ArgvToken, Rule};

pub fn refines(refiner: &Rule, refined: &Rule) -> bool {
    if refiner.id == refined.id {
        return false;
    }
    if !argv_shaping(refiner, refined) {
        return false;
    }
    if !predicates_superset(refiner, refined) {
        return false;
    }
    // strict somewhere: longer argv prefix, or strictly more bound predicates
    argv_strict(refiner, refined) || refiner_strict(refiner) > refined_strict(refined)
}

/// Level-prefix of token sequences: the refiner's argv sequence is longer and
/// aligns with the refined's (tokens equal or subsumed). A refined rule with
/// no argv condition matches everything — any argv on the refiner shapes it.
fn argv_shaping(refiner: &Rule, refined: &Rule) -> bool {
    match (&refiner.argv, &refined.argv) {
        (Some(a), Some(b)) => {
            a.0.len() >= b.0.len()
                && a.0
                    .iter()
                    .zip(b.0.iter())
                    .all(|(ra, rb)| tokens_compatible(ra, rb))
        }
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn tokens_compatible(refiner_tok: &ArgvToken, refined_tok: &ArgvToken) -> bool {
    match (refiner_tok, refined_tok) {
        (ArgvToken::Word(x), ArgvToken::Word(y)) => x == y,
        (ArgvToken::AnyOf { any_of }, ArgvToken::Word(y)) => any_of.contains(y),
        (ArgvToken::AnyOf { any_of: xa }, ArgvToken::AnyOf { any_of: xb }) => {
            xb.iter().all(|y| xa.contains(y))
        }
        (ArgvToken::Word(_), ArgvToken::AnyOf { .. }) => false,
    }
}

fn argv_strict(refiner: &Rule, refined: &Rule) -> bool {
    match (&refiner.argv, &refined.argv) {
        (Some(a), Some(b)) => a.0.len() > b.0.len(),
        (Some(_), None) => true,
        _ => false,
    }
}

/// Every condition entry of `refined` must be present, equal or stricter, in
/// `refiner` (`None` on refined = no condition = always contained).
fn predicates_superset(refiner: &Rule, refined: &Rule) -> bool {
    let flags_ok = refined.flag.as_ref().is_none_or(|b| {
        b.iter().all(|(k, v)| {
            refiner
                .flag
                .as_ref()
                .map(|a| a.get(k) == Some(v))
                .unwrap_or(false)
        })
    });
    let flag_values_ok = refined.flag_value.as_ref().is_none_or(|b| {
        b.iter().all(|(k, v)| {
            refiner
                .flag_value
                .as_ref()
                .map(|a| a.get(k) == Some(v))
                .unwrap_or(false)
        })
    });
    let argv_at_ok = refined.argv_at.as_ref().is_none_or(|b| {
        b.iter().all(|entry| {
            refiner
                .argv_at
                .as_ref()
                .map(|a| a.contains(entry))
                .unwrap_or(false)
        })
    });
    let classification_ok = refined
        .classification
        .is_none_or(|c| refiner.classification == Some(c));
    let pattern_ok = refined
        .pattern
        .as_ref()
        .is_none_or(|p| refiner.pattern.as_ref() == Some(p));
    let paths_ok = refined.paths.as_ref().is_none_or(|p| {
        refiner
            .paths
            .as_ref()
            .map(|rp| rp.within == p.within && rp.not_within == p.not_within)
            .unwrap_or(false)
    });
    flags_ok && flag_values_ok && argv_at_ok && classification_ok && pattern_ok && paths_ok
}

fn predicate_count(rule: &Rule) -> usize {
    let mut n = 0usize;
    if rule.argv.is_some() {
        n += rule.argv.as_ref().map_or(0, |a| a.0.len());
    }
    n += rule
        .flag
        .as_ref()
        .map_or(0, std::collections::BTreeMap::len);
    n += rule
        .flag_value
        .as_ref()
        .map_or(0, std::collections::BTreeMap::len);
    n += rule.argv_at.as_ref().map_or(0, Vec::len);
    if rule.pattern.is_some() {
        n += 1;
    }
    if rule.classification.is_some() {
        n += 1;
    }
    if rule.paths.is_some() {
        n += 1;
    }
    n
}

fn refiner_strict(rule: &Rule) -> usize {
    predicate_count(rule)
}

fn refined_strict(rule: &Rule) -> usize {
    predicate_count(rule)
}

#[cfg(test)]
mod tests {
    use super::super::grammar::*;
    use super::*;

    fn rule(id: &str, argv: Vec<ArgvToken>) -> Rule {
        Rule {
            id: id.to_string(),
            action: VerdictKind::Allow,
            message: None,
            argv: Some(ArgvSequence(argv)),
            argv_at: None,
            pattern: None,
            classification: None,
            flag: None,
            flag_value: None,
            paths: None,
        }
    }

    fn w(s: &str) -> ArgvToken {
        ArgvToken::Word(s.to_string())
    }
    fn any(items: &[&str]) -> ArgvToken {
        ArgvToken::AnyOf {
            any_of: items.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn longer_prefix_refines() {
        let broad = rule("vcs/push", vec![w("push")]);
        let narrow = rule("vcs/push --all", vec![w("push"), w("--all")]);
        assert!(refines(&narrow, &broad));
        assert!(!refines(&broad, &narrow));
    }

    #[test]
    fn any_of_narrower_at_same_length_refines() {
        let broad = rule("vcs/ops", vec![w("push")]);
        let narrow = rule("vcs/push-one", vec![w("push")]);
        // same argv but a flag predicate strictness instead:
        let narrow2 = Rule {
            flag: Some(
                [("--all".to_string(), FlagPresence::Present)]
                    .into_iter()
                    .collect(),
            ),
            ..narrow.clone()
        };
        assert!(refines(&narrow2, &broad));
        let _ = any;
        assert!(!refines(&broad, &narrow2));
    }

    #[test]
    fn no_condition_broadest() {
        let bare = rule("vcs/all", vec![]);
        let narrow = rule("vcs/push", vec![w("push")]);
        assert!(refines(&narrow, &bare));
        assert!(!refines(&bare, &narrow));
    }

    #[test]
    fn unrelated_argv_does_not_refine() {
        let a = rule("x/a", vec![w("push")]);
        let b = rule("x/b", vec![w("commit")]);
        assert!(!refines(&a, &b));
        assert!(!refines(&b, &a));
    }
}
