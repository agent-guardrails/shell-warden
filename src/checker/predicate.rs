//! Three-valued proofs. Unknown is not false, a matched vote, or an error.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Match,
    NoMatch,
    Unknown(Vec<String>),
}

impl Predicate {
    pub fn known(value: bool) -> Self {
        if value { Self::Match } else { Self::NoMatch }
    }

    pub fn unknown(coordinate: String) -> Self {
        Self::Unknown(vec![coordinate])
    }

    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }

    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::NoMatch, _) | (_, Self::NoMatch) => Self::NoMatch,
            (Self::Match, value) | (value, Self::Match) => value,
            (Self::Unknown(mut a), Self::Unknown(b)) => {
                a.extend(b);
                a.sort();
                a.dedup();
                Self::Unknown(a)
            }
        }
    }

    /// Evaluate the next conjunct only while it can affect the complete proof.
    /// Unknown must continue: a later NoMatch can still settle the rule.
    pub fn and_then(self, other: impl FnOnce() -> Self) -> Self {
        match self {
            Self::NoMatch => Self::NoMatch,
            value => value.and(other()),
        }
    }

    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Match, _) | (_, Self::Match) => Self::Match,
            (Self::NoMatch, value) | (value, Self::NoMatch) => value,
            (Self::Unknown(mut a), Self::Unknown(b)) => {
                a.extend(b);
                a.sort();
                a.dedup();
                Self::Unknown(a)
            }
        }
    }

    pub fn negate(self) -> Self {
        match self {
            Self::Match => Self::NoMatch,
            Self::NoMatch => Self::Match,
            unknown => unknown,
        }
    }

    pub fn all(values: impl IntoIterator<Item = Self>) -> Self {
        let mut result = Self::Match;
        for value in values {
            result = result.and(value);
            if matches!(result, Self::NoMatch) {
                break;
            }
        }
        result
    }

    pub fn any(values: impl IntoIterator<Item = Self>) -> Self {
        let mut result = Self::NoMatch;
        for value in values {
            result = result.or(value);
            if matches!(result, Self::Match) {
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Predicate as P;

    #[test]
    fn lazy_conjunction_skips_no_match_but_continues_after_unknown() {
        assert_eq!(
            P::NoMatch.and_then(|| panic!("a settled conjunction must not evaluate its tail")),
            P::NoMatch
        );
        let unknown = P::unknown("/first".into());
        assert_eq!(unknown.clone().and_then(|| P::NoMatch), P::NoMatch);
        assert_eq!(unknown.clone().and_then(|| P::Match), unknown);
        assert_eq!(
            unknown.and_then(|| P::unknown("/second".into())),
            P::Unknown(vec!["/first".into(), "/second".into()])
        );
    }

    #[test]
    fn all_and_any_stop_evaluating_after_a_known_decisive_result() {
        use std::cell::Cell;
        let evaluated = Cell::new(0);
        let values = (0..64).flat_map(|pattern| {
            let evaluated = &evaluated;
            (0..1000).map(move |token| {
                evaluated.set(evaluated.get() + 1);
                P::known(pattern == 0 && token == 0)
            })
        });
        assert_eq!(P::any(values), P::Match);
        assert_eq!(evaluated.get(), 1);

        evaluated.set(0);
        let values = (0..64).flat_map(|pattern| {
            let evaluated = &evaluated;
            (0..1000).map(move |token| {
                evaluated.set(evaluated.get() + 1);
                P::known(pattern != 0 || token != 0)
            })
        });
        assert_eq!(P::all(values), P::NoMatch);
        assert_eq!(evaluated.get(), 1);
    }

    #[test]
    fn unknown_keeps_evaluating_until_a_later_decisive_result() {
        use std::cell::Cell;
        let evaluated = Cell::new(0);
        let values = [P::unknown("/first".into()), P::Match, P::NoMatch]
            .into_iter()
            .inspect(|_| evaluated.set(evaluated.get() + 1));
        assert_eq!(P::any(values), P::Match);
        assert_eq!(evaluated.get(), 2);
        evaluated.set(0);
        let values = [P::unknown("/first".into()), P::NoMatch, P::Match]
            .into_iter()
            .inspect(|_| evaluated.set(evaluated.get() + 1));
        assert_eq!(P::all(values), P::NoMatch);
        assert_eq!(evaluated.get(), 2);
    }

    #[test]
    fn unresolved_unknowns_still_collect_all_sorted_unique_coordinates() {
        for actual in [
            P::all([
                P::unknown("/z".into()),
                P::Match,
                P::unknown("/a".into()),
                P::unknown("/z".into()),
            ]),
            P::any([
                P::unknown("/z".into()),
                P::NoMatch,
                P::unknown("/a".into()),
                P::unknown("/z".into()),
            ]),
        ] {
            assert_eq!(actual, P::Unknown(vec!["/a".into(), "/z".into()]));
        }
    }

    #[test]
    fn unknown_composes_without_boolean_shortcuts() {
        let u = P::unknown("/paths/any/0".into());
        assert_eq!(u.clone().and(P::NoMatch), P::NoMatch);
        assert_eq!(P::NoMatch.and(u.clone()), P::NoMatch);
        assert_eq!(u.clone().or(P::Match), P::Match);
        assert_eq!(P::Match.or(u.clone()), P::Match);
        assert_eq!(u.clone().and(P::Match), u);
        assert_eq!(u.clone().or(P::NoMatch), u);
        assert_eq!(u.clone().negate(), u);
        assert_eq!(P::any([u.clone(), P::NoMatch]), u);
        assert_eq!(P::all([u.clone(), P::Match]), u);
        assert_eq!(P::any([]), P::NoMatch);
        assert_eq!(P::all([]), P::Match);
    }
}
