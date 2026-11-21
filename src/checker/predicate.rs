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
        values.into_iter().fold(Self::Match, Self::and)
    }

    pub fn any(values: impl IntoIterator<Item = Self>) -> Self {
        values.into_iter().fold(Self::NoMatch, Self::or)
    }
}

#[cfg(test)]
mod tests {
    use super::Predicate as P;

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
