//! Syntactic parameter evidence, never a runtime value or an authorization.
//!
//! Recognition uses the original source, before quote removal or replacement
//! markers. A supported expression has exactly one leading simple reference
//! followed by literal text. Context-specific permission and coverage belong
//! to the matcher, not this parser.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterForm {
    DoubleQuoted,
    /// Eligible only where the caller has established assignment semantics.
    UnquotedAssignment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterWord {
    pub name: String,
    pub suffix: String,
    pub form: ParameterForm,
}

pub fn is_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a value word, not an assignment's destination. Unquoted recognition
/// does not establish assignment semantics; callers must prove that separately.
pub fn parse(source: &str) -> Option<ParameterWord> {
    // Shell line continuations disappear before identifier tokenization.
    // Preserve escaped backslash pairs: the second slash of "\\\\\n" is
    // already escaped and cannot start a continuation.
    let mut normalized = String::new();
    let mut chars = source.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\n') => {}
                Some(next) => {
                    normalized.push(c);
                    normalized.push(next);
                }
                None => normalized.push(c),
            }
        } else {
            normalized.push(c);
        }
    }
    let source = normalized.as_str();
    let (body, form) = if source.starts_with('"') {
        (
            source.strip_prefix('"')?.strip_suffix('"')?,
            ParameterForm::DoubleQuoted,
        )
    } else {
        (source, ParameterForm::UnquotedAssignment)
    };
    let reference = body.strip_prefix('$')?;
    let (name, tail) = if let Some(braced) = reference.strip_prefix('{') {
        let (name, tail) = braced.split_once('}')?;
        (name, tail)
    } else {
        let end = reference
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(reference.len());
        (&reference[..end], &reference[end..])
    };
    if !is_name(name) {
        return None;
    }
    let suffix = literal_suffix(tail, form)?;
    Some(ParameterWord {
        name: name.to_string(),
        suffix,
        form,
    })
}

fn literal_suffix(source: &str, form: ParameterForm) -> Option<String> {
    let mut chars = source.chars().peekable();
    let mut literal = String::new();
    while let Some(c) = chars.next() {
        match c {
            '$' | '`' | '"' => return None,
            '\\' => {
                let next = chars.next()?;
                match (form, next) {
                    (_, '\n') => {}
                    (ParameterForm::DoubleQuoted, '$' | '`' | '"' | '\\')
                    | (ParameterForm::UnquotedAssignment, _) => literal.push(next),
                    (ParameterForm::DoubleQuoted, _) => {
                        // In double quotes, backslash is retained before
                        // characters other than $, `, ", \, or newline.
                        literal.push('\\');
                        literal.push(next);
                    }
                }
            }
            // This first grammar deliberately excludes concatenated quoting,
            // brace/tilde expansion, and shell operators in unquoted values.
            // Assignment semantics suppress splitting/globbing, but do not
            // suppress every other shell expansion.
            c if form == ParameterForm::UnquotedAssignment
                && (c.is_whitespace()
                    || matches!(
                        c,
                        '\'' | '{' | '}' | '~' | ';' | '&' | '|' | '<' | '>' | '(' | ')'
                    )) =>
            {
                return None;
            }
            c => literal.push(c),
        }
    }
    Some(literal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_spellings_have_the_same_typed_value() {
        for suffix in [
            "",
            "/cache",
            "-backup",
            "/a b",
            "/*?[x]",
            "/../other",
            "/日本語",
        ] {
            let expected = ParameterWord {
                name: "HOME".to_string(),
                suffix: suffix.to_string(),
                form: ParameterForm::DoubleQuoted,
            };
            assert_eq!(parse(&format!("\"$HOME{suffix}\"")), Some(expected.clone()));
            assert_eq!(parse(&format!("\"${{HOME}}{suffix}\"")), Some(expected));
        }
    }

    #[test]
    fn consumes_the_complete_case_sensitive_identifier() {
        for name in ["HOME", "HOME_BACKUP", "HOME2", "home", "_HOME", "_"] {
            assert_eq!(parse(&format!("\"${name}\"")).unwrap().name, name, "{name}");
        }
        assert_eq!(parse("\"$HOMEbackup\"").unwrap().name, "HOMEbackup");
        assert_eq!(parse("\"${HOME}backup\"").unwrap().suffix, "backup");
    }

    #[test]
    fn line_continuations_do_not_shorten_variable_identifiers() {
        for source in [
            "\"$HO\\\nME/cache\"",
            "\"${HO\\\nME}/cache\"",
            "$HO\\\nME/cache",
        ] {
            let parsed = parse(source).unwrap();
            assert_eq!(parsed.name, "HOME", "{source}");
            assert_eq!(parsed.suffix, "/cache", "{source}");
        }
        assert_eq!(parse("\"$HOME/\\\\\nnext\"").unwrap().suffix, "/\\\nnext");
    }

    #[test]
    fn double_quote_escapes_follow_shell_literal_semantics() {
        for (source, suffix) in [
            (r#""$HOME/\$USER""#, "/$USER"),
            (r#""$HOME/\`literal\`""#, "/`literal`"),
            (r#""$HOME/\"name\"""#, "/\"name\""),
            (r#""$HOME/\\path""#, "/\\path"),
            (r#""$HOME/\q""#, "/\\q"),
            ("\"$HOME/a\\\nb\"", "/ab"),
            ("\"$HOME/'literal'\"", "/'literal'"),
        ] {
            assert_eq!(parse(source).unwrap().suffix, suffix, "{source}");
        }
    }

    #[test]
    fn unquoted_values_are_marked_assignment_only() {
        for source in [
            "$HOME",
            "${HOME}/cache",
            "$HOME-backup",
            "$HOME/a\\ b",
            "$HOME/*?[x]",
        ] {
            let parsed = parse(source).unwrap();
            assert_eq!(parsed.name, "HOME");
            assert_eq!(parsed.form, ParameterForm::UnquotedAssignment);
        }
        assert_eq!(parse("$HOME/a\\ b").unwrap().suffix, "/a b");
    }

    #[test]
    fn unsupported_expansions_and_composite_words_never_qualify() {
        for source in [
            "\"$HOME/$USER\"",
            "\"$HOME/$(touch marker)\"",
            "\"$HOME/`touch marker`\"",
            "\"$HOME/$((1+2))\"",
            "\"${HOME:-/tmp}\"",
            "\"${HOME-default}\"",
            "\"${HOME:=/tmp}\"",
            "\"${HOME:?missing}\"",
            "\"${HOME:+other}\"",
            "\"${HOME%/*}\"",
            "\"${HOME#prefix}\"",
            "\"${HOME/old/new}\"",
            "\"${!HOME}\"",
            "\"${#HOME}\"",
            "\"${HOME[0]}\"",
            "\"$1\"",
            "\"$@\"",
            "\"$*\"",
            "\"$?\"",
            "\"$$\"",
            "\"$((1+2))\"",
            "\"$(pwd)\"",
            "\"${}\"",
            "\"${HOME\"",
            "\"$HOME",
            "\"$HOME\"tail",
            "prefix\"$HOME\"",
            "\"$HOME\"\"/cache\"",
            "\"$HOME/'\"\"quoted\"",
            "'$HOME/cache'",
            "\"\\$HOME/cache\"",
            "~/cache",
            "HOME=$HOME",
            "$HOME/{a,b}",
            "$HOME/:~root",
            "$HOME/$USER",
            "$HOME/$(pwd)",
            "$HOME/'literal'",
            "$HOME/\"literal\"",
            "$HOME/space here",
            "$HOME/unfinished\\",
            "",
        ] {
            assert_eq!(parse(source), None, "{source}");
        }
    }

    #[test]
    fn names_are_portable_identifiers_not_patterns_or_runtime_values() {
        for name in ["HOME", "_", "_2", "home2"] {
            assert!(is_name(name), "{name}");
        }
        for name in [
            "", "2HOME", "H*", "$HOME", "HOME/x", "HÖME", "HOME\n", "A B",
        ] {
            assert!(!is_name(name), "{name}");
        }
    }
}
