// Built-in analyzers (design §Profiles, option grammars, and analyzers):
// versioned evidence producers over a closed fact catalog. They never load
// config code, never issue a verdict, never alter evaluation order, and never
// grant a command. Only `xargs-v1` contributes `analyzerCommand` nesting.
//
// Implementation-owned fact catalog (closed): each analyzer lists its fact
// names, typed value shape, and whether a fact is safety-relevant.
// Validation consults this table; an unknown fact reference invalidates the
// config and a typed value selector must agree with the catalogued fact type
// (no cross-type coercion). Every emitted safety-relevant fact needs allow
// coverage.

use super::evidence::ArgToken;
use super::evidence::FactObs;
use super::grammar::AnalyzerId;

/// Typed value shape of a catalogued fact (closed; matched without
/// coercion by typed value selectors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactValueType {
    /// Complete literal string facts (fact values come from decoded argv
    /// tokens); matched by `any`/`exact`/`string` selectors only.
    Str,
    /// Integer facts are full 64-bit signed integers; matched by
    /// `any`/`exact`/`integer` selectors only.
    Integer,
    /// Floating facts; matched by `any`/`exact`/`number` selectors only.
    Number,
    /// Boolean facts (true/false on the wire); matched by
    /// `any`/`exact`/`boolean` selectors only.
    Boolean,
    /// Lexical-path facts; matched by `any`/`exact`/`path` selectors only.
    Path,
}

/// One closed fact-catalog entry: name + typed value shape + safety
/// relevance.
#[derive(Debug, Clone, Copy)]
pub struct FactSpec {
    pub name: &'static str,
    pub value_type: FactValueType,
    pub safety_relevant: bool,
}

/// Closed analyzer version string ("sed-v1" ⇒ "1").
pub const ANALYZER_VERSION: &str = "1";

/// Version suffix of a catalogued analyzer id (`"sed-v1"` ⇒ `"1"`).
pub fn analyzer_version(analyzer_id: &str) -> Option<&'static str> {
    match analyzer_id {
        "generic-v1" | "sed-v1" | "export-v1" | "xargs-v1" => Some(ANALYZER_VERSION),
        _ => None,
    }
}

/// Closed, versioned fact catalog per analyzer id.
pub fn fact_catalog(analyzer: AnalyzerId) -> &'static [FactSpec] {
    match analyzer {
        AnalyzerId::GenericV1 => &[],
        AnalyzerId::SedV1 => &[
            FactSpec {
                name: "executionPrimitive",
                value_type: FactValueType::Str,
                safety_relevant: true,
            },
            FactSpec {
                name: "programForm",
                value_type: FactValueType::Str,
                safety_relevant: false,
            },
        ],
        AnalyzerId::ExportV1 => &[FactSpec {
            name: "assignment",
            value_type: FactValueType::Str,
            safety_relevant: true,
        }],
        AnalyzerId::XargsV1 => &[],
    }
}

/// True when `analyzer` declares `name`.
pub fn knows_fact(analyzer: AnalyzerId, name: &str) -> bool {
    fact_catalog(analyzer).iter().any(|f| f.name == name)
}

pub fn safety_relevant(analyzer: AnalyzerId, name: &str) -> bool {
    fact_catalog(analyzer)
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.safety_relevant)
        .unwrap_or(false)
}

/// Catalogued typed value shape of one emitted fact, addressed by analyzer
/// id string (fail closed: unknown analyzer/fact pairs have no type).
pub fn fact_value_type(analyzer_id: &str, name: &str) -> Option<FactValueType> {
    let analyzer = match analyzer_id {
        "generic-v1" => AnalyzerId::GenericV1,
        "sed-v1" => AnalyzerId::SedV1,
        "export-v1" => AnalyzerId::ExportV1,
        "xargs-v1" => AnalyzerId::XargsV1,
        _ => return None,
    };
    fact_catalog(analyzer)
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value_type)
}

/// Analyze one profile-selected executable part. `canonical_occurred` lists
/// canonical option ids that actually occurred (source order, deduped); the
/// positional operand words come from profile option parsing.
pub fn analyze(
    analyzer: AnalyzerId,
    head: &str,
    positionals: &[ArgToken],
    canonical_occurred: &[String],
) -> Vec<FactObs> {
    match analyzer {
        AnalyzerId::GenericV1 | AnalyzerId::XargsV1 => Vec::new(),
        AnalyzerId::SedV1 => sed_v1(head, positionals, canonical_occurred),
        AnalyzerId::ExportV1 => export_v1(head, positionals),
    }
}

/// sed-v1: closed execution-primitive and program-form facts.
///   executionPrimitive = "inPlace" (safety-relevant: `-i` / `--in-place`,
///                        the only file-mutating mode)
///                      | "readOnly"  (`sed` reads its operand files and
///                        writes stdout; `-n` and `-E` are read-only options)
///   programForm        = "expression" | "file" | "positional"
fn sed_v1(head: &str, positionals: &[ArgToken], canonical_occurred: &[String]) -> Vec<FactObs> {
    if head != "sed" {
        return Vec::new();
    }
    let mut facts = Vec::new();
    let in_place = canonical_occurred.iter().any(|c| c == "inPlace");
    facts.push(FactObs {
        analyzer_id: "sed-v1",
        fact_name: "executionPrimitive".into(),
        value: if in_place { "inPlace" } else { "readOnly" }.into(),
        occurrence: 1,
        safety_relevant: true,
    });
    let program_form = if canonical_occurred.iter().any(|c| c == "expression") {
        Some("expression")
    } else if canonical_occurred.iter().any(|c| c == "file") {
        Some("file")
    } else if !positionals.is_empty() {
        Some("positional")
    } else {
        None
    };
    if let Some(form) = program_form {
        facts.push(FactObs {
            analyzer_id: "sed-v1",
            fact_name: "programForm".into(),
            value: form.into(),
            occurrence: 1,
            safety_relevant: false,
        });
    }
    facts
}

/// export-v1: closed assignment facts — every operand word names an
/// environment variable that becomes visible to executed children.
///   assignment = NAME
fn export_v1(head: &str, positionals: &[ArgToken]) -> Vec<FactObs> {
    if head != "export" {
        return Vec::new();
    }
    positionals
        .iter()
        .filter(|t| t.resolvable && is_identifier_operand(&t.text))
        .map(|t| {
            let name = t.text.split('=').next().unwrap_or(&t.text).to_string();
            FactObs {
                analyzer_id: "export-v1",
                fact_name: "assignment".into(),
                value: name,
                occurrence: 0,
                safety_relevant: true,
            }
        })
        .enumerate()
        .map(|(i, mut f)| {
            f.occurrence = i as u32 + 1;
            f
        })
        .collect()
}

fn is_identifier_operand(t: &str) -> bool {
    let name = t.split('=').next().unwrap_or(t);
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<ArgToken> {
        list.iter()
            .map(|s| ArgToken {
                text: (*s).to_string(),
                resolvable: true,
                span: (0, 0),
            })
            .collect()
    }

    #[test]
    fn sed_inplace_is_safety_relevant() {
        let facts = analyze(
            AnalyzerId::SedV1,
            "sed",
            &args(&["s/a/b/", "f.txt"]),
            &["inPlace".to_string()],
        );
        assert_eq!(facts[0].fact_name, "executionPrimitive");
        assert_eq!(facts[0].value, "inPlace");
        assert!(facts[0].safety_relevant);
        assert_eq!(facts[1].value, "positional");
        // per-fact-name occurrence ordinals (each closed fact occurs once)
        assert_eq!(facts[0].occurrence, 1);
        assert_eq!(facts[1].occurrence, 1);
    }

    /// `sed -n` and `sed -E` are read-only: executionPrimitive says
    /// "readOnly" and they stay safety-relevant (coverage required to allow).
    #[test]
    fn sed_read_only_options_emit_read_only_facts() {
        for occurred in [
            vec!["noPrint".to_string()],
            vec!["extendedRegexp".to_string()],
            vec!["noPrint".to_string(), "extendedRegexp".to_string()],
        ] {
            let facts = analyze(AnalyzerId::SedV1, "sed", &args(&["file.txt"]), &occurred);
            assert_eq!(facts[0].fact_name, "executionPrimitive");
            assert_eq!(facts[0].value, "readOnly");
            assert!(facts[0].safety_relevant);
            // noPrint/-E by itself does not change the program form
            assert_eq!(facts[1].value, "positional");
            assert!(!facts[1].safety_relevant);
        }
    }

    /// Plain `sed script file` is also read-only (stdout writer).
    #[test]
    fn sed_without_in_place_is_read_only() {
        let facts = analyze(AnalyzerId::SedV1, "sed", &args(&["s/a/b/", "f.txt"]), &[]);
        assert_eq!(facts[0].value, "readOnly");
        assert!(facts[0].safety_relevant);
    }

    #[test]
    fn sed_expression_and_file_forms() {
        let expr = analyze(
            AnalyzerId::SedV1,
            "sed",
            &args(&["f.txt"]),
            &["expression".to_string()],
        );
        assert_eq!(expr[1].value, "expression");
        let file = analyze(
            AnalyzerId::SedV1,
            "sed",
            &args(&["f.txt"]),
            &["file".to_string()],
        );
        assert_eq!(file[1].value, "file");
    }

    /// The closed catalog: fact names, typed value shapes, safety metadata.
    #[test]
    fn fact_catalog_is_closed_and_typed() {
        let sed = fact_catalog(AnalyzerId::SedV1);
        assert_eq!(
            sed.iter().map(|f| f.name).collect::<Vec<_>>(),
            vec!["executionPrimitive", "programForm"]
        );
        assert!(sed.iter().all(|f| f.value_type == FactValueType::Str));
        assert!(safety_relevant(AnalyzerId::SedV1, "executionPrimitive"));
        assert!(!safety_relevant(AnalyzerId::SedV1, "programForm"));
        assert!(!safety_relevant(AnalyzerId::SedV1, "unknown"));

        // export-v1 assignment facts are typed strings and safety-relevant
        assert!(knows_fact(AnalyzerId::ExportV1, "assignment"));
        assert!(safety_relevant(AnalyzerId::ExportV1, "assignment"));
        assert!(!knows_fact(AnalyzerId::ExportV1, "executionPrimitive"));
        // generic-v1 and xargs-v1 emit no facts
        assert!(fact_catalog(AnalyzerId::GenericV1).is_empty());
        assert!(fact_catalog(AnalyzerId::XargsV1).is_empty());
    }

    /// Fact type lookup keyed by analyzer id string fails closed.
    #[test]
    fn fact_value_type_fails_closed() {
        assert_eq!(
            fact_value_type("sed-v1", "executionPrimitive"),
            Some(FactValueType::Str)
        );
        assert_eq!(fact_value_type("sed-v1", "unknown"), None);
        assert_eq!(
            fact_value_type("unknown-analyzer", "executionPrimitive"),
            None
        );
    }

    /// Closed analyzer version resolution.
    #[test]
    fn analyzer_versions_are_closed() {
        assert_eq!(analyzer_version("sed-v1"), Some(ANALYZER_VERSION));
        assert_eq!(analyzer_version("generic-v1"), Some(ANALYZER_VERSION));
        assert_eq!(analyzer_version("sed-v2"), None);
        assert_eq!(ANALYZER_VERSION, "1");
    }

    #[test]
    fn export_lists_assignment_names() {
        let facts = analyze(
            AnalyzerId::ExportV1,
            "export",
            &args(&["FOO=1", "BAR"]),
            &[],
        );
        let names: Vec<&str> = facts.iter().map(|f| f.value.as_str()).collect();
        assert_eq!(names, vec!["FOO", "BAR"]);
        assert!(facts.iter().all(|f| f.safety_relevant));
        assert_eq!(
            facts.iter().map(|f| f.occurrence).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn generic_has_no_facts() {
        assert!(analyze(AnalyzerId::GenericV1, "git", &args(&["status"]), &[]).is_empty());
    }
}
