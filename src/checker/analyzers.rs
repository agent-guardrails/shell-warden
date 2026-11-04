// Built-in analyzers (design §Profiles, option grammars, and analyzers):
// versioned evidence producers over a closed fact catalog. They never load
// config code, never issue a verdict, never alter evaluation order, and never
// grant a command. Only `xargs-v1` contributes `analyzerCommand` nesting.
//
// Implementation-owned fact catalog (closed): each analyzer lists its fact
// names and whether a fact is safety-relevant. Validation consults this
// table; an unknown fact reference invalidates the config. Every emitted
// safety-relevant fact needs allow coverage.

use super::evidence::ArgToken;
use super::evidence::FactObs;
use super::grammar::AnalyzerId;

/// One closed fact-catalog entry: name + safety relevance.
#[derive(Debug, Clone, Copy)]
pub struct FactSpec {
    pub name: &'static str,
    pub safety_relevant: bool,
}

/// Closed, versioned fact catalog per analyzer id.
pub fn fact_catalog(analyzer: AnalyzerId) -> &'static [FactSpec] {
    match analyzer {
        AnalyzerId::GenericV1 => &[],
        AnalyzerId::SedV1 => &[
            FactSpec {
                name: "executionPrimitive",
                safety_relevant: true,
            },
            FactSpec {
                name: "programForm",
                safety_relevant: false,
            },
        ],
        AnalyzerId::ExportV1 => &[FactSpec {
            name: "assignment",
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
///   executionPrimitive = "inPlace"  (safety-relevant: `-i` / `--in-place`)
///   programForm        = "expression" | "file" | "positional"
fn sed_v1(head: &str, positionals: &[ArgToken], canonical_occurred: &[String]) -> Vec<FactObs> {
    if head != "sed" {
        return Vec::new();
    }
    let mut facts = Vec::new();
    let in_place = canonical_occurred.iter().any(|c| c == "inPlace");
    if in_place {
        facts.push(FactObs {
            analyzer_id: "sed-v1",
            fact_name: "executionPrimitive".into(),
            value: "inPlace".into(),
            occurrence: facts.len() as u32 + 1,
            safety_relevant: true,
        });
    }
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
            occurrence: facts.len() as u32 + 1,
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
        assert!(facts[0].safety_relevant);
        assert_eq!(facts[1].value, "positional");
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
    }

    #[test]
    fn generic_has_no_facts() {
        assert!(analyze(AnalyzerId::GenericV1, "git", &args(&["status"]), &[]).is_empty());
    }
}
