// Verdict v2 conformance — consumes the shared fixture manifest vectors by
// role (HANDOFF-verdict-v2 §Rust 5, 10 §10.8): `checker-producer` vectors are
// checked against the semantic output invariants and `checker-serialization`
// vectors against the closed v2 schema. `hook-consumer`-only vectors are
// skipped here by the role filter — flat v1 rejection and the other
// consumer-only anomalies are hook requirements, not checker requirements.
//
// Fixture provenance: byte-identical copy of docs schemas/fixtures/
// shell-warden.verdict.v2 at docs@a5480bd (contract PR #34, ADR-0023).
// The schema-equivalent checker below mirrors
// docs/scripts/validate-shell-warden-verdict-v2-fixtures.mjs; the manifest
// phases pin the expected accept/reject outcome of every vector.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Stdio};

const MAX_VERDICT_BYTES: usize = 65_536;
const MAX_FACTS_BYTES: usize = 16_384;
const MAX_FACTS_DEPTH: usize = 8;
const PROTOCOL: &str = "shell-warden.verdict.v2";

const FULL_FACT_FIELDS: [&str; 7] = [
    "evidence",
    "reasons",
    "selectedProfiles",
    "matched",
    "qualified",
    "rejected",
    "votes",
];
const TRUNCATED_FACT_FIELDS: [&str; 3] = ["evidence", "reasons", "diagnostics"];
const RESERVED_DIAGNOSTIC_KEYS: [&str; 8] = [
    "evidence",
    "reasons",
    "diagnostics",
    "selectedProfiles",
    "matched",
    "qualified",
    "rejected",
    "votes",
];
const STABLE_REASONS: [&str; 17] = [
    "complete",
    "opaque-expansion",
    "unknown-option",
    "option-value-missing",
    "invalid-inline-option",
    "unsupported-syntax",
    "empty-command",
    "evidence-limit",
    "allow-evidence-not-complete",
    "allow-coverage-missing",
    "required-option-missing",
    "option-not-repeatable",
    "option-not-allowed",
    "option-value-uncovered",
    "option-value-position-uncovered",
    "remainder-uncovered",
    "redirect-policy-uncovered",
];
const INVALID_REASONS: [&str; 6] = [
    "unknown-option",
    "option-value-missing",
    "invalid-inline-option",
    "unsupported-syntax",
    "empty-command",
    "evidence-limit",
];
const COVERAGE_REASONS: [&str; 9] = [
    "allow-evidence-not-complete",
    "allow-coverage-missing",
    "required-option-missing",
    "option-not-repeatable",
    "option-not-allowed",
    "option-value-uncovered",
    "option-value-position-uncovered",
    "remainder-uncovered",
    "redirect-policy-uncovered",
];
const VALID_TUPLES: [&str; 7] = [
    "static/argv/allow",
    "static/argv/ask",
    "static/argv/deny",
    "opaque/raw/ask",
    "opaque/raw/deny",
    "invalid/raw/ask",
    "invalid/raw/deny",
];

fn rank(verdict: &str) -> u8 {
    match verdict {
        "deny" => 2,
        "ask" => 1,
        _ => 0,
    }
}

fn strongest<'a>(a: &'a str, b: &'a str) -> &'a str {
    if rank(a) >= rank(b) { a } else { b }
}

fn is_invalid_reason(reason: &str) -> bool {
    INVALID_REASONS.contains(&reason)
}

// ── Schema-equivalent v2 validation ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
struct SchemaError {
    code: String,
    instance_path: String,
    schema_path: String,
    params: BTreeMap<String, String>,
}

impl SchemaError {
    fn new(code: &str, instance_path: &str, schema_path: &str) -> Self {
        SchemaError {
            code: code.to_string(),
            instance_path: instance_path.to_string(),
            schema_path: schema_path.to_string(),
            params: BTreeMap::new(),
        }
    }

    fn param(mut self, key: &str, value: impl Into<String>) -> Self {
        self.params.insert(key.to_string(), value.into());
        self
    }

    fn matches(&self, expected: &Value) -> bool {
        let want_code = expected.get("code").and_then(Value::as_str);
        let want_location = expected.get("location").and_then(Value::as_str);
        let want_schema = expected.get("schemaPath").and_then(Value::as_str);
        let want_params = expected.get("params").and_then(Value::as_object);
        if let Some(code) = want_code
            && self.code != code
        {
            return false;
        }
        if let Some(location) = want_location
            && self.instance_path != location
        {
            return false;
        }
        if let Some(schema_path) = want_schema
            && self.schema_path != schema_path
        {
            return false;
        }
        if let Some(params) = want_params {
            for (key, value) in params {
                if self.params.get(key).map(String::as_str) != value.as_str() {
                    return false;
                }
            }
        }
        true
    }
}

fn is_identifier(value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    let chars = text.chars().count();
    (1..=128).contains(&chars) && !text.chars().any(char::is_whitespace)
}

fn identifier_array(value: &Value, max: usize, unique: bool) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    if items.len() > max {
        return false;
    }
    if !items.iter().all(is_identifier) {
        return false;
    }
    if unique {
        let set: std::collections::HashSet<&Value> = items.iter().collect();
        if set.len() != items.len() {
            return false;
        }
    }
    true
}

fn vote_ok(vote: &Value) -> bool {
    let Some(text) = vote.as_str() else {
        return false;
    };
    let Some((action, rule_id)) = text.split_once(':') else {
        return false;
    };
    matches!(action, "allow" | "ask" | "deny") && {
        let chars = rule_id.chars().count();
        (1..=128).contains(&chars) && !rule_id.chars().any(char::is_whitespace)
    }
}

fn reason_enum_ok(value: &Value) -> bool {
    value.as_str().is_some_and(|s| STABLE_REASONS.contains(&s))
}

/// Facts diagnostics member shape/bounds (FullDiagnostics ‖ TruncatedDiagnostics).
fn diagnostics_members_ok(facts: &Value, shape: &str) -> bool {
    let Some(obj) = facts.as_object() else {
        return false;
    };
    let evidence_ok = obj
        .get("evidence")
        .and_then(Value::as_str)
        .is_some_and(|e| matches!(e, "complete" | "opaque" | "invalid"));
    let max_reasons = if shape == "full" { 17 } else { 8 };
    let reasons_ok = obj
        .get("reasons")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.len() <= max_reasons && items.iter().all(|r| r.is_string() && reason_enum_ok(r))
        });
    if !evidence_ok || !reasons_ok {
        return false;
    }
    if shape == "truncated" {
        return obj.get("diagnostics").and_then(Value::as_str) == Some("truncated-after-decision");
    }
    let profiles_ok = identifier_array(
        obj.get("selectedProfiles").unwrap_or(&Value::Null),
        1024,
        false,
    );
    let matched_ok = identifier_array(obj.get("matched").unwrap_or(&Value::Null), 4096, false);
    let qualified_ok = identifier_array(obj.get("qualified").unwrap_or(&Value::Null), 4096, true);
    let rejected_ok = obj
        .get("rejected")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.len() <= 4096
                && items.iter().all(|entry| {
                    let Some(entry_obj) = entry.as_object() else {
                        return false;
                    };
                    entry_obj.len() == 2
                        && is_identifier(entry_obj.get("ruleId").unwrap_or(&Value::Null))
                        && entry_obj
                            .get("reasons")
                            .and_then(Value::as_array)
                            .is_some_and(|reasons| {
                                (1..=9).contains(&reasons.len())
                                    && reasons.iter().all(|r| {
                                        r.as_str().is_some_and(|s| COVERAGE_REASONS.contains(&s))
                                    })
                            })
                })
        });
    let votes_ok = obj
        .get("votes")
        .and_then(Value::as_array)
        .is_some_and(|items| items.len() <= 4096 && items.iter().all(vote_ok));
    profiles_ok && matched_ok && qualified_ok && rejected_ok && votes_ok
}

/// Exact diagnostics key set: full, truncated, malformed (reserved keys, wrong
/// shapes), or absent (facts disjoint from all reserved keys — impossible in
/// v2 documents produced against the closed schema, but the checker mirrors
/// the shared validator).
fn diagnostics_shape(facts: &Value) -> Option<&'static str> {
    let Value::Object(obj) = facts else {
        return None;
    };
    let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    let mut full = FULL_FACT_FIELDS.to_vec();
    full.sort_unstable();
    let mut truncated = TRUNCATED_FACT_FIELDS.to_vec();
    truncated.sort_unstable();
    let mut actual = keys.clone();
    actual.sort_unstable();
    if actual == full {
        return Some("full");
    }
    if actual == truncated {
        return Some("truncated");
    }
    if keys.iter().any(|k| RESERVED_DIAGNOSTIC_KEYS.contains(k)) {
        return Some("malformed");
    }
    None
}

fn command_schema_errors(prefix: &str, command: &Value, errors: &mut Vec<SchemaError>) {
    let Some(obj) = command.as_object() else {
        errors.push(SchemaError::new("schema.type", prefix, "#/type"));
        return;
    };
    for key in obj.keys() {
        if ![
            "classification",
            "facts",
            "index",
            "match",
            "ruleId",
            "verdict",
        ]
        .contains(&key.as_str())
        {
            errors.push(SchemaError::new(
                "schema.additionalProperties",
                prefix,
                "#/additionalProperties",
            ));
        }
    }
    for key in ["index", "verdict", "classification", "match"] {
        if !obj.contains_key(key) {
            errors.push(
                SchemaError::new("schema.required", prefix, "#/required")
                    .param("missingProperty", key),
            );
        }
    }
    let classification = obj.get("classification").and_then(Value::as_str);
    let verdict = obj.get("verdict").and_then(Value::as_str);
    let r#match = obj.get("match").and_then(Value::as_str);
    // base property constraints (any type mismatch fails the constraint)
    match obj.get("verdict") {
        None => {}
        Some(v) if matches!(v.as_str(), Some("allow" | "ask" | "deny")) => {}
        Some(_) => errors.push(SchemaError::new(
            "schema.enum",
            &format!("{prefix}/verdict"),
            "#/properties/verdict/enum",
        )),
    }
    match obj.get("classification") {
        None => {}
        Some(v) if matches!(v.as_str(), Some("static" | "opaque" | "invalid")) => {}
        Some(_) => errors.push(SchemaError::new(
            "schema.enum",
            &format!("{prefix}/classification"),
            "#/properties/classification/enum",
        )),
    }
    match obj.get("match") {
        None => {}
        Some(v) if matches!(v.as_str(), Some("argv" | "raw")) => {}
        Some(_) => errors.push(SchemaError::new(
            "schema.enum",
            &format!("{prefix}/match"),
            "#/properties/match/enum",
        )),
    }
    if let Some(rule_id) = obj.get("ruleId")
        && !is_identifier(rule_id)
    {
        errors.push(SchemaError::new(
            "schema.pattern",
            &format!("{prefix}/ruleId"),
            "#/properties/ruleId/pattern",
        ));
    }
    if let Some(v) = obj.get("index")
        && !v.is_u64()
    {
        errors.push(SchemaError::new(
            "schema.type",
            &format!("{prefix}/index"),
            "#/properties/index/type",
        ));
    }
    // allOf[0]: the classification/match/verdict tuple oneOf — every arm is
    // evaluated independently; the oneOf is satisfied when exactly one arm
    // matches, so per-arm errors surface only when no arm matches (Ajv
    // reports subschema errors only on oneOf failure).
    let tuple_arms: [(&str, &str, &[&str]); 3] = [
        ("static", "argv", &["allow", "ask", "deny"]),
        ("opaque", "raw", &["ask", "deny"]),
        ("invalid", "raw", &["ask", "deny"]),
    ];
    let mut arms_matched = 0;
    let mut arm_errors: Vec<SchemaError> = Vec::new();
    for (arm_index, (expected_class, expected_match, verdict_options)) in
        tuple_arms.iter().enumerate()
    {
        let arm_prefix = format!("#/allOf/0/oneOf/{arm_index}/properties");
        let mut arm_ok = true;
        if classification != Some(expected_class) {
            arm_errors.push(
                SchemaError::new(
                    "schema.const",
                    &format!("{prefix}/classification"),
                    &format!("{arm_prefix}/classification/const"),
                )
                .param("const", *expected_class),
            );
            arm_ok = false;
        }
        if r#match.is_some() && r#match != Some(expected_match) {
            arm_errors.push(SchemaError::new(
                "schema.const",
                &format!("{prefix}/match"),
                &format!("{arm_prefix}/match/const"),
            ));
            arm_ok = false;
        }
        if verdict.is_some() && !verdict_options.contains(&verdict.unwrap_or("")) {
            arm_errors.push(SchemaError::new(
                "schema.enum",
                &format!("{prefix}/verdict"),
                &format!("{arm_prefix}/verdict/enum"),
            ));
            arm_ok = false;
        }
        if arm_ok {
            arms_matched += 1;
        }
    }
    if arms_matched == 0 {
        errors.append(&mut arm_errors);
        errors.push(SchemaError::new("schema.oneOf", prefix, "#/allOf/0/oneOf"));
    } else if arms_matched > 1 {
        errors.push(SchemaError::new("schema.oneOf", prefix, "#/allOf/0/oneOf"));
    }
    // allOf[1]: deny requires ruleId
    if verdict == Some("deny") && !obj.contains_key("ruleId") {
        errors.push(
            SchemaError::new("schema.required", prefix, "#/allOf/1/then/required")
                .param("missingProperty", "ruleId"),
        );
    }
    // allOf[2..=4]: facts evidence must equal the classification
    if let Some(facts) = obj.get("facts") {
        let expected_evidence = match classification {
            Some("static") => Some("complete"),
            Some("opaque") => Some("opaque"),
            Some("invalid") => Some("invalid"),
            _ => None,
        };
        if let (Some(expected), Some(actual)) = (
            expected_evidence,
            facts.get("evidence").and_then(Value::as_str),
        ) && actual != expected
        {
            let index = match classification {
                Some("static") => 2,
                Some("opaque") => 3,
                _ => 4,
            };
            errors.push(
                SchemaError::new(
                    "schema.const",
                    &format!("{prefix}/facts/evidence"),
                    &format!("#/allOf/{index}/then/properties/facts/properties/evidence/const"),
                )
                .param("const", expected),
            );
        }
        // facts diagnostics oneOf (full ‖ truncated)
        if facts.is_object() {
            let shape = diagnostics_shape(facts);
            match shape {
                None => errors.push(SchemaError::new(
                    "schema.oneOf",
                    &format!("{prefix}/facts"),
                    "#/properties/facts/oneOf",
                )),
                Some("malformed") | Some("full")
                    if !diagnostics_members_ok(facts, shape.unwrap()) =>
                {
                    errors.push(SchemaError::new(
                        "schema.oneOf",
                        &format!("{prefix}/facts"),
                        "#/properties/facts/oneOf",
                    ));
                }
                Some(_) => {}
            }
            if let Some(facts_obj) = facts.as_object() {
                let allowed_keys = [
                    "evidence",
                    "reasons",
                    "selectedProfiles",
                    "matched",
                    "qualified",
                    "rejected",
                    "votes",
                    "diagnostics",
                ];
                for key in facts_obj.keys() {
                    if !allowed_keys.contains(&key.as_str()) {
                        errors.push(
                            SchemaError::new(
                                "schema.additionalProperties",
                                &format!("{prefix}/facts"),
                                "#/additionalProperties",
                            )
                            .param("additionalProperty", key.clone()),
                        );
                    }
                }
            }
        } else if !facts.is_null() {
            errors.push(SchemaError::new(
                "schema.type",
                &format!("{prefix}/facts"),
                "#/properties/facts/type",
            ));
        }
    }
}

/// Closed schema check equivalent to draft-07 validation of
/// shell-warden.verdict.v2.schema.json (same error codes, locations,
/// schemaPaths and params the shared Ajv harness reports).
fn schema_errors(document: &Value) -> Vec<SchemaError> {
    let mut errors = Vec::new();
    let Some(obj) = document.as_object() else {
        errors.push(SchemaError::new("schema.type", "/", "#/type"));
        return errors;
    };
    for key in obj.keys() {
        if key != "protocol" && key != "result" {
            errors.push(SchemaError::new(
                "schema.additionalProperties",
                "/",
                "#/additionalProperties",
            ));
        }
    }
    if !obj.contains_key("protocol") {
        errors.push(
            SchemaError::new("schema.required", "/", "#/required")
                .param("missingProperty", "protocol"),
        );
    }
    if !obj.contains_key("result") {
        errors.push(
            SchemaError::new("schema.required", "/", "#/required")
                .param("missingProperty", "result"),
        );
    }
    if let Some(protocol) = obj.get("protocol")
        && protocol.as_str() != Some(PROTOCOL)
    {
        errors.push(
            SchemaError::new("schema.const", "/protocol", "#/properties/protocol/const")
                .param("const", PROTOCOL),
        );
    }
    let Some(result) = obj.get("result").filter(|r| r.is_object()) else {
        if obj.contains_key("result") {
            errors.push(SchemaError::new(
                "schema.type",
                "/result",
                "#/properties/result/type",
            ));
        }
        return errors;
    };
    let result_obj = result.as_object().unwrap();
    for key in result_obj.keys() {
        if !["commands", "invocationId", "message", "verdict"].contains(&key.as_str()) {
            errors.push(SchemaError::new(
                "schema.additionalProperties",
                "/result",
                "#/additionalProperties",
            ));
        }
    }
    for key in ["invocationId", "verdict", "commands"] {
        if !result_obj.contains_key(key) {
            errors.push(
                SchemaError::new("schema.required", "/result", "#/required")
                    .param("missingProperty", key),
            );
        }
    }
    if let Some(invocation_id) = result_obj.get("invocationId") {
        let length = invocation_id.as_str().map(str::chars).map(Iterator::count);
        if !invocation_id.is_string() {
            errors.push(SchemaError::new(
                "schema.type",
                "/result/invocationId",
                "#/properties/invocationId/type",
            ));
        } else if !length.is_some_and(|n| (1..=256).contains(&n)) {
            errors.push(SchemaError::new(
                "schema.maxLength",
                "/result/invocationId",
                "#/properties/invocationId/maxLength",
            ));
        }
    }
    if let Some(v) = result_obj.get("verdict")
        && !matches!(v.as_str(), Some("allow" | "ask" | "deny"))
    {
        errors.push(SchemaError::new(
            "schema.enum",
            "/result/verdict",
            "#/properties/verdict/enum",
        ));
    }
    if let Some(message) = result_obj.get("message") {
        let length = message.as_str().map(str::chars).map(Iterator::count);
        if !message.is_string() {
            errors.push(SchemaError::new(
                "schema.type",
                "/result/message",
                "#/properties/message/type",
            ));
        } else if !length.is_some_and(|n| (1..=512).contains(&n)) {
            errors.push(SchemaError::new(
                "schema.maxLength",
                "/result/message",
                "#/properties/message/maxLength",
            ));
        }
    }
    // allOf[0]: aggregate deny requires message
    if result_obj.get("verdict").and_then(Value::as_str) == Some("deny")
        && !result_obj.contains_key("message")
    {
        errors.push(
            SchemaError::new("schema.required", "/result", "#/allOf/0/then/required")
                .param("missingProperty", "message"),
        );
    }
    if let Some(commands) = result_obj.get("commands").filter(|c| c.is_array()) {
        let items = commands.as_array().unwrap();
        if items.is_empty() {
            errors.push(SchemaError::new(
                "schema.minItems",
                "/result/commands",
                "#/properties/commands/minItems",
            ));
        }
        if items.len() > 128 {
            errors.push(SchemaError::new(
                "schema.maxItems",
                "/result/commands",
                "#/properties/commands/maxItems",
            ));
        }
        for (position, command) in items.iter().enumerate() {
            command_schema_errors(
                &format!("/result/commands/{position}"),
                command,
                &mut errors,
            );
        }
    } else if result_obj.contains_key("commands") {
        errors.push(SchemaError::new(
            "schema.type",
            "/result/commands",
            "#/properties/commands/type",
        ));
    }
    errors
}

// ── Semantic invariants (02 §2.8) — port of the shared validator ────────────

#[derive(Debug, Clone, PartialEq)]
struct SemError {
    code: String,
    location: String,
}

impl SemError {
    fn new(code: &str, location: &str) -> Self {
        SemError {
            code: code.to_string(),
            location: location.to_string(),
        }
    }

    fn matches(&self, expected: &Value) -> bool {
        expected.get("code").and_then(Value::as_str) == Some(self.code.as_str())
            && expected.get("location").and_then(Value::as_str) == Some(self.location.as_str())
    }
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn sorted_unique(values: &[&str]) -> bool {
    values.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes())
}

fn facts_shape_of(facts: &Value) -> Option<&'static str> {
    diagnostics_shape(facts)
}

fn coherence_errors(command: &Value, position: usize) -> Vec<SemError> {
    let mut errors = Vec::new();
    let Some(facts) = command.get("facts") else {
        return errors;
    };
    let reason_location = format!("/result/commands/{position}/facts/reasons");
    let Some(reasons) = facts.get("reasons").and_then(Value::as_array) else {
        return errors;
    };
    let reason_strings: Vec<&str> = reasons.iter().filter_map(Value::as_str).collect();
    if !sorted_unique(&reason_strings) {
        errors.push(SemError::new("reasons.not_sorted_unique", &reason_location));
    }
    let evidence = facts.get("evidence").and_then(Value::as_str).unwrap_or("");
    match evidence {
        "complete" => {
            if !reason_strings.contains(&"complete") {
                errors.push(SemError::new("reasons.complete_required", &reason_location));
            }
            if reason_strings.iter().any(|r| {
                *r == "opaque-expansion"
                    || *r == "allow-evidence-not-complete"
                    || is_invalid_reason(r)
            }) {
                errors.push(SemError::new(
                    "reasons.complete_incompatible",
                    &reason_location,
                ));
            }
        }
        "opaque" => {
            if !reason_strings.contains(&"opaque-expansion") {
                errors.push(SemError::new("reasons.opaque_required", &reason_location));
            }
            if reason_strings.iter().any(|r| is_invalid_reason(r)) {
                errors.push(SemError::new(
                    "reasons.opaque_incompatible",
                    &reason_location,
                ));
            }
        }
        "invalid" if !reason_strings.iter().any(|r| is_invalid_reason(r)) => {
            errors.push(SemError::new("reasons.invalid_required", &reason_location));
        }
        _ => {}
    }
    let classification = command
        .get("classification")
        .and_then(Value::as_str)
        .unwrap_or("");
    let expected_evidence = match classification {
        "static" => "complete",
        "opaque" => "opaque",
        "invalid" => "invalid",
        _ => "",
    };
    if evidence != expected_evidence {
        errors.push(SemError::new(
            "evidence.classification_mismatch",
            &format!("/result/commands/{position}/facts/evidence"),
        ));
    }
    errors
}

fn full_diagnostics_errors(command: &Value, position: usize) -> Vec<SemError> {
    let mut errors = Vec::new();
    let Some(facts) = command.get("facts") else {
        return errors;
    };
    let votes: Vec<(String, String)> = facts
        .get("votes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(|v| {
                    v.split_once(':')
                        .map(|(a, r)| (a.to_string(), r.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let matched: Vec<&str> = facts
        .get("matched")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let qualified: Vec<&str> = facts
        .get("qualified")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let base = format!("/result/commands/{position}");

    let classification = command
        .get("classification")
        .and_then(Value::as_str)
        .unwrap_or("");
    let r#match = command.get("match").and_then(Value::as_str).unwrap_or("");
    let verdict = command.get("verdict").and_then(Value::as_str).unwrap_or("");
    if classification == "static"
        && r#match == "argv"
        && verdict == "allow"
        && !votes.iter().any(|(action, _)| action == "allow")
    {
        errors.push(SemError::new(
            "votes.allow_required",
            &format!("{base}/facts/votes"),
        ));
    }

    // canonical ordering is checked on the raw arrays: converting to a set
    // first would sort and deduplicate, making the check vacuous (08 §8.7:
    // `matched`/`qualified` are sorted and unique by UTF-8 bytes).
    if !sorted_unique(&matched) {
        errors.push(SemError::new(
            "matched.not_sorted_unique",
            &format!("{base}/facts/matched"),
        ));
    }
    if !sorted_unique(&qualified) {
        errors.push(SemError::new(
            "qualified.not_sorted_unique",
            &format!("{base}/facts/qualified"),
        ));
    }
    let matched: BTreeSet<&str> = matched.iter().copied().collect();

    let rejected = facts
        .get("rejected")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (entry_position, entry) in rejected.iter().enumerate() {
        let reasons: Vec<&str> = entry
            .get("reasons")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !sorted_unique(&reasons) {
            errors.push(SemError::new(
                "rejected.reasons_not_sorted_unique",
                &format!("{base}/facts/rejected/{entry_position}/reasons"),
            ));
        }
    }
    let rejected_ids: Vec<&str> = rejected
        .iter()
        .filter_map(|e| e.get("ruleId").and_then(Value::as_str))
        .collect();
    let mut duplicate_ids: BTreeSet<&str> = BTreeSet::new();
    for id in &rejected_ids {
        if rejected_ids.iter().filter(|other| **other == *id).count() > 1 {
            duplicate_ids.insert(id);
        }
    }
    if !duplicate_ids.is_empty() {
        errors.push(SemError::new(
            "rejected.duplicate_rule_id",
            &format!("{base}/facts/rejected"),
        ));
    }

    for (action, rule_id) in &votes {
        if !matches!(action.as_str(), "allow" | "ask" | "deny") || rule_id.is_empty() {
            errors.push(SemError::new(
                "votes.invalid",
                &format!("{base}/facts/votes"),
            ));
        }
    }
    for rule in &qualified {
        if !matched.contains(*rule) {
            errors.push(SemError::new(
                "qualified.unmatched",
                &format!("{base}/facts/qualified"),
            ));
        }
        if !votes
            .iter()
            .any(|(action, r)| action == "allow" && r == rule)
        {
            errors.push(SemError::new(
                "qualified.missing_vote",
                &format!("{base}/facts/qualified"),
            ));
        }
    }
    for entry in &rejected {
        let Some(rule_id) = entry.get("ruleId").and_then(Value::as_str) else {
            continue;
        };
        if !matched.contains(rule_id) {
            errors.push(SemError::new(
                "rejected.unmatched",
                &format!("{base}/facts/rejected"),
            ));
        }
    }
    for (action, rule_id) in &votes {
        if !matched.contains(rule_id.as_str()) {
            errors.push(SemError::new(
                "votes.unmatched",
                &format!("{base}/facts/votes"),
            ));
        }
        if action == "allow" && !qualified.contains(&rule_id.as_str()) {
            errors.push(SemError::new(
                "votes.allow_unqualified",
                &format!("{base}/facts/votes"),
            ));
        }
    }

    let vote_actions: Vec<&str> = votes
        .iter()
        .map(|(action, _)| action.as_str())
        .filter(|a| matches!(*a, "allow" | "ask" | "deny"))
        .collect();
    if let Some(strongest_vote) = vote_actions.iter().copied().reduce(|a, b| strongest(a, b))
        && rank(verdict) < rank(strongest_vote)
    {
        errors.push(SemError::new(
            "votes.verdict_mismatch",
            &format!("{base}/facts/votes"),
        ));
    }

    let mut winning: Vec<&str> = votes
        .iter()
        .filter(|(action, _)| action == verdict)
        .map(|(_, rule)| rule.as_str())
        .collect();
    winning.sort_unstable();
    let rule_id = command.get("ruleId").and_then(Value::as_str);
    match (winning.first(), rule_id) {
        (Some(expected), Some(actual)) if actual == *expected => {}
        (Some(_), _) => errors.push(SemError::new(
            if rule_id.is_none() {
                "rule_id.required"
            } else {
                "rule_id.winner_mismatch"
            },
            &format!("{base}/ruleId"),
        )),
        (None, Some(_)) => errors.push(SemError::new(
            "rule_id.unexpected",
            &format!("{base}/ruleId"),
        )),
        (None, None) => {}
    }
    errors
}

fn semantic_errors(
    document: &Value,
    expected_invocation_id: &str,
    expected_commands: usize,
) -> Vec<SemError> {
    let Some(result) = document.get("result") else {
        return vec![SemError::new("commands.empty", "/result/commands")];
    };
    let Some(commands) = result.get("commands").and_then(Value::as_array) else {
        return vec![SemError::new("commands.empty", "/result/commands")];
    };
    if commands.is_empty() {
        return vec![SemError::new("commands.empty", "/result/commands")];
    }
    let mut errors = Vec::new();
    // aggregate consistency: deny > ask > allow
    let command_verdicts: Vec<&str> = commands
        .iter()
        .map(|c| c.get("verdict").and_then(Value::as_str).unwrap_or(""))
        .collect();
    if command_verdicts
        .iter()
        .any(|v| !matches!(*v, "allow" | "ask" | "deny"))
    {
        errors.push(SemError::new("aggregate.mismatch", "/result/verdict"));
    } else {
        let expected = command_verdicts
            .iter()
            .copied()
            .fold("allow", |a, b| if rank(b) > rank(a) { b } else { a });
        if result.get("verdict").and_then(Value::as_str) != Some(expected) {
            errors.push(SemError::new("aggregate.mismatch", "/result/verdict"));
        }
    }
    // invocation echo
    if result.get("invocationId").and_then(Value::as_str) != Some(expected_invocation_id) {
        errors.push(SemError::new("invocation.mismatch", "/result/invocationId"));
    }
    // positional indexes: compare the actual index set against the expected
    // positional set (missing = letter command without a verdict entry,
    // unexpected = verdict entry without a letter command).
    let indexes: Vec<u64> = commands
        .iter()
        .filter_map(|c| c.get("index").and_then(Value::as_u64))
        .collect();
    let expected_set: BTreeSet<u64> = (0..expected_commands as u64).collect();
    let actual_set: BTreeSet<u64> = indexes.iter().copied().collect();
    let missing: Vec<u64> = expected_set.difference(&actual_set).copied().collect();
    let unexpected: Vec<u64> = actual_set.difference(&expected_set).copied().collect();
    if !missing.is_empty() {
        errors.push(SemError::new("indexes.missing", "/result/commands"));
    }
    if !unexpected.is_empty() {
        errors.push(SemError::new("indexes.unexpected", "/result/commands"));
    }
    for (position, index) in commands
        .iter()
        .map(|c| c.get("index").and_then(Value::as_u64))
        .enumerate()
    {
        if index != Some(position as u64) {
            errors.push(SemError::new(
                "indexes.position",
                &format!("/result/commands/{position}/index"),
            ));
        }
    }
    let has_duplicates =
        (0..indexes.len()).any(|i| indexes.iter().position(|v| *v == indexes[i]) != Some(i));
    if has_duplicates {
        errors.push(SemError::new("indexes.duplicate", "/result/commands"));
    }

    for (position, command) in commands.iter().enumerate() {
        let tuple = format!(
            "{}/{}/{}",
            command
                .get("classification")
                .and_then(Value::as_str)
                .unwrap_or(""),
            command.get("match").and_then(Value::as_str).unwrap_or(""),
            command.get("verdict").and_then(Value::as_str).unwrap_or("")
        );
        if !VALID_TUPLES.contains(&tuple.as_str()) {
            errors.push(SemError::new(
                "tuple.impossible",
                &format!("/result/commands/{position}"),
            ));
        }
        if let Some(facts) = command.get("facts").filter(|f| !f.is_null()) {
            let depth = json_depth(facts);
            if depth > MAX_FACTS_DEPTH {
                errors.push(SemError::new(
                    "resource.facts_depth",
                    &format!("/result/commands/{position}/facts"),
                ));
                continue;
            }
            let bytes = serde_json::to_vec(facts)
                .map(|b| b.len())
                .unwrap_or(usize::MAX);
            if bytes > MAX_FACTS_BYTES {
                errors.push(SemError::new(
                    "resource.facts_bytes",
                    &format!("/result/commands/{position}/facts"),
                ));
            }
            let shape = facts_shape_of(facts);
            let Some(shape) = shape else { continue };
            if shape == "malformed" || !diagnostics_members_ok(facts, shape) {
                errors.push(SemError::new(
                    "diagnostics.malformed",
                    &format!("/result/commands/{position}/facts"),
                ));
                continue;
            }
            errors.extend(coherence_errors(command, position));
            if shape == "full" {
                errors.extend(full_diagnostics_errors(command, position));
            }
        }
    }
    errors
}

// ── Manifest-driven conformance ─────────────────────────────────────────────

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/verdict_v2")
}

#[derive(Debug)]
struct Vector {
    path: String,
    roles: Vec<String>,
    phase: String,
    expected_invocation_id: String,
    positional_indexes: usize,
    expected_error: Option<Value>,
}

fn load_manifest() -> Vec<Vector> {
    let text =
        std::fs::read_to_string(fixtures_dir().join("manifest.json")).expect("fixture manifest");
    let manifest: Value = serde_json::from_str(&text).expect("manifest is one JSON value");
    manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures array")
        .iter()
        .map(|entry| Vector {
            path: entry
                .get("path")
                .and_then(Value::as_str)
                .expect("path")
                .to_string(),
            roles: entry
                .get("roles")
                .and_then(Value::as_array)
                .map(|roles| {
                    roles
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .expect("roles"),
            phase: entry
                .get("phase")
                .and_then(Value::as_str)
                .expect("phase")
                .to_string(),
            expected_invocation_id: entry
                .get("expectedInvocationId")
                .and_then(Value::as_str)
                .expect("expectedInvocationId")
                .to_string(),
            positional_indexes: entry
                .get("positionalIndexes")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .expect("positionalIndexes"),
            expected_error: entry.get("expectedError").cloned(),
        })
        .collect()
}

fn run_role(role: &str, vectors: &[Vector]) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();
    let mut selected = 0;
    for vector in vectors {
        if !vector.roles.iter().any(|r| r == role) {
            continue;
        }
        selected += 1;
        let file = fixtures_dir().join(&vector.path);
        let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        if text.len() > MAX_VERDICT_BYTES {
            failures.push(format!("{} exceeds the 64 KiB verdict cap", vector.path));
            continue;
        }
        let document: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", vector.path));
        let schema_valid = schema_errors(&document).is_empty();
        match vector.phase.as_str() {
            "schema" => {
                let errors = schema_errors(&document);
                let expected = vector.expected_error.as_ref().expect("schema expectation");
                if schema_valid || !errors.iter().any(|e| e.matches(expected)) {
                    failures.push(format!(
                        "{}: schema result did not contain {expected}: {errors:?}",
                        vector.path
                    ));
                }
            }
            // consumer-rejection vectors (flat v1) are hook-consumer only; the
            // role filter keeps them out of the checker run.
            "consumer-rejection" => {
                failures.push(format!(
                    "{}: consumer-rejection vector reached the checker run",
                    vector.path
                ));
            }
            "semantic" | "valid" => {
                if !schema_valid {
                    failures.push(format!(
                        "{}: unexpectedly failed schema validation: {:?}",
                        vector.path,
                        schema_errors(&document)
                    ));
                    continue;
                }
                let errors = semantic_errors(
                    &document,
                    &vector.expected_invocation_id,
                    vector.positional_indexes,
                );
                match vector.phase.as_str() {
                    "semantic" => {
                        let expected = vector
                            .expected_error
                            .as_ref()
                            .expect("semantic expectation");
                        if !errors.iter().any(|e| e.matches(expected)) {
                            failures.push(format!(
                                "{}: semantic result did not contain {expected}: {errors:?}",
                                vector.path
                            ));
                        }
                    }
                    _ => {
                        if !errors.is_empty() {
                            failures.push(format!(
                                "{}: unexpectedly failed semantic validation: {errors:?}",
                                vector.path
                            ));
                        }
                    }
                }
            }
            other => failures.push(format!("{}: unknown phase {other}", vector.path)),
        }
    }
    if selected == 0 {
        failures.push(format!("role {role} selected no vectors"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

#[test]
fn checker_producer_conformance() {
    let vectors = load_manifest();
    run_role("checker-producer", &vectors).unwrap();
}

#[test]
fn checker_serialization_conformance() {
    let vectors = load_manifest();
    run_role("checker-serialization", &vectors).unwrap();
}

#[test]
fn hook_consumer_only_vectors_are_not_checker_requirements() {
    let vectors = load_manifest();
    let consumer_only: Vec<&Vector> = vectors
        .iter()
        .filter(|v| v.roles.iter().all(|r| r == "hook-consumer"))
        .collect();
    assert!(
        consumer_only
            .iter()
            .all(|v| v.phase == "consumer-rejection"),
        "hook-only vectors must be consumer-rejection phases"
    );
}

// ── Bounds and emission requirements beyond the shared vectors ──────────────

#[test]
fn full_diagnostics_requires_canonical_ordering_of_matched_and_qualified() {
    // The raw arrays must be checked before any set conversion: an unsorted
    // or duplicated `matched`/`qualified` list is a producer defect even
    // though a BTreeSet would silently canonicalize it (08 §8.7).
    let unsorted = serde_json::json!({
        "index": 0,
        "verdict": "ask",
        "classification": "static",
        "match": "argv",
        "facts": {
            "evidence": "complete",
            "reasons": ["complete"],
            "selectedProfiles": ["p"],
            "matched": ["policy/b", "policy/a"],
            "qualified": [],
            "rejected": [],
            "votes": []
        }
    });
    let errors = full_diagnostics_errors(&unsorted, 0);
    let codes: Vec<&str> = errors.iter().map(|e| e.code.as_str()).collect();
    assert!(
        codes.contains(&"matched.not_sorted_unique"),
        "unsorted matched must be rejected: {codes:?}"
    );

    // `qualified` carries an allow-vote requirement, so the unsorted fixture
    // emits matching allow votes to isolate the ordering error.
    let unsorted_qualified = serde_json::json!({
        "index": 0,
        "verdict": "ask",
        "classification": "static",
        "match": "argv",
        "facts": {
            "evidence": "complete",
            "reasons": ["complete"],
            "selectedProfiles": ["p"],
            "matched": ["policy/a", "policy/b"],
            "qualified": ["policy/b", "policy/a"],
            "rejected": [],
            "votes": ["allow:policy/a", "allow:policy/b"]
        }
    });
    let errors = full_diagnostics_errors(&unsorted_qualified, 0);
    let codes: Vec<&str> = errors.iter().map(|e| e.code.as_str()).collect();
    assert!(
        codes.contains(&"qualified.not_sorted_unique"),
        "unsorted qualified must be rejected: {codes:?}"
    );
}

#[test]
fn full_diagnostics_accepts_canonically_ordered_matched_and_qualified() {
    let canonical = serde_json::json!({
        "index": 0,
        "verdict": "ask",
        "classification": "static",
        "match": "argv",
        "facts": {
            "evidence": "complete",
            "reasons": ["complete"],
            "selectedProfiles": ["p"],
            "matched": ["policy/a", "policy/b"],
            "qualified": ["policy/a", "policy/b"],
            "rejected": [],
            "votes": ["allow:policy/a", "allow:policy/b"]
        }
    });
    let errors = full_diagnostics_errors(&canonical, 0);
    let codes: Vec<&str> = errors.iter().map(|e| e.code.as_str()).collect();
    assert!(
        codes.is_empty(),
        "canonical lists must pass cleanly: {codes:?}"
    );
}

#[test]
fn semantic_bounds_reject_oversize_and_deep_facts() {
    let document = serde_json::json!({
        "protocol": PROTOCOL,
        "result": {
            "invocationId": "bounds:oversize",
            "verdict": "ask",
            "commands": [{
                "index": 0,
                "verdict": "ask",
                "classification": "static",
                "match": "argv",
                "facts": {
                    "evidence": "complete",
                    "reasons": ["complete"],
                    "selectedProfiles": ["p"],
                    "matched": (0..4096).map(|i| format!("rule/{i:05}")).collect::<Vec<_>>(),
                    "qualified": [],
                    "rejected": [],
                    "votes": []
                }
            }]
        }
    });
    let errors = semantic_errors(&document, "bounds:oversize", 1);
    assert!(
        errors.iter().any(|e| e.code == "resource.facts_bytes"),
        "oversize facts must fail: {errors:?}"
    );

    let mut facts = document["result"]["commands"][0]["facts"].clone();
    let mut deep = serde_json::json!({"votes": []});
    for _ in 0..10 {
        deep = serde_json::json!({ "nested": deep });
    }
    facts["extra"] = deep;
    let mut document = document.clone();
    document["result"]["commands"][0]["facts"] = facts;
    let errors = semantic_errors(&document, "bounds:oversize", 1);
    assert!(
        errors.iter().any(|e| e.code == "resource.facts_depth"),
        "deep facts must fail: {errors:?}"
    );
}

/// v2-only emission (HANDOFF §Rust 3): the binary writes the exact envelope
/// root for every outcome and never a flat v1 response.
#[test]
fn binary_emits_v2_only_for_every_outcome() {
    let bin = env!("CARGO_BIN_EXE_shell-warden");
    let config = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/configs/shell-warden.example.jsonc"
    );
    let letters = [
        r#"{"version":1,"invocation":{"id":"v2-only:allow","sessionID":"s"},"action":"shell","commands":[{"index":0,"raw":"git status","cwd":"/repo"}]}"#,
        r#"{"version":1,"invocation":{"id":"v2-only:ask","sessionID":"s"},"action":"shell","commands":[{"index":0,"raw":"git push origin main","cwd":"/repo"}]}"#,
        r#"{"version":1,"invocation":{"id":"v2-only:invalid","sessionID":"s"},"action":"shell","commands":[{"index":0,"raw":"git status --no-such-option","cwd":"/repo"}]}"#,
        r#"{"version":1,"invocation":{"id":"v2-only:opaque","sessionID":"s"},"action":"shell","commands":[{"index":0,"raw":"echo $(whoami)","cwd":"/repo"}]}"#,
        r#"{"version":1,"invocation":{"id":"v2-only:empty","sessionID":"s"},"action":"shell","commands":[{"index":0,"raw":"   ","cwd":"/repo"}]}"#,
    ];
    for letter in letters {
        let mut child = Command::new(bin)
            .arg("--config")
            .arg(config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shell-warden");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(letter.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait");
        assert!(out.status.success(), "checker exited non-zero: {letter}");
        let document: Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("not one JSON value: {e}"));
        let root = document.as_object().expect("envelope root object");
        assert_eq!(
            root.len(),
            2,
            "root MUST contain exactly protocol and result: {root:?}"
        );
        assert_eq!(document["protocol"], PROTOCOL);
        let invocation_id = letter
            .split("\"id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("letter invocation id");
        assert_eq!(document["result"]["invocationId"], invocation_id);
        let errors = semantic_errors(&document, invocation_id, 1);
        assert!(
            schema_errors(&document).is_empty() && errors.is_empty(),
            "checker output must be valid v2 for {invocation_id}: {:?} / {errors:?}",
            schema_errors(&document)
        );
    }
}
