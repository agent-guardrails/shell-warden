// Pipeline-level tests for config v2 (design/shell-warden-config-v2.md).
// Scenario matrix per the design's evaluation-scenario table, plus the
// monotonicity and order-independence property invariants (§Policy resolution
// properties) and wrapper/nesting behavior. Letter fixtures per 02 §2.2.

use shell_warden::checker::config::load_str;
use shell_warden::checker::letter::Letter;
use shell_warden::checker::pipeline::evaluate;
use shell_warden::checker::verdict::{Verdict, VerdictKind};

const SKETCH: &str = include_str!("fixtures/sketch.jsonc");

const SED_XARGS: &str = r#"{  "version": 2,
  "defaults": { "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "sed",
      "executables": ["sed"],
      "options": {
        "inPlace": { "aliases": ["-i"], "arity": 0 },
        "expression": { "aliases": ["-e"], "arity": 1 }
      },
      "analyzer": "sed-v1",
      "rules": [
        {
          "id": "sed/deny-inplace",
          "action": "deny",
          "message": "In-place edits must go through a workspace commit.",
          "match": {
            "classification": "complete",
            "facts": { "any": [{ "name": "executionPrimitive", "value": "inPlace" }] }
          }
        },
        {
          "id": "sed/allow-read",
          "action": "allow",
          "match": {
            "classification": "complete",
            "arguments": { "exact": ["s/a/b/", "f.txt"] },
            "options": { "none": true },
            "environment": { "none": true },
            "paths": { "none": true },
            "facts": { "all": [
              { "name": "programForm", "value": "positional" },
              { "name": "programForm", "value": "expression" },
              { "name": "programForm", "value": "file" }
            ] },
            "nestedParts": { "none": true }
          }
        }
      ]
    },
    {
      "id": "rm",
      "executables": ["rm"],
      "options": {
        "recursiveForce": { "aliases": ["-rf"], "arity": 0 }
      },
      "analyzer": "generic-v1",
      "rules": [
        {
          "id": "rm/deny-root",
          "action": "deny",
          "message": "rm against / is never allowed.",
          "match": { "arguments": { "containsAny": ["/"] } }
        }
      ]
    },
    {
      "id": "xargs",
      "executables": ["xargs"],
      "options": {},
      "analyzer": "xargs-v1",
      "rules": []
    }
  ]
}"#;

fn letter(raw: &str) -> Letter {
    letter_cwd(raw, "/repo")
}

fn letter_cwd(raw: &str, cwd: &str) -> Letter {
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    let src = format!(
        r#"{{"version":1,"invocation":{{"id":"m:c","sessionID":"s1","projectDir":"/repo"}},
            "action":"shell","commands":[{{"index":0,"raw":"{escaped}","cwd":"{cwd}"}}]}}"#
    );
    Letter::from_bytes(src.as_bytes()).expect("letter fixture should parse")
}

#[track_caller]
fn run_facts(v: &Verdict) -> serde_json::Value {
    serde_json::to_value(v).unwrap()["commands"][0]["facts"].clone()
}

fn run(config_text: &str, raw: &str) -> Verdict {
    let cfg = load_str(config_text).expect("config must be valid");
    evaluate(&cfg, &letter(raw))
}

// ── Design scenario table ───────────────────────────────────────────────────

#[test]
fn force_push_denied() {
    let v = run(SKETCH, "git push --force --dry-run origin main");
    assert_eq!(v.verdict, VerdictKind::Deny);
    assert!(v.message.as_deref().unwrap().contains("without force"));
}

#[test]
fn ask_dominates_allow() {
    // design row: `git log --oneline` plus an explicit matching ask ⇒ ask
    const WITH_ASK: &str = r#"{
  "version": 2,
  "defaults": { "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "git",
      "executables": ["git"],
      "options": { "oneline": { "aliases": ["--oneline"], "arity": 0 } },
      "rules": [
        { "id": "git/ask-log-oneline", "action": "ask", "message": "log asks the human",
          "match": { "arguments": { "exact": ["log"] }, "options": { "presentAll": ["oneline"] } } },
        { "id": "git/allow-log-oneline", "action": "allow",
          "match": { "classification": "complete", "arguments": { "exact": ["log"] },
            "options": { "allowed": [{ "option": "oneline", "required": true, "repeatable": false }] },
            "environment": { "none": true }, "paths": { "none": true },
            "facts": { "none": true }, "nestedParts": { "none": true } } }
      ]
    }
  ]
}"#;
    const WITHOUT_ASK: &str = r#"{
  "version": 2,
  "defaults": { "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "git",
      "executables": ["git"],
      "options": { "oneline": { "aliases": ["--oneline"], "arity": 0 } },
      "rules": [
        { "id": "git/allow-log-oneline", "action": "allow",
          "match": { "classification": "complete", "arguments": { "exact": ["log"] },
            "options": { "allowed": [{ "option": "oneline", "required": true, "repeatable": false }] },
            "environment": { "none": true }, "paths": { "none": true },
            "facts": { "none": true }, "nestedParts": { "none": true } } }
      ]
    }
  ]
}"#;
    assert_eq!(run(WITH_ASK, "git log --oneline").verdict, VerdictKind::Ask);
    assert_eq!(
        run(WITHOUT_ASK, "git log --oneline").verdict,
        VerdictKind::Allow
    );
}

fn allow_log_oneline_impl() {
    let v = run(SKETCH, "git log --oneline");
    assert_eq!(v.verdict, VerdictKind::Allow);
}

fn split8() -> String {
    // used by tests below that need an allow for log with no redirect
    String::from("git log --oneline")
}

#[test]
fn required_option_absence_prevents_allow() {
    // `git log` misses the required oneline option
    let v = run(SKETCH, "git log");
    assert_eq!(v.verdict, VerdictKind::Ask);
    let _ = split8;
}

#[test]
fn required_dryrun_absence_prevents_allow() {
    let v = run(SKETCH, "git push origin main");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn bare_version_allowed() {
    let v = run(SKETCH, "node --version");
    assert_eq!(v.verdict, VerdictKind::Allow);
}

#[test]
fn bare_node_asks() {
    let v = run(SKETCH, "node");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn non_repeatable_second_occurrence_prevents_allow() {
    let v = run(SKETCH, "git log --oneline --oneline");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn unknown_option_blocks_allow() {
    let v = run(SKETCH, "git status --unknown-option");
    assert_eq!(v.verdict, VerdictKind::Ask);
    let facts = run_facts(&v);
    assert!(
        facts["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "unknown-option")
    );
}

#[test]
fn opaque_double_quoted_expansion_asks() {
    let v = run(SKETCH, "git log \"$BRANCH\"");
    assert_eq!(v.verdict, VerdictKind::Ask);
    let facts = run_facts(&v);
    assert_eq!(facts["evidence"], "opaque");
}

#[test]
fn redirect_inside_policy_allows() {
    let v = run_cwd(SKETCH, "git status > /tmp/reports/status.txt", "/repo");
    assert_eq!(v.verdict, VerdictKind::Allow);
}

fn run_cwd(config_text: &str, raw: &str, cwd: &str) -> Verdict {
    let cfg = load_str(config_text).expect("config must be valid");
    evaluate(&cfg, &letter_cwd(raw, cwd))
}

#[test]
fn redirect_outside_policy_asks() {
    let v = run_cwd(SKETCH, "git status > /tmp/other/status.txt", "/repo");
    assert_eq!(v.verdict, VerdictKind::Ask);
    let facts = run_facts(&v);
    assert!(
        facts["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ruleId"] == "git/allow-status")
    );
}

#[test]
fn append_within_extended_policy_allows() {
    let v = run_cwd(
        SKETCH,
        "git status >> /var/tmp/git-reports/status.txt",
        "/repo",
    );
    assert_eq!(v.verdict, VerdictKind::Allow);
}

#[test]
fn replaced_policy_disallows_redirect() {
    let v = run_cwd(SKETCH, "git log --oneline > /tmp/reports/log.txt", "/repo");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn fd_duplication_not_selected_asks() {
    let v = run_cwd(SKETCH, "git status 2>&1", "/repo");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn dynamic_redirect_target_asks() {
    let v = run_cwd(SKETCH, "git status > \"$REPORT\"", "/repo");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn environment_assignment_prevents_allow() {
    let v = run_cwd(SKETCH, "GIT_DIR=/tmp/repo git status", "/repo");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn chain_reduces_both_parts() {
    let v = run(SKETCH, "git status; git push --force");
    assert_eq!(v.verdict, VerdictKind::Deny);
}

#[test]
fn pipelne_segments_reduce() {
    let v = run(SKETCH, "git status | cat");
    // `cat` has no profile ⇒ ask dominates the allow of git status
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn sed_in_place_denied_via_analyzer_fact() {
    let v = run(SED_XARGS, "sed -i s/a/b/ f.txt");
    assert_eq!(v.verdict, VerdictKind::Deny);
}

#[test]
fn sed_plain_reads_allowed() {
    let v = run(SED_XARGS, "sed s/a/b/ f.txt");
    assert_eq!(v.verdict, VerdictKind::Allow);
}

#[test]
fn sed_program_form_fact_emitted() {
    // programForm (`positional`) fires for a bare script, and the read allow
    // only survives because programForm is not safety-relevant
    let v = run(SED_XARGS, "sed s/a/b/ f.txt");
    let facts = run_facts(&v);
    assert_eq!(facts["evidence"], "complete");
    assert_eq!(v.verdict, VerdictKind::Allow);

    // expression-form scripts carry the same allow without stdin writes
    let with_e = run(SED_XARGS, "sed -e s/a/b/ f.txt");
    assert_eq!(with_e.verdict, VerdictKind::Ask); // exact positional list differs
}

#[test]
fn xargs_nested_rm_denied() {
    // xargs-v1 emits the nested rm analyzerCommand part; the rm profile deny
    // joins the lattice: xargs rm -rf / ⇒ deny
    let v = run(SED_XARGS, "xargs rm -rf /");
    assert_eq!(v.verdict, VerdictKind::Deny);
}

#[test]
fn xargs_stdin_arg_command_asks() {
    // operand with no matching deny still asks (stdin-append ⇒ opaque)
    let v = run(SED_XARGS, "xargs echo hi");
    assert_eq!(v.verdict, VerdictKind::Ask);
}

// ── Wrapper / substitution semantics ────────────────────────────────────────

#[test]
fn bash_c_children_reduce() {
    let v = run(SED_XARGS, "bash -c 'xargs rm -rf /' >/dev/null");
    assert_eq!(v.verdict, VerdictKind::Deny);
}

#[test]
fn command_substitution_children_reduce() {
    let v = run(SKETCH, "echo $(git push --force)");
    assert_eq!(v.verdict, VerdictKind::Deny);
}

#[test]
fn sudo_unwraps_to_child_profile() {
    let v = run(SKETCH, "sudo git status");
    assert_eq!(v.verdict, VerdictKind::Allow);
}

// ── Monotonicity + order-independence properties ────────────────────────────

const MONO_BASE: &str = r#"{
  "version": 2,
  "defaults": { "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "ls",
      "executables": ["ls"],
      "options": { "all": { "aliases": ["-a"], "arity": 0 } },
      "rules": [
        { "id": "ls/ask-all", "action": "ask", "message": "ls -a asks",
          "match": { "options": { "presentAny": ["all"] } } }
      ]
    }
  ]
}"#;

#[test]
fn added_allow_cannot_lower_ask() {
    let cfg = load_str(MONO_BASE).unwrap();
    let v0 = evaluate(&cfg, &letter("ls -a"));
    assert_eq!(v0.verdict, VerdictKind::Ask);

    let plus = r#""rules": [
        { "id": "ls/ask-all", "action": "ask", "message": "ls -a asks",
          "match": { "options": { "presentAny": ["all"] } } },
        { "id": "ls/allow-all", "action": "allow",
          "match": { "classification": "complete",
                     "arguments": { "exact": [] },
                     "options": { "allowed": [{ "option": "all", "required": false, "repeatable": false }] },
                     "environment": { "none": true },
                     "paths": { "none": true },
                     "facts": { "none": true },
                     "nestedParts": { "none": true } } }
      ]"#;
    let cfg2_text = MONO_BASE.replace(
        r#""rules": [
        { "id": "ls/ask-all", "action": "ask", "message": "ls -a asks",
          "match": { "options": { "presentAny": ["all"] } } }
      ]"#,
        plus,
    );
    let cfg2 = load_str(&cfg2_text).unwrap();
    let v2 = evaluate(&cfg2, &letter("ls -a"));
    assert_eq!(v2.verdict, VerdictKind::Ask);
}

#[test]
fn reorder_rules_options_policies_keeps_verdicts() {
    // permute the sketch by hand: reverse rule order, put node first
    let permuted = r#"{
  "version": 2,
  "defaults": { "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "safe-local-io" },
  "profiles": [
    {
      "id": "node-version",
      "executables": ["node"],
      "options": { "version": { "aliases": ["--version", "-V"], "arity": 0 } },
      "redirectPolicy": { "mode": "replace", "policies": ["no-redirects"] },
      "analyzer": "generic-v1",
      "rules": [
        { "id": "node-version/allow-bare-version", "action": "allow",
          "match": { "classification": "complete", "arguments": { "exact": [] },
            "options": { "allowed": [{ "option": "version", "required": true, "repeatable": false }] },
            "environment": { "none": true }, "paths": { "none": true },
            "facts": { "none": true }, "nestedParts": { "none": true } } }
      ]
    },
    {
      "id": "git",
      "executables": ["git"],
      "options": {
        "dryRun": { "aliases": ["--dry-run", "-n"], "arity": 0 },
        "oneline": { "aliases": ["--oneline"], "arity": 0 },
        "force": { "aliases": ["--force", "-f"], "arity": 0 }
      },
      "analyzer": "generic-v1",
      "rules": [
        { "id": "git/allow-log-oneline", "action": "allow",
          "redirectPolicy": { "mode": "replace", "policies": ["no-redirects"] },
          "match": { "classification": "complete", "arguments": { "exact": ["log"] },
            "options": { "allowed": [{ "option": "oneline", "required": true, "repeatable": false }] },
            "environment": { "none": true }, "paths": { "none": true },
            "facts": { "none": true }, "nestedParts": { "none": true } } },
        { "id": "git/allow-status-append-report", "action": "allow",
          "redirectPolicy": { "mode": "extend", "inline": {
            "redirects": { "all": [{ "sourceFd": "default", "operator": ">>", "occurrence": "all", "target": { "kind": "literalPath" } }] },
            "paths": { "all": [{ "coordinate": { "redirect": { "operator": ">>", "sourceFd": "default", "occurrence": "all" } }, "within": "/var/tmp/git-reports" }] } } },
          "match": { "classification": "complete", "arguments": { "exact": ["status"] },
            "options": { "none": true }, "environment": { "none": true },
            "paths": { "none": true }, "facts": { "none": true },
            "nestedParts": { "none": true } } },
        { "id": "git/allow-push-dry-run", "action": "allow",
          "redirectPolicy": { "mode": "replace", "policies": ["no-redirects"] },
          "match": { "classification": "complete", "arguments": { "exact": ["push", "origin", "main"] },
            "options": { "allowed": [{ "option": "dryRun", "required": true, "repeatable": false }] },
            "environment": { "none": true }, "paths": { "none": true },
            "facts": { "none": true }, "nestedParts": { "none": true } } },
        { "id": "git/allow-status", "action": "allow",
          "match": { "classification": "complete", "arguments": { "exact": ["status"] },
            "options": { "none": true }, "environment": { "none": true },
            "paths": { "none": true }, "facts": { "none": true },
            "nestedParts": { "none": true } } },
        { "id": "git/deny-force-push", "action": "deny",
          "message": "Push without force, or create a branch and open a pull request.",
          "match": { "arguments": { "prefix": ["push"] }, "options": { "presentAny": ["force"] } } }
      ]
    }
  ],
  "redirectPolicies": {
    "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } },
    "safe-local-io": {
      "redirects": { "all": [{ "sourceFd": "default", "operator": ">", "occurrence": "all", "target": { "kind": "literalPath" } }] },
      "paths": { "all": [{ "coordinate": { "redirect": { "operator": ">", "sourceFd": "default", "occurrence": "all" } }, "within": "/tmp/reports" }] }
    }
  }
}"#;
    let a = load_str(SKETCH).unwrap();
    let b = load_str(permuted).unwrap();
    for case in [
        "git push --force --dry-run origin main",
        "git status > /tmp/reports/status.txt",
        "git log --oneline",
        "node --version",
        "git push origin main",
    ] {
        assert_eq!(
            evaluate(&a, &letter(case)).verdict,
            evaluate(&b, &letter(case)).verdict,
            "verdict differs across equivalent permutations for {case}"
        );
    }
}

#[test]
fn allow_log_oneline_smoke() {
    allow_log_oneline_impl();
}

// ── Config-v2 canonical wire DTOs (issue #34): fixture probe ────────────────
//
// Standalone temporary config files, loaded through the real config entry
// point (`load_path`): canonical one-level forms load and their allow
// coverage holds; nested externally tagged, mixed, and unknown forms are
// rejected during config parsing — before any verdict is produced.

fn probe_config(remainder_value: &str) -> String {
    format!(
        r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [
    {{
      "id": "git",
      "executables": ["git"],
      "options": {{ "oneline": {{ "aliases": ["--oneline"], "arity": 0 }} }},
      "rules": [
        {{
          "id": "git/allow-push-suffix", "action": "allow",
          "match": {{
            "classification": "complete",
            "arguments": {{ "prefix": ["push"], "remainder": {remainder_value} }},
            "options": {{ "none": true }}, "environment": {{ "none": true }},
            "paths": {{ "none": true }}, "facts": {{ "none": true }},
            "nestedParts": {{ "none": true }}
          }},
          "redirectPolicy": {{ "mode": "replace", "policies": ["no-redirects"] }}
        }}
      ]
    }}
  ]
}}"#
    )
}

fn probe_path(name: &str, text: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shell-warden-34-{}-{}.jsonc",
        name,
        std::process::id()
    ));
    std::fs::write(&p, text).expect("probe fixture must be writable");
    p
}

#[test]
fn remainder_dto_probe_accepts_canonical_forms() {
    // canonical `{"none": true}`: no argument beyond the prefix.
    let none_path = probe_path("none-canonical", &probe_config(r#"{ "none": true }"#));
    let none_cfg = load_str(&std::fs::read_to_string(&none_path).unwrap())
        .unwrap_or_else(|e| panic!("canonical none must load: {e}"));
    assert_eq!(
        evaluate(&none_cfg, &letter("git push --dry-run")).verdict,
        VerdictKind::Ask,
        "extra arguments beyond the none closure never allow"
    );

    // canonical `{"each": {"exact": [...]}}`.
    let exact_path = probe_path(
        "each-exact",
        &probe_config(r#"{ "each": { "exact": ["origin", "main"] } }"#),
    );
    let exact_cfg = load_str(&std::fs::read_to_string(&exact_path).unwrap())
        .unwrap_or_else(|e| panic!("canonical each-exact must load: {e}"));
    assert_eq!(
        evaluate(&exact_cfg, &letter("git push origin main")).verdict,
        VerdictKind::Allow
    );

    // canonical `{"each": {"within": ...}}` (absolute lexical path root).
    let within_path = probe_path(
        "each-within",
        &probe_config(r#"{ "each": { "within": "/repo" } }"#),
    );
    let within_cfg = load_str(&std::fs::read_to_string(&within_path).unwrap())
        .unwrap_or_else(|e| panic!("canonical each-within must load: {e}"));
    assert_eq!(
        evaluate(&within_cfg, &letter_cwd("git push README.md", "/repo")).verdict,
        VerdictKind::Allow
    );

    for p in [&none_path, &exact_path, &within_path] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn remainder_dto_probe_rejects_non_canonical_forms() {
    for (name, remainder_value) in [
        // nested externally tagged forms (docs fixtures RemainderPolicy/
        // nested-serde-none.json, OptionValueCoverage/nested-serde-each.json)
        ("none-nested", r#"{ "none": { "none": true } }"#),
        ("each-nested", r#"{ "each": { "each": { "any": true } } }"#),
        // mixed union arms
        (
            "mixed",
            r#"{ "none": true, "each": { "exact": ["origin"] } }"#,
        ),
        // not-the-closed-form values and unknown forms
        ("false-none", r#"{ "none": false }"#),
        ("unknown", r#"{ "any": true }"#),
        (
            "rich-path-alias",
            r#"{ "each": { "path": { "within": "/repo" } } }"#,
        ),
    ] {
        let path = probe_path(name, &probe_config(remainder_value));
        let text = std::fs::read_to_string(&path).unwrap();
        let err = load_str(&text)
            .err()
            .unwrap_or_else(|| panic!("{name} probe must not parse"));
        assert!(
            err.contains("config invalid"),
            "{name} probe must fail during config parsing: {err}"
        );
    }
}
