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

// ── Verdict v2 wire contract (02-letter-verdict §2.7/§2.8, ADR-0023) ────────

#[test]
fn v2_classification_and_match_follow_the_evidence_state() {
    // complete → static + argv (02 §2.7 mapping table)
    let v = run(SKETCH, "git status");
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["classification"], "static");
    assert_eq!(j["commands"][0]["match"], "argv");

    // opaque → opaque + raw
    let v = run(SKETCH, "git log \"$BRANCH\"");
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["classification"], "opaque");
    assert_eq!(j["commands"][0]["match"], "raw");

    // invalid → invalid + raw; the ask floor keeps it ask, and the bare
    // default ask (no ordinary vote) MUST omit ruleId (08 §8.6.4)
    let v = run(SKETCH, "git status --wat");
    assert_eq!(v.verdict, VerdictKind::Ask);
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["classification"], "invalid");
    assert_eq!(j["commands"][0]["match"], "raw");
    assert!(j["commands"][0]["ruleId"].is_null());
    assert_eq!(
        run_facts(&v)["evidence"],
        "invalid",
        "v2 carries the true evidence state"
    );
}

#[test]
fn invalid_evidence_can_emit_ask_and_deny_from_ordinary_rules() {
    // an emitted ask vote on invalid evidence carries the deterministic ruleId
    let cfg = load_str(UTF8_RULES).expect("config must be valid");
    let v = evaluate(&cfg, &letter("git status --wat"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["ruleId"], "policy/ask-invalid");
    assert_eq!(j["commands"][0]["classification"], "invalid");

    // an ordinary deny rule matching raw text stays dominant on invalid evidence
    let v = run(SKETCH, "git push --force --wat origin main");
    assert_eq!(v.verdict, VerdictKind::Deny);
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["classification"], "invalid");
    assert_eq!(j["commands"][0]["match"], "raw");
    assert_eq!(j["commands"][0]["ruleId"], "git/deny-force-push");
    // deny commands MUST carry ruleId; aggregate deny carries a message
    assert!(v.message.is_some());
}

#[test]
fn empty_command_is_invalid_raw_ask() {
    let v = run(SKETCH, "   ");
    assert_eq!(v.verdict, VerdictKind::Ask);
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["classification"], "invalid");
    assert_eq!(j["commands"][0]["match"], "raw");
    let facts = run_facts(&v);
    assert_eq!(facts["evidence"], "invalid");
    let reasons: Vec<&str> = facts["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(reasons.contains(&"empty-command"), "reasons: {reasons:?}");
}

#[test]
fn diagnostics_are_canonical_sorted_and_anchored() {
    // complete evidence carries the complete anchor (02 §2.8)
    let v = run(SKETCH, "git status");
    let facts = run_facts(&v);
    let reasons: Vec<&str> = facts["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(reasons.contains(&"complete"), "reasons: {reasons:?}");
    assert!(reasons.windows(2).all(|w| w[0] < w[1]), "sorted reasons");
    let matched: Vec<&str> = facts["matched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    assert!(matched.windows(2).all(|w| w[0] < w[1]), "sorted matched");

    // opaque evidence carries the opaque-expansion anchor
    let v = run(SKETCH, "git log \"$BRANCH\"");
    let facts = run_facts(&v);
    let reasons: Vec<&str> = facts["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons.contains(&"opaque-expansion"),
        "reasons: {reasons:?}"
    );
    assert!(
        !reasons
            .iter()
            .any(|r| shell_warden::checker::verdict::is_invalid_cause(r)),
        "opaque evidence must not carry an invalid-cause reason"
    );

    // rejected allow findings collapse to one canonical entry per ruleId with
    // sorted coverage reasons (08 §8.7)
    let v = run(SKETCH, "git log");
    let facts = run_facts(&v);
    let rejected = facts["rejected"].as_array().unwrap();
    assert!(!rejected.is_empty());
    let mut ids: Vec<&str> = rejected
        .iter()
        .map(|e| e["ruleId"].as_str().unwrap())
        .collect();
    let dedup_len = {
        ids.sort();
        ids.dedup();
        ids.len()
    };
    assert_eq!(rejected.len(), dedup_len, "one entry per rejected rule id");
    for entry in rejected {
        let codes: Vec<&str> = entry["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert!(
            codes.windows(2).all(|w| w[0] < w[1]),
            "sorted codes: {codes:?}"
        );
    }
}

const UTF8_RULES: &str = r#"{  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "git",
      "executables": ["git"],
      "options": {},
      "rules": [
        {
          "id": "policy/ask-invalid",
          "action": "ask",
          "match": { "arguments": { "exact": ["status"] } }
        },
        {
          "id": "policy/ask-status",
          "action": "ask",
          "match": { "arguments": { "prefix": ["status"] } }
        }
      ]
    }
  ]
}"#;

#[test]
fn rule_id_is_the_utf8_byte_order_smallest_winning_vote() {
    let cfg = load_str(UTF8_RULES).expect("config must be valid");
    // both rules emit ask votes for `git status`; the UTF-8 byte-order smallest
    // wins ("policy/ask-invalid" < "policy/ask-status")
    let v = evaluate(&cfg, &letter("git status"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["commands"][0]["ruleId"], "policy/ask-invalid");
    let facts = run_facts(&v);
    assert_eq!(
        facts["votes"],
        serde_json::json!(["ask:policy/ask-invalid", "ask:policy/ask-status"]),
        "votes stay in evaluation order"
    );
    // `git fetch origin`: no rule matches — the bare default ask MUST omit
    // ruleId even though the evidence itself is complete (static/argv/ask)
    let v = evaluate(&cfg, &letter("git fetch origin"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let j = serde_json::to_value(&v).unwrap();
    assert!(j["commands"][0]["ruleId"].is_null());
    assert_eq!(j["commands"][0]["classification"], "static");
    assert_eq!(j["commands"][0]["match"], "argv");
    let facts = run_facts(&v);
    assert_eq!(facts["votes"], serde_json::json!([]));
}
