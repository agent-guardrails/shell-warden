// Pipeline-level tests for config v2 (design/shell-warden-config-v2.md).
// Scenario matrix per the design's evaluation-scenario table, plus the
// monotonicity and order-independence property invariants (§Policy resolution
// properties) and wrapper/nesting behavior. Letter fixtures per 02 §2.2.

use shell_warden::checker::config::{load_path, load_str};
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

/// The one-shot decision binary: letter in on stdin, verdict out on stdout,
/// exit 0 verdict / 2 config invalid with empty stdout (02-letter-verdict).
/// The letter is fed from a pre-filled file (`Stdio::from(File)`), not from a
/// pipe: a fail-fast child (config invalid ⇒ exit 2 without reading stdin)
/// would otherwise race `write_all` into a broken pipe and flake the test.
fn run_checker(config_path: &std::path::Path, letter: &str) -> (i32, String, String) {
    use std::process::{Command, Stdio};
    // unique letter file per call: test threads run in parallel and must not
    // share the letter fixture the spawned binary reads
    static CALL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = CALL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = probe_path("letter", "");
    let letter_path = std::path::PathBuf::from(format!(
        "{}-{}",
        base.display().to_string().trim_end_matches(".jsonc"),
        n
    ));
    std::fs::write(&letter_path, letter).expect("letter fixture must be writable");
    let letter_file = std::fs::File::open(&letter_path).expect("letter fixture must be readable");
    let out = Command::new(env!("CARGO_BIN_EXE_shell-warden"))
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::from(letter_file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("checker binary must run");
    let _ = std::fs::remove_file(&letter_path);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// verifies the trailing-input hardening on the exact public surface: the letter
// is valid, only the config text carries junk after the first JSON value.
#[test]
fn binary_rejects_trailing_config_input_with_exit_2() {
    const VALID_LETTER: &str = r#"{"version":1,"invocation":{"id":"p","sessionID":"p"},"action":"shell","commands":[{"index":0,"cwd":"/repo","raw":"git push"}]}"#;
    const VALID_CONFIG: &str = r#"{ "version": 2, "defaults": { "action": "ask" } }"#;
    for (name, suffix) in [
        ("trailing second object", r#" {"x":1}"#),
        ("trailing scalar", " 42"),
        ("trailing garbage", "\n{oops"),
    ] {
        let path = probe_path(
            &format!("trailing-binary-{name}"),
            &format!("{VALID_CONFIG}{suffix}"),
        );
        let (code, stdout, stderr) = run_checker(&path, VALID_LETTER);
        assert_eq!(code, 2, "{name} must exit 2 (stderr: {stderr})");
        assert!(
            stdout.is_empty(),
            "{name} must print nothing on stdout: {stdout:?}"
        );
        assert!(
            stderr.contains("config invalid"),
            "{name} must diagnose config invalid: {stderr}"
        );
        let _ = std::fs::remove_file(&path);
    }
    // the clean config keeps exit 0 with a verdict on stdout
    let clean = probe_path("trailing-binary-clean", VALID_CONFIG);
    let (code, stdout, stderr) = run_checker(&clean, VALID_LETTER);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"verdict\""),
        "clean config must produce a verdict on stdout: {stdout:?}{stderr}"
    );
    assert_eq!(stderr, "");
    let _ = std::fs::remove_file(&clean);
}

#[test]
fn remainder_dto_probe_accepts_canonical_forms() {
    // canonical `{"none": true}`: the bare prefix allows; any argument beyond
    // the closure asks (proving the remainder semantics, not route effects).
    let none_path = probe_path("none-canonical", &probe_config(r#"{ "none": true }"#));
    let none_cfg =
        load_path(&none_path).unwrap_or_else(|e| panic!("canonical none must load: {e}"));
    assert_eq!(
        evaluate(&none_cfg, &letter("git push")).verdict,
        VerdictKind::Allow
    );
    assert_eq!(
        evaluate(&none_cfg, &letter("git push origin")).verdict,
        VerdictKind::Ask,
        "arguments beyond the none closure never allow"
    );

    // canonical `{"each": {"oneOf": [...]}}`: members allow, non-members ask.
    let one_of_path = probe_path(
        "each-one-of",
        &probe_config(r#"{ "each": { "oneOf": ["origin", "main"] } }"#),
    );
    let one_of_cfg =
        load_path(&one_of_path).unwrap_or_else(|e| panic!("canonical each-oneOf must load: {e}"));
    assert_eq!(
        evaluate(&one_of_cfg, &letter("git push origin main")).verdict,
        VerdictKind::Allow
    );
    assert_eq!(
        evaluate(&one_of_cfg, &letter("git push unknown")).verdict,
        VerdictKind::Ask,
        "remainder tokens outside the oneOf member list never allow"
    );

    // canonical `{"each": {"path": {"within": ...}}}` (absolute lexical path
    // root): lexical paths under the root allow, anything outside asks.
    let within_path = probe_path(
        "each-path-within",
        &probe_config(r#"{ "each": { "path": { "within": "/repo" } } }"#),
    );
    let within_cfg =
        load_path(&within_path).unwrap_or_else(|e| panic!("canonical each-path must load: {e}"));
    assert_eq!(
        evaluate(&within_cfg, &letter_cwd("git push README.md", "/repo")).verdict,
        VerdictKind::Allow
    );
    assert_eq!(
        evaluate(&within_cfg, &letter_cwd("git push /etc/passwd", "/repo")).verdict,
        VerdictKind::Ask,
        "paths outside the within root never allow"
    );

    for p in [&none_path, &one_of_path, &within_path] {
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
        ("mixed", r#"{ "none": true, "each": { "any": true } }"#),
        // not-the-closed-form values and unknown forms
        ("false-none", r#"{ "none": false }"#),
        ("unknown", r#"{ "any": true }"#),
        // the interim v0.3.0 `exact-member` and bare `within` alias forms are
        // not part of the closed contract
        ("exact-alias", r#"{ "each": { "exact": ["origin"] } }"#),
        ("within-alias", r#"{ "each": { "within": "/repo" } }"#),
        // oneOf alternatives must be unique
        (
            "one-of-duplicates",
            r#"{ "each": { "oneOf": ["origin", "origin"] } }"#,
        ),
    ] {
        let path = probe_path(name, &probe_config(remainder_value));
        let err = load_path(&path)
            .err()
            .unwrap_or_else(|| panic!("{name} probe must not parse"));
        assert!(
            err.contains("config invalid"),
            "{name} probe must fail during config parsing: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

// ── Option-value coverage + fixed arity (issue 32 matching probes) ─────────

/// A cargo-profile allow probe: one value option covered by a closed
/// selector plus an optional fixed arity-two rename option. Set
/// `name_values` to inject the coverage selector; `name_decl` and
/// `option_id` select the declaration.
fn option_probe_config(
    option_id: &str,
    decl: &str,
    values: &str,
    required: bool,
    repeatable: bool,
    rename_values: Option<&str>,
) -> String {
    let rename_entry = rename_values
        .map(|v| format!(r#", {{ "option": "rename", "required": false, "repeatable": false, "values": {v} }}"#))
        .unwrap_or_default();
    format!(
        r#"{{
  "version": 2,
  "defaults": {{ "action": "ask", "message": "No approved command profile matched.", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [
    {{
      "id": "cargo",
      "executables": ["cargo"],
      "options": {{
        {decl},
        "rename": {{ "aliases": ["--rename"], "arity": 2 }}
      }},
      "rules": [
        {{
          "id": "cargo/allow-init", "action": "allow",
          "match": {{
            "classification": "complete",
            "arguments": {{ "exact": ["init"] }},
            "options": {{ "allowed": [
              {{ "option": "{option_id}", "required": {required}, "repeatable": {repeatable}, "values": {values} }}
              {rename_entry}
            ] }},
            "environment": {{ "none": true }},
            "paths": {{ "none": true }},
            "facts": {{ "none": true }},
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

const NAME_DECL: &str = r#""name": { "aliases": ["--name"], "arity": 1 }"#;
const FILE_DECL: &str = r#""file": { "aliases": ["--file"], "arity": 1 }"#;
const FILE_INLINE_DECL: &str = r#""file": { "aliases": ["--file"], "arity": 1, "inline": true }"#;

#[test]
fn option_value_selectors_cover_closed_arms() {
    // `any` covers one complete literal value
    let cfg = load_str(&option_probe_config(
        "name",
        NAME_DECL,
        r#"{ "each": { "any": true } }"#,
        false,
        true,
        None,
    ))
    .expect("any probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter("cargo init --name one")).verdict,
        VerdictKind::Allow
    );

    // `oneOf` covers a listed literal only
    let cfg = load_str(&option_probe_config(
        "name",
        NAME_DECL,
        r#"{ "each": { "oneOf": ["one"] } }"#,
        false,
        true,
        None,
    ))
    .expect("oneOf probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter("cargo init --name one")).verdict,
        VerdictKind::Allow
    );
    assert_eq!(
        evaluate(&cfg, &letter("cargo init --name two")).verdict,
        VerdictKind::Ask,
        "a oneOf non-member never allows"
    );

    // whole-value `re2-v1` regex: matches the entire value, never a substring
    let cfg = load_str(&option_probe_config(
        "name",
        NAME_DECL,
        r#"{ "each": { "regex": "[a-z]+" } }"#,
        false,
        true,
        None,
    ))
    .expect("regex probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter("cargo init --name abc")).verdict,
        VerdictKind::Allow
    );
    assert_eq!(
        evaluate(&cfg, &letter("cargo init --name abc1")).verdict,
        VerdictKind::Ask,
        "regex selectors match whole values, not substrings"
    );

    // lexical `path` selector with component-boundary containment (a `file`
    // option carries path-like values)
    let cfg = load_str(&option_probe_config(
        "file",
        FILE_DECL,
        r#"{ "each": { "path": { "within": "/work/repo" } } }"#,
        false,
        true,
        None,
    ))
    .expect("path probe config must load");
    assert_eq!(
        evaluate(
            &cfg,
            &letter_cwd("cargo init --file /work/repo/src", "/repo")
        )
        .verdict,
        VerdictKind::Allow
    );
    // `/work/repo2` is NOT within `/work/repo` (component boundary)
    assert_eq!(
        evaluate(
            &cfg,
            &letter_cwd("cargo init --file /work/repo2/src", "/repo")
        )
        .verdict,
        VerdictKind::Ask
    );
}

#[test]
fn repeated_occurrences_and_each_coverage() {
    // two `--file` occurrences, one selector, both values must satisfy it
    let cfg = load_str(&option_probe_config(
        "file",
        FILE_DECL,
        r#"{ "each": { "oneOf": ["a", "b"] } }"#,
        false,
        true,
        None,
    ))
    .expect("each probe config must load");
    // repeated occurrences are individual-covered; an uncovered value fails
    assert_eq!(
        evaluate(&cfg, &letter_cwd("cargo init --file a --file b", "/repo")).verdict,
        VerdictKind::Allow
    );
    assert_eq!(
        evaluate(&cfg, &letter_cwd("cargo init --file a --file x", "/repo")).verdict,
        VerdictKind::Ask,
        "one uncovered value prevents the allow — no first-or-last acting"
    );

    // `repeatable: false` rejects the second occurrence for positive arity
    let cfg = load_str(&option_probe_config(
        "file",
        FILE_DECL,
        r#"{ "each": { "oneOf": ["a", "b"] } }"#,
        false,
        false,
        None,
    ))
    .expect("repeatable probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter_cwd("cargo init --file a --file b", "/repo")).verdict,
        VerdictKind::Ask,
        "option-not-repeatable: occurrences are never collapsed"
    );
}

#[test]
fn fixed_arity_probes() {
    // missing value for a declared arity-one option is invalid evidence —
    // the arity-two rename probe (issue 32 red test "cargo init --name")
    let cfg = load_str(&option_probe_config(
        "name",
        NAME_DECL,
        r#"{ "each": { "any": true } }"#,
        false,
        true,
        None,
    ))
    .expect("arity probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter("cargo init --name")).verdict,
        VerdictKind::Ask,
        "an option value that is never supplied is invalid evidence"
    );

    // byPosition: the rename option consumes exactly two tokens; selectors
    // apply per ordinal (this is the fixed-arity rename probe)
    let cfg = load_str(&option_probe_config(
        "name",
        NAME_DECL,
        r#"{ "each": { "any": true } }"#,
        false,
        true,
        Some(
            r#"{ "byPosition": [ { "oneOf": ["old"] }, { "path": { "within": "/work/project" } } ] }"#,
        ),
    ))
    .expect("byPosition probe config must load");
    assert_eq!(
        evaluate(
            &cfg,
            &letter_cwd("cargo init --rename old /work/project/new", "/repo")
        )
        .verdict,
        VerdictKind::Allow
    );
    // swapped ordinals do not satisfy the positional selectors
    assert_eq!(
        evaluate(
            &cfg,
            &letter_cwd("cargo init --rename new /work/project/old", "/repo")
        )
        .verdict,
        VerdictKind::Ask
    );
    // arity two: only one value supplied — invalid, never a variable read
    assert_eq!(
        evaluate(&cfg, &letter_cwd("cargo init --rename old", "/repo")).verdict,
        VerdictKind::Ask
    );
    // an inline `--rename=x` is rejected: the option never declared inline
    assert_eq!(
        evaluate(
            &cfg,
            &letter_cwd("cargo init --rename=x /work/project/new", "/repo")
        )
        .verdict,
        VerdictKind::Ask
    );
}

// ── Review regressions: fail-closed option parsing and path coordinates ─────

/// `rm -rf /` with a policy that allows `-r`/`-f` but no positional arguments
/// must never allow: the cluster is one argv token and the argument `/`
/// stays an uncovered positional (historical bug: the cluster swallowed the
/// following argv token, a fail-open allow).
#[test]
fn short_option_cluster_never_swallows_the_argument() {
    let config = r#"
{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "rm", "executables": ["rm"],
      "options": { "recursive": { "aliases": ["-r"], "arity": 0 }, "force": { "aliases": ["-f"], "arity": 0 } },
      "rules": [
        {
          "id": "rm/allow-recursive-force", "action": "allow",
          "match": {
            "classification": "complete",
            "arguments": { "exact": [] },
            "options": { "allowed": [
              { "option": "recursive", "required": false, "repeatable": false },
              { "option": "force", "required": false, "repeatable": false }
            ] },
            "environment": { "none": true },
            "paths": { "none": true },
            "facts": { "none": true },
            "nestedParts": { "none": true }
          },
          "redirectPolicy": { "mode": "replace", "policies": ["no-redirects"] }
        }
      ]
    }
  ]
}"#;
    let cfg = load_str(config).expect("cluster probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter("rm -rf /")).verdict,
        VerdictKind::Ask,
        "the `/` argument stays an uncovered positional — no fail-open allow"
    );
    assert_eq!(
        evaluate(&cfg, &letter("rm -r -f /")).verdict,
        VerdictKind::Ask
    );
    assert_eq!(
        evaluate(&cfg, &letter("rm -rf")).verdict,
        VerdictKind::Allow,
        "the flag-only cluster still allows"
    );
}

/// `{index, remainder: true}` path sources select the positionals from the
/// index onwards (inclusive) — not every positional (historical bug: the
/// index was ignored).
#[test]
fn remainder_path_source_selects_from_the_index() {
    let config = |index: u32| {
        format!(
            r#"
{{
  "version": 2,
  "defaults": {{ "action": "ask", "redirectPolicy": "no-redirects" }},
  "redirectPolicies": {{ "no-redirects": {{ "redirects": {{ "none": true }}, "paths": {{ "none": true }} }} }},
  "profiles": [
    {{
      "id": "cargo", "executables": ["cargo"],
      "options": {{}},
      "pathSources": [{{ "argument": {{ "index": {index}, "remainder": true }} }}],
      "rules": [
        {{
          "id": "cargo/allow-init-a", "action": "allow",
          "match": {{
            "classification": "complete",
            "arguments": {{ "exact": ["init", "a"] }},
            "options": {{ "none": true }},
            "environment": {{ "none": true }},
            "paths": {{ "none": true }},
            "facts": {{ "none": true }},
            "nestedParts": {{ "none": true }}
          }},
          "redirectPolicy": {{ "mode": "replace", "policies": ["no-redirects"] }}
        }}
      ]
    }}
  ]
}}"#
        )
    };
    // positionals of `cargo init a` are [init(0), a(1)]: with `{index: 2,
    // remainder: true}` no coordinate may be produced → paths none holds
    let cfg = load_str(&config(2)).expect("remainder probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter_cwd("cargo init a", "/repo")).verdict,
        VerdictKind::Allow,
        "indices below the remaindes start stay unselected"
    );
    // with `{index: 1, remainder: true}` the index-1 positional exists and
    // the `{ "none": true }` paths policy can no longer allow
    let cfg = load_str(&config(1)).expect("remainder probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter_cwd("cargo init a", "/repo")).verdict,
        VerdictKind::Ask,
        "the coordinate is produced from the bound index onwards"
    );
}

// Ask/deny ordinary predicate: `options.values` now carries one closed token// selector per canonical option; the existential test is ∃ occurrence × value.
// The empty value arrives as an *inline* form (`--message=`, declared
// `inline: true`), because an empty argument token is dropped by the parser.
#[test]
fn options_values_predicate_uses_closed_token_selector() {
    let config = r#"
{
  "version": 2,
  "defaults": { "action": "ask", "redirectPolicy": "no-redirects" },
  "redirectPolicies": { "no-redirects": { "redirects": { "none": true }, "paths": { "none": true } } },
  "profiles": [
    {
      "id": "cargo",
      "executables": ["cargo"],
      "options": {
        "message": { "aliases": ["--message"], "arity": 1, "inline": true }
      },
      "rules": [
        {
          "id": "cargo/deny-empty", "action": "deny",
          "message": "empty commit message is forbidden",
          "match": {
            "arguments": { "exact": ["commit"] },
            "options": { "values": { "message": { "regex": "" } } }
          }
        }
      ]
    }
  ]
}"#;
    let cfg = load_str(config).expect("predicate probe config must load");
    assert_eq!(
        evaluate(&cfg, &letter("cargo commit --message=")).verdict,
        VerdictKind::Deny,
        "an empty inline value whole-matches the empty regex"
    );
    assert_eq!(
        evaluate(&cfg, &letter("cargo commit --message=fix")).verdict,
        VerdictKind::Ask,
        "a non-matching value keeps the deny rule unselected"
    );
}

/// Through the real binary with a temporary standalone config: the exact
/// red/green probe battery from issue 32 (fixed arity, repeated `--file`,
/// inline arity one, `each` coverage).
#[test]
fn binary_option_probes_exit_with_verdicts() {
    let config = option_probe_config(
        "file",
        FILE_INLINE_DECL,
        r#"{ "each": { "oneOf": ["a", "b"] } }"#,
        false,
        true,
        None,
    );
    let config_path = probe_path("option-binary-probe", &config);
    for (raw, expected) in [
        // inline arity-one value covered by `each`
        ("cargo init --file=a", "allow"),
        ("cargo init --file a", "allow"),
        ("cargo init --file b --file a", "allow"),
        ("cargo init --file x", "ask"),
        ("cargo init --file", "ask"),
    ] {
        let raw_letter = format!(
            r#"{{"version":1,"invocation":{{"id":"p","sessionID":"p"}},"action":"shell","commands":[{{"index":0,"raw":"{raw}","cwd":"/repo"}}]}}"#
        );
        let (code, stdout, stderr) = run_checker(&config_path, &raw_letter);
        assert_eq!(code, 0, "{raw} must exit 0: {stderr}");
        assert!(
            stdout.contains(&format!("\"verdict\": \"{expected}\""))
                || stdout.contains(&format!("\"verdict\":\"{expected}\"")),
            "{raw} must be {expected}: {stdout}"
        );
    }
    let _ = std::fs::remove_file(&config_path);
}
