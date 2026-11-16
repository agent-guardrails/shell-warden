// Contract: https://github.com/agent-guardrails/docs/issues/39.
// Regression coverage: https://github.com/agent-guardrails/shell-warden/issues/51.
use serde_json::{Value, json};
use shell_warden::checker::config::{load_paths, load_str};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Files(PathBuf);

impl Files {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sw-repeatable-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn write(&self, name: &str, policy: &Value) -> PathBuf {
        self.text(name, &serde_json::to_string(policy).unwrap())
    }

    fn text(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_shell-warden"));
        command.env("HOME", &self.0).env("XDG_CONFIG_HOME", &self.0);
        command
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn policy(profiles: Vec<Value>) -> Value {
    json!({
        "version": 2,
        "defaults": {"action": "ask", "redirectPolicy": "no-redirects"},
        "redirectPolicies": {
            "no-redirects": {"redirects": {"none": true}, "paths": {"none": true}}
        },
        "profiles": profiles
    })
}

fn profile(id: &str, executable: &str) -> Value {
    json!({
        "id": id, "executables": [executable], "options": {},
        "rules": [{
            "id": "allow", "action": "allow",
            "match": {
                "classification": "complete", "arguments": {"exact": []},
                "options": {"none": true}, "environment": {"none": true},
                "paths": {"none": true}, "facts": {"none": true},
                "nestedParts": {"none": true}
            }
        }],
        "fallbackHints": [{"id": "hint", "message": "Not approved."}]
    })
}

fn invoke(mut command: Command, raw: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let letter = json!({
        "version": 1,
        "invocation": {"id": "m:c", "sessionID": "s1", "projectDir": "/repo"},
        "action": "shell", "commands": [{"index": 0, "raw": raw, "cwd": "/repo"}]
    });
    // Invalid configuration deliberately exits before reading the letter.
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(letter.to_string().as_bytes());
    child.wait_with_output().unwrap()
}

fn verdict(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn config_error(mut command: Command, paths: &[&Path]) -> String {
    for path in paths {
        command.arg("--config").arg(path);
    }
    // No stdin: detecting an invalid later input must not depend on a letter.
    let out = command.stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    String::from_utf8(out.stderr).unwrap()
}

fn conflict(files: &Files, a: &Value, b: &Value, expected: &str) {
    let first = files.write("first.jsonc", a);
    let second = files.write("second.jsonc", b);
    for paths in [[&first, &second], [&second, &first]] {
        let error = config_error(files.cli(), &[paths[0], paths[1]]);
        assert!(error.contains(expected), "{error}");
        for path in paths {
            assert!(error.contains(path.to_str().unwrap()), "{error}");
        }
    }
}

#[test]
fn disjoint_profiles_work_in_both_orders_and_keep_local_rule_and_hint_ids() {
    let f = Files::new();
    let first_policy = policy(vec![profile("first", "first")]);
    let second_policy = policy(vec![profile("second", "second")]);
    let a = f.write("first.jsonc", &first_policy);
    let b = f.write("second.jsonc", &second_policy);
    for paths in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
        let config = load_paths(&paths).unwrap();
        assert_eq!(config.profiles().len(), 2);
        assert_eq!(
            config.raw.profiles[0].id,
            if paths[0] == a { "first" } else { "second" }
        );
        assert_eq!(config.raw.redirect_policies.len(), 1);
        for raw in ["first", "second", "first && second"] {
            let mut cmd = f.cli();
            for path in &paths {
                cmd.arg("--config").arg(path);
            }
            assert_eq!(verdict(invoke(cmd, raw))["result"]["verdict"], "allow");
        }
    }
    // Each original profile survives unchanged, including its rules/hints.
    let config = load_paths(&[a, b]).unwrap();
    assert_eq!(
        serde_json::to_value(&config.raw.profiles[0]).unwrap(),
        serde_json::to_value(&load_str(&first_policy.to_string()).unwrap().raw.profiles[0])
            .unwrap()
    );
}

#[test]
fn unchanged_deny_rules_and_fallback_hints_survive_assembly() {
    let f = Files::new();
    let mut a_profile = profile("a", "a");
    a_profile["rules"].as_array_mut().unwrap().push(json!({
        "id": "deny", "action": "deny", "message": "Blocked.",
        "match": {"arguments": {"exact": ["blocked"]}}
    }));
    let a = f.write("a", &policy(vec![a_profile]));
    let b = f.write("b", &policy(vec![profile("b", "b")]));
    for paths in [[&a, &b], [&b, &a]] {
        for (raw, expected, message) in [
            ("a blocked && b", "deny", "Blocked."),
            ("a unmatched", "ask", ""),
            ("unknown", "ask", ""),
        ] {
            let mut cmd = f.cli();
            for path in paths {
                cmd.arg("--config").arg(path);
            }
            let out = verdict(invoke(cmd, raw));
            assert_eq!(out["result"]["verdict"], expected, "{out}");
            let mut single = f.cli();
            single.arg("--config").arg(&a);
            let baseline = verdict(invoke(single, raw));
            assert_eq!(out["result"]["message"], baseline["result"]["message"]);
            if !message.is_empty() {
                assert!(
                    out["result"]["message"].as_str().unwrap().contains(message),
                    "{out}"
                );
            }
        }
    }
}

#[test]
fn single_file_and_default_path_remain_compatible_and_explicit_paths_suppress_default() {
    let f = Files::new();
    std::fs::create_dir(f.0.join("shell-warden")).unwrap();
    let default = f.write(
        "shell-warden/config.jsonc",
        &policy(vec![profile("default", "default")]),
    );
    assert_eq!(
        verdict(invoke(f.cli(), "default"))["result"]["verdict"],
        "allow"
    );
    let a = f.write("a.jsonc", &policy(vec![profile("a", "a")]));
    let b = f.write("b.jsonc", &policy(vec![profile("b", "b")]));
    std::fs::write(&default, "invalid default must not be read").unwrap();
    for paths in [vec![&a], vec![&a, &b]] {
        let mut cmd = f.cli();
        for path in paths {
            cmd.arg("--config").arg(path);
        }
        assert_eq!(verdict(invoke(cmd, "a"))["result"]["verdict"], "allow");
    }
    let error = config_error(f.cli(), &[]);
    assert!(error.contains(default.to_str().unwrap()), "{error}");

    // HOME fallback when XDG is absent.
    std::fs::create_dir_all(f.0.join(".config/shell-warden")).unwrap();
    f.write(
        ".config/shell-warden/config.jsonc",
        &policy(vec![profile("home", "home")]),
    );
    let mut cmd = f.cli();
    cmd.env_remove("XDG_CONFIG_HOME");
    assert_eq!(verdict(invoke(cmd, "home"))["result"]["verdict"], "allow");
}

#[test]
fn profiles_executables_defaults_and_redirect_conflicts_name_both_sources() {
    let f = Files::new();
    let a = policy(vec![profile("p", "first")]);
    conflict(&f, &a, &policy(vec![profile("p", "second")]), "profile id");
    conflict(&f, &a, &a, "profile id");
    conflict(&f, &a, &policy(vec![profile("q", "first")]), "executable");
    for field in ["message", "redirectPolicy"] {
        let mut b = policy(vec![]);
        b["defaults"][field] = json!(if field == "message" {
            "different"
        } else {
            "other"
        });
        b["redirectPolicies"]["other"] = b["redirectPolicies"]["no-redirects"].clone();
        conflict(&f, &a, &b, "defaults");
    }
    let mut b = policy(vec![]);
    b["redirectPolicies"]["no-redirects"]["paths"] = json!({
        "all": [{"coordinate": {"redirect": {"operator": ">", "sourceFd": "default", "occurrence": "all"}},
                 "within": "/repo"}]
    });
    conflict(&f, &a, &b, "redirect policy");
}

#[test]
fn distinct_redirect_names_are_unioned_without_replacing_definitions() {
    let f = Files::new();
    let a = f.write("a", &policy(vec![]));
    let mut second = policy(vec![]);
    second["redirectPolicies"]["other"] = second["redirectPolicies"]["no-redirects"].clone();
    let b = f.write("b", &second);
    assert_eq!(load_paths(&[a, b]).unwrap().raw.redirect_policies.len(), 2);
}

#[test]
fn executable_aliases_conflict_but_option_aliases_remain_profile_local() {
    let f = Files::new();
    let mut node = profile("node", "node");
    node["executables"] = json!(["node", "nodejs"]);
    conflict(
        &f,
        &policy(vec![node]),
        &policy(vec![profile("other", "nodejs")]),
        "executable",
    );
    let mut a = profile("a", "a");
    let mut b = profile("b", "b");
    for p in [&mut a, &mut b] {
        p["options"] = json!({"version": {"aliases": ["--version"], "arity": 0}});
    }
    let a = f.write("a", &policy(vec![a]));
    let b = f.write("b", &policy(vec![b]));
    assert!(load_paths(&[a, b]).is_ok());
}

#[test]
fn duplicate_rule_and_hint_ids_within_a_file_still_reject_the_entire_set() {
    let f = Files::new();
    let a = f.write("a", &policy(vec![profile("a", "a")]));
    for field in ["rules", "fallbackHints"] {
        let mut p = profile("b", "b");
        p[field] = json!([p[field][0].clone(), p[field][0].clone()]);
        let b = f.write("b", &policy(vec![p]));
        let error = config_error(f.cli(), &[&a, &b]);
        assert!(error.contains("duplicate"), "{error}");
        assert!(error.contains(b.to_str().unwrap()), "{error}");
    }
}

#[test]
fn invalid_later_files_never_activate_a_valid_prefix() {
    let f = Files::new();
    let a = f.write("valid", &policy(vec![profile("a", "a")]));
    for invalid in [
        "",
        "{}",
        "[]",
        "invalid",
        "{\"version\":2,\"version\":2}",
        "{\"version\":1}",
    ] {
        let b = f.text("invalid", invalid);
        for paths in [[&a, &b], [&b, &a]] {
            let error = config_error(f.cli(), &[paths[0], paths[1]]);
            assert!(error.contains(b.to_str().unwrap()), "{error}");
        }
    }
    let missing = f.0.join("missing");
    let error = config_error(f.cli(), &[&a, &missing]);
    assert!(error.contains(missing.to_str().unwrap()), "{error}");
    let bad_utf8 = f.0.join("non-utf8");
    std::fs::write(&bad_utf8, [0xff]).unwrap();
    assert!(config_error(f.cli(), &[&a, &bad_utf8]).contains("UTF-8"));
}

#[test]
fn complete_empty_policies_are_valid_but_an_empty_input_set_is_not() {
    let f = Files::new();
    let a = f.write("a", &policy(vec![]));
    let b = f.write("b", &policy(vec![]));
    let mut cmd = f.cli();
    cmd.arg("--config").arg(a).arg("--config").arg(b);
    assert_eq!(verdict(invoke(cmd, "unknown"))["result"]["verdict"], "ask");
    assert!(load_paths(&[]).is_err());
}

#[test]
fn duplicate_canonical_paths_and_symlinks_are_errors() {
    let f = Files::new();
    let a = f.write("policy.jsonc", &policy(vec![]));
    for b in [a.clone(), f.0.join("./policy.jsonc")] {
        let error = config_error(f.cli(), &[&a, &b]);
        assert!(error.contains("canonical path"), "{error}");
        assert!(error.contains(a.to_str().unwrap()), "{error}");
        assert!(error.contains(b.to_str().unwrap()), "{error}");
    }
    #[cfg(unix)]
    {
        let b = f.0.join("symlink");
        std::os::unix::fs::symlink(&a, &b).unwrap();
        let error = config_error(f.cli(), &[&a, &b]);
        assert!(error.contains("canonical path"), "{error}");
        assert!(error.contains(b.to_str().unwrap()), "{error}");
    }
}

#[test]
fn environment_expansion_applies_to_every_path_before_loading() {
    let f = Files::new();
    f.write("first-é.jsonc", &policy(vec![profile("first", "first")]));
    f.write("second.jsonc", &policy(vec![profile("second", "second")]));
    let mut cmd = f.cli();
    cmd.env("SW_TEST_ROOT", &f.0)
        .arg("--config")
        .arg("{env:SW_TEST_ROOT}/first-é.jsonc")
        .arg("--config")
        .arg("{env:SW_TEST_ROOT}/second.jsonc");
    assert_eq!(
        verdict(invoke(cmd, "first && second"))["result"]["verdict"],
        "allow"
    );
    // Unicode before a placeholder must not panic.
    let path = f.write("préfixe.jsonc", &policy(vec![]));
    let mut cmd = f.cli();
    cmd.env("SW_TEST_SUFFIX", "jsonc")
        .arg("--config")
        .arg(format!("{}/préfixe.{{env:SW_TEST_SUFFIX}}", f.0.display()));
    assert_eq!(verdict(invoke(cmd, "unknown"))["result"]["verdict"], "ask");
    let mut cmd = f.cli();
    cmd.env("SW_TEST_PATH", &path);
    assert!(
        config_error(cmd, &[&path, Path::new("{env:SW_TEST_PATH}")]).contains("canonical path")
    );
    let mut cmd = f.cli();
    cmd.env_remove("SW_TEST_MISSING");
    assert!(config_error(cmd, &[&path, Path::new("{env:SW_TEST_MISSING}/x")]).contains("unset"));
    assert!(config_error(f.cli(), &[&path, Path::new("relative.jsonc")]).contains("absolute"));
}

#[test]
fn minimum_limits_apply_in_both_orders_and_raw_bytes_are_aggregate() {
    let f = Files::new();
    let mut first = policy(vec![profile("a", "a")]);
    first["limits"] = json!({"configBytes": 10000, "profiles": 8, "rules": 10, "evidenceItems": 7});
    let mut second = policy(vec![profile("b", "b")]);
    second["limits"] =
        json!({"configBytes": 20000, "profiles": 4, "rules": 5, "diagnosticsBytes": 9});
    let a = f.write("a", &first);
    let b = f.write("b", &second);
    for paths in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
        let limits = load_paths(&paths).unwrap().raw.limits;
        assert_eq!(
            (
                limits.config_bytes,
                limits.profiles,
                limits.rules,
                limits.evidence_items,
                limits.diagnostics_bytes
            ),
            (10000, 4, 5, 7, 9)
        );
    }
    let mut empty = policy(vec![]);
    empty["limits"] = json!({"configBytes": 600});
    let text = format!("{}\n//{}", empty, "x".repeat(130));
    assert!(text.len() < 600 && text.len() * 2 > 600, "{}", text.len());
    let a = f.text("bytes-a", &text);
    let b = f.text("bytes-b", &text);
    let error = config_error(f.cli(), &[&a, &b]);
    assert!(error.contains("total bytes exceeds configBytes"), "{error}");
    assert!(
        error.contains(a.to_str().unwrap()) && error.contains(b.to_str().unwrap()),
        "{error}"
    );
}

#[test]
fn minimum_evidence_and_diagnostic_limits_reach_cli_evaluation() {
    let f = Files::new();
    let mut first = policy(vec![profile("a", "a")]);
    first["limits"] = json!({"evidenceItems": 1});
    let mut second = policy(vec![profile("b", "b")]);
    second["limits"] = json!({"diagnosticsBytes": 1});
    let a = f.write("a", &first);
    let b = f.write("b", &second);
    for paths in [[&a, &b], [&b, &a]] {
        let mut cmd = f.cli();
        for path in paths {
            cmd.arg("--config").arg(path);
        }
        let out = verdict(invoke(cmd, "a && b"));
        assert_eq!(out["result"]["verdict"], "ask", "{out}");
        let facts = &out["result"]["commands"][0]["facts"];
        assert_eq!(facts["diagnostics"], "truncated-after-decision", "{out}");
        assert!(
            facts["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("evidence-limit")),
            "{out}"
        );
    }
}

#[test]
fn profile_and_rule_caps_apply_to_the_assembled_policy() {
    let f = Files::new();
    for field in ["profiles", "rules"] {
        let mut a = policy(vec![profile("a", "a")]);
        a["limits"] = json!({field: 1});
        let b = policy(vec![profile("b", "b")]);
        conflict(&f, &a, &b, &format!("{field} count 2 exceeds cap 1"));
    }
}

#[test]
fn files_are_independently_validated_and_cannot_borrow_references() {
    let f = Files::new();
    let mut first = policy(vec![]);
    first["redirectPolicies"]["only-a"] = first["redirectPolicies"]["no-redirects"].clone();
    let a = f.write("a", &first);
    let mut b = policy(vec![profile("b", "b")]);
    b["redirectPolicies"] =
        json!({"other": {"redirects": {"none": true}, "paths": {"none": true}}});
    b["defaults"]["redirectPolicy"] = json!("other");
    b["profiles"][0]["redirectPolicy"] = json!({"mode": "replace", "policies": ["only-a"]});
    let b = f.write("b", &b);
    let error = config_error(f.cli(), &[&a, &b]);
    assert!(
        error.contains("only-a") && error.contains(b.to_str().unwrap()),
        "{error}"
    );
}

#[test]
fn another_file_cannot_replace_the_legacy_implicit_default_bundle() {
    let f = Files::new();
    let mut first = policy(vec![profile("a", "a")]);
    first["redirectPolicies"] = json!({});
    let a = f.write("implicit", &first);
    // Existing single-file behavior remains unchanged.
    assert!(load_paths(std::slice::from_ref(&a)).is_ok());
    let mut second = policy(vec![profile("b", "b")]);
    second["redirectPolicies"]["no-redirects"]["paths"] = json!({
        "all": [{"coordinate": {"redirect": {"operator": ">", "sourceFd": "default", "occurrence": "all"}},
                 "within": "/repo"}]
    });
    let b = f.write("declared", &second);
    for paths in [[&a, &b], [&b, &a]] {
        let error = config_error(f.cli(), &[paths[0], paths[1]]);
        assert!(
            error.contains("must be declared in its own file"),
            "{error}"
        );
        assert!(error.contains(a.to_str().unwrap()), "{error}");
    }
}

#[test]
fn limits_stay_positive_and_bounded_by_engine_maxima() {
    for (field, maximum) in [
        ("configBytes", 262144),
        ("profiles", 256),
        ("rules", 4096),
        ("evidenceItems", 1024),
        ("diagnosticsBytes", 16384),
    ] {
        for invalid in [0, maximum + 1] {
            let mut p = policy(vec![]);
            p["limits"] = json!({field: invalid});
            let error = load_str(&p.to_string()).unwrap_err();
            assert!(error.contains(field), "{error}");
        }
    }
    let f = Files::new();
    let a = f.text("oversize", &" ".repeat(262145));
    assert!(config_error(f.cli(), &[&a]).contains("configBytes cap"));
}

#[test]
fn help_and_missing_config_argument_are_explicit() {
    let f = Files::new();
    let out = f.cli().arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for expected in [
        "[--config FILE]...",
        "No override precedence",
        "suppress",
        "exit 2",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    let out = f.cli().arg("--config").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}
