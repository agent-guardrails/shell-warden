// https://github.com/agent-guardrails/shell-warden/issues/74
// Payloads are checker inputs only. Never execute the represented shell commands.
use serde_json::{Value, json};
use shell_warden::checker::config::load_str;
use shell_warden::checker::evidence::EvidenceState;
use shell_warden::checker::grammar::Relation;
use shell_warden::checker::letter::Letter;
use shell_warden::checker::pipeline::evaluate;
use shell_warden::checker::split::extract;
use std::io::Write;
use std::process::{Command, Stdio};

fn profile(id: &str, executable: &str, arguments: Value) -> Value {
    json!({
        "id": id, "executables": [executable], "options": {},
        "rules": [{
            "id": "allow", "action": "allow",
            "match": {
                "classification": "complete", "arguments": arguments,
                "options": {"none": true}, "environment": {"none": true},
                "paths": {"none": true}, "facts": {"none": true},
                "nestedParts": {"none": true}
            }
        }]
    })
}

fn policy() -> Value {
    let mut denied = profile("blocked", "blocked", json!({"exact": []}));
    denied["rules"] = json!([{
        "id": "deny", "action": "deny", "message": "Use an approved command.",
        "match": {"arguments": {"exact": []}}
    }]);
    json!({
        "version": 2,
        "defaults": {"action": "ask", "redirectPolicy": "none"},
        "redirectPolicies": {
            "none": {"redirects": {"none": true}, "paths": {"none": true}}
        },
        "profiles": [
            profile("probe", "probe", json!({"exact": []})),
            profile("script", "/approved/task.sh", json!({"exact": ["safe"]})),
            denied
        ]
    })
}

fn letter(raw: &str) -> Value {
    json!({
        "version": 1,
        "invocation": {"id": "bash-test", "sessionID": "test", "projectDir": "/repo"},
        "action": "shell", "commands": [{"index": 0, "raw": raw, "cwd": "/repo"}]
    })
}

fn verdict(config: &Value, raw: &str) -> Value {
    let config = load_str(&config.to_string()).expect("valid policy");
    let letter = Letter::from_bytes(letter(raw).to_string().as_bytes()).unwrap();
    serde_json::to_value(evaluate(&config, &letter)).unwrap()
}

#[test]
fn startup_environment_never_disappears() {
    let config = policy();
    assert_eq!(verdict(&config, "bash -c 'probe'")["verdict"], "allow");
    for raw in [
        "BASH_ENV=/tmp/inject.sh bash -c 'probe'",
        "env BASH_ENV=/tmp/inject.sh bash -c 'probe'",
        "LANG=C BASH_ENV=/tmp/inject.sh bash -c 'probe'",
        "env LANG=C BASH_ENV=/tmp/inject.sh bash -c 'probe'",
        "BASH_ENV=/tmp/inject.sh nohup env LANG=C bash -c 'probe'",
        "env BASH_ENV=/tmp/inject.sh nice -n 1 timeout 5 bash -c 'probe'",
        "bash -c 'env BASH_ENV=/tmp/inject.sh bash -c \"probe\"'",
        "BASH_ENV= bash -c 'probe'",
        "SHELLOPTS=xtrace bash -c 'probe'",
        "LD_PRELOAD=/tmp/inject.so bash -c 'probe'",
        "ENV=/tmp/inject.sh sh -c 'probe'",
        "BASH_ENV=/tmp/inject.sh bash /approved/task.sh safe",
    ] {
        let result = verdict(&config, raw);
        assert_eq!(result["verdict"], "ask", "{raw}: {result}");
        let graph = extract(raw);
        assert!(
            graph.parts.iter().any(|part| {
                !graph.collapsed.contains(&part.id)
                    && matches!(part.state, EvidenceState::Opaque(_))
                    && !part.assigns.is_empty()
            }),
            "{raw}: {graph:?}"
        );
    }
}

#[test]
fn startup_context_cannot_be_approved_as_an_environment_string() {
    let mut config = policy();
    config["profiles"][0]["rules"][0]["match"]["environment"] = json!({"all": [{
        "name": "BASH_ENV", "value": {"oneOf": ["/tmp/inject.sh"]},
        "prefix": true, "occurrence": "all"
    }]});
    assert_eq!(
        verdict(&config, "BASH_ENV=/tmp/inject.sh probe")["verdict"],
        "allow"
    );
    assert_eq!(
        verdict(&config, "BASH_ENV=/tmp/inject.sh bash -c 'probe'")["verdict"],
        "ask"
    );
}

#[test]
fn explicit_script_path_and_arguments_select_the_script_profile() {
    let config = policy();
    for raw in [
        "/approved/task.sh safe",
        "bash /approved/task.sh safe",
        "bash -- /approved/task.sh safe",
        "env nohup bash /approved/task.sh safe",
        "bash -c 'bash /approved/task.sh safe'",
    ] {
        assert_eq!(verdict(&config, raw)["verdict"], "allow", "{raw}");
    }
    for raw in [
        "bash /other/task.sh safe",
        "bash /approved/task.sh unsafe",
        "bash /approved/task.sh safe extra",
        "bash /approved/task.sh safe ''",
        "bash /approved/task.sh safe \"\"",
        "bash ./task.sh safe",
        "bash task.sh safe",
        "bash /approved/../approved/task.sh safe",
        "bash /approved//task.sh safe",
        "bash $SCRIPT safe",
        "bash -s /approved/task.sh safe",
        "sh /approved/task.sh safe",
    ] {
        assert_eq!(verdict(&config, raw)["verdict"], "ask", "{raw}");
    }
    let graph = extract("bash -- /approved/task.sh safe");
    let script = graph.parts.last().unwrap();
    assert_eq!(script.relation, Relation::Wrapper);
    assert_eq!(script.parent, Some(0));
    assert_eq!(script.argv[0].text, "/approved/task.sh");
    assert_eq!(script.argv[1].text, "safe");
}

#[test]
fn interpreter_mode_is_not_inferred_from_a_later_script_argument() {
    let config = policy();
    for raw in [
        "bash /untrusted/task.sh -c probe",
        "bash -- /untrusted/task.sh -c probe",
        "bash /approved/task.sh -c probe",
        "bash -- -c probe",
        "bash --rcfile /tmp/inject.sh -c probe",
        "bash --init-file /tmp/inject.sh -c probe",
        "bash -l -c probe",
        "bash -i -c probe",
        "bash -O extdebug -c probe",
        "bash -lc probe",
        "bash -c",
        "bash -c 'probe' ignored",
    ] {
        assert_eq!(verdict(&config, raw)["verdict"], "ask", "{raw}");
    }
}

#[test]
fn wrapper_evidence_is_preserved_with_distinct_occurrences() {
    let graph = extract("A=outer env A=inner B=2 nohup probe >/outer");
    let part = graph.parts.last().unwrap();
    assert_eq!(part.argv[0].text, "probe");
    assert_eq!(
        part.assigns
            .iter()
            .map(|a| (a.text.as_str(), a.ordinal))
            .collect::<Vec<_>>(),
        [("A=outer", 1), ("A=inner", 2), ("B=2", 3)]
    );
    assert_eq!(part.redirects.len(), 1);
    assert_eq!(part.redirects[0].target, "/outer");

    let graph = extract("A=outer bash -c 'B=inner probe >/inner' >/outer");
    let part = graph.parts.last().unwrap();
    assert_eq!(
        part.assigns
            .iter()
            .map(|a| (a.text.as_str(), a.ordinal))
            .collect::<Vec<_>>(),
        [("A=outer", 1), ("B=inner", 2)]
    );
    assert_eq!(
        part.redirects
            .iter()
            .map(|r| (r.target.as_str(), r.ordinal))
            .collect::<Vec<_>>(),
        [("/outer", 1), ("/inner", 2)]
    );
}

#[test]
fn wrapper_redirects_cannot_inherit_clean_command_permission() {
    for raw in [
        "bash -c 'probe' >/tmp/output",
        "env bash -c 'probe' >/tmp/output",
        "nohup probe >/tmp/output",
        "nice -n 1 probe >/tmp/output",
        "timeout 5 probe >/tmp/output",
        "bash /approved/task.sh safe >/tmp/output",
        "bash -c 'probe; probe' >/tmp/output",
    ] {
        assert_eq!(verdict(&policy(), raw)["verdict"], "ask", "{raw}");
    }
}

#[test]
fn restrictive_children_survive_opaque_startup_context() {
    for raw in [
        "BASH_ENV=/tmp/inject.sh bash -c 'blocked'",
        "env A=1 BASH_ENV=/tmp/inject.sh bash -c 'blocked'",
        "bash -c 'blocked' ignored",
    ] {
        assert_eq!(verdict(&policy(), raw)["verdict"], "deny", "{raw}");
    }
}

#[test]
fn script_child_is_not_reinterpreted_as_an_interpreter() {
    let graph = extract("bash /approved/bash -c probe");
    let child = graph.parts.last().unwrap();
    assert_eq!(graph.parts.len(), 2);
    assert_eq!(child.argv[0].text, "/approved/bash");
    assert_eq!(child.argv[1].text, "-c");
    assert_eq!(child.argv[2].text, "probe");
}

#[test]
fn script_depth_and_evidence_limits_remain_fail_closed() {
    let mut config = policy();
    config["limits"] = json!({"evidenceItems": 1});
    assert_eq!(
        verdict(&config, "bash /approved/task.sh safe")["verdict"],
        "ask"
    );
    let raw = format!("{}bash /approved/task.sh safe", "nohup ".repeat(33));
    assert_eq!(verdict(&policy(), &raw)["verdict"], "ask");
}

#[test]
fn assignment_only_segments_cannot_disappear_before_bash() {
    for raw in [
        "BASH_ENV=/tmp/inject.sh; bash -c 'probe'",
        "BASH_ENV=/tmp/inject.sh; bash /approved/task.sh safe",
        "bash -c 'BASH_ENV=/tmp/inject.sh; probe'",
    ] {
        assert_eq!(verdict(&policy(), raw)["verdict"], "ask", "{raw}");
    }
}

#[test]
fn script_arguments_and_quoted_empty_words_keep_their_positions() {
    let mut config = policy();
    config["profiles"][1]["rules"][0]["match"]["arguments"] = json!({"exact": ["-c", "probe"]});
    assert_eq!(
        verdict(&config, "bash /approved/task.sh -- -c probe")["verdict"],
        "allow"
    );
    config["profiles"][1]["rules"][0]["match"]["arguments"] = json!({"exact": ["", "safe"]});
    for raw in [
        "bash /approved/task.sh '' safe",
        "bash /approved/task.sh \"\" safe",
    ] {
        assert_eq!(verdict(&config, raw)["verdict"], "allow", "{raw}");
    }
    assert_eq!(
        verdict(&config, "bash /approved/task.sh safe")["verdict"],
        "ask"
    );
    let graph = extract("bash /approved/task.sh ''#literal '2'>/output");
    let child = graph.parts.last().unwrap();
    assert_eq!(child.argv[1].text, "#literal");
    assert_eq!(child.argv[2].text, "2");
    assert_eq!(child.redirects[0].source_fd, None);
}

#[test]
fn multi_command_letter_keeps_startup_ask_and_child_deny() {
    let config = load_str(&policy().to_string()).unwrap();
    let mut input = letter("probe");
    input["commands"] = json!([
        {"index": 0, "raw": "probe", "cwd": "/repo"},
        {"index": 1, "raw": "BASH_ENV=/tmp/inject.sh bash -c 'probe'", "cwd": "/repo"}
    ]);
    let parsed = Letter::from_bytes(input.to_string().as_bytes()).unwrap();
    let output = serde_json::to_value(evaluate(&config, &parsed)).unwrap();
    assert_eq!(output["verdict"], "ask");
    assert_eq!(output["commands"][0]["verdict"], "allow");
    assert_eq!(output["commands"][1]["verdict"], "ask");
    input["commands"].as_array_mut().unwrap().push(json!({
        "index": 2, "raw": "BASH_ENV=/tmp/inject.sh bash -c 'blocked'", "cwd": "/repo"
    }));
    let parsed = Letter::from_bytes(input.to_string().as_bytes()).unwrap();
    let output = serde_json::to_value(evaluate(&config, &parsed)).unwrap();
    assert_eq!(output["verdict"], "deny");
    assert_eq!(output["commands"][2]["verdict"], "deny");
}

#[test]
fn escaped_digits_are_script_arguments_not_redirect_fd_prefixes() {
    let mut config = policy();
    config["redirectPolicies"]["none"] = json!({
        "redirects": {"all": [
            {"sourceFd": "default", "operator": ">", "occurrence": "all", "target": {"kind": "literalPath"}},
            {"sourceFd": 2, "operator": ">", "occurrence": "all", "target": {"kind": "literalPath"}}
        ]},
        "paths": {"all": [
            {"coordinate": {"redirect": {"operator": ">", "sourceFd": "default", "occurrence": "all"}}, "within": "/tmp/reports"},
            {"coordinate": {"redirect": {"operator": ">", "sourceFd": 2, "occurrence": "all"}}, "within": "/tmp/reports"}
        ]}
    });
    assert_eq!(
        verdict(&config, "bash /approved/task.sh safe >/tmp/reports/out")["verdict"],
        "allow"
    );
    for raw in [
        r"bash /approved/task.sh safe \2>/tmp/reports/out",
        "bash /approved/task.sh safe '2'>/tmp/reports/out",
        "bash /approved/task.sh safe \"2\">/tmp/reports/out",
    ] {
        assert_eq!(verdict(&config, raw)["verdict"], "ask", "{raw}");
        let graph = extract(raw);
        let child = graph.parts.last().unwrap();
        assert_eq!(child.argv[2].text, "2");
        assert_eq!(child.redirects[0].source_fd, None);
    }
}

#[test]
fn real_checker_rejects_startup_injection_and_checks_script_arguments() {
    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
    let path = std::env::temp_dir().join(format!("sw-bash-execution-{}.json", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let config = ConfigFile(path);
    file.write_all(policy().to_string().as_bytes()).unwrap();
    drop(file);
    for (raw, expected) in [
        ("bash -c 'probe'", "allow"),
        ("BASH_ENV=/tmp/inject.sh bash -c 'probe'", "ask"),
        ("env BASH_ENV=/tmp/inject.sh bash -c 'probe'", "ask"),
        ("bash /approved/task.sh safe", "allow"),
        ("bash /approved/task.sh unsafe", "ask"),
        ("bash /untrusted/task.sh -c probe", "ask"),
        ("BASH_ENV=/tmp/inject.sh bash -c 'blocked'", "deny"),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_shell-warden"))
            .arg("--config")
            .arg(&config.0)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(letter(raw).to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{raw}: {output:?}");
        assert!(output.stderr.is_empty(), "{raw}: {output:?}");
        let verdict: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(verdict["result"]["verdict"], expected, "{raw}: {verdict}");
    }
}
