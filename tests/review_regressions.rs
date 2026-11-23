use serde_json::{Value, json};
use shell_warden::checker::{
    config::load_str,
    letter::Letter,
    pipeline::evaluate,
    split::extract,
    verdict::{PROTOCOL, VerdictEnvelope},
};

fn policy() -> Value {
    json!({
        "version":3,
        "defaults":{"action":"ask","redirectPolicy":"none"},
        "redirectPolicies":{"none":{"redirects":{"none":true},"paths":{"none":true}}},
        "profiles":[
            {
                "id":"export","executables":["export"],"options":{},"analyzer":"export-v1",
                "rules":[{
                    "id":"allow-export","action":"allow",
                    "expansions":{"assignmentValues":["HOME"]},
                    "match":{
                        "arguments":{"prefix":[],"remainder":{"each":{"any":true}}},
                        "options":{"none":true},
                        "environment":{"all":[
                            {"name":"A","prefix":false,"occurrence":"all","value":{"any":true}},
                            {"name":"C","prefix":false,"occurrence":"all","value":{"any":true}},
                            {"name":"PRE","prefix":true,"occurrence":"all","value":{"any":true}}
                        ]},
                        "paths":{"none":true},"nestedParts":{"none":true},
                        "facts":{"all":[{
                            "analyzer":"export-v1","version":"1","name":"assignment",
                            "occurrence":"all","value":{"any":true}
                        }]}
                    }
                }]
            },
            {
                "id":"git","executables":["git"],"analyzer":"generic-v1",
                "options":{"force":{"aliases":["--force"],"arity":0}},
                "rules":[
                    {"id":"deny-force-push","action":"deny","message":"Force push denied.",
                        "match":{"arguments":{"prefix":["push"]},"options":{"presentAny":["force"]}}},
                    {"id":"allow-status","action":"allow",
                        "match":{"classification":"complete","arguments":{"exact":["status"]},
                            "options":{"none":true},"environment":{"none":true},
                            "paths":{"none":true},"facts":{"none":true},"nestedParts":{"none":true}}}
                ]
            }
        ]
    })
}

fn deny_export(config: &mut Value, name: &str, occurrence: usize) {
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"deny-export","action":"deny","message":"Export destination denied.",
            "match":{"facts":{"any":[{
                "analyzer":"export-v1","version":"1","name":"assignment",
                "occurrence":occurrence,"value":{"exact":name}
            }]}}
        }));
}

fn result(config: &Value, raw: &str) -> Value {
    result_text(&config.to_string(), raw, "/repo")
}

fn result_text(config: &str, raw: &str, cwd: &str) -> Value {
    let config = load_str(config).unwrap();
    let input = json!({
        "version":1,"invocation":{"id":"review:test","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":cwd}]
    });
    let letter = Letter::from_bytes(input.to_string().as_bytes()).unwrap();
    let envelope = VerdictEnvelope::new(evaluate(&config, &letter));
    envelope.validate_against("review:test", 1).unwrap();
    serde_json::from_slice(&envelope.to_wire().unwrap()).unwrap()
}

#[test]
fn export_fact_occurrences_follow_source_order_for_mixed_operands() {
    let config = policy();
    for (raw, names) in [
        ("export A=one B", vec!["A", "B"]),
        ("export A=one C=two B", vec!["A", "C", "B"]),
        ("export \"A=one\" B", vec!["A", "B"]),
        ("export A=$HOME B", vec!["A", "B"]),
        ("PRE=one export A=two B", vec!["A", "B"]),
        ("export A=one -- B", vec!["A", "B"]),
    ] {
        assert_eq!(result(&config, raw)["result"]["verdict"], "allow", "{raw}");
        for (index, name) in names.iter().enumerate() {
            let mut restricted = config.clone();
            deny_export(&mut restricted, name, index + 1);
            let output = result(&restricted, raw);
            let command = &output["result"]["commands"][0];
            assert_eq!(command["verdict"], "deny", "{raw}: {name} at {}", index + 1);
            assert_eq!(command["ruleId"], "deny-export", "{raw}");
        }
    }
    let mut prefix_is_not_a_declaration_fact = config;
    deny_export(&mut prefix_is_not_a_declaration_fact, "PRE", 1);
    assert_eq!(
        result(&prefix_is_not_a_declaration_fact, "PRE=one export A=two B")["result"]["verdict"],
        "allow"
    );
}

#[test]
fn export_assignments_after_bare_operands_are_opaque_not_argument_grants() {
    let config = policy();
    for raw in [
        "export A=$HOME B PATH=/untrusted",
        "export A=one B C=two D",
        "export B A=one",
        "export B \"PATH=/untrusted\"",
        "export B PATH=$HOME",
    ] {
        let output = result(&config, raw);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "ask", "{raw}");
        assert_eq!(command["classification"], "opaque", "{raw}");
    }
    // A supported leading declaration prefix still uses assignment coverage.
    assert_eq!(
        result(&config, "export A=$HOME C=two B")["result"]["verdict"],
        "allow"
    );
    // Known literal destinations remain visible to restrictive fact predicates.
    for (raw, names) in [
        ("export A=$HOME B PATH=/untrusted", vec!["A", "B", "PATH"]),
        ("export A=one B C=two D", vec!["A", "B", "C", "D"]),
        ("export B A=one", vec!["B", "A"]),
    ] {
        for (index, name) in names.iter().enumerate() {
            let mut restricted = config.clone();
            deny_export(&mut restricted, name, index + 1);
            assert_eq!(
                result(&restricted, raw)["result"]["verdict"],
                "deny",
                "{raw}"
            );
        }
    }
}

#[test]
fn export_append_assignments_cannot_use_ordinary_argument_coverage() {
    let config = policy();
    for raw in [
        "export A=$HOME PATH+=/untrusted",
        "export A=$HOME B PATH+=/untrusted",
        "export A=$HOME -- PATH+=/untrusted",
        "export PATH+=/untrusted",
        "export \"PATH+=/untrusted\"",
        "export A=$HOME A+=/suffix",
        "export \"PATH[0]+=/untrusted\"",
    ] {
        let output = result(&config, raw);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "ask", "{raw}");
        assert_eq!(command["classification"], "opaque", "{raw}");
    }
    assert_eq!(
        result(&config, "export A=$HOME C=/trusted")["result"]["verdict"],
        "allow"
    );
}

#[test]
fn empty_quotes_start_a_word_before_a_hash_and_keep_redirect_substitutions() {
    let example = include_str!("../examples/configs/shell-warden.example.jsonc");
    for quotes in ["''", "\"\""] {
        let raw = format!("git status >>{quotes}#$(git push --force origin main)");
        let output = result_text(example, &raw, "/var/tmp/git-reports");
        assert_eq!(output["result"]["verdict"], "deny", "{raw}");
        let graph = extract(&raw);
        assert!(
            graph.parts.iter().any(|part| {
                part.argv.first().is_some_and(|head| head.text == "git")
                    && part.argv.get(1).is_some_and(|arg| arg.text == "push")
            }),
            "{raw}"
        );
        assert!(!graph.parts[0].redirects[0].target.is_empty(), "{raw}");
    }
    let raw = "git status >>report #$(git push --force origin main)";
    assert_eq!(extract(raw).parts.len(), 1);
    assert_eq!(
        result_text(example, raw, "/var/tmp/git-reports")["result"]["verdict"],
        "allow"
    );
}

#[test]
fn invalid_shell_wrappers_keep_invalid_owners_and_known_script_children() {
    use shell_warden::checker::evidence::EvidenceState;
    for shell in ["sh", "bash"] {
        let raw = format!("{shell} -c 'git push --force origin main' 2>&-");
        let output = result(&policy(), &raw);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "deny", "{raw}");
        assert_eq!(command["classification"], "invalid", "{raw}");
        let graph = extract(&raw);
        assert!(matches!(graph.parts[0].state, EvidenceState::Invalid(_)));
        assert!(!graph.collapsed.contains(&0));
        assert!(
            graph.parts.iter().any(|part| {
                part.parent == Some(0) && part.argv.first().is_some_and(|head| head.text == "git")
            }),
            "{raw}"
        );
    }
    for raw in ["sh -c 'git status' 2>&-", "sh -c \"$HOME\" 2>&-", "sh 2>&-"] {
        let output = result(&policy(), raw);
        assert_eq!(output["result"]["verdict"], "ask", "{raw}");
        assert_eq!(
            output["result"]["commands"][0]["classification"], "invalid",
            "{raw}"
        );
    }
}

fn option_policy() -> Value {
    let mut config = policy();
    config["profiles"].as_array_mut().unwrap().push(json!({
        "id":"ls","executables":["ls"],"analyzer":"generic-v1",
        "options":{"output":{"aliases":["-o"],"arity":1}},
        "rules":[{"id":"deny-invalid","action":"deny","message":"Invalid command.",
            "match":{"classification":"invalid"}}]
    }));
    config
}

fn nested_dynamic_option() -> String {
    let mut raw = "ls -o \"$HOME\"".to_string();
    for _ in 0..33 {
        raw = format!("ls -o $({raw})");
    }
    raw
}

#[test]
fn opaque_refinements_do_not_replace_existing_invalid_evidence() {
    let config = option_policy();
    for (raw, reason) in [
        (nested_dynamic_option(), "evidence-limit"),
        ("ls -o \"$HOME\" 2>&-".to_string(), "unsupported-syntax"),
        ("sh -c 'ls -o $HOME' 2>&-".to_string(), "unsupported-syntax"),
    ] {
        let output = result(&config, &raw);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "deny", "{raw}");
        assert_eq!(command["classification"], "invalid", "{raw}");
        assert!(
            command["facts"]["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!(reason)),
            "{raw}"
        );
    }
    assert_eq!(
        result(&config, "ls -o \"$HOME\"")["result"]["verdict"],
        "ask"
    );
}

#[test]
fn unsupported_env_assignments_keep_known_children_without_allowing_wrappers() {
    let config = policy();
    for raw in [
        "env CACHE=\"$HOME\" git push --force origin main",
        "env CACHE=\"$HOME\" OTHER=\"$USER\" git push --force origin main",
        "env CACHE=\"$(git status)\" git push --force origin main",
        "env CACHE=\"$HOME\" git push --force origin main 2>&-",
    ] {
        assert_eq!(result(&config, raw)["result"]["verdict"], "deny", "{raw}");
    }
    let raw = "env CACHE=\"$HOME\" git status";
    assert_eq!(result(&config, raw)["result"]["verdict"], "ask");
    assert!(extract(raw).collapsed.is_empty());
    let raw = "env \"$HOME\" git push --force origin main";
    assert_eq!(result(&config, raw)["result"]["verdict"], "ask");
    assert!(!extract(raw).parts.iter().any(|part| {
        part.parent.is_some() && part.argv.first().is_some_and(|head| head.text == "git")
    }));
}

#[test]
fn unsupported_nice_priority_keeps_known_children_without_allowing_wrappers() {
    let config = policy();
    for raw in [
        "nice -n \"$HOME\" git push --force origin main",
        "nice -n $HOME git push --force origin main",
        "nice -n not-a-number git push --force origin main",
        "nice -n \"$HOME\" git push --force origin main 2>&-",
    ] {
        assert_eq!(result(&config, raw)["result"]["verdict"], "deny", "{raw}");
    }
    for raw in [
        "nice -n \"$HOME\" git status",
        "nice -n not-a-number git status",
        "nice -n \"$HOME\" \"$CMD\" git push --force origin main",
        "nice -n \"$HOME\"",
    ] {
        assert_eq!(result(&config, raw)["result"]["verdict"], "ask", "{raw}");
        assert!(!extract(raw).collapsed.contains(&0), "{raw}");
    }
    assert_eq!(
        result(&config, "nice -n 0 git status")["result"]["verdict"],
        "allow"
    );
}

#[test]
fn recursive_sibling_ordinals_are_assigned_inside_extraction() {
    for raw in [
        "sh -c 'git status; git status'",
        "git status > \"$(git status; git status)\"",
    ] {
        let graph = extract(raw);
        let ordinals: Vec<_> = graph
            .parts
            .iter()
            .filter(|part| part.parent == Some(0))
            .map(|part| part.relation_ordinal)
            .collect();
        assert_eq!(ordinals, [1, 2], "{raw}");
    }
}

#[test]
fn real_cli_preserves_children_and_invalid_precedence_in_full_review_cases() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.0.join("config.json")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }
    let dir = std::env::temp_dir().join(format!("sw-more-review-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let file = ConfigFile(dir);
    std::fs::write(file.0.join("config.json"), option_policy().to_string()).unwrap();
    let commands = [
        (
            "git status >>''#$(git push --force origin main)".to_string(),
            "deny",
        ),
        ("export A=$HOME B PATH=/untrusted".to_string(), "ask"),
        ("export A=$HOME PATH+=/untrusted".to_string(), "ask"),
        ("export A=$HOME B PATH+=/untrusted".to_string(), "ask"),
        ("export A=$HOME -- PATH+=/untrusted".to_string(), "ask"),
        (
            "sh -c 'git push --force origin main' 2>&-".to_string(),
            "deny",
        ),
        (nested_dynamic_option(), "deny"),
        (
            "env CACHE=\"$HOME\" git push --force origin main".to_string(),
            "deny",
        ),
        (
            "nice -n \"$HOME\" git push --force origin main".to_string(),
            "deny",
        ),
        ("nice -n \"$HOME\" git status".to_string(), "ask"),
        ("git status".to_string(), "allow"),
        ("export A=$HOME C=one B".to_string(), "allow"),
    ];
    let input = json!({
        "version":1,"invocation":{"id":"review:more","sessionID":"test"},
        "action":"shell",
        "commands":commands.iter().enumerate().map(|(index, (raw, _))| {
            json!({"index":index,"raw":raw,"cwd":"/repo"})
        }).collect::<Vec<_>>()
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_shell-warden"))
        .arg("--config")
        .arg(file.0.join("config.json"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope: VerdictEnvelope = serde_json::from_slice(&output.stdout).unwrap();
    envelope
        .validate_against("review:more", commands.len())
        .unwrap();
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, (raw, verdict)) in commands.iter().enumerate() {
        assert_eq!(
            output["result"]["commands"][index]["verdict"], *verdict,
            "{raw}"
        );
    }
}

#[test]
fn export_fact_coverage_still_covers_both_operand_kinds() {
    let mut config = policy();
    config["profiles"][0]["rules"][0]["match"]["facts"] = json!({"all":[{
        "analyzer":"export-v1","version":"1","name":"assignment",
        "occurrence":1,"value":{"exact":"A"}
    }]});
    assert_eq!(
        result(&config, "export A=one B")["result"]["verdict"],
        "ask"
    );
    config["profiles"][0]["rules"][0]["match"]["facts"]["all"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "analyzer":"export-v1","version":"1","name":"assignment",
            "occurrence":2,"value":{"exact":"B"}
        }));
    assert_eq!(
        result(&config, "export A=one B")["result"]["verdict"],
        "allow"
    );
}

#[test]
fn literal_dollar_redirect_cannot_hide_a_later_executable() {
    let config = policy();
    for target in [r#""$""#, "$", r#""$?""#, r#""$$""#, r#""$1""#] {
        let raw = format!("git status > {target}; git push --force origin main");
        let graph = extract(&raw);
        assert_eq!(graph.parts.len(), 2, "{raw}");
        assert_eq!(graph.parts[1].argv[1].text, "push", "{raw}");
        let output = result(&config, &raw);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "deny", "{raw}");
        assert_eq!(command["ruleId"], "deny-force-push", "{raw}");
    }
    let raw = r#"git status > "$"; git push --force origin main"#;
    let example = load_str(include_str!("fixtures/sketch.jsonc")).unwrap();
    let letter = Letter::from_bytes(
        json!({
            "version":1,"invocation":{"id":"review:example","sessionID":"test"},
            "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/repo"}]
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let envelope = VerdictEnvelope::new(evaluate(&example, &letter));
    envelope.validate_against("review:example", 1).unwrap();
    let output: Value = serde_json::from_slice(&envelope.to_wire().unwrap()).unwrap();
    assert_eq!(output["result"]["verdict"], "deny");
}

#[test]
fn cli_help_names_the_actual_response_protocol() {
    for flag in ["--help", "-h"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_shell-warden"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains(PROTOCOL), "{help}");
        assert!(!help.contains("verdict v2"), "{help}");
    }
}

#[test]
fn real_cli_preserves_export_restrictions_and_later_deny_parts() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.0.join("config.json")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }
    let dir = std::env::temp_dir().join(format!("sw-review-regressions-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let file = ConfigFile(dir);
    let mut config = policy();
    deny_export(&mut config, "A", 1);
    std::fs::write(file.0.join("config.json"), config.to_string()).unwrap();
    let commands = [
        (r#"git status > "$"; git push --force origin main"#, "deny"),
        ("export A=one B", "deny"),
        ("git status", "allow"),
    ];
    let input = json!({
        "version":1,"invocation":{"id":"review:cli","sessionID":"test"},
        "action":"shell",
        "commands":commands.iter().enumerate().map(|(index, (raw, _))| {
            json!({"index":index,"raw":raw,"cwd":"/repo"})
        }).collect::<Vec<_>>()
    });
    // Only the checker runs; shell/export/git command text is not executed.
    let mut child = Command::new(env!("CARGO_BIN_EXE_shell-warden"))
        .arg("--config")
        .arg(file.0.join("config.json"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope: VerdictEnvelope = serde_json::from_slice(&output.stdout).unwrap();
    envelope
        .validate_against("review:cli", commands.len())
        .unwrap();
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, (raw, verdict)) in commands.iter().enumerate() {
        assert_eq!(
            output["result"]["commands"][index]["verdict"], *verdict,
            "{raw}"
        );
    }
}
