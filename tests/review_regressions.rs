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
    let config = load_str(&config.to_string()).unwrap();
    let input = json!({
        "version":1,"invocation":{"id":"review:test","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/repo"}]
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
        ("export A=one B C=two D", vec!["A", "B", "C", "D"]),
        ("export B A=one", vec!["B", "A"]),
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
