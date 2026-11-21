use serde_json::{Value, json};
use shell_warden::checker::{
    config::load_str, evidence::EvidenceState, grammar::RedirectOp, letter::Letter,
    pipeline::evaluate, split::extract, verdict::VerdictEnvelope,
};

fn policy() -> Value {
    json!({
        "version":3,
        "defaults":{"action":"ask","redirectPolicy":"fd-only"},
        "redirectPolicies":{"fd-only":{
            "redirects":{"all":[
                {"operator":">&","sourceFd":"default","occurrence":"all","target":{"kind":"fd"}},
                {"operator":">&","sourceFd":2,"occurrence":"all","target":{"kind":"fd"}},
                {"operator":"<&","sourceFd":"default","occurrence":"all","target":{"kind":"fd"}}
            ]},
            "paths":{"none":true}
        }},
        "profiles":[{
            "id":"ls","executables":["ls"],"analyzer":"generic-v1","options":{},
            "rules":[{
                "id":"allow","action":"allow",
                "match":{
                    "classification":"complete","arguments":{"exact":[]},
                    "options":{"none":true},"environment":{"none":true},
                    "paths":{"none":true},"facts":{"none":true},"nestedParts":{"none":true}
                }
            }]
        }]
    })
}

fn result(config: &Value, raw: &str) -> Value {
    let config = load_str(&config.to_string()).unwrap();
    let input = json!({
        "version":1,"invocation":{"id":"redirect:test","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/repo"}]
    });
    let letter = Letter::from_bytes(input.to_string().as_bytes()).unwrap();
    let envelope = VerdictEnvelope::new(evaluate(&config, &letter));
    envelope.validate_against("redirect:test", 1).unwrap();
    serde_json::from_slice(&envelope.to_wire().unwrap()).unwrap()
}

#[test]
fn duplication_targets_require_unsigned_literal_descriptor_operands() {
    for raw in [
        "ls >& /path/file",
        "ls >& filename",
        "ls >& 'a b'",
        "ls >& +1",
        "ls >& -1",
        "ls <& filename",
        "ls <& +1",
        "ls <& -1",
        "ls >& 2147483648",
        "ls >& -",
        "ls >& \"$FD\"",
    ] {
        let graph = extract(raw);
        let part = &graph.parts[0];
        assert!(!part.redirects[0].is_fd_target, "{raw}");
        assert!(matches!(part.state, EvidenceState::Invalid(_)), "{raw}");
    }
    for raw in ["ls 2>&1", "ls >& 1", "ls >& '1'", "ls >& 01", "ls <& 0"] {
        let graph = extract(raw);
        let part = &graph.parts[0];
        assert!(part.redirects[0].is_fd_target, "{raw}");
        assert_eq!(part.state, EvidenceState::Complete, "{raw}");
    }
}

#[test]
fn fd_only_policy_cannot_cover_file_duplication_targets() {
    let config = policy();
    for raw in [
        "ls >& /path/file",
        "ls >& filename",
        "ls >& +1",
        "ls >& -1",
        "ls <& filename",
        "ls <& +1",
        "ls <& -1",
    ] {
        let output = result(&config, raw);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "ask", "{raw}");
        assert_eq!(command["classification"], "invalid", "{raw}");
        assert_eq!(command["facts"]["selectedProfiles"], json!(["ls"]), "{raw}");
    }
    for raw in ["ls 2>&1", "ls >& 1", "ls >& '1'", "ls <& 0"] {
        assert_eq!(result(&config, raw)["result"]["verdict"], "allow", "{raw}");
    }
    for raw in ["ls > 2", "ls 2>&1 > 2", "ls > 2 2>&1"] {
        assert_eq!(result(&config, raw)["result"]["verdict"], "ask", "{raw}");
    }
}

#[test]
fn numeric_filename_requires_file_redirect_path_coverage() {
    let raw = "ls > 2";
    let graph = extract(raw);
    let redirect = &graph.parts[0].redirects[0];
    assert_eq!(redirect.op, Some(RedirectOp::Out));
    assert_eq!(redirect.target, "2");
    assert!(!redirect.is_fd_target);
    assert_eq!(graph.parts[0].state, EvidenceState::Complete);

    let mut config = policy();
    assert_eq!(result(&config, raw)["result"]["verdict"], "ask");
    config["redirectPolicies"]["fd-only"]["redirects"] = json!({"all":[{
        "operator":">","sourceFd":"default","occurrence":"all","target":{"kind":"literalPath"}
    }]});
    // Correct operator and target kind alone do not cover the file path.
    assert_eq!(result(&config, raw)["result"]["verdict"], "ask");
    config["redirectPolicies"]["fd-only"]["paths"] = json!({"all":[{
        "coordinate":{"redirect":{"operator":">","sourceFd":"default","occurrence":"all"}},
        "exact":"/repo/other"
    }]});
    assert_eq!(result(&config, raw)["result"]["verdict"], "ask");
    config["redirectPolicies"]["fd-only"]["paths"]["all"][0]["exact"] = json!("/repo/2");
    assert_eq!(result(&config, raw)["result"]["verdict"], "allow");
}

#[test]
fn real_cli_distinguishes_fd_operands_from_file_redirects() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.0.join("config.json")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }

    let dir = std::env::temp_dir().join(format!("sw-redirect-fds-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let file = ConfigFile(dir);
    std::fs::write(file.0.join("config.json"), policy().to_string()).unwrap();
    let commands = [
        ("ls >& /path/file", "ask", "invalid"),
        ("ls >& +1", "ask", "invalid"),
        ("ls >& -1", "ask", "invalid"),
        ("ls 2>&1", "allow", "static"),
        ("ls <& 0", "allow", "static"),
        ("ls > 2", "ask", "static"),
        ("ls 2>&1 > 2", "ask", "static"),
        ("ls > 2 2>&1", "ask", "static"),
    ];
    let input = json!({
        "version":1,"invocation":{"id":"redirect:cli","sessionID":"test"},
        "action":"shell",
        "commands":commands.iter().enumerate().map(|(index, (raw, _, _))| {
            json!({"index":index,"raw":raw,"cwd":"/repo"})
        }).collect::<Vec<_>>()
    });
    // Only the checker runs; redirect text is never submitted to a shell.
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
        .validate_against("redirect:cli", commands.len())
        .unwrap();
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, (raw, verdict, classification)) in commands.iter().enumerate() {
        let command = &output["result"]["commands"][index];
        assert_eq!(command["verdict"], *verdict, "{raw}");
        assert_eq!(command["classification"], *classification, "{raw}");
    }
}
