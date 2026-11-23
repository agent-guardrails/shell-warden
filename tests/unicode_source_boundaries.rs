use serde_json::{Value, json};
use shell_warden::checker::{
    config::load_str, letter::Letter, pipeline::evaluate, split::extract, verdict::VerdictEnvelope,
};

fn policy(parameters: bool) -> Value {
    let mut config = json!({
        "version":3,
        "defaults":{"action":"ask","redirectPolicy":"none"},
        "redirectPolicies":{"none":{"redirects":{"none":true},"paths":{"none":true}}},
        "profiles":[{
            "id":"ls","executables":["ls"],"analyzer":"generic-v1","options":{},
            "rules":[{
                "id":"allow","action":"allow",
                "match":{
                    "arguments":{"exact":[]},"options":{"none":true},
                    "environment":{"all":[{
                        "name":"CACHE","prefix":true,"occurrence":"all","value":{"any":true}
                    }]},
                    "paths":{"none":true},"facts":{"none":true},"nestedParts":{"none":true}
                }
            }]
        }]
    });
    if parameters {
        config["profiles"][0]["rules"][0]["expansions"] = json!({"assignmentValues":["HOME"]});
    }
    config
}

fn input(raw: &str) -> Value {
    json!({
        "version":1,"invocation":{"id":"unicode:test","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/repo"}]
    })
}

fn result(config: &Value, raw: &str) -> Value {
    let config = load_str(&config.to_string()).unwrap();
    let letter = Letter::from_bytes(input(raw).to_string().as_bytes()).unwrap();
    let envelope = VerdictEnvelope::new(evaluate(&config, &letter));
    envelope.validate_against("unicode:test", 1).unwrap();
    serde_json::from_slice(&envelope.to_wire().unwrap()).unwrap()
}

fn check_unicode_prefixes(parameters: bool, value: &str) {
    let config = policy(parameters);
    for leading in [
        '\u{a0}', '\u{2003}', '\u{2028}', '\u{202f}', '\u{3000}', '\u{b}', '\u{c}',
    ] {
        for padding in ["", " ", "\t", " \t"] {
            let raw = format!("{padding}{leading}CACHE={value} ls");
            let output = result(&config, &raw);
            let command = &output["result"]["commands"][0];
            assert_eq!(command["verdict"], "ask", "{raw:?}");
            assert_eq!(command["facts"]["selectedProfiles"], json!([]), "{raw:?}");
            let graph = extract(&raw);
            let part = &graph.parts[0];
            assert!(part.assigns.is_empty(), "{raw:?}");
            assert_eq!(part.argv.len(), 2, "{raw:?}");
            assert!(part.argv[0].text.starts_with(leading), "{raw:?}");
            assert_eq!(part.argv[1].text, "ls", "{raw:?}");
        }
    }
}

#[test]
fn unicode_prefixed_literal_assignments_do_not_select_the_following_executable() {
    check_unicode_prefixes(false, "/tmp");
}

#[test]
fn unicode_prefixed_parameter_assignments_do_not_select_the_following_executable() {
    check_unicode_prefixes(true, "$HOME");
}

#[test]
fn ordinary_ascii_assignment_prefixes_still_allow_with_their_own_grants() {
    for (parameters, value) in [(false, "/tmp"), (true, "$HOME")] {
        let config = policy(parameters);
        for padding in ["", " ", "\t", " \t"] {
            let raw = format!("{padding}CACHE={value} ls");
            let output = result(&config, &raw);
            assert_eq!(output["result"]["verdict"], "allow", "{raw:?}");
            assert_eq!(
                output["result"]["commands"][0]["facts"]["selectedProfiles"],
                json!(["ls"])
            );
        }
    }
    // A variable permission is still necessary for the real assignment form.
    assert_eq!(
        result(&policy(false), "CACHE=$HOME ls")["result"]["verdict"],
        "ask"
    );
}

#[test]
fn real_cli_keeps_literal_and_parameterized_nbsp_executables_distinct() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    struct ConfigFiles(std::path::PathBuf);
    impl Drop for ConfigFiles {
        fn drop(&mut self) {
            std::fs::remove_file(self.0.join("literal.json")).unwrap();
            std::fs::remove_file(self.0.join("parameter.json")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }
    let dir = std::env::temp_dir().join(format!("sw-unicode-source-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let files = ConfigFiles(dir);
    std::fs::write(files.0.join("literal.json"), policy(false).to_string()).unwrap();
    std::fs::write(files.0.join("parameter.json"), policy(true).to_string()).unwrap();
    for (file, value) in [("literal.json", "/tmp"), ("parameter.json", "$HOME")] {
        // Unicode escapes become actual NBSP characters, not backslash text.
        let commands = [
            (format!("\u{a0}CACHE={value} ls"), "ask"),
            (format!(" \t\u{a0}CACHE={value} ls"), "ask"),
            (format!("CACHE={value} ls"), "allow"),
            (format!(" \tCACHE={value} ls"), "allow"),
        ];
        let input = json!({
            "version":1,"invocation":{"id":"unicode:cli","sessionID":"test"},
            "action":"shell",
            "commands":commands.iter().enumerate().map(|(index, (raw, _))| {
                json!({"index":index,"raw":raw,"cwd":"/repo"})
            }).collect::<Vec<_>>()
        });
        // Only the checker runs. The executable-looking input is never executed.
        let mut child = Command::new(env!("CARGO_BIN_EXE_shell-warden"))
            .arg("--config")
            .arg(files.0.join(file))
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
            .validate_against("unicode:cli", commands.len())
            .unwrap();
        let output: Value = serde_json::from_slice(&output.stdout).unwrap();
        for (index, (raw, verdict)) in commands.iter().enumerate() {
            let command = &output["result"]["commands"][index];
            assert_eq!(command["verdict"], *verdict, "{raw:?}");
            let profiles = if *verdict == "allow" {
                json!(["ls"])
            } else {
                json!([])
            };
            assert_eq!(command["facts"]["selectedProfiles"], profiles, "{raw:?}");
        }
    }
}
