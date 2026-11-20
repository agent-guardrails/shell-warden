use serde_json::{Value, json};
use shell_warden::checker::{
    config::load_str, letter::Letter, pipeline::evaluate, verdict::VerdictEnvelope,
};

fn policy() -> Value {
    json!({
        "version": 3,
        "defaults": {"action":"ask", "redirectPolicy":"none"},
        "redirectPolicies":{"none":{"redirects":{"none":true},"paths":{"none":true}}},
        "profiles":[{
            "id":"ls", "executables":["ls"], "analyzer":"generic-v1",
            "options":{"recursive":{"aliases":["-R"],"arity":0}},
            "pathSources":[{"argument":{"index":0,"remainder":true}}],
            "rules":[{
                "id":"allow", "action":"allow",
                "expansions":{"arguments":["HOME"]},
                "match":{
                    "arguments":{"prefix":[],"remainder":{"each":{"any":true}}},
                    "options":{"none":true}, "environment":{"none":true},
                    "paths":{"all":[{"coordinate":{"argument":{"index":0,"remainder":true}},"any":true}]},
                    "facts":{"none":true}, "nestedParts":{"none":true}
                }
            }]
        }]
    })
}

fn result(config: &Value, raw: &str) -> Value {
    let config = load_str(&config.to_string()).unwrap();
    let input = json!({
        "version":1,"invocation":{"id":"parameter:test","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/repo"}]
    });
    let letter = Letter::from_bytes(input.to_string().as_bytes()).unwrap();
    let verdict = VerdictEnvelope::new(evaluate(&config, &letter));
    verdict.validate_against("parameter:test", 1).unwrap();
    serde_json::from_slice(&verdict.to_wire().unwrap()).unwrap()
}

fn verdict(config: &Value, raw: &str) -> String {
    result(config, raw)["result"]["verdict"]
        .as_str()
        .unwrap()
        .into()
}

fn restriction(action: &str, paths: Value) -> Value {
    json!({"id":"restriction","action":action,"match":{"paths":paths}})
}

fn secret_path() -> Value {
    json!({"any":[{"coordinate":{"argument":{"index":0,"remainder":true}},"within":"/secret"}]})
}

#[test]
fn explicit_argument_grants_cover_simple_names_and_literal_suffixes() {
    let config = policy();
    for word in [
        "\"$HOME\"",
        "\"${HOME}\"",
        "\"$HOME/cache\"",
        "\"${HOME}/cache\"",
        "\"$HOME-backup\"",
        "\"$HOME/a b\"",
        "\"$HOME/*?[x]\"",
        "\"$HOME/../other\"",
        "\"$HOME/日本語\"",
        "\"$HOME/\\$USER\"",
    ] {
        let output = result(&config, &format!("ls -- {word}"));
        assert_eq!(output["result"]["verdict"], "allow", "{word}");
        assert_eq!(
            output["result"]["commands"][0]["classification"],
            "parameter"
        );
        assert_eq!(output["result"]["commands"][0]["match"], "expression");
    }
    for word in [
        "\"$HOME_BACKUP\"",
        "\"$HOME2\"",
        "\"$home\"",
        "\"$HOME/$USER\"",
        "\"${HOME:-/tmp}\"",
        "\"$HOME/$(missing)\"",
        "$HOME",
        "~",
    ] {
        assert_ne!(
            verdict(&config, &format!("ls -- {word}")),
            "allow",
            "{word}"
        );
    }
}

#[test]
fn argument_roles_require_a_literal_operand_boundary() {
    let config = policy();
    for raw in [
        "ls \"$HOME\"",
        "ls \"$HOME\" --",
        "ls \"$HOME\" -- /public",
        "ls \"$HOME\" \"--\"",
    ] {
        assert_eq!(verdict(&config, raw), "ask", "{raw}");
    }
    assert_eq!(verdict(&config, "ls \"--\" \"$HOME\""), "allow");
    let mut option_value = config.clone();
    option_value["profiles"][0]["options"]["output"] = json!({"aliases":["-o"],"arity":1});
    option_value["profiles"][0]["rules"][0]["match"]["options"] = json!({
        "allowed":[{"option":"output","required":false,"repeatable":true,"values":{"each":{"any":true}}}]
    });
    assert_eq!(verdict(&option_value, "ls -o \"$HOME\" --"), "ask");
    assert_eq!(verdict(&option_value, "ls -o -- \"$HOME\""), "ask");
}

#[test]
fn context_grants_and_rules_do_not_borrow_permissions() {
    for grants in [
        json!({}),
        json!({"arguments":[]}),
        json!({"redirectTargets":["HOME"]}),
        json!({"assignmentValues":["HOME"]}),
    ] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["expansions"] = grants;
        assert_eq!(verdict(&config, "ls -- \"$HOME\""), "ask");
    }
    let mut config = policy();
    let mut granting_but_uncovered = config["profiles"][0]["rules"][0].clone();
    granting_but_uncovered["id"] = json!("grant-only");
    granting_but_uncovered["match"]["arguments"] = json!({"exact":["different"]});
    config["profiles"][0]["rules"][0]["expansions"] = json!({});
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(granting_but_uncovered);
    assert_eq!(verdict(&config, "ls -- \"$HOME\""), "ask");
}

#[test]
fn continuations_cannot_hide_a_longer_identifier_behind_a_shorter_grant() {
    let mut config = policy();
    config["profiles"][0]["rules"][0]["expansions"]["arguments"] = json!(["HO"]);
    assert_eq!(verdict(&config, "ls -- \"$HO\\\nME\""), "ask");
    assert_eq!(verdict(&config, "ls -- \"${HO\\\nME}\""), "ask");
    config["profiles"][0]["rules"][0]["expansions"]["arguments"] = json!(["HOME"]);
    assert_eq!(verdict(&config, "ls -- \"$HO\\\nME\""), "allow");
}

#[test]
fn runtime_value_constraints_cannot_be_proved_from_names() {
    for selector in [
        json!({"oneOf":["$HOME"]}),
        json!({"regex":".*"}),
        json!({"path":{"within":"/"}}),
    ] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["match"]["arguments"]["remainder"]["each"] = selector;
        assert_eq!(verdict(&config, "ls -- \"$HOME\""), "ask");
    }
    let mut config = policy();
    config["profiles"][0]["rules"][0]["match"]["paths"]["all"][0] = json!({
        "coordinate":{"argument":{"index":0,"remainder":true}},"within":"/"
    });
    assert_eq!(verdict(&config, "ls -- \"$HOME\""), "ask");
    assert_eq!(verdict(&config, "ls -- /public"), "allow");
}

#[test]
fn unknown_restrictive_predicates_establish_an_attributed_ask_floor() {
    for action in ["ask", "deny"] {
        let mut config = policy();
        config["profiles"][0]["rules"]
            .as_array_mut()
            .unwrap()
            .push(restriction(action, secret_path()));
        let output = result(&config, "ls -- \"$HOME\"");
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "ask");
        assert!(command.get("ruleId").is_none());
        assert_eq!(
            command["facts"]["uncertain"],
            json!([{
                "ruleId":"restriction","predicates":["/parts/0/match/paths/any/0"]
            }])
        );
        assert_eq!(command["facts"]["votes"], json!(["allow:allow"]));
        assert_eq!(command["facts"]["matched"], json!(["allow"]));
        assert_eq!(verdict(&config, "ls -- /secret"), action);
        assert_eq!(verdict(&config, "ls -- /public"), "allow");
    }
}

#[test]
fn unknown_allow_proofs_do_not_veto_an_independent_allow() {
    let mut config = policy();
    let mut failed = config["profiles"][0]["rules"][0].clone();
    failed["id"] = json!("failed");
    failed["match"]["paths"]["all"][0] = json!({
        "coordinate":{"argument":{"index":0,"remainder":true}},"within":"/secret"
    });
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(failed);
    assert_eq!(verdict(&config, "ls -- \"$HOME\""), "allow");
}

#[test]
fn complete_rule_composition_finds_decisive_known_conditions() {
    let mut config = policy();
    let mut denied = restriction("deny", secret_path());
    denied["match"]["options"] = json!({"presentAny":["recursive"]});
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(denied);
    assert_eq!(verdict(&config, "ls -- \"$HOME\""), "allow");

    config["profiles"][0]["rules"][1] = restriction("deny", secret_path());
    assert_eq!(verdict(&config, "ls -- \"$HOME\" /secret"), "deny");
    config["profiles"][0]["rules"][1]["match"]["paths"] = json!({
        "all":[{"coordinate":{"argument":{"index":0,"remainder":true}},"within":"/secret"}]
    });
    assert_eq!(verdict(&config, "ls -- \"$HOME\" /public"), "allow");
    assert_eq!(verdict(&config, "ls --"), "deny"); // all over a known-empty domain
    config["profiles"][0]["rules"][1]["match"]["paths"] = secret_path();
    assert_eq!(verdict(&config, "ls --"), "allow"); // any over a known-empty domain
    config["profiles"][0]["rules"][1]["match"]["paths"] = json!({
        "any":[{"coordinate":{"argument":{"index":0,"remainder":true}},"outside":"/secret"}]
    });
    assert_eq!(verdict(&config, "ls -- \"$HOME\""), "ask");
}

fn with_redirects() -> Value {
    let mut config = policy();
    config["defaults"]["redirectPolicy"] = json!("io");
    let mut entries = Vec::new();
    let mut paths = Vec::new();
    for operator in [">", ">>"] {
        for kind in ["parameterPath", "literalPath"] {
            entries.push(json!({"operator":operator,"sourceFd":"default","occurrence":"all","target":{"kind":kind}}));
        }
        paths.push(json!({"coordinate":{"redirect":{"operator":operator,"sourceFd":"default","occurrence":"all"}},"any":true}));
    }
    config["redirectPolicies"]["io"] = json!({"redirects":{"all":entries},"paths":{"all":paths}});
    config["profiles"][0]["rules"][0]["expansions"]["redirectTargets"] = json!(["HOME"]);
    config
}

#[test]
fn redirect_permissions_preserve_operator_kind_occurrence_and_path_coverage() {
    let config = with_redirects();
    for raw in [
        "ls > \"$HOME\"",
        "ls >> \"${HOME}/cache\"",
        "ls > \"$HOME/a\" > \"$HOME/b\"",
    ] {
        assert_eq!(verdict(&config, raw), "allow", "{raw}");
    }
    for raw in [
        "ls 2> \"$HOME\"",
        "ls < \"$HOME\"",
        "ls > $HOME",
        "ls > \"$HOME/$USER\"",
    ] {
        assert_eq!(verdict(&config, raw), "ask", "{raw}");
    }
    let mut missing = config.clone();
    missing["profiles"][0]["rules"][0]["expansions"] = json!({"arguments":["HOME"]});
    assert_eq!(verdict(&missing, "ls > \"$HOME\""), "ask");
    missing = config.clone();
    missing["redirectPolicies"]["io"]["paths"] = json!({"none":true});
    assert_eq!(verdict(&missing, "ls > \"$HOME\""), "ask");
    missing = config.clone();
    missing["redirectPolicies"]["io"]["redirects"]["all"][0]["occurrence"] = json!(1);
    assert_eq!(verdict(&missing, "ls > \"$HOME/a\" > \"$HOME/b\""), "ask");
}

fn with_assignments() -> Value {
    let mut config = policy();
    config["profiles"][0]["rules"][0]["expansions"]["assignmentValues"] = json!(["HOME"]);
    config["profiles"][0]["rules"][0]["match"]["environment"] = json!({
        "all":[{"name":"CACHE","prefix":true,"occurrence":"all","value":{"any":true}}]
    });
    config
}

#[test]
fn prefix_assignment_values_are_reads_not_destination_grants() {
    let config = with_assignments();
    for raw in [
        "CACHE=$HOME/cache ls",
        "CACHE=\"${HOME}/cache\" ls",
        "CACHE=$HOME CACHE=${HOME}/other ls",
    ] {
        assert_eq!(verdict(&config, raw), "allow", "{raw}");
    }
    for raw in ["HOME=$HOME ls", "PATH=$HOME ls", "CACHE=$USER ls"] {
        assert_eq!(verdict(&config, raw), "ask", "{raw}");
    }
    let mut unknown = config.clone();
    unknown["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"assignment-restriction","action":"deny",
            "match":{"environment":{"any":[{"name":"CACHE","value":{"oneOf":["/secret"]}}]}}
        }));
    assert_eq!(verdict(&unknown, "CACHE=$HOME ls"), "ask");
    unknown["profiles"][0]["rules"][1]["match"]["environment"]["any"][0]["name"] = json!("OTHER");
    assert_eq!(verdict(&unknown, "CACHE=$HOME ls"), "allow");
    let mut no_value_policy = config;
    no_value_policy["profiles"][0]["rules"][0]["match"]["environment"]["all"][0]
        .as_object_mut()
        .unwrap()
        .remove("value");
    assert_eq!(verdict(&no_value_policy, "CACHE=$HOME ls"), "ask");
    assert_eq!(verdict(&no_value_policy, "CACHE=/public ls"), "allow");
}

#[test]
fn declarations_keep_destination_kind_and_fact_coverage() {
    let mut config = with_assignments();
    config["profiles"][0]["id"] = json!("export");
    config["profiles"][0]["executables"] = json!(["export"]);
    config["profiles"][0]["analyzer"] = json!("export-v1");
    config["profiles"][0]["options"] = json!({});
    config["profiles"][0]["rules"][0]["match"]["environment"]["all"][0]["prefix"] = json!(false);
    config["profiles"][0]["rules"][0]["match"]["facts"] = json!({
        "all":[{"analyzer":"export-v1","version":"1","name":"assignment","occurrence":"all","value":{"any":true}}]
    });
    assert_eq!(verdict(&config, "export CACHE=\"$HOME/cache\""), "allow");
    assert_eq!(verdict(&config, "export CACHE=$HOME/cache"), "allow");
    assert_eq!(verdict(&config, "export \"CACHE=literal\""), "allow");
    assert_eq!(verdict(&config, "export -- \"$HOME\""), "ask");
    assert_eq!(verdict(&config, "export -- \"$HOME=other\""), "ask");
    assert_eq!(verdict(&config, "\"export\" CACHE=$HOME/cache"), "ask");
    assert_eq!(verdict(&config, "export HOME=\"$HOME/cache\""), "ask");
    assert_eq!(verdict(&config, "CACHE=$HOME export"), "ask");
    config["profiles"][0]["rules"][0]["match"]["facts"] = json!({"none":true});
    assert_eq!(verdict(&config, "export CACHE=$HOME"), "ask");
}

#[test]
fn literal_scripts_use_the_same_values_and_retain_outer_coverage() {
    assert_eq!(verdict(&policy(), "bash -c 'ls -- \"$HOME\"'"), "allow");
    assert_eq!(
        verdict(&policy(), "CACHE=/public bash -c 'ls -- \"$HOME\"'"),
        "ask"
    );
    assert_eq!(
        verdict(
            &with_assignments(),
            "CACHE=/public bash -c 'ls -- \"$HOME\"'"
        ),
        "allow"
    );
    assert_eq!(
        verdict(&with_assignments(), "CACHE=$HOME bash -c 'ls'"),
        "allow"
    );
    assert_eq!(verdict(&policy(), "bash -c 'ls' > \"$HOME\""), "ask");
    assert_eq!(
        verdict(&with_redirects(), "bash -c 'ls' > \"$HOME\""),
        "allow"
    );
    for raw in [
        "bash -c \"$HOME\"",
        "bash -c 'ls -- \"$HOME\"' extra",
        "bash -c 'ls' \"$HOME\"",
        "bash -c 'PATH=/untrusted; ls -- \"$HOME\"'",
        "ls -- \"$HOME\"; missing",
    ] {
        assert_eq!(verdict(&policy(), raw), "ask", "{raw}");
    }
    let mut config = policy();
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(restriction("deny", secret_path()));
    assert_eq!(
        verdict(&config, "bash -c 'ls -- /secret' \"$HOME\""),
        "deny"
    );
    for wrapper in ["sudo", "nohup", "nice", "timeout 1s", "env"] {
        assert_eq!(
            verdict(&config, &format!("{wrapper} ls -- /secret \"$HOME\"")),
            "deny",
            "{wrapper}"
        );
    }
    assert_eq!(
        verdict(&policy(), "env PATH=/untrusted bash -c 'ls -- \"$HOME\"'"),
        "ask"
    );
}

#[test]
fn path_spelled_wrappers_cannot_authorize_dynamic_operands() {
    for name in ["env", "sudo", "nohup", "nice", "timeout", "xargs"] {
        for head in [format!("/usr/bin/{name}"), format!("./{name}")] {
            let mut config = policy();
            config["profiles"][0]["id"] = json!("wrapper");
            config["profiles"][0]["executables"] = json!([head]);
            for operand in ["\"$HOME\"", "\"${HOME}/command\""] {
                let raw = format!("{head} -- {operand}");
                let output = result(&config, &raw);
                let command = &output["result"]["commands"][0];
                assert_eq!(command["verdict"], "ask", "{raw}");
                assert_eq!(command["classification"], "opaque", "{raw}");
                assert_eq!(command["match"], "raw", "{raw}");
                assert_eq!(
                    command["facts"]["selectedProfiles"],
                    json!(["wrapper"]),
                    "{raw}"
                );
            }
        }
    }
    // A basename is a blocking check, not a transparent wrapper alias.
    assert_eq!(verdict(&policy(), "/usr/bin/env ls -- \"$HOME\""), "ask");
}

#[test]
fn awk_operand_boundary_does_not_prove_a_data_role() {
    for head in ["awk", "/usr/bin/awk", "./awk"] {
        let mut config = policy();
        config["profiles"][0]["id"] = json!("awk");
        config["profiles"][0]["executables"] = json!([head]);
        // The policy really covers ordinary literal arguments for this spelling.
        assert_eq!(
            verdict(&config, &format!("{head} -- '{{ print $0 }}' /public")),
            "allow",
            "{head}"
        );
        for args in ["-- \"$HOME\"", "-- \"${HOME}/program\" /public"] {
            let raw = format!("{head} {args}");
            let output = result(&config, &raw);
            let command = &output["result"]["commands"][0];
            assert_eq!(command["verdict"], "ask", "{raw}");
            assert_eq!(command["classification"], "opaque", "{raw}");
            assert_eq!(command["match"], "raw", "{raw}");
            assert_eq!(command["facts"]["selectedProfiles"], json!(["awk"]));
        }
        // Without a program-role analyzer, a literal program is not a proof
        // that an unknown later operand is ordinary data either.
        assert_eq!(
            verdict(&config, &format!("{head} -- '{{ print $0 }}' \"$HOME\"")),
            "ask",
            "{head}"
        );
    }
}

#[test]
fn dynamic_execution_operands_fail_closed_through_cli() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.0.join("config.json")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }

    let dir = std::env::temp_dir().join(format!("sw-contextual-roles-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let file = ConfigFile(dir);
    let mut config = policy();
    config["profiles"] = ["/usr/bin/env", "awk", "/usr/bin/awk"]
        .iter()
        .enumerate()
        .map(|(index, head)| {
            let mut profile = config["profiles"][0].clone();
            profile["id"] = json!(format!("command-{index}"));
            profile["executables"] = json!([head]);
            profile
        })
        .collect();
    std::fs::write(file.0.join("config.json"), config.to_string()).unwrap();
    let commands = [
        "/usr/bin/env -- \"$HOME\"",
        "awk -- \"$HOME\"",
        "/usr/bin/awk -- \"$HOME\"",
        "awk -- '{ print $0 }' /public",
    ];
    let input = json!({
        "version":1,"invocation":{"id":"parameter:cli","sessionID":"test"},
        "action":"shell",
        "commands":commands.iter().enumerate().map(|(index, raw)| {
            json!({"index":index,"raw":raw,"cwd":"/repo"})
        }).collect::<Vec<_>>()
    });
    // Only the checker is spawned: submitted shell text is never executed.
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
        .validate_against("parameter:cli", commands.len())
        .unwrap();
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output["result"]["verdict"], "ask");
    for (index, raw) in commands.iter().enumerate() {
        let command = &output["result"]["commands"][index];
        let (verdict, classification) = if index < 3 {
            ("ask", "opaque")
        } else {
            ("allow", "static")
        };
        assert_eq!(command["verdict"], verdict, "{raw}");
        assert_eq!(command["classification"], classification, "{raw}");
    }
}

#[test]
fn ordinary_argument_grants_do_not_authorize_dynamic_code_operands() {
    for head in [
        "eval",
        "exec",
        "command",
        "builtin",
        "source",
        ".",
        "node",
        "python3",
        "/bin/bash",
    ] {
        let mut config = policy();
        config["profiles"][0]["id"] = json!("interpreter");
        config["profiles"][0]["executables"] = json!([head]);
        assert_eq!(
            verdict(&config, &format!("{head} -- \"$HOME\"")),
            "ask",
            "{head}"
        );
    }
    let mut config = policy();
    config["profiles"][0]["id"] = json!("sed");
    config["profiles"][0]["executables"] = json!(["sed"]);
    config["profiles"][0]["analyzer"] = json!("sed-v1");
    config["profiles"][0]["options"] = json!({});
    config["profiles"][0]["rules"][0]["match"]["facts"] = json!({"all":[
        {"analyzer":"sed-v1","version":"1","name":"executionPrimitive","occurrence":"all","value":{"any":true}},
        {"analyzer":"sed-v1","version":"1","name":"programForm","occurrence":"all","value":{"any":true}}
    ]});
    assert_eq!(verdict(&config, "sed -- \"$HOME\""), "ask");
    assert_eq!(verdict(&config, "sed -- s/a/b/ \"$HOME\""), "allow");
}

#[test]
fn uncertainty_survives_aggregation_truncation_and_real_ask_votes() {
    let mut config = policy();
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(restriction("deny", secret_path()));
    let output = result(&config, "ls -- /public; ls -- \"$HOME\"");
    assert_eq!(output["result"]["verdict"], "ask");
    assert_eq!(
        output["result"]["commands"][0]["facts"]["uncertain"][0]["ruleId"],
        "restriction"
    );
    config["limits"] = json!({"diagnosticsBytes":256});
    let output = result(&config, "ls -- \"$HOME\"");
    let facts = &output["result"]["commands"][0]["facts"];
    assert_eq!(facts["diagnostics"], "truncated-after-decision");
    assert!(
        facts["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("predicate-unknown"))
    );
    assert_eq!(output["result"]["verdict"], "ask");
    config.as_object_mut().unwrap().remove("limits");
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"real-ask","action":"ask","match":{"classification":"parameter"}}));
    assert_eq!(
        result(&config, "ls -- \"$HOME\"")["result"]["commands"][0]["ruleId"],
        "real-ask"
    );
    config["profiles"][0]["rules"].as_array_mut().unwrap().push(json!({"id":"real-deny","action":"deny","message":"denied","match":{"classification":"parameter"}}));
    assert_eq!(verdict(&config, "ls -- \"$HOME\""), "deny");
}

#[test]
fn malformed_permissions_and_retired_versions_fail_loading() {
    for grants in [
        json!({"arguments":["HOME","HOME"]}),
        json!({"arguments":["H*"]}),
        json!({"arguments":["2HOME"]}),
        json!({"arguments":["HÖME"]}),
        json!({"arguments":{"HOME":"/home/example"}}),
        json!({"arguments":null}),
        json!({"arguments":vec!["HOME";65]}),
        json!({"arguments":["HOME"],"other":[]}),
        Value::Null,
    ] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["expansions"] = grants;
        assert!(load_str(&config.to_string()).is_err());
    }
    let mut config = policy();
    config["profiles"][0]["rules"][0]["action"] = json!("ask");
    assert!(load_str(&config.to_string()).is_err());
    for version in [1, 2, 4] {
        config = policy();
        config["version"] = json!(version);
        assert!(load_str(&config.to_string()).is_err());
    }
}
