//! https://github.com/agent-guardrails/shell-warden/issues/80
//! Commands are checker input data, never executed by a shell.
use serde_json::{Value, json};
use shell_warden::checker::{
    config::load_str, letter::Letter, pipeline::evaluate, verdict::VerdictEnvelope,
};

fn policy() -> Value {
    json!({
        "version":3,
        "defaults":{"action":"ask","redirectPolicy":"none"},
        "redirectPolicies":{"none":{"redirects":{"none":true},"paths":{"none":true}}},
        "profiles":[{
            "id":"tool","executables":["example-tool"],"analyzer":"generic-v1",
            "options":{
                "config":{"aliases":["--config","-c","--config.file"],"arity":1,"inline":true},
                "pair":{"aliases":["--pair"],"arity":2},
                "verbose":{"aliases":["-v"],"arity":0}
            },
            "rules":[{
                "id":"allow","action":"allow","expansions":{"optionValues":["HOME"]},
                "match":{
                    "arguments":{"exact":["list"]},
                    "options":{"allowed":[
                        {"option":"config","required":false,"repeatable":true,"values":{"each":{"any":true}}},
                        {"option":"pair","required":false,"repeatable":true,"values":{"byPosition":[{"any":true},{"any":true}]}},
                        {"option":"verbose","required":false,"repeatable":false}
                    ]},
                    "environment":{"none":true},"paths":{"none":true},
                    "facts":{"none":true},"nestedParts":{"none":true}
                }
            }]
        }]
    })
}

fn result(config: &Value, raw: &str) -> Value {
    let config = load_str(&config.to_string()).unwrap();
    let input = json!({
        "version":1,"invocation":{"id":"option-value:test","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/workspace"}]
    });
    let letter = Letter::from_bytes(input.to_string().as_bytes()).unwrap();
    let envelope = VerdictEnvelope::new(evaluate(&config, &letter));
    envelope
        .validate_against("option-value:test", 1)
        .unwrap_or_else(|e| panic!("{raw}: {e}; {envelope:?}"));
    serde_json::from_slice(&envelope.to_wire().unwrap()).unwrap()
}

fn verdict(config: &Value, raw: &str) -> String {
    result(config, raw)["result"]["verdict"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn quoted_values_preserve_aliases_arity_occurrences_and_inline_forms() {
    let config = policy();
    assert_eq!(
        verdict(&config, "example-tool --config /public/config.yaml list"),
        "allow"
    );
    for raw in [
        r#"example-tool --config "$HOME/config.yaml" list"#,
        r#"example-tool -c "${HOME}/config.yaml" list"#,
        r#"example-tool --config.file="$HOME/config.yaml" list"#,
        r#"example-tool --config="$HOME/config.yaml" list"#,
        r#"example-tool -c="${HOME}/config.yaml" list"#,
        r#"example-tool -vc "$HOME/config.yaml" list"#,
        r#"example-tool --pair "$HOME/a" "${HOME}/b" list"#,
        r#"example-tool --pair -- "$HOME/b" list"#,
        r#"example-tool -c "$HOME/a" --config="${HOME}/b" list"#,
        r#"example-tool --config "$HOME/../a b/*" list"#,
        "example-tool --config \"$HO\\\nME/a\" list",
        r#"example-tool --config "$HOME/\$USER" list"#,
    ] {
        let output = result(&config, raw);
        assert_eq!(output["result"]["verdict"], "allow", "{raw}: {output}");
        assert_eq!(
            output["result"]["commands"][0]["classification"], "parameter",
            "{raw}"
        );
        assert_eq!(
            output["result"]["commands"][0]["match"], "expression",
            "{raw}"
        );
    }
}

#[test]
fn option_grants_are_local_and_do_not_borrow_argument_or_other_grants() {
    for grants in [
        json!({}),
        json!({"optionValues":[]}),
        json!({"optionValues":["USER"]}),
        json!({"arguments":["HOME"]}),
        json!({"redirectTargets":["HOME"]}),
        json!({"assignmentValues":["HOME"]}),
    ] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["expansions"] = grants;
        for raw in [
            r#"example-tool --config "$HOME/a" list"#,
            r#"example-tool --config="$HOME/a" list"#,
        ] {
            assert_eq!(verdict(&config, raw), "ask", "{raw}");
            assert_eq!(
                result(&config, raw)["result"]["commands"][0]["classification"],
                "parameter"
            );
        }
    }
    let mut config = policy();
    let mut uncovered = config["profiles"][0]["rules"][0].clone();
    uncovered["id"] = json!("grant-only");
    uncovered["match"]["arguments"] = json!({"exact":["other"]});
    config["profiles"][0]["rules"][0]["expansions"] = json!({});
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(uncovered);
    assert_eq!(verdict(&config, r#"example-tool -c "$HOME" list"#), "ask");

    let mut config = policy();
    config["profiles"][0]["rules"][0]["match"]["arguments"] =
        json!({"prefix":[],"remainder":{"each":{"any":true}}});
    assert_eq!(verdict(&config, r#"example-tool -- "$HOME""#), "ask");
    config["profiles"][0]["rules"][0]["expansions"]["arguments"] = json!(["HOME"]);
    assert_eq!(verdict(&config, r#"example-tool -- "$HOME""#), "allow");
    assert_eq!(
        verdict(&config, r#"example-tool -- --config="$HOME""#),
        "ask"
    );
    assert_eq!(
        result(&config, r#"example-tool -- --config="$HOME""#)["result"]["commands"][0]["classification"],
        "opaque"
    );
    assert_eq!(
        verdict(&config, r#"example-tool -c --config="$HOME" --"#),
        "ask"
    );
}

#[test]
fn unsupported_syntax_and_dynamic_names_never_qualify() {
    let config = policy();
    for raw in [
        r#"example-tool --config $HOME/a list"#,
        r#"example-tool --config=$HOME/a list"#,
        r#"example-tool "--config=$HOME/a" list"#,
        r#"example-tool --con""fig="$HOME/a" list"#,
        r#"example-tool --config "$HOME"/a list"#,
        r#"example-tool --config "${HOME:-/tmp}/a" list"#,
        r#"example-tool --config "$HOME/$USER" list"#,
        r#"example-tool --config "$HOME_BACKUP/a" list"#,
        r#"example-tool --config "${!HOME}" list"#,
        r#"example-tool --config "$HOME/$(missing)" list"#,
        r#"example-tool --config="$HOME/$(missing)" list"#,
        r#"example-tool "$OPTION" "$HOME/a" list"#,
        r#""$TOOL" --config "$HOME/a" list"#,
        r#"example-tool --pair="$HOME/a" list"#,
        r#"example-tool --unknown "$HOME/a" list"#,
        r#"example-tool --config"#,
    ] {
        assert_ne!(verdict(&config, raw), "allow", "{raw}");
    }
    let output = result(&config, r#"example-tool -c "$HOME/$(missing)" list"#);
    assert!(
        output["result"]["commands"][0]["facts"]["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("opaque-expansion"))
    );
}

#[test]
fn inline_opt_in_occurrence_and_ordinal_coverage_remain_required() {
    let mut config = policy();
    config["profiles"][0]["options"]["config"]["inline"] = json!(false);
    assert_eq!(
        verdict(&config, r#"example-tool --config="$HOME" list"#),
        "ask"
    );
    config["profiles"][0]["rules"][0]["match"]["options"]["allowed"][0]["repeatable"] =
        json!(false);
    assert_eq!(
        verdict(&config, r#"example-tool -c "$HOME" -c /public list"#),
        "ask"
    );
    config["profiles"][0]["rules"][0]["match"]["options"]["allowed"][0]["required"] = json!(true);
    assert_eq!(verdict(&config, "example-tool list"), "ask");
    config["profiles"][0]["rules"][0]["match"]["options"]["allowed"][1]["values"] =
        json!({"byPosition":[{"oneOf":["literal"]},{"any":true}]});
    assert_eq!(
        verdict(
            &config,
            r#"example-tool -c /public --pair literal "$HOME" list"#
        ),
        "allow"
    );
    assert_eq!(
        verdict(
            &config,
            r#"example-tool -c /public --pair "$HOME" literal list"#
        ),
        "ask"
    );
}

#[test]
fn runtime_value_predicates_remain_unknown_for_allow_and_restrictions() {
    for selector in [
        json!({"oneOf":["$HOME/config"]}),
        json!({"regex":".*"}),
        json!({"path":{"within":"/"}}),
    ] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["match"]["options"]["allowed"][0]["values"]["each"] =
            selector.clone();
        assert_eq!(
            verdict(&config, r#"example-tool -c "$HOME/config" list"#),
            "ask"
        );

        let mut config = policy();
        config["profiles"][0]["rules"].as_array_mut().unwrap().push(json!({
            "id":"restriction","action":"deny","match":{"options":{"values":{"config":selector}}}
        }));
        let output = result(&config, r#"example-tool --config="$HOME/config" list"#);
        let command = &output["result"]["commands"][0];
        assert_eq!(command["verdict"], "ask");
        assert!(command.get("ruleId").is_none());
        assert_eq!(
            command["facts"]["uncertain"],
            json!([{
                "ruleId":"restriction","predicates":["/parts/0/match/options/values/config"]
            }])
        );
        config["profiles"][0]["rules"][1]["match"]["options"]["presentAll"] = json!(["verbose"]);
        assert_eq!(
            verdict(&config, r#"example-tool -c "$HOME/config" list"#),
            "allow"
        );
    }
    let mut config = policy();
    config["profiles"][0]["rules"].as_array_mut().unwrap().push(json!({
        "id":"deny","action":"deny","match":{"options":{"values":{"config":{"oneOf":["/secret"]}}}}
    }));
    assert_eq!(verdict(&config, "example-tool -c /secret list"), "deny");
    assert_eq!(verdict(&config, "example-tool -c /public list"), "allow");
}

#[test]
fn unresolved_option_paths_need_independent_value_free_coverage() {
    let mut config = policy();
    let coordinate = json!({"optionValue":{"option":"config","valueOrdinal":1}});
    config["profiles"][0]["pathSources"] = json!([coordinate.clone()]);
    config["profiles"][0]["rules"][0]["match"]["paths"] =
        json!({"all":[{"coordinate":coordinate,"any":true}]});
    assert_eq!(
        verdict(&config, r#"example-tool -c "$HOME/config" list"#),
        "allow"
    );
    config["profiles"][0]["rules"][0]["match"]["paths"]["all"][0] =
        json!({"coordinate":coordinate,"within":"/"});
    assert_eq!(
        verdict(&config, r#"example-tool -c "$HOME/config" list"#),
        "ask"
    );
    assert_eq!(verdict(&config, "example-tool -c /public list"), "allow");
}

#[test]
fn option_value_grant_validation_uses_existing_closed_name_lists() {
    for invalid in [
        json!(null),
        json!("HOME"),
        json!(["*"]),
        json!(["HOME", "HOME"]),
        json!(["1HOME"]),
        json!(["HOME".repeat(33)]),
        json!((0..65).map(|i| format!("NAME_{i}")).collect::<Vec<_>>()),
    ] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["expansions"]["optionValues"] = invalid;
        assert!(load_str(&config.to_string()).is_err());
    }
    for action in ["ask", "deny"] {
        let mut config = policy();
        config["profiles"][0]["rules"][0]["action"] = json!(action);
        config["profiles"][0]["rules"][0]["expansions"] = json!({"optionValues":[]});
        assert!(load_str(&config.to_string()).is_err());
    }
}

#[test]
fn code_and_wrapper_operands_remain_opaque_and_children_remain_visible() {
    for head in [
        "bash",
        "sh",
        "node",
        "python3",
        "awk",
        "env",
        "sudo",
        "sed",
        "/usr/bin/sed",
    ] {
        let mut config = policy();
        config["profiles"][0]["executables"] = json!([head]);
        for syntax in [r#"-c "$HOME/program""#, r#"--config="$HOME/program""#] {
            let output = result(&config, &format!("{head} {syntax} list"));
            assert_ne!(output["result"]["verdict"], "allow", "{head} {syntax}");
        }
    }
    let mut config = policy();
    config["profiles"].as_array_mut().unwrap().push(json!({
        "id":"missing","executables":["missing"],"analyzer":"generic-v1","options":{},
        "rules":[{"id":"deny-child","action":"deny","match":{}}]
    }));
    for raw in [
        r#"example-tool -c "$HOME/$(missing)" list"#,
        r#"example-tool --config="$HOME/$(missing)" list"#,
    ] {
        let output = result(&config, raw);
        assert_eq!(output["result"]["verdict"], "deny", "{raw}: {output}");
        assert!(
            output["result"]["commands"][0]["facts"]["selectedProfiles"]
                .as_array()
                .unwrap()
                .contains(&json!("missing"))
        );
    }
}

#[test]
fn sed_analyzer_program_options_do_not_acquire_parameter_permission() {
    let mut config = policy();
    let profile = &mut config["profiles"][0];
    profile["executables"] = json!(["sed"]);
    profile["analyzer"] = json!("sed-v1");
    profile["options"] = json!({
        "expression":{"aliases":["-e","--expression"],"arity":1,"inline":true},
        "file":{"aliases":["-f","--file"],"arity":1,"inline":true}
    });
    profile["rules"][0]["match"]["options"] = json!({"allowed":[
        {"option":"expression","required":false,"repeatable":true,"values":{"each":{"any":true}}},
        {"option":"file","required":false,"repeatable":true,"values":{"each":{"any":true}}}
    ]});
    profile["rules"][0]["match"]["facts"] = json!({"all":[
        {"analyzer":"sed-v1","version":"1","name":"executionPrimitive","occurrence":"all","value":{"any":true}},
        {"analyzer":"sed-v1","version":"1","name":"programForm","occurrence":"all","value":{"any":true}}
    ]});
    assert_eq!(verdict(&config, "sed -e literal list"), "allow");
    for raw in [
        r#"sed -e "$HOME/program" list"#,
        r#"sed --expression="$HOME/program" list"#,
        r#"sed -f "${HOME}/program" list"#,
        r#"sed --file="${HOME}/program" list"#,
    ] {
        let output = result(&config, raw);
        assert_eq!(output["result"]["verdict"], "ask", "{raw}");
        assert_eq!(
            output["result"]["commands"][0]["classification"], "opaque",
            "{raw}"
        );
    }
}

#[test]
fn every_option_value_needs_a_grant_but_unproved_allow_peers_do_not_veto() {
    let mut config = policy();
    for raw in [
        r#"example-tool -c "$HOME/a" -c "$USER/b" list"#,
        r#"example-tool --pair "$HOME/a" "${USER}/b" list"#,
    ] {
        assert_eq!(verdict(&config, raw), "ask", "{raw}");
    }
    config["profiles"][0]["rules"][0]["expansions"]["optionValues"] = json!(["HOME", "USER"]);
    assert_eq!(
        verdict(&config, r#"example-tool -c "$HOME/a" -c "$USER/b" list"#),
        "allow"
    );
    let mut unproved = config["profiles"][0]["rules"][0].clone();
    unproved["id"] = json!("unproved");
    unproved["match"]["options"]["allowed"][0]["values"]["each"] = json!({"regex":".*"});
    config["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(unproved);
    assert_eq!(
        verdict(&config, r#"example-tool --config="$HOME/a" list"#),
        "allow"
    );
}
