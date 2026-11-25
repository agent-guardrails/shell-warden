// https://github.com/agent-guardrails/shell-warden/issues/73
// https://github.com/agent-guardrails/docs/issues/51
use serde_json::{Value, json};
use shell_warden::checker::config::load_str;
use shell_warden::checker::evidence::EvidenceState;
use shell_warden::checker::grammar::Relation;
use shell_warden::checker::letter::Letter;
use shell_warden::checker::pipeline::evaluate;
use shell_warden::checker::split::extract;
use shell_warden::checker::verdict::VerdictEnvelope;

fn policy(profiles: Vec<Value>) -> Value {
    json!({
        "version": 3,
        "defaults": {"action": "ask", "redirectPolicy": "no-redirects"},
        "redirectPolicies": {
            "no-redirects": {"redirects": {"none": true}, "paths": {"none": true}}
        },
        "profiles": profiles
    })
}

fn profile(spellings: &[&str]) -> Value {
    json!({
        "id": "arbitrary-profile-id", "executables": spellings, "options": {},
        "rules": [{
            "id": "allow", "action": "allow",
            "match": {
                "classification": "complete",
                "arguments": {"prefix": [], "remainder": {"each": {"any": true}}},
                "options": {"none": true}, "environment": {"none": true},
                "paths": {"none": true}, "facts": {"none": true},
                "nestedParts": {"none": true}
            }
        }]
    })
}

fn letter(raw: &str) -> Letter {
    Letter::from_bytes(
        json!({
            "version": 1, "invocation": {"id": "spellings", "sessionID": "test"},
            "action": "shell", "commands": [{"index": 0, "cwd": "/repo", "raw": raw}]
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

fn run(config: &Value, raw: &str) -> Value {
    let config = load_str(&config.to_string()).unwrap();
    let envelope = VerdictEnvelope::new(evaluate(&config, &letter(raw)));
    envelope
        .validate_against("spellings", 1)
        .unwrap_or_else(|error| panic!("{raw}: {error}; {envelope:?}"));
    serde_json::to_value(envelope).unwrap()["result"].clone()
}

#[track_caller]
fn outcome(config: &Value, raw: &str, expected: &str) -> Value {
    let result = run(config, raw);
    assert_eq!(result["verdict"], expected, "{raw}: {result}");
    result
}

#[test]
fn design_validation_examples_and_boundaries() {
    for spellings in [
        vec!["tool"],
        vec!["/opt/tools/tool"],
        vec!["tool", "/opt/tools/tool", "/home/user/bin/tool"],
        vec!["/opt/tools/tool", "/home/user/bin/tool"],
        vec!["node", "nodejs"],
        vec!["node", "/opt/tools/node", "/usr/bin/nodejs"],
        vec!["/opt/tools/python", "/usr/bin/python3"],
        vec!["python", "python3"],
        vec!["tool", "/a b/tool"],
        vec!["工具", "/工具/工具"],
        vec!["Tool", "/opt/Tool"],
        vec!["*", "/opt/*"],
        vec![r"c:\tool", r"/opt/c:\tool"],
    ] {
        let mut p = profile(&spellings);
        assert!(
            load_str(&policy(vec![p.clone()]).to_string()).is_ok(),
            "{spellings:?}"
        );
        p["executables"].as_array_mut().unwrap().reverse();
        assert!(
            load_str(&policy(vec![p]).to_string()).is_ok(),
            "{spellings:?}"
        );
    }
    for spellings in [
        vec![],
        vec![""],
        vec!["."],
        vec![".."],
        vec!["/"],
        vec!["./tool"],
        vec!["dir/tool"],
        vec!["//tool"],
        vec!["/opt//tools/tool"],
        vec!["/opt/tools/../tools/tool"],
        vec!["/opt/./tool"],
        vec!["/tool/"],
        vec!["tool", "tool"],
        vec!["tool", "/opt/other"],
        vec!["node", "python"],
        vec!["Tool", "/opt/tool"],
        vec!["node", "nodejs", "python", "python3"],
        vec!["to\0ol"],
        vec!["to\nol"],
        vec!["to\u{7f}ol"],
    ] {
        assert!(
            load_str(&policy(vec![profile(&spellings)]).to_string()).is_err(),
            "{spellings:?}"
        );
    }
    for byte in (0..=31).chain(std::iter::once(127)) {
        let spelling = format!("to{}ol", char::from(byte));
        assert!(load_str(&policy(vec![profile(&[&spelling])]).to_string()).is_err());
    }
    for (s, valid) in [
        ("a".repeat(4096), true),
        ("a".repeat(4097), false),
        ("é".repeat(2048), true),
        ("é".repeat(2049), false),
    ] {
        assert_eq!(
            load_str(&policy(vec![profile(&[&s])]).to_string()).is_ok(),
            valid
        );
    }
    for count in [8, 9] {
        let paths: Vec<_> = (0..count).map(|i| format!("/install{i}/tool")).collect();
        let names: Vec<_> = paths.iter().map(String::as_str).collect();
        assert_eq!(
            load_str(&policy(vec![profile(&names)]).to_string()).is_ok(),
            count == 8
        );
    }
}

#[test]
fn analyzer_compatibility_checks_every_spelling_and_export_is_bare_only() {
    for (analyzer, names, valid) in [
        ("sed-v1", vec!["sed", "/opt/sed"], true),
        ("sed-v1", vec!["/opt/sed"], true),
        ("xargs-v1", vec!["xargs", "/opt/xargs"], true),
        ("export-v1", vec!["export"], true),
        ("sed-v1", vec!["tool"], false),
        ("sed-v1", vec!["sed", "/opt/tool"], false),
        ("sed-v1", vec!["node", "nodejs"], false),
        ("xargs-v1", vec!["tool"], false),
        ("export-v1", vec!["tool"], false),
        ("export-v1", vec!["export", "/opt/export"], false),
        ("generic-v1", vec!["/opt/export"], false),
    ] {
        let mut p = profile(&names);
        p["analyzer"] = json!(analyzer);
        assert_eq!(
            load_str(&policy(vec![p]).to_string()).is_ok(),
            valid,
            "{analyzer} {names:?}"
        );
    }
    assert!(load_str(&policy(vec![profile(&["/opt/export"])]).to_string()).is_err());
}

#[test]
fn exact_decoded_selection_never_inherits_a_basename() {
    let config = policy(vec![profile(&["tool", "/opt/tool", "/a b/tool", "*"])]);
    // '*' is unrelated to tool, so keep literal-wildcard enrollment separate.
    assert!(load_str(&config.to_string()).is_err());
    let config = policy(vec![profile(&["tool", "/opt/tool", "/a b/tool"])]);
    for raw in [
        "tool ok",
        "'tool' ok",
        "/opt/tool ok",
        "'/opt/tool' ok",
        "'/a b/tool' ok",
    ] {
        outcome(&config, raw, "allow");
    }
    for raw in [
        "/tmp/tool ok",
        "./tool ok",
        "/opt/./tool ok",
        "/x/../opt/tool ok",
        "$TOOL ok",
    ] {
        outcome(&config, raw, "ask");
    }
    let paths_only = policy(vec![profile(&["/opt/tool", "/home/user/tool"])]);
    outcome(&paths_only, "/opt/tool ok", "allow");
    outcome(&paths_only, "tool ok", "ask");
    let wildcard = policy(vec![profile(&["*", "/opt/*"])]);
    outcome(&wildcard, "'/opt/*' ok", "allow");
    outcome(&wildcard, "/opt/* ok", "ask");
    outcome(&wildcard, "/opt/tool ok", "ask");
    let unicode = policy(vec![profile(&["工具", "/工具/工具"])]);
    outcome(&unicode, "/工具/工具 ok", "allow");
    outcome(&unicode, "'工具' ok", "allow");
}

#[test]
fn ownership_is_by_full_spelling_and_order_independent() {
    let a = profile(&["tool", "/opt/tool"]);
    let mut b = profile(&["/other/tool"]);
    b["id"] = json!("different");
    for profiles in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
        let config = policy(profiles);
        outcome(&config, "/other/tool ok", "allow");
        outcome(&config, "/opt/tool ok", "allow");
    }
    b["executables"] = json!(["/opt/tool"]);
    for profiles in [vec![a.clone(), b.clone()], vec![b, a]] {
        assert!(
            load_str(&policy(profiles).to_string())
                .unwrap_err()
                .contains("already owned")
        );
    }
}

#[test]
fn complete_alias_groups_share_typed_policy_across_enrolled_installations() {
    for names in [
        ["node", "nodejs", "/opt/node", "/usr/bin/nodejs"],
        ["python", "python3", "/opt/python", "/usr/bin/python3"],
    ] {
        let mut p = profile(&names);
        p["options"] = json!({"version": {"aliases": ["--version"], "arity": 0}});
        p["rules"][0]["match"]["arguments"] = json!({"exact": []});
        p["rules"][0]["match"]["options"] = json!({"allowed": [
            {"option": "version", "required": true, "repeatable": false}
        ]});
        p["rules"].as_array_mut().unwrap().push(json!({
            "id": "deny-danger", "action": "deny", "match": {"arguments": {"containsAny": ["danger"]}}
        }));
        for reverse in [false, true] {
            let mut configured = p.clone();
            if reverse {
                configured["executables"].as_array_mut().unwrap().reverse();
                configured["rules"].as_array_mut().unwrap().reverse();
            }
            let config = policy(vec![configured]);
            for name in names {
                outcome(&config, &format!("{name} --version"), "allow");
                outcome(&config, &format!("{name} danger"), "deny");
            }
            outcome(&config, &format!("/tmp/{} --version", names[0]), "ask");
        }
    }
}

#[test]
fn typed_coverage_and_denies_agree_but_raw_remains_source_sensitive() {
    let mut p = profile(&["tool", "/opt/tool"]);
    p["options"] = json!({"mode": {"aliases": ["--mode"], "arity": 1}});
    p["rules"][0]["match"]["arguments"] = json!({"exact": ["ok"]});
    p["rules"][0]["match"]["options"] = json!({"allowed": [
        {"option": "mode", "required": true, "repeatable": false, "values": {"each": {"oneOf": ["safe"]}}}
    ]});
    p["rules"][0]["match"]["environment"] = json!({"all": [
        {"name": "X", "value": {"oneOf": ["1"]}, "prefix": true, "occurrence": "all"}
    ]});
    p["rules"].as_array_mut().unwrap().push(json!({
        "id": "typed-deny", "action": "deny", "match": {"arguments": {"containsAny": ["danger"]}}
    }));
    p["rules"].as_array_mut().unwrap().push(json!({
        "id": "raw-deny", "action": "deny", "match": {"raw": "tool raw *"}
    }));
    let config = policy(vec![p]);
    for head in ["tool", "/opt/tool"] {
        for (tail, expected) in [
            ("ok --mode safe", "allow"),
            ("ok --mode unsafe", "ask"),
            ("ok --mode safe --mode safe", "ask"),
            ("ok --unknown", "ask"),
            ("danger --mode safe", "deny"),
            ("ok --mode safe > /tmp/out", "ask"),
        ] {
            outcome(&config, &format!("X=1 {head} {tail}"), expected);
        }
        outcome(&config, &format!("X=2 {head} ok --mode safe"), "ask");
    }
    outcome(&config, "tool raw arg", "deny");
    outcome(&config, "/opt/tool raw arg", "ask");
    outcome(&config, "'tool' raw arg", "ask");
    let mut redirect_config = config;
    redirect_config["redirectPolicies"]["no-redirects"] = json!({
        "redirects": {"all": [{
            "sourceFd": "default", "operator": ">", "occurrence": "all",
            "target": {"kind": "literalPath"}
        }]},
        "paths": {"all": [{
            "coordinate": {"redirect": {"operator": ">", "sourceFd": "default", "occurrence": "all"}},
            "within": "/tmp/approved"
        }]}
    });
    for head in ["tool", "/opt/tool"] {
        outcome(
            &redirect_config,
            &format!("X=1 {head} ok --mode safe > /tmp/approved/out"),
            "allow",
        );
        outcome(
            &redirect_config,
            &format!("X=1 {head} ok --mode safe > /tmp/other"),
            "ask",
        );
    }
}

fn wrapper_profile(name: &str, absolute: bool) -> Value {
    let path = format!("/opt/{name}");
    let mut p = profile(&[if absolute { &path } else { name }]);
    p["id"] = json!("parent");
    p["rules"][0]["id"] = json!("parent-allow");
    p["rules"][0]["match"]["nestedParts"] = json!({"all": [
        {"relation": "wrapper", "occurrence": "all", "profile": "child", "classification": "complete", "verdict": "allow"}
    ]});
    if matches!(name, "bash" | "sh" | "nice") {
        let (id, alias, value) = if name == "nice" {
            ("priority", "-n", "1")
        } else {
            ("command", "-c", "tool ok")
        };
        p["options"] = json!({id: {"aliases": [alias], "arity": 1}});
        p["rules"][0]["match"]["options"] = json!({"allowed": [
            {"option": id, "required": true, "repeatable": false, "values": {"each": {"oneOf": [value]}}}
        ]});
    }
    p
}

fn child_profile() -> Value {
    let mut p = profile(&["tool"]);
    p["id"] = json!("child");
    p["rules"][0]["id"] = json!("child-allow");
    p
}

const WRAPPERS: &[(&str, &str)] = &[
    ("bash", "-c 'tool ok'"),
    ("sh", "-c 'tool ok'"),
    ("sudo", "tool ok"),
    ("nohup", "tool ok"),
    ("nice", "-n 1 tool ok"),
    ("timeout", "1s tool ok"),
    ("env", "X=1 tool ok"),
    ("xargs", "tool ok"),
];

#[test]
fn every_wrapper_parent_participates_and_requires_independent_full_coverage() {
    for &(name, operand) in WRAPPERS {
        for absolute in [false, true] {
            let head = if absolute {
                format!("/opt/{name}")
            } else {
                name.into()
            };
            let raw = format!("{head} {operand}");
            let p = wrapper_profile(name, absolute);
            let child = child_profile();
            let expected = if matches!(name, "xargs" | "env") {
                "ask"
            } else {
                "allow"
            };
            outcome(&policy(vec![p.clone(), child.clone()]), &raw, expected);
            outcome(&policy(vec![child.clone()]), &raw, "ask");
            let mut missing_child = p.clone();
            missing_child["rules"][0]["match"]["nestedParts"] = json!({"all": [
                {"relation": "wrapper", "occurrence": "all", "profile": "none", "classification": "complete", "verdict": "allow"}
            ]});
            outcome(&policy(vec![missing_child]), &raw, "ask");
            let mut no_allow = p.clone();
            no_allow["rules"] = json!([]);
            outcome(&policy(vec![no_allow, child.clone()]), &raw, "ask");
            let mut no_nested = p.clone();
            no_nested["rules"][0]["match"]["nestedParts"] = json!({"none": true});
            outcome(&policy(vec![no_nested, child.clone()]), &raw, "ask");
            let mut no_arguments = p.clone();
            no_arguments["rules"][0]["match"]["arguments"] = json!({"exact": []});
            if !matches!(name, "bash" | "sh") {
                outcome(&policy(vec![no_arguments, child.clone()]), &raw, "ask");
            }
            if matches!(name, "bash" | "sh" | "nice") {
                let mut no_options = p.clone();
                no_options["rules"][0]["match"]["options"] = json!({"none": true});
                outcome(&policy(vec![no_options, child.clone()]), &raw, "ask");
            }
            let mut deny_parent = p.clone();
            deny_parent["rules"].as_array_mut().unwrap().push(json!({
                "id": "parent-deny", "action": "deny", "match": {"raw": "*"}
            }));
            outcome(&policy(vec![deny_parent, child.clone()]), &raw, "deny");
            let mut deny_child = child.clone();
            deny_child["rules"] = json!([{
                "id": "child-deny", "action": "deny", "match": {"arguments": {"containsAny": ["ok"]}}
            }]);
            // An unenrolled parent cannot hide a recognized child's deny.
            outcome(&policy(vec![deny_child.clone()]), &raw, "deny");
            outcome(&policy(vec![p.clone(), deny_child.clone()]), &raw, "deny");
            outcome(
                &policy(vec![deny_child.clone()]),
                &format!("{raw} $(tool ok)"),
                "deny",
            );
            if name != "xargs" {
                let nested = format!("{head} {}", operand.replace("tool ok", "sudo tool ok"));
                outcome(&policy(vec![deny_child]), &nested, "deny");
            }
            let config = policy(vec![p.clone(), child.clone()]);
            outcome(&config, &format!("{raw} > /tmp/out"), "ask");
            outcome(&config, &format!("Y=2 {raw}"), "ask");
            outcome(&config, &format!("{head} --unknown {operand}"), "ask");
            outcome(&config, &head, "ask");
            outcome(&config, &format!("{raw} $(tool ok)"), "ask");
            let mut limited = config.clone();
            limited["limits"] = json!({"evidenceItems": 1});
            let v = outcome(&limited, &raw, "ask");
            assert_eq!(v["commands"][0]["facts"]["evidence"], "invalid");
            let graph = extract(&format!("Y=2 {raw} > /tmp/out"));
            let parent = &graph.parts[0];
            assert_eq!(parent.argv[0].text, head);
            assert_eq!(parent.assigns.len(), 1);
            assert_eq!(parent.redirects.len(), 1);
            assert!(parent.argv.len() > 1);
            assert!(graph.parts.iter().any(|c| c.parent == Some(0)));
        }
    }
}

#[test]
fn all_wrapper_spellings_respect_the_same_depth_boundary() {
    for &(name, operand) in WRAPPERS {
        for head in [name.to_string(), format!("/opt/{name}")] {
            let raw = format!("{head} {operand}");
            let at_limit = extract(&format!("{}{raw}", "sudo ".repeat(31)));
            assert!(
                !at_limit
                    .parts
                    .iter()
                    .any(|p| matches!(p.state, EvidenceState::Invalid(_))),
                "{head}"
            );
            let overflow = format!("{}{raw}", "sudo ".repeat(32));
            let v = outcome(&policy(vec![child_profile()]), &overflow, "ask");
            assert_eq!(v["commands"][0]["facts"]["evidence"], "invalid", "{head}");
            assert!(
                v["commands"][0]["facts"]["reasons"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("evidence-limit"))
            );
        }
    }
}

#[test]
fn absolute_sed_facts_and_xargs_relations_are_preserved() {
    let mut sed = profile(&["sed", "/opt/sed"]);
    sed["analyzer"] = json!("sed-v1");
    sed["options"] = json!({"inPlace": {"aliases": ["-i"], "arity": 0}});
    sed["rules"][0]["match"]["facts"] = json!({"all": [
        {"analyzer": "sed-v1", "version": "1", "name": "executionPrimitive", "occurrence": "all", "value": {"exact": "readOnly"}},
        {"analyzer": "sed-v1", "version": "1", "name": "programForm", "occurrence": "all", "value": {"exact": "positional"}}
    ]});
    sed["rules"].as_array_mut().unwrap().push(json!({
        "id": "sed-deny", "action": "deny",
        "match": {"facts": {"any": [{"name": "executionPrimitive", "value": {"exact": "inPlace"}}]}}
    }));
    for head in ["sed", "/opt/sed"] {
        outcome(
            &policy(vec![sed.clone()]),
            &format!("{head} 's/a/b/' file"),
            "allow",
        );
        outcome(
            &policy(vec![sed.clone()]),
            &format!("{head} -i 's/a/b/' file"),
            "deny",
        );
        let mut uncovered = sed.clone();
        uncovered["rules"][0]["match"]["facts"] = json!({"none": true});
        outcome(
            &policy(vec![uncovered]),
            &format!("{head} 's/a/b/' file"),
            "ask",
        );
    }
    for head in ["xargs", "/opt/xargs"] {
        let mut p = profile(&[head]);
        p["analyzer"] = json!("xargs-v1");
        p["rules"] = json!([{
            "id": "xargs-deny", "action": "deny",
            "match": {"nestedParts": {"any": [
                {"relation": "analyzer-command", "profile": "child", "classification": "opaque"}
            ]}}
        }]);
        let v = outcome(
            &policy(vec![p, child_profile()]),
            &format!("{head} tool ok"),
            "deny",
        );
        assert_eq!(v["commands"][0]["facts"]["evidence"], "opaque");
        let graph = extract(&format!("{head} tool ok"));
        assert_eq!(graph.parts[1].relation, Relation::Wrapper);
        assert!(matches!(graph.parts[1].state, EvidenceState::Opaque(_)));
    }
}

#[test]
fn nested_wrapper_depth_and_diagnostic_budgets_include_parents() {
    let mut parent = profile(&["sudo", "/opt/sudo"]);
    parent["id"] = json!("parent");
    parent["rules"][0]["id"] = json!("parent-allow");
    parent["rules"][0]["match"]["nestedParts"] = json!({"all": [
        {"relation": "wrapper", "occurrence": "all", "profile": "parent", "classification": "complete", "verdict": "allow"},
        {"relation": "wrapper", "occurrence": "all", "profile": "child", "classification": "complete", "verdict": "allow"}
    ]});
    for head in ["sudo", "/opt/sudo"] {
        let config = policy(vec![parent.clone(), child_profile()]);
        let raw = format!("{}tool ok", format!("{head} ").repeat(32));
        let v = outcome(&config, &raw, "allow");
        assert_eq!(
            v["commands"][0]["facts"]["selectedProfiles"]
                .as_array()
                .unwrap()
                .len(),
            33
        );
        let raw = format!("{head} {raw}");
        let v = outcome(&config, &raw, "ask");
        assert_eq!(v["commands"][0]["facts"]["evidence"], "invalid");
        let mut bounded = config;
        bounded["limits"] = json!({"diagnosticsBytes": 256});
        let raw = format!("{}tool ok", format!("{head} ").repeat(10));
        let v = outcome(&bounded, &raw, "allow");
        assert!(v["commands"][0]["facts"].to_string().len() <= 256);
        assert_eq!(
            v["commands"][0]["facts"]["diagnostics"],
            "truncated-after-decision"
        );
    }
}
