// Golden-level pipeline tests against the worked config sketch (06 §6.7 /
// ADR-0016) and refinement cases. Letter fixtures per 02 §2.2.

use shell_warden::checker::config::load_str;
use shell_warden::checker::letter::Letter;
use shell_warden::checker::pipeline::evaluate;
use shell_warden::checker::verdict::VerdictKind;

const SKETCH: &str = include_str!("fixtures/sketch.jsonc");
const REFINEMENT: &str = r#"{
  "version": 1,
  "defaults": { "action": "ask", "message": "no rule matched — ask the human" },
  "stages": [
    { "id": "vcs",
      "scope":  { "anyOf": [ { "argv": ["git"] } ] },
      "flags":  { "--all": 0 },
      "rules": [
        { "id": "vcs/push-allow", "argv": ["push"], "action": "allow" },
        { "id": "vcs/push-all-ask",
          "argv": ["push"], "flag": { "--all": "present" },
          "action": "ask", "message": "push --all asks the human" }
      ] }
  ]
}"#;

fn letter(raw: &str) -> Letter {
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    let src = format!(
        r#"{{"version":1,"invocation":{{"id":"m:c","sessionID":"s1","projectDir":"/repo"}},
            "action":"shell","commands":[{{"index":0,"raw":"{escaped}","cwd":"/repo"}}]}}"#
    );
    Letter::from_bytes(src.as_bytes()).expect("letter fixture should parse")
}

#[track_caller]
fn command(v: &serde_json::Value) -> serde_json::Value {
    v["commands"][0].clone()
}

#[test]
fn force_push_denied() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("git push --force origin main"));
    assert_eq!(v.verdict, VerdictKind::Deny);
    assert!(v
        .message
        .as_deref()
        .is_some_and(|m| m.contains("forbidden")));
    let c = serde_json::to_value(&v).unwrap();
    assert_eq!(command(&c)["ruleId"], "vcs/no-force-push");
    assert_eq!(command(&c)["classification"], "static");
    assert_eq!(command(&c)["match"], "argv");
}

#[test]
fn plain_push_asks_by_default() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("git push origin main"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    assert!(v
        .message
        .as_deref()
        .is_some_and(|m| m.contains("ask the human")));
}

#[test]
fn inspection_is_allowed() {
    let cfg = load_str(SKETCH).unwrap();
    for raw in ["git status", "git log origin main", "git diff -C /repo"] {
        let v = evaluate(&cfg, &letter(raw));
        assert_eq!(v.verdict, VerdictKind::Allow, "{raw}");
        assert!(v.message.is_none());
    }
}

#[test]
fn opaque_degrades_to_ask_case() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("echo $(whoami)"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let c = serde_json::to_value(&v).unwrap();
    assert_eq!(command(&c)["classification"], "opaque");
    assert_eq!(command(&c)["match"], "raw");
}

#[test]
fn wrapper_unwraps_and_denies() {
    let cfg = load_str(SKETCH).unwrap();
    for raw in ["bash -c 'git push --force'", "sh -c \"git push --force\""] {
        let v = evaluate(&cfg, &letter(raw));
        assert_eq!(v.verdict, VerdictKind::Deny, "{raw}");
        let c = serde_json::to_value(&v).unwrap();
        assert_eq!(command(&c)["ruleId"], "vcs/no-force-push", "{raw}");
    }
}

#[test]
fn docker_root_mount_denied_by_flag_value() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("docker run -v /:/mnt alpine"));
    assert_eq!(v.verdict, VerdictKind::Deny);
    let c = serde_json::to_value(&v).unwrap();
    assert_eq!(command(&c)["ruleId"], "docker/no-root-mount");
}

#[test]
fn docker_root_mount_inline_form_denied() {
    let cfg = load_str(SKETCH).unwrap();
    // `--long=value` inline: base flag `--volume` + inline value consumed
    let v = evaluate(&cfg, &letter("docker run --volume=/:/mnt alpine"));
    assert_eq!(
        v.verdict,
        VerdictKind::Deny,
        "inline form must reach the same rule"
    );
}

#[test]
fn docker_other_mount_asks() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("docker run -v /home:/work alpine"));
    assert_eq!(v.verdict, VerdictKind::Ask);
}

#[test]
fn chain_splits_resolved_and_restricted() {
    let cfg = load_str(SKETCH).unwrap();
    // part 1 = allow, part 2 = ask via catch-all ⇒ aggregate ask
    let v = evaluate(&cfg, &letter("git status; rm -rf /"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let c = serde_json::to_value(&v).unwrap();
    // both parts static at the parse level, but the ask part decides
    assert_eq!(command(&c)["classification"], "static");
}

#[test]
fn deny_in_any_chain_part_wins() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("git status && bash -c 'git push --force'"));
    assert_eq!(v.verdict, VerdictKind::Deny);
}

#[test]
fn refined_ask_wins_over_broad_allow() {
    let cfg = load_str(REFINEMENT).unwrap();
    let v = evaluate(&cfg, &letter("git push --all"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let c = serde_json::to_value(&v).unwrap();
    assert_eq!(command(&c)["ruleId"], "vcs/push-all-ask");

    let v = evaluate(&cfg, &letter("git push"));
    assert_eq!(v.verdict, VerdictKind::Allow);
}

#[test]
fn env_prefix_assignment_stripped() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("GIT_TERMINAL_PROMPT=0 git status"));
    assert_eq!(v.verdict, VerdictKind::Allow);
}

#[test]
fn unknown_flag_blocks_allow() {
    let cfg = load_str(SKETCH).unwrap();
    let v = evaluate(&cfg, &letter("git status --stealth-x"));
    assert_eq!(v.verdict, VerdictKind::Ask);
    let c = serde_json::to_value(&v).unwrap();
    assert_eq!(command(&c)["classification"], "static");
    assert_eq!(command(&c)["match"], "argv");
}
