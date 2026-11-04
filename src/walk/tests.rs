// Stage-walk tests over a scripted invoker — 08 §8.1–§8.5 semantics:
// most-restrictive, first-deny-stops, exclusive claim, messageMode, onError
// policies and the rejection budget (ADR-0010).

use super::*;
use crate::config::{Budget, Stage, ToolSpec};
use crate::wire::{CheckCommand, Invocation};

use crate::config::Lifecycle;
use crate::config::MessageMode;
use crate::config::OnError;

/// Scripted invoker: pops one outcome per call; records the stage order.
struct Mock {
    script: Vec<(String, InvokeResult)>,
    calls: Vec<String>,
}

impl StageInvoker for Mock {
    fn invoke(
        &mut self,
        stage: &Stage,
        _cmd: &CheckCommand,
        _invocation: &Invocation,
        _now: Instant,
    ) -> InvokeResult {
        self.calls.push(stage.id.clone());
        let item = self
            .script
            .first()
            .unwrap_or_else(|| panic!("script exhausted at call to {}", stage.id))
            .clone();
        assert_eq!(&item.0, &stage.id, "script out of order");
        self.script.remove(0).1
    }
}

fn tool() -> ToolSpec {
    ToolSpec {
        argv: vec!["/bin/tool".into()],
        cwd: None,
        env_set: vec![],
        env_unset: vec![],
        lifecycle: Lifecycle::Spawn,
        idle_timeout_ms: None,
        timeout_ms: 1_000,
        kill_grace_ms: 50,
        max_output_bytes: 65_536,
        on_error: OnError::Ask,
        sha256: None,
        input_session_id: false,
        input_session_agent: false,
        input_mcp: false,
    }
}

fn stage(id: &str) -> Stage {
    Stage {
        id: id.into(),
        tool: tool(),
        message_mode: MessageMode::Append,
        exclusive: false,
        budget: None,
        enabled: true,
    }
}

fn enabled(mut s: Stage, enabled: bool) -> Stage {
    s.enabled = enabled;
    s
}

fn decided(verdict: Verdict) -> StageOutcome {
    StageOutcome::Decided(ToolVerdict {
        verdict,
        message: None,
        rule_id: None,
        reason: None,
        classification: None,
        cache_ttl_ms: None,
    })
}

fn decided_with(
    verdict: Verdict,
    message: Option<&str>,
    rule_id: Option<&str>,
    ttl: Option<u64>,
) -> StageOutcome {
    StageOutcome::Decided(ToolVerdict {
        verdict,
        message: message.map(str::to_string),
        rule_id: rule_id.map(str::to_string),
        reason: None,
        classification: Some(Classification::Static),
        cache_ttl_ms: ttl,
    })
}

fn on_error(reason: &str) -> StageOutcome {
    StageOutcome::OnError {
        reason: reason.into(),
        violation: false,
    }
}

fn error_result(reason: &str, violation: bool) -> StageOutcome {
    StageOutcome::OnError {
        reason: reason.into(),
        violation,
    }
}

fn invocation(session: &str) -> Invocation {
    Invocation {
        id: "m:c".into(),
        session_id: session.into(),
        agent: None,
        hook: crate::wire::HookKind::PermissionEvaluate,
        project_dir: None,
        started_at: None,
    }
}

fn one_command() -> CheckCommand {
    CheckCommand {
        index: 0,
        raw: "ls".into(),
        argv: None,
        cwd: "/w".into(),
    }
}

fn params(session: &str, commands: Vec<CheckCommand>) -> CheckParams {
    CheckParams {
        invocation: invocation(session),
        action: "shell".into(),
        commands,
        context: None,
    }
}

fn run(mock: &mut Mock, stages: &[Stage], session: &str, budgets: &mut BudgetTable) -> WalkOutcome {
    run_with(mock, stages, session, budgets, vec![one_command()])
}

fn run_all(
    mock: &mut Mock,
    stages: &[Stage],
    session: &str,
    budgets: &mut BudgetTable,
) -> WalkOutcome {
    run_with(mock, stages, session, budgets, vec![one_command()])
}

fn run_with(
    mock: &mut Mock,
    stages: &[Stage],
    session: &str,
    budgets: &mut BudgetTable,
    commands: Vec<CheckCommand>,
) -> WalkOutcome {
    let p = params(session, commands);
    walk(stages, &p, mock, budgets, Instant::now()).expect("no pin")
}

// ── Aggregation (08 §8.3) ──

#[test]
fn no_stage_contributed_falls_to_defaults_ask() {
    let mut mock = Mock {
        script: vec![],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &[], "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Ask, "defaults.action");
    assert!(!out.contributed);
    assert_eq!(out.decisive_stage, None);
    assert!(!out.commands.is_empty());
    assert_eq!(out.commands[0].verdict, Verdict::Ask);
    assert_eq!(out.commands[0].stage, None);
}

#[test]
fn aggregate_is_most_restrictive_across_stages() {
    let stages = [stage("s1"), stage("s2")];
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(decided(Verdict::Allow))),
            ("s2".into(), Ok(decided(Verdict::Ask))),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Ask);
    assert!(out.contributed);
    assert_eq!(out.decisive_stage.as_deref(), Some("s2"));
    assert_eq!(out.commands[0].verdict, Verdict::Ask);
}

#[test]
fn allow_verdicts_aggregate_to_allow() {
    let stages = [stage("s1"), stage("s2")];
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(decided(Verdict::Allow))),
            ("s2".into(), Ok(decided(Verdict::Allow))),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Allow);
    assert_eq!(out.commands[0].cacheTtlMs, None);
}

#[test]
fn the_first_deny_stops_the_walk() {
    let stages = [stage("s1"), stage("s2"), stage("s3")];
    let mut mock = Mock {
        script: vec![
            (
                "s1".into(),
                Ok(decided_with(Verdict::Deny, Some("no"), Some("s1/r"), None)),
            ),
            ("s2".into(), panic_marker()),
            ("s3".into(), panic_marker()),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Deny);
    assert_eq!(out.message.as_deref(), Some("no"));
    assert_eq!(out.commands[0].stage.as_deref(), Some("s1"));
    assert_eq!(out.commands[0].ruleId.as_deref(), Some("s1/r"));
    assert_eq!(
        mock.calls,
        vec!["s1".to_string()],
        "later stages must not be invoked (ADR-0012)"
    );
}

fn panic_marker() -> InvokeResult {
    Ok(decided(Verdict::Allow))
}

#[test]
fn enabled_filter_skips_disabled_stages() {
    let stages = [stage("s1"), enabled(stage("s2"), false), stage("s3")];
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(decided(Verdict::Allow))),
            ("s3".into(), Ok(decided(Verdict::Allow))),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(mock.calls, vec!["s1".to_string(), "s3".to_string()]);
}

// ── Message composition (08 §8.3) ──

#[test]
fn append_composes_in_stage_order() {
    let mut s1 = stage("s1");
    let mut s2 = stage("s2");
    s1.message_mode = MessageMode::Append;
    s2.message_mode = MessageMode::Append;
    let mut mock = Mock {
        script: vec![
            (
                "s1".into(),
                Ok(decided_with(Verdict::Ask, Some("first reason"), None, None)),
            ),
            (
                "s2".into(),
                Ok(decided_with(
                    Verdict::Allow,
                    Some("extra context"),
                    None,
                    None,
                )),
            ),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &[s1, s2], "s1", &mut budgets);
    assert_eq!(out.message.as_deref(), Some("first reason — extra context"));
}

#[test]
fn replace_replaces_the_accumulated_message() {
    let mut s1 = stage("s1");
    let mut s2 = stage("s2");
    s1.message_mode = MessageMode::Append;
    s2.message_mode = MessageMode::Replace; // redirect family (06 §6.3)
    let mut mock = Mock {
        script: vec![
            (
                "s1".into(),
                Ok(decided_with(Verdict::Allow, Some("old text"), None, None)),
            ),
            (
                "s2".into(),
                Ok(decided_with(
                    Verdict::Ask,
                    Some("use the API instead"),
                    None,
                    None,
                )),
            ),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &[s1, s2], "s1", &mut budgets);
    assert_eq!(out.message.as_deref(), Some("use the API instead"));
}

// ── OnError policies (08 §8.2, never allow — I3) ──

#[test]
fn on_error_skip_is_silent_and_falls_to_defaults() {
    let mut s1 = stage("s1");
    s1.tool.on_error = OnError::Skip;
    let stages = [s1];
    let mut mock = Mock {
        script: vec![("s1".into(), Ok(error_result("hook crashed", true)))],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    // A skipped stage contributes nothing → defaults.action (ask).
    assert_eq!(out.verdict, Verdict::Ask);
    assert!(!out.contributed, "skip does not count as a contribution");
    assert_eq!(out.message, None, "onError contributes no message");
    // A noop carries no per-command diagnostics (§8.2: silent on a foreign deny).
    assert_eq!(out.commands[0].verdict, Verdict::Ask);
    assert_eq!(out.commands[0].stage, None);
    assert_eq!(out.commands[0].reason, None);
}

#[test]
fn on_error_ask_contributes_ask_with_stage_diagnostics() {
    let mut s1 = stage("s1");
    s1.tool.on_error = OnError::Ask;
    let mut mock = Mock {
        script: vec![("s1".into(), Ok(error_result("tool stall", true)))],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &[s1], "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Ask);
    assert!(out.contributed);
    assert_eq!(out.decisive_stage.as_deref(), Some("s1"));
    assert_eq!(out.commands[0].verdict, Verdict::Ask);
}

#[test]
fn on_error_deny_stops_the_walk() {
    let mut s1 = stage("s1");
    s1.tool.on_error = OnError::Deny;
    let stages = [s1, stage("s2")];
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(on_error("unreadable"))),
            ("s2".into(), panic_marker()),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Deny, "fail-closed onError deny");
    assert_eq!(mock.calls, vec!["s1".to_string()]);
    assert_eq!(out.message, None);
}

// ── Exclusive claim (06 §6.5) ──

#[test]
fn exclusive_claim_absorbs_the_command() {
    let mut s1 = stage("s1");
    s1.exclusive = true;
    let stages = [s1, stage("s2")];
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(decided(Verdict::Allow))),
            ("s2".into(), panic_marker()),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(
        mock.calls,
        vec!["s1".to_string()],
        "a definite response claims the command"
    );
    assert_eq!(out.verdict, Verdict::Allow);
}

#[test]
fn exclusive_skip_does_not_claim() {
    let mut s1 = stage("s1");
    s1.exclusive = true;
    s1.tool.on_error = OnError::Skip;
    let stages = [s1, stage("s2")];
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(on_error("broken"))),
            ("s2".into(), Ok(decided(Verdict::Ask))),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(mock.calls, vec!["s1".to_string(), "s2".to_string()]);
}

// ── Per-command isolation (ADR-0014) ──

#[test]
fn commands_are_judged_independently() {
    let stages = [stage("s1")];
    let c0 = CheckCommand {
        index: 0,
        raw: "a".into(),
        argv: None,
        cwd: "/w".into(),
    };
    let c1 = CheckCommand {
        index: 1,
        raw: "b".into(),
        argv: None,
        cwd: "/w".into(),
    };
    // First call → allow, second call → deny (same stage, later statement).
    let mut mock = Mock {
        script: vec![
            ("s1".into(), Ok(decided(Verdict::Allow))),
            ("s1".into(), Ok(decided(Verdict::Deny))),
        ],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run_with(&mut mock, &stages, "s1", &mut budgets, vec![c0, c1]);
    assert_eq!(out.verdict, Verdict::Deny, "aggregate over both commands");
    assert_eq!(out.commands[0].verdict, Verdict::Allow);
    assert_eq!(out.commands[1].verdict, Verdict::Deny);
    assert!(out.commands.iter().all(|c| c.stage == Some("s1".into())));
}

// ── Rejection budget (ADR-0010) ──

fn budgeted_stage(id: &str, max_rejections: u32) -> Stage {
    let mut s = stage(id);
    s.budget = Some(Budget {
        max_rejections,
        window_ms: 1_800_000,
    });
    s
}

#[test]
fn budget_exhaustion_bypasses_the_stage_with_a_notice() {
    let s1 = budgeted_stage("s1", 2);
    let stages = [s1.clone()];
    let mut budgets = BudgetTable::default();

    // Check 1: deny #1.
    let mut mock = Mock {
        script: vec![(
            "s1".into(),
            Ok(decided_with(Verdict::Deny, Some("deny you"), None, None)),
        )],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Deny);

    // Check 2: deny #2 → budget exhausted.
    let mut mock = Mock {
        script: vec![(
            "s1".into(),
            Ok(decided_with(Verdict::Deny, Some("deny you"), None, None)),
        )],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Deny);

    // Check 3: bypassed — no tool call; the notice composes once; the walk
    // contributes nothing → commands fall to defaults (ask), never auto-allow.
    let mut mock = Mock {
        script: vec![("s1".into(), panic_marker())],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert!(
        out.message
            .unwrap_or_default()
            .contains("suspended for this session after 2 rejections"),
    );
    assert!(!out.contributed);
    assert_eq!(out.verdict, Verdict::Ask);

    // Check 4: still bypassed, and the notice does not repeat.
    let mut mock = Mock {
        script: vec![("s1".into(), panic_marker())],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.message, None, "suspension notice is composed once");
    assert_eq!(out.verdict, Verdict::Ask);
}

#[test]
fn non_deny_verdict_resets_the_budget() {
    let s1 = budgeted_stage("s1", 2);
    let stages = [s1.clone()];
    let mut budgets = BudgetTable::default();
    // deny (count 1) → allow resets → deny (count 1) → deny (count 2 = max,
    // suspended) → next check is bypassed.
    let mut mock = Mock {
        script: vec![("s1".into(), Ok(decided(Verdict::Deny)))],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert_eq!(out.verdict, Verdict::Deny);
    let mut mock = Mock {
        script: vec![("s1".into(), Ok(decided(Verdict::Ask)))],
        calls: vec![],
    };
    run(&mut mock, &stages, "s1", &mut budgets);
    for _ in 0..2 {
        let mut mock = Mock {
            script: vec![("s1".into(), Ok(decided(Verdict::Deny)))],
            calls: vec![],
        };
        let out = run(&mut mock, &stages, "s1", &mut budgets);
        assert_eq!(out.verdict, Verdict::Deny);
    }
    let mut mock = Mock {
        script: vec![("s1".into(), panic_marker())],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "s1", &mut budgets);
    assert!(out.message.as_deref().unwrap().contains("suspended"));
}

#[test]
fn budget_is_per_session() {
    let s1 = budgeted_stage("s1", 2);
    let stages = [s1.clone()];
    let mut budgets = BudgetTable::default();
    for _ in 0..2 {
        let mut mock = Mock {
            script: vec![("s1".into(), Ok(decided(Verdict::Deny)))],
            calls: vec![],
        };
        run(&mut mock, &stages, "sesA", &mut budgets);
    }
    // sesA exhausted; sesB still served normally.
    let mut mock = Mock {
        script: vec![(
            "s1".into(),
            Ok(decided_with(Verdict::Ask, Some("normal"), None, None)),
        )],
        calls: vec![],
    };
    let out = run(&mut mock, &stages, "sesB", &mut budgets);
    assert!(mock.calls.contains(&"s1".to_string()));
    assert_eq!(out.message.as_deref(), Some("normal"));
}

// ── Fatal pin propagation (I8) ──

#[test]
fn sha_pin_failure_propagates_from_the_walk() {
    let stages = [stage("s1")];
    let mut mock = Mock {
        script: vec![(
            "s1".into(),
            Err(crate::stagetools::FatalPin {
                reason: "pin mismatch".into(),
            }),
        )],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let p = params("s1", vec![one_command()]);
    let err = walk(&stages, &p, &mut mock, &mut budgets, Instant::now()).unwrap_err();
    assert!(err.reason.contains("pin"));
}

#[test]
fn audit_decision_reports_type_and_verdict() {
    let stages = [stage("s1")];
    let mut mock = Mock {
        script: vec![("s1".into(), Ok(decided(Verdict::Deny)))],
        calls: vec![],
    };
    let mut budgets = BudgetTable::default();
    let out = run(&mut mock, &stages, "ses1", &mut budgets);
    let p = params("ses1", vec![one_command()]);
    let event = audit_decision(&p, &out, "2026-11-01T00:00:00Z".into());
    assert_eq!(event.kind, "decision");
    assert_eq!(event.verdict, Verdict::Deny);
    assert_eq!(event.stage.as_deref(), Some("s1"));
    assert_eq!(event.sessionID.as_deref(), Some("ses1"));
}
