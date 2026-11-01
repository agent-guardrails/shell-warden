// Stage walk — docs/spec/shell-warden/08-request-processing.md (§8.1–8.5).
//
// The core is a pure orchestrator (ADR-0008): no parsing, no matching — it
// invokes stage tools in config array order and composes their verdicts.
// Per-command letters (ADR-0014): each of commands[] is judged independently,
// the tool receives `command: {raw, cwd}` verbatim. Aggregation is
// most-restrictive-wins; the first deny stops the walk (ADR-0012); message
// composition follows stage array order (§8.3); budgeted stages are bypassed
// for a session after maxRejections denies (ADR-0010).

use crate::config::{MessageMode, Stage};
use crate::stagetools::{FatalPin, InvokeResult, StageOutcome, ToolVerdict};
use crate::wire::{AuditEvent, CheckCommand, CheckCommandResult, CheckParams, Classification, Invocation, Verdict};
use std::collections::HashMap;
use std::time::Instant;

/// Who executes a stage: the real pools in production, a script in tests.
pub trait StageInvoker {
    fn invoke(&mut self, stage: &Stage, cmd: &CheckCommand, invocation: &Invocation, now: Instant) -> InvokeResult;
}

/// `existing — reason` (08 §8.3 / 06 §6.5).
pub fn compose(existing: Option<String>, reason: &str) -> String {
    match existing {
        Some(existing) => format!("{existing} — {reason}"),
        None => reason.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct WalkOutcome {
    pub verdict: Verdict,
    pub message: Option<String>,
    pub commands: Vec<CheckCommandResult>,
    /// The stage that produced the final aggregate verdict (for audit).
    pub decisive_stage: Option<String>,
    /// Whether any stage contributed a verdict (else defaults apply).
    pub contributed: bool,
}

/// Rejection budget state per (stage, sessionID) — 06 §6.6, ADR-0010.
#[derive(Default)]
pub struct BudgetTable {
    entries: HashMap<(String, String), BudgetEntry>,
    /// Stages whose suspension notice has been composed for a session.
    notices: HashMap<(String, String), ()>,
}

#[derive(Clone, Copy)]
struct BudgetEntry {
    rejections: u32,
    window_start: Instant,
}

const BUDGET_TABLE_CAP: usize = 1024;

impl BudgetTable {
    fn entry(&self, stage: &Stage, session: &str, now: Instant) -> Option<BudgetEntry> {
        let budget = stage.budget.as_ref()?;
        let e = self.entries.get(&(stage.id.clone(), session.to_string()))?;
        (now.duration_since(e.window_start).as_millis() as u64 <= budget.window_ms).then_some(*e)
    }

    /// True when the budget is exhausted for this session; `mark_notice`
    /// returns true exactly once per suspension so the walk composes the
    /// suspension notice into the message only on the first bypass (§8.4).
    fn is_suspended(&self, stage: &Stage, session: &str, now: Instant) -> bool {
        let Some(budget) = &stage.budget else { return false };
        self.entry(stage, session, now)
            .map(|e| e.rejections >= budget.max_rejections)
            .unwrap_or(false)
    }

    fn mark_notice(&mut self, stage: &Stage, session: &str) -> bool {
        let key = (stage.id.clone(), session.to_string());
        self.notices.insert(key, ()).is_none()
    }

    /// Charge one deny; no-op for stages without a budget. Returns the fresh
    /// denial count when the stage is budgeted.
    fn charge_deny(&mut self, stage: &Stage, session: &str, now: Instant) -> u32 {
        let Some(budget) = stage.budget.as_ref() else { return 0 };
        let key = (stage.id.clone(), session.to_string());
        let e = match self.entries.get(&key) {
            Some(e) if now.duration_since(e.window_start).as_millis() as u64 <= budget.window_ms => {
                BudgetEntry { rejections: e.rejections + 1, window_start: e.window_start }
            }
            _ => BudgetEntry { rejections: 1, window_start: now },
        };
        self.entries.insert(key.clone(), e);
        e.rejections
    }

    /// Reset on a non-deny verdict from the stage for that session (06 §6.6);
    /// also clears the notice state — a new cycle may notify again.
    fn reset(&mut self, stage_id: &str, session: &str) {
        let key = (stage_id.to_string(), session.to_string());
        self.entries.remove(&key);
        self.notices.remove(&key);
    }

    /// Explicit drops: 02 §2.6 cache/invalidate and session/ended.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.notices.clear();
    }

    pub fn drop_session(&mut self, session_id: &str) {
        let prefix = session_id.to_string();
        self.entries.retain(|(_, s), _| *s != prefix);
        self.notices.retain(|(_, s), _| *s != prefix);
    }

    fn drop_overflow(&mut self) {
        if self.entries.len() > BUDGET_TABLE_CAP {
            eprintln!("shell-warden: budget table overflow (> {BUDGET_TABLE_CAP}), clearing per-session budget state");
            self.clear();
        }
    }
}

struct PerCommand {
    verdict: Option<Verdict>,
    stage: Option<String>,
    rule_id: Option<String>,
    reason: Option<String>,
    classification: Option<Classification>,
    cache_ttl_ms: Option<u64>,
    /// exclusive claim (06 §6.5): a definite response removes the command
    /// from later stages; onError: skip does not claim.
    owned: bool,
}

/// The walk of 08 §8.5, stage-major: every enabled stage runs for every
/// still-owned command of the request; messages compose in stage array order.
/// The first deny stops the walk (remaining stages are not invoked).
pub fn walk(
    stages: &[Stage],
    params: &CheckParams,
    invoker: &mut dyn StageInvoker,
    budgets: &mut BudgetTable,
    now: Instant,
) -> Result<WalkOutcome, FatalPin> {
    let invocation = &params.invocation;
    let mut per_command: Vec<PerCommand> = params
        .commands
        .iter()
        .map(|_| PerCommand {
            verdict: None,
            stage: None,
            rule_id: None,
            reason: None,
            classification: None,
            cache_ttl_ms: None,
            owned: true,
        })
        .collect();

    let mut message: Option<String> = None;
    let mut aggregate = Verdict::Allow;
    let mut decisive_stage: Option<String> = None;
    let mut contributed = false;
    let mut stop = false;

    for stage in stages.iter().filter(|s| s.enabled) {
        if stop {
            break; // the first deny stops the walk (ADR-0012)
        }

        // Per-stage budget bypass (§8.4): the suspension applies to the whole
        // session; the first bypass composes the suspension notice once.
        if budgets.is_suspended(stage, &invocation.session_id, now) {
            if budgets.mark_notice(stage, &invocation.session_id) {
                let budget = stage.budget.as_ref().expect("budget stage");
                let text = format!(
                    "[{}] suspended for this session after {} rejections — commands will be reviewed manually",
                    stage.id, budget.max_rejections
                );
                message = Some(compose(message.take(), &text));
            }
            continue;
        }

        for (i, cmd) in params.commands.iter().enumerate() {
            if !per_command[i].owned {
                continue; // exclusive claim already absorbed this command
            }

            let outcome = invoker.invoke(stage, cmd, invocation, now)?;
            let (action, decided): (Option<Verdict>, Option<&ToolVerdict>) = match &outcome {
                StageOutcome::Decided(v) => (Some(v.verdict), Some(v)),
                // 08 §8.2: onError contributes the stage policy action with
                // no message; skip is a noop. Never allow (I3).
                StageOutcome::OnError { .. } => match stage.tool.on_error {
                    crate::config::OnError::Skip => (None, None),
                    crate::config::OnError::Ask => (Some(Verdict::Ask), None),
                    crate::config::OnError::Deny => (Some(Verdict::Deny), None),
                },
            };

            // Message composition (§8.3): tool messages only.
            if let Some(v) = decided {
                if let Some(reason) = &v.message {
                    if stage.message_mode == MessageMode::Replace {
                        message = Some(reason.clone());
                    } else {
                        message = Some(compose(message.take(), reason));
                    }
                }
            }

            if let Some(action) = action {
                // A definite verdict is a contribution; a noop (skip) is not.
                contributed = true;
                let takes = per_command[i]
                    .verdict
                    .map_or(true, |prev| action.rank() > prev.rank());
                if takes {
                    let (rule_id, reason, classification, cache_ttl_ms) = match decided {
                        Some(v) => (v.rule_id.clone(), v.reason.clone(), v.classification, v.cache_ttl_ms),
                        None => {
                            // onError: the core supplies the stage id and the reason.
                            let reason = match &outcome {
                                StageOutcome::OnError { reason, .. } => Some(reason.clone()),
                                _ => None,
                            };
                            (None, reason, None, None)
                        }
                    };
                    per_command[i] = PerCommand {
                        verdict: Some(action),
                        stage: Some(stage.id.clone()),
                        rule_id,
                        reason,
                        classification,
                        cache_ttl_ms,
                        owned: per_command[i].owned,
                    };
                }
                if aggregate.rank() < action.rank() {
                    aggregate = action;
                    decisive_stage = Some(stage.id.clone());
                }
            }

            // Rejection budget (ADR-0010): deny counts, non-deny resets.
            if action == Some(Verdict::Deny) {
                let charged = budgets.charge_deny(stage, &invocation.session_id, now);
                if let Some(budget) = &stage.budget {
                    if charged >= budget.max_rejections {
                        stop = true; // suspended from here on; walk ends at this deny
                    }
                }
            }
            if action != Some(Verdict::Deny) {
                budgets.reset(&stage.id, &invocation.session_id);
            }
            budgets.drop_overflow();

            match aggregate {
                Verdict::Deny => {
                    stop = true;
                    break;
                }
                _ => {
                    // exclusive: a definite response absorbs the command; a
                    // noop (skip) does not claim.
                    let definite = action.is_some();
                    if stage.exclusive && definite {
                        per_command[i].owned = false;
                    }
                }
            }
        }
    }

    let commands_out = per_command
        .iter()
        .zip(&params.commands)
        .map(|(pc, cmd)| CheckCommandResult {
            index: cmd.index,
            // Advisory per-command verdict; a command nothing contributed to
            // falls to defaults.action (ask in v1.1). cacheTtlMs rides only on
            // pass verdicts; I9 keeps denies uncached (shim-side).
            verdict: pc.verdict.unwrap_or(Verdict::Ask),
            stage: pc.stage.clone(),
            ruleId: pc.rule_id.clone(),
            reason: pc.reason.clone(),
            classification: pc.classification,
            cacheTtlMs: pc.cache_ttl_ms.filter(|_| !matches!(pc.verdict, Some(Verdict::Deny))),
        })
        .collect();

    if !contributed {
        // No stage contributed → defaults.action (§8.3; ask in v1.1).
        aggregate = Verdict::Ask;
    }
    Ok(WalkOutcome { verdict: aggregate, message, commands: commands_out, decisive_stage, contributed })
}

/// The engine → shim audit event for a decision (02 §2.5, 08 §8.1).
pub fn audit_decision(params: &CheckParams, outcome: &WalkOutcome, ts: String) -> AuditEvent {
    AuditEvent {
        kind: "decision".into(),
        invocationId: params.invocation.id.clone(),
        sessionID: Some(params.invocation.session_id.clone()),
        verdict: outcome.verdict,
        stage: outcome.decisive_stage.clone(),
        ruleId: None,
        ts,
    }
}

#[cfg(test)]
mod tests;
