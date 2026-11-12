// Verdict output — the closed verdict v2 envelope (02-letter-verdict.md §2.7/§2.8,
// ADR-0023: verdict v2 only).
//
// One writer, one response version: the checker emits `shell-warden.verdict.v2`
// for every outcome and never selects, negotiates, or falls back. The released
// v1 verdict schema stays an immutable historical record; nothing here reads or
// writes it (letter v1 parsing is unchanged, 02 §2.2).
//
// Evidence → wire mapping (02 §2.7): complete → static/argv, opaque →
// opaque/raw, invalid → invalid/raw. The invalid-over-opaque-over-complete
// precedence and the `deny > ask > allow` reduction stay in the pipeline (08
// §8.6); §8.9 self-validation rejects any envelope that violates the semantic
// invariants before a byte reaches stdout (fail closed, never synthesized).

use serde::Serialize;

pub const PROTOCOL: &str = "shell-warden.verdict.v2";
pub const MAX_VERDICT_BYTES: usize = 64 * 1024; // 02 §2.7
pub const MAX_FACTS_BYTES: usize = 16 * 1024; // 02 §2.8 (I6)
pub const MAX_FACTS_DEPTH: usize = 8; // 02 §2.8 (I6)
pub const TRUNCATED_MARKER: &str = "truncated-after-decision"; // 08 §8.7
pub const MAX_MESSAGE_CHARS: usize = 512; // 02 §2.7

pub use super::grammar::VerdictKind;

/// Stable reason codes (07 §7.3): the closed vocabulary accepted in
/// `facts.reasons`. Sorted as in the v2 schema `Reason` enum.
pub const STABLE_REASONS: [&str; 17] = [
    "complete",
    "opaque-expansion",
    "unknown-option",
    "option-value-missing",
    "invalid-inline-option",
    "unsupported-syntax",
    "empty-command",
    "evidence-limit",
    "allow-evidence-not-complete",
    "allow-coverage-missing",
    "required-option-missing",
    "option-not-repeatable",
    "option-not-allowed",
    "option-value-uncovered",
    "option-value-position-uncovered",
    "remainder-uncovered",
    "redirect-policy-uncovered",
];

/// Invalid-cause reasons (07 §7.3): the subset that marks evidence invalid.
pub const INVALID_CAUSES: [&str; 6] = [
    "unknown-option",
    "option-value-missing",
    "invalid-inline-option",
    "unsupported-syntax",
    "empty-command",
    "evidence-limit",
];

/// Coverage reasons (07 §7.3): the closed vocabulary of rejected allow entries.
pub const COVERAGE_REASONS: [&str; 9] = [
    "allow-evidence-not-complete",
    "allow-coverage-missing",
    "required-option-missing",
    "option-not-repeatable",
    "option-not-allowed",
    "option-value-uncovered",
    "option-value-position-uncovered",
    "remainder-uncovered",
    "redirect-policy-uncovered",
];

pub fn is_invalid_cause(reason: &str) -> bool {
    INVALID_CAUSES.contains(&reason)
}

/// Aggregate evidence state of one letter command (08 §8.6): complete only
/// when every participating part is complete; invalid dominates opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClass {
    Complete,
    Opaque,
    Invalid,
}

impl EvidenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceClass::Complete => "complete",
            EvidenceClass::Opaque => "opaque",
            EvidenceClass::Invalid => "invalid",
        }
    }

    /// The required diagnostics reason anchor (08 §8.7): `complete` for
    /// complete evidence, `opaque-expansion` for opaque, and the UTF-8
    /// byte-order lowest invalid cause for invalid evidence.
    pub fn reason_anchor(self) -> &'static str {
        match self {
            EvidenceClass::Complete => "complete",
            EvidenceClass::Opaque => "opaque-expansion",
            EvidenceClass::Invalid => "", // lowest invalid cause, not a constant
        }
    }

    /// Wire mapping (02 §2.7): complete → static/argv, opaque → opaque/raw,
    /// invalid → invalid/raw.
    pub fn classification(self) -> ClassificationWire {
        match self {
            EvidenceClass::Complete => ClassificationWire::Static,
            EvidenceClass::Opaque => ClassificationWire::Opaque,
            EvidenceClass::Invalid => ClassificationWire::Invalid,
        }
    }

    pub fn r#match(self) -> MatchKind {
        match self {
            EvidenceClass::Complete => MatchKind::Argv,
            EvidenceClass::Opaque | EvidenceClass::Invalid => MatchKind::Raw,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ClassificationWire {
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "opaque")]
    Opaque,
    #[serde(rename = "invalid")]
    Invalid,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum MatchKind {
    /// Fully parsed token match (the only kind allow may carry).
    #[serde(rename = "argv")]
    Argv,
    /// Decided on raw text / non-participating evidence (deny/ask only).
    #[serde(rename = "raw")]
    Raw,
}

/// Canonical rejected allow entry (08 §8.7): one per rule ID, coverage reasons
/// sorted and deduplicated by UTF-8 bytes.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RejectedAllow {
    pub rule_id: String,
    pub reasons: Vec<String>,
}

/// Full diagnostics (08 §8.7): emitted votes only, canonical ordering.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FullDiagnostics {
    pub evidence: &'static str,
    pub reasons: Vec<String>,
    pub selected_profiles: Vec<String>,
    pub matched: Vec<String>,
    pub qualified: Vec<String>,
    pub rejected: Vec<RejectedAllow>,
    pub votes: Vec<String>,
}

/// Truncated diagnostics (08 §8.7): bounded after the decision, never before.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TruncatedDiagnostics {
    pub evidence: &'static str,
    pub reasons: Vec<String>,
    pub diagnostics: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Diagnostics {
    Full(FullDiagnostics),
    Truncated(TruncatedDiagnostics),
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Verdict {
    pub invocation_id: String,
    pub verdict: VerdictKind,
    /// Present on tighten; required on deny (schema top-level allOf).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub commands: Vec<CommandVerdict>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommandVerdict {
    pub index: u32,
    pub verdict: VerdictKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub classification: ClassificationWire,
    pub r#match: MatchKind,
    /// Bounded v2 diagnostics (08 §8.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<Diagnostics>,
}

/// The closed v2 response envelope (02 §2.7): exactly `protocol` and `result`.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictEnvelope {
    pub protocol: &'static str,
    pub result: Verdict,
}

impl VerdictEnvelope {
    pub fn new(result: Verdict) -> Self {
        VerdictEnvelope {
            protocol: PROTOCOL,
            result,
        }
    }

    /// One explicit v2 writer (HANDOFF §Rust 1/3): 64 KiB output bound with a
    /// trailing newline (whitespace after the single JSON value, 02 §2.1).
    pub fn to_wire(&self) -> Result<Vec<u8>, String> {
        let mut out =
            serde_json::to_vec(self).map_err(|e| format!("verdict serialization failed: {e}"))?;
        if out.len() > MAX_VERDICT_BYTES {
            return Err(format!(
                "verdict exceeds {} bytes — checker defect",
                MAX_VERDICT_BYTES
            ));
        }
        out.push(b'\n');
        Ok(out)
    }
}

// ── Diagnostics construction (08 §8.7) ──────────────────────────────────────

/// Deduplicate and sort by UTF-8 bytes (byte order == Rust `str` ordering).
pub fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut out = values.to_vec();
    out.sort();
    out.dedup();
    out
}

/// Truncated `reasons` per 08 §8.7: when the full sorted set exceeds eight
/// entries, retain exactly the evidence anchor plus the UTF-8-lowest other
/// reasons, then sort the selected entries. At most eight entries.
pub fn select_truncated_reasons(
    evidence: EvidenceClass,
    full_reasons: &[String],
) -> Result<Vec<String>, String> {
    let canonical = sorted_unique(full_reasons);
    let anchor = match evidence {
        EvidenceClass::Complete => "complete".to_string(),
        EvidenceClass::Opaque => "opaque-expansion".to_string(),
        EvidenceClass::Invalid => canonical
            .iter()
            .filter(|r| is_invalid_cause(r))
            .min()
            .cloned()
            .ok_or_else(|| "invalid evidence requires an invalid-cause reason".to_string())?,
    };
    if canonical.len() <= 8 {
        return Ok(canonical);
    }
    let mut out: Vec<String> = Vec::with_capacity(8);
    out.push(anchor.clone());
    for reason in canonical.iter() {
        if out.len() >= 8 {
            break;
        }
        if reason != &anchor {
            out.push(reason.clone());
        }
    }
    out.sort();
    Ok(out)
}

// ── §8.9 post-construction self-validation ──────────────────────────────────

fn utf8_lt(a: &str, b: &str) -> bool {
    a.as_bytes() < b.as_bytes()
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|w| utf8_lt(&w[0], &w[1]))
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.chars().all(|c| !c.is_whitespace())
}

fn vote_parts(vote: &str) -> Option<(VerdictKind, &str)> {
    let (action, rule_id) = vote.split_once(':')?;
    let action = match action {
        "allow" => VerdictKind::Allow,
        "ask" => VerdictKind::Ask,
        "deny" => VerdictKind::Deny,
        _ => return None,
    };
    (is_identifier(rule_id)).then_some((action, rule_id))
}

fn rank(verdict: VerdictKind) -> u8 {
    verdict.rank()
}

impl VerdictEnvelope {
    /// §8.9 pre-serialization validation against the expected letter context.
    /// Any error is a checker anomaly: the caller must not write stdout.
    pub fn validate_against(
        &self,
        expected_invocation_id: &str,
        expected_command_count: usize,
    ) -> Result<(), String> {
        let result = &self.result;
        if result.invocation_id != expected_invocation_id {
            return Err(format!(
                "verdict invocationId {:?} does not echo the letter invocation {:?}",
                result.invocation_id, expected_invocation_id
            ));
        }
        if result.commands.len() != expected_command_count {
            return Err(format!(
                "verdict covers {} commands, letter has {expected_command_count}",
                result.commands.len()
            ));
        }
        let mut strongest = VerdictKind::Allow;
        for (position, command) in result.commands.iter().enumerate() {
            if command.index != position as u32 {
                return Err(format!(
                    "verdict commands[{position}].index is {} (must equal position)",
                    command.index
                ));
            }
            // legal classification/match/verdict tuples (02 §2.7)
            let legal = matches!(
                (command.classification, command.r#match, command.verdict),
                (ClassificationWire::Static, MatchKind::Argv, _)
                    | (ClassificationWire::Opaque, MatchKind::Raw, VerdictKind::Ask)
                    | (
                        ClassificationWire::Opaque,
                        MatchKind::Raw,
                        VerdictKind::Deny
                    )
                    | (
                        ClassificationWire::Invalid,
                        MatchKind::Raw,
                        VerdictKind::Ask
                    )
                    | (
                        ClassificationWire::Invalid,
                        MatchKind::Raw,
                        VerdictKind::Deny
                    )
            );
            if !legal {
                return Err(format!(
                    "commands[{position}] has an impossible classification/match/verdict combination"
                ));
            }
            if command.verdict == VerdictKind::Deny && command.rule_id.is_none() {
                return Err(format!("commands[{position}] deny without ruleId"));
            }
            if let Some(facts) = &command.facts {
                self.validate_facts(position, command, facts)?;
            }
            if rank(command.verdict) > rank(strongest) {
                strongest = command.verdict;
            }
        }
        if result.verdict != strongest {
            return Err(format!(
                "aggregate verdict {:?} is not the most restrictive command verdict ({strongest:?})",
                result.verdict
            ));
        }
        if let Some(message) = &result.message
            && (message.is_empty() || message.chars().count() > MAX_MESSAGE_CHARS)
        {
            return Err("aggregate message overbound".to_string());
        }
        if result.verdict == VerdictKind::Deny && result.message.is_none() {
            return Err("aggregate deny without message".to_string());
        }
        Ok(())
    }

    fn validate_facts(
        &self,
        position: usize,
        command: &CommandVerdict,
        facts: &Diagnostics,
    ) -> Result<(), String> {
        match facts {
            Diagnostics::Full(full) => self.validate_full_facts(position, command, full)?,
            Diagnostics::Truncated(truncated) => {
                self.validate_truncated_facts(position, command, truncated)?
            }
        }
        // serialized bounds (16 KiB facts, depth ≤ 8) — 02 §2.8 / 08 §8.9
        self.check_facts_bounds(position, &serde_json::to_value(facts).unwrap_or_default())
    }

    fn check_evidence_classification(
        &self,
        position: usize,
        command: &CommandVerdict,
        evidence: &str,
    ) -> Result<EvidenceClass, String> {
        let expected = match command.classification {
            ClassificationWire::Static => EvidenceClass::Complete,
            ClassificationWire::Opaque => EvidenceClass::Opaque,
            ClassificationWire::Invalid => EvidenceClass::Invalid,
        };
        let class = match evidence {
            "complete" => EvidenceClass::Complete,
            "opaque" => EvidenceClass::Opaque,
            "invalid" => EvidenceClass::Invalid,
            other => {
                return Err(format!(
                    "commands[{position}] facts evidence {other:?} unknown"
                ));
            }
        };
        if class != expected {
            return Err(format!(
                "commands[{position}] facts evidence {:?} does not match classification",
                evidence
            ));
        }
        Ok(class)
    }

    fn validate_truncated_facts(
        &self,
        position: usize,
        command: &CommandVerdict,
        truncated: &TruncatedDiagnostics,
    ) -> Result<(), String> {
        let class = self.check_evidence_classification(position, command, truncated.evidence)?;
        if truncated.diagnostics != TRUNCATED_MARKER {
            return Err(format!(
                "commands[{position}] truncated facts carry a foreign diagnostics marker"
            ));
        }
        if truncated.reasons.len() > 8 {
            return Err(format!("commands[{position}] truncated reasons exceed 8"));
        }
        if !truncated
            .reasons
            .iter()
            .all(|r| STABLE_REASONS.contains(&r.as_str()))
        {
            return Err(format!(
                "commands[{position}] truncated reasons outside the stable vocabulary"
            ));
        }
        if !is_sorted_unique(&truncated.reasons) {
            return Err(format!(
                "commands[{position}] truncated reasons not sorted/unique"
            ));
        }
        // evidence/reason coherence (02 §2.8)
        match class {
            EvidenceClass::Complete => {
                if !truncated.reasons.iter().any(|r| r == "complete") {
                    return Err(format!(
                        "commands[{position}] complete evidence truncated reasons miss the complete anchor"
                    ));
                }
            }
            EvidenceClass::Opaque => {
                if !truncated.reasons.iter().any(|r| r == "opaque-expansion") {
                    return Err(format!(
                        "commands[{position}] opaque evidence truncated reasons miss the opaque-expansion anchor"
                    ));
                }
                if truncated.reasons.iter().any(|r| is_invalid_cause(r)) {
                    return Err(format!(
                        "commands[{position}] opaque evidence carries an invalid-cause reason"
                    ));
                }
            }
            EvidenceClass::Invalid => {
                if !truncated.reasons.iter().any(|r| is_invalid_cause(r)) {
                    return Err(format!(
                        "commands[{position}] invalid evidence carries no invalid-cause reason"
                    ));
                }
            }
        }
        // serialized bound (16 KiB, depth ≤ 8) is checked in validate_facts
        Ok(())
    }

    fn validate_full_facts(
        &self,
        position: usize,
        command: &CommandVerdict,
        full: &FullDiagnostics,
    ) -> Result<(), String> {
        let class = self.check_evidence_classification(position, command, full.evidence)?;
        if full.reasons.len() > STABLE_REASONS.len() {
            return Err(format!(
                "commands[{position}] reasons exceed the vocabulary"
            ));
        }
        if !full
            .reasons
            .iter()
            .all(|r| STABLE_REASONS.contains(&r.as_str()))
        {
            return Err(format!(
                "commands[{position}] reasons outside the stable vocabulary"
            ));
        }
        if !is_sorted_unique(&full.reasons) {
            return Err(format!("commands[{position}] reasons not sorted/unique"));
        }
        // evidence/reason coherence (02 §2.8)
        match class {
            EvidenceClass::Complete => {
                if !full.reasons.iter().any(|r| r == "complete") {
                    return Err(format!(
                        "commands[{position}] complete evidence misses the complete anchor"
                    ));
                }
                if full.reasons.iter().any(|r| {
                    r == "opaque-expansion"
                        || r == "allow-evidence-not-complete"
                        || is_invalid_cause(r)
                }) {
                    return Err(format!(
                        "commands[{position}] complete evidence carries incompatible reasons"
                    ));
                }
            }
            EvidenceClass::Opaque => {
                if !full.reasons.iter().any(|r| r == "opaque-expansion") {
                    return Err(format!(
                        "commands[{position}] opaque evidence misses the opaque-expansion anchor"
                    ));
                }
                if full.reasons.iter().any(|r| is_invalid_cause(r)) {
                    return Err(format!(
                        "commands[{position}] opaque evidence carries an invalid-cause reason"
                    ));
                }
            }
            EvidenceClass::Invalid => {
                if !full.reasons.iter().any(|r| is_invalid_cause(r)) {
                    return Err(format!(
                        "commands[{position}] invalid evidence carries no invalid-cause reason"
                    ));
                }
            }
        }
        if full.selected_profiles.len() > 1024
            || !full.selected_profiles.iter().all(|p| is_identifier(p))
        {
            return Err(format!("commands[{position}] selectedProfiles overbound"));
        }
        if full.matched.len() > 4096 || !full.matched.iter().all(|r| is_identifier(r)) {
            return Err(format!("commands[{position}] matched overbound"));
        }
        if !is_sorted_unique(&full.matched) {
            return Err(format!("commands[{position}] matched not sorted/unique"));
        }
        if full.qualified.len() > 4096 || !full.qualified.iter().all(|r| is_identifier(r)) {
            return Err(format!("commands[{position}] qualified overbound"));
        }
        if !is_sorted_unique(&full.qualified) {
            return Err(format!("commands[{position}] qualified not sorted/unique"));
        }
        if full.rejected.len() > 4096 {
            return Err(format!("commands[{position}] rejected overbound"));
        }
        let matched: std::collections::BTreeSet<&str> =
            full.matched.iter().map(String::as_str).collect();
        let qualified: std::collections::BTreeSet<&str> =
            full.qualified.iter().map(String::as_str).collect();
        let mut seen_rejected: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (entry_position, entry) in full.rejected.iter().enumerate() {
            if !is_identifier(&entry.rule_id) {
                return Err(format!(
                    "commands[{position}] rejected[{entry_position}] ruleId malformed"
                ));
            }
            if entry.reasons.is_empty() || entry.reasons.len() > 9 {
                return Err(format!(
                    "commands[{position}] rejected[{entry_position}] reasons overbound"
                ));
            }
            if !entry
                .reasons
                .iter()
                .all(|r| COVERAGE_REASONS.contains(&r.as_str()))
            {
                return Err(format!(
                    "commands[{position}] rejected[{entry_position}] reasons outside the coverage vocabulary"
                ));
            }
            if !is_sorted_unique(&entry.reasons) {
                return Err(format!(
                    "commands[{position}] rejected[{entry_position}] reasons not sorted/unique"
                ));
            }
            if !matched.contains(entry.rule_id.as_str()) {
                return Err(format!(
                    "commands[{position}] rejected[{entry_position}] rule is not matched"
                ));
            }
            if !seen_rejected.insert(entry.rule_id.as_str()) {
                return Err(format!(
                    "commands[{position}] rejected has a duplicate ruleId {}",
                    entry.rule_id
                ));
            }
        }
        if full.votes.len() > 4096 {
            return Err(format!("commands[{position}] votes overbound"));
        }
        let mut strongest_vote: Option<VerdictKind> = None;
        let mut winning: Vec<&str> = Vec::new();
        for vote in &full.votes {
            let Some((action, rule_id)) = vote_parts(vote) else {
                return Err(format!("commands[{position}] vote {vote:?} malformed"));
            };
            if !matched.contains(rule_id) {
                return Err(format!("commands[{position}] vote {vote:?} is not matched"));
            }
            if action == VerdictKind::Allow && !qualified.contains(rule_id) {
                return Err(format!(
                    "commands[{position}] allow vote {vote:?} is not qualified"
                ));
            }
            if rank(action) > rank(strongest_vote.unwrap_or(VerdictKind::Allow)) {
                strongest_vote = Some(action);
            }
            if action == command.verdict {
                winning.push(rule_id);
            }
        }
        for rule in &full.qualified {
            if !matched.contains(rule.as_str()) {
                return Err(format!(
                    "commands[{position}] qualified rule {rule:?} is not matched"
                ));
            }
            if !full
                .votes
                .iter()
                .any(|v| vote_parts(v).is_some_and(|(a, r)| a == VerdictKind::Allow && r == rule))
            {
                return Err(format!(
                    "commands[{position}] qualified rule {rule:?} has no allow vote"
                ));
            }
        }
        if command.classification == ClassificationWire::Static
            && command.r#match == MatchKind::Argv
            && command.verdict == VerdictKind::Allow
            && !full
                .votes
                .iter()
                .any(|v| vote_parts(v).is_some_and(|(a, _)| a == VerdictKind::Allow))
        {
            return Err(format!(
                "commands[{position}] full static/argv/allow diagnostics without an emitted allow vote"
            ));
        }
        if let Some(strongest) = strongest_vote
            && rank(command.verdict) < rank(strongest)
        {
            return Err(format!(
                "commands[{position}] verdict is less restrictive than an emitted vote"
            ));
        }
        // ruleId selection: UTF-8 byte-order smallest emitted vote with the
        // command's action; absent when no such vote exists (default ask).
        winning.sort();
        match (winning.first(), command.rule_id.as_deref()) {
            (Some(winner), Some(rule)) if rule == *winner => {}
            (Some(winner), _) => {
                return Err(format!(
                    "commands[{position}] ruleId is not the smallest winning vote ({winner})"
                ));
            }
            (None, Some(_)) => {
                return Err(format!(
                    "commands[{position}] ruleId present without a winning emitted vote"
                ));
            }
            (None, None) => {}
        }
        Ok(())
    }

    fn check_facts_bounds(&self, position: usize, facts: &serde_json::Value) -> Result<(), String> {
        let serialized = serde_json::to_vec(facts)
            .map_err(|e| format!("commands[{position}] facts serialization failed: {e}"))?;
        if serialized.len() > MAX_FACTS_BYTES {
            return Err(format!(
                "commands[{position}] facts exceed {} bytes",
                MAX_FACTS_BYTES
            ));
        }
        if json_depth(facts) > MAX_FACTS_DEPTH {
            return Err(format!(
                "commands[{position}] facts exceed depth {MAX_FACTS_DEPTH}"
            ));
        }
        Ok(())
    }
}

/// JSON object/array depth as counted by the contract validator (01-based,
/// nested objects and arrays only).
fn json_depth(value: &serde_json::Value) -> usize {
    fn walk(value: &serde_json::Value, depth: usize, max: &mut usize) {
        match value {
            serde_json::Value::Object(map) => {
                *max = (*max).max(depth);
                for child in map.values() {
                    walk(child, depth + 1, max);
                }
            }
            serde_json::Value::Array(items) => {
                *max = (*max).max(depth);
                for child in items {
                    walk(child, depth + 1, max);
                }
            }
            _ => {}
        }
    }
    if value.is_object() || value.is_array() {
        let mut max = 0;
        walk(value, 1, &mut max);
        max
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_facts() -> FullDiagnostics {
        FullDiagnostics {
            evidence: "complete",
            reasons: vec!["complete".to_string()],
            selected_profiles: vec!["base".to_string()],
            matched: vec!["policy/a".to_string()],
            qualified: vec!["policy/a".to_string()],
            rejected: Vec::new(),
            votes: vec!["allow:policy/a".to_string()],
        }
    }

    fn sample(verdict: VerdictKind, classification: ClassificationWire) -> VerdictEnvelope {
        VerdictEnvelope::new(Verdict {
            invocation_id: "m:c".into(),
            verdict,
            message: (verdict == VerdictKind::Deny)
                .then(|| "push --force is forbidden — history is protected".to_string()),
            commands: vec![CommandVerdict {
                index: 0,
                verdict,
                rule_id: Some("policy/a".into()),
                classification,
                r#match: MatchKind::Argv,
                facts: Some(Diagnostics::Full(full_facts())),
            }],
        })
    }

    fn valid_sample() -> VerdictEnvelope {
        sample(VerdictKind::Allow, ClassificationWire::Static)
    }

    #[test]
    fn envelope_shape_matches_the_v2_contract() {
        let json = String::from_utf8(valid_sample().to_wire().unwrap()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["protocol"], PROTOCOL);
        assert_eq!(parsed["result"]["invocationId"], "m:c");
        assert_eq!(parsed["result"]["commands"][0]["classification"], "static");
        assert_eq!(parsed["result"]["commands"][0]["match"], "argv");
        assert_eq!(
            parsed["result"]["commands"][0]["facts"]["evidence"],
            "complete"
        );
        assert!(parsed["result"]["message"].is_null()); // allow carries no message here
        let root = parsed.as_object().unwrap();
        assert_eq!(
            root.len(),
            2,
            "root MUST contain exactly protocol and result"
        );
    }

    #[test]
    fn validation_accepts_the_well_formed_envelope() {
        valid_sample().validate_against("m:c", 1).unwrap();
    }

    #[test]
    fn validation_rejects_foreign_invocation_and_bad_coverage() {
        assert!(valid_sample().validate_against("other:c", 1).is_err());
        assert!(valid_sample().validate_against("m:c", 2).is_err());
    }

    #[test]
    fn invalid_maps_to_invalid_classification_with_raw_match() {
        let mut env = sample(VerdictKind::Ask, ClassificationWire::Invalid);
        env.result.commands[0].r#match = MatchKind::Raw;
        let json = String::from_utf8(env.to_wire().unwrap()).unwrap();
        assert!(json.contains("\"classification\":\"invalid\""));
        assert!(json.contains("\"match\":\"raw\""));
    }

    #[test]
    fn allow_has_no_message_serialized() {
        let mut env = sample(VerdictKind::Allow, ClassificationWire::Static);
        env.result.message = None;
        let json = String::from_utf8(env.to_wire().unwrap()).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn oversize_output_is_a_checker_defect() {
        let mut env = valid_sample();
        let filler = "x".repeat(MAX_VERDICT_BYTES);
        env.result.message = Some(filler);
        assert!(env.to_wire().is_err());
    }

    #[test]
    fn facts_bounds_reject_oversize_and_depth() {
        let mut env = valid_sample();
        if let Some(Diagnostics::Full(full)) = &mut env.result.commands[0].facts {
            full.matched = (0..4096).map(|i| format!("r/{i:0>4}")).collect();
        }
        assert!(env.validate_against("m:c", 1).is_err());

        let deep =
            serde_json::json!({"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": 1}}}}}}}}});
        assert!(json_depth(&deep) > MAX_FACTS_DEPTH);
        assert!(
            json_depth(
                &serde_json::json!({"rejected": [{"ruleId": "r", "reasons": ["allow-coverage-missing"]}]})
            ) <= MAX_FACTS_DEPTH
        );
    }

    #[test]
    fn truncated_reason_selection_keeps_the_evidence_anchor() {
        let many: Vec<String> = [
            "complete",
            "allow-coverage-missing",
            "option-not-allowed",
            "option-not-repeatable",
            "option-value-position-uncovered",
            "option-value-uncovered",
            "redirect-policy-uncovered",
            "remainder-uncovered",
            "required-option-missing",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let picked = select_truncated_reasons(EvidenceClass::Complete, &many).unwrap();
        assert_eq!(picked.len(), 8);
        assert!(picked.contains(&"complete".to_string()));
        assert!(is_sorted_unique(&picked));
        // invalid anchor: lowest invalid-cause reason
        let invalid: Vec<String> = [
            "unsupported-syntax",
            "allow-coverage-missing",
            "unknown-option",
            "option-not-allowed",
            "option-value-uncovered",
            "redirect-policy-uncovered",
            "remainder-uncovered",
            "required-option-missing",
            "evidence-limit",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let picked = select_truncated_reasons(EvidenceClass::Invalid, &invalid).unwrap();
        assert_eq!(picked.len(), 8);
        assert!(picked.contains(&"evidence-limit".to_string()));
        assert!(is_sorted_unique(&picked));
        // at most eight entries retains the full set verbatim when ≤ 8
        let small = vec!["complete".to_string(), "unknown-option".to_string()];
        assert_eq!(
            select_truncated_reasons(EvidenceClass::Complete, &small).unwrap(),
            vec!["complete".to_string(), "unknown-option".to_string()]
        );
    }

    #[test]
    fn rule_id_must_be_the_smallest_winning_vote() {
        let mut env = valid_sample();
        if let Some(Diagnostics::Full(full)) = &mut env.result.commands[0].facts {
            full.matched = vec!["policy/a".to_string(), "policy/b".to_string()];
            full.qualified = vec!["policy/a".to_string(), "policy/b".to_string()];
            full.votes = vec!["allow:policy/b".to_string(), "allow:policy/a".to_string()];
        }
        env.result.commands[0].rule_id = Some("policy/b".into());
        assert!(env.validate_against("m:c", 1).is_err());
        env.result.commands[0].rule_id = Some("policy/a".into());
        env.result.verdict = VerdictKind::Allow;
        assert!(env.validate_against("m:c", 1).is_ok());
        // default ask with no emitted ask vote MUST omit ruleId
        let mut env = sample(VerdictKind::Ask, ClassificationWire::Static);
        if let Some(Diagnostics::Full(full)) = &mut env.result.commands[0].facts {
            full.votes = vec!["allow:policy/a".to_string()];
        }
        assert!(env.validate_against("m:c", 1).is_err());
        env.result.commands[0].rule_id = None;
        assert!(env.validate_against("m:c", 1).is_ok());
    }

    #[test]
    fn votes_must_not_exceed_the_command_verdict() {
        let mut env = sample(VerdictKind::Ask, ClassificationWire::Static);
        if let Some(Diagnostics::Full(full)) = &mut env.result.commands[0].facts {
            full.matched = vec!["policy/d".to_string()];
            full.qualified = Vec::new();
            full.votes = vec!["deny:policy/d".to_string()];
        }
        env.result.commands[0].rule_id = Some("policy/d".into());
        assert!(env.validate_against("m:c", 1).is_err());
    }

    #[test]
    fn static_allow_requires_an_emitted_allow_vote() {
        let mut env = valid_sample();
        if let Some(Diagnostics::Full(full)) = &mut env.result.commands[0].facts {
            full.votes = Vec::new();
        }
        env.result.commands[0].rule_id = None;
        assert!(env.validate_against("m:c", 1).is_err());
    }
}
