// Verdict output (02-letter-verdict.md §2.3) — types mirror
// schemas/shell-warden.verdict.v1.schema.json.

use serde::Serialize;

pub const MAX_VERDICT_BYTES: usize = 64 * 1024; // 02 §2.3

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
    pub classification: ClassificationKind,
    /// `argv` = fully parsed token match (the only kind allow may carry);
    /// `raw` = raw-glob match (deny/ask only).
    pub r#match: MatchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<serde_json::Value>,
}

// Reuse the config's kinds through aliases so the pipeline has one enum type each.
pub use super::grammar::Classification as ClassificationKind;
pub use super::grammar::VerdictKind;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum MatchKind {
    #[serde(rename = "argv")]
    Argv,
    #[serde(rename = "raw")]
    Raw,
}

impl Verdict {
    pub fn to_wire(&self) -> Result<Vec<u8>, String> {
        let mut out =
            serde_json::to_vec(self).map_err(|e| format!("verdict serialization failed: {e}"))?;
        if out.len() > MAX_VERDICT_BYTES {
            return Err(format!(
                "verdict exceeds {} bytes — checker defect",
                MAX_VERDICT_BYTES
            ));
        }
        out.push(b'\n'); // trailing newline: whitespace after the JSON value
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundshapes_match_schema_expectations() {
        let v = Verdict {
            invocation_id: "m:c".into(),
            verdict: VerdictKind::Deny,
            message: Some("push --force is forbidden — history is protected".into()),
            commands: vec![CommandVerdict {
                index: 0,
                verdict: VerdictKind::Deny,
                rule_id: Some("vcs/no-force-push".into()),
                classification: ClassificationKind::Static,
                r#match: MatchKind::Argv,
                facts: None,
            }],
        };
        let bytes = v.to_wire().unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.contains("\"invocationId\":\"m:c\""));
        assert!(json.contains("\"verdict\":\"deny\""));
        assert!(json.contains("\"ruleId\":\"vcs/no-force-push\""));
        assert!(json.contains("\"classification\":\"static\""));
        assert!(json.contains("\"match\":\"argv\""));
        // deny always carries message (schema: top-level allOf)
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["message"].is_string());
    }

    #[test]
    fn allow_has_no_message_serialized() {
        let v = Verdict {
            invocation_id: "i".into(),
            verdict: VerdictKind::Allow,
            message: None,
            commands: vec![CommandVerdict {
                index: 0,
                verdict: VerdictKind::Allow,
                rule_id: Some("vcs/allow-inspection".into()),
                classification: ClassificationKind::Static,
                r#match: MatchKind::Argv,
                facts: None,
            }],
        };
        let json = String::from_utf8(v.to_wire().unwrap()).unwrap();
        assert!(!json.contains("message"));
    }
}
