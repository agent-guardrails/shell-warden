// Verdict output (02-letter-verdict.md §2.3 + v2 wire compatibility).
//
// The published hook validates `classification` against `static|opaque` only
// and `match` against `argv|raw`; it does not reject unknown keys and bounds
// `facts` by byte size. V2 therefore keeps that closed vocabulary at the
// policy boundary: complete → static; opaque AND invalid → opaque (invalid
// blocks allow exactly like opaque and deny still matches), with the true
// state and stable reason codes carried in bounded `facts` diagnostics.
// A coordinated spec 02 + schema update documents this mapping (design
// §Diagnostics and verdict wire); a hook ticket lifts `invalid` later.

use serde::Serialize;

pub const MAX_VERDICT_BYTES: usize = 64 * 1024; // 02 §2.3

pub use super::grammar::VerdictKind;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ClassificationWire {
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "opaque")]
    Opaque,
}

impl ClassificationWire {
    pub fn from_static(complete_everywhere: bool) -> Self {
        if complete_everywhere {
            ClassificationWire::Static
        } else {
            ClassificationWire::Opaque
        }
    }
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
    /// Bounded v2 diagnostics: evidence state, stable reasons, matched/
    /// qualified/rejected allow ids, emitted votes (design §Diagnostics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<serde_json::Value>,
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

    fn sample(verdict: VerdictKind, classification: ClassificationWire) -> Verdict {
        Verdict {
            invocation_id: "m:c".into(),
            verdict,
            message: (verdict == VerdictKind::Deny)
                .then(|| "push --force is forbidden — history is protected".to_string()),
            commands: vec![CommandVerdict {
                index: 0,
                verdict,
                rule_id: Some("git/deny-force-push".into()),
                classification,
                r#match: MatchKind::Argv,
                facts: Some(serde_json::json!({ "evidence": "complete" })),
            }],
        }
    }

    #[test]
    fn wire_shapes_match_hook_validation() {
        let json = String::from_utf8(
            sample(VerdictKind::Deny, ClassificationWire::Static)
                .to_wire()
                .unwrap(),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["invocationId"], "m:c");
        assert_eq!(parsed["verdict"], "deny");
        assert_eq!(parsed["commands"][0]["classification"], "static");
        assert_eq!(parsed["commands"][0]["match"], "argv");
        assert!(parsed["commands"][0]["facts"]["evidence"].is_string());
        // deny always carries message
        assert!(parsed["message"].is_string());
    }

    #[test]
    fn invalid_maps_to_opaque_classification() {
        let v = sample(VerdictKind::Ask, ClassificationWire::Opaque);
        let json = String::from_utf8(v.to_wire().unwrap()).unwrap();
        assert!(json.contains("\"classification\":\"opaque\""));
    }

    #[test]
    fn allow_has_no_message_serialized() {
        let mut v = sample(VerdictKind::Allow, ClassificationWire::Static);
        v.message = None;
        let json = String::from_utf8(v.to_wire().unwrap()).unwrap();
        assert!(!json.contains("message"));
    }
}
