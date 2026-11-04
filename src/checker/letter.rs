// Letter input (02-letter-verdict.md §2.2) — types mirror
// schemas/shell-warden.letter.v1.schema.json; strict: unknown fields rejected.

use serde::Deserialize;

pub const LETTER_VERSION: u32 = 1;
pub const MAX_LETTER_BYTES: usize = 64 * 1024; // I4

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Letter {
    pub version: u32,
    pub invocation: Invocation,
    pub action: String,
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub id: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(rename = "projectDir", skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub index: u32,
    pub raw: String,
    pub cwd: String,
}

impl Letter {
    pub fn from_bytes(bytes: &[u8]) -> Result<Letter, String> {
        if bytes.len() > MAX_LETTER_BYTES {
            // I4: oversize letter; this is usage failure, hook-side postures apply.
            return Err(format!(
                "letter exceeds {} bytes — usage failure (I4)",
                MAX_LETTER_BYTES
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| format!("letter is not one JSON value: {e}"))?;
        let letter: Letter =
            serde_json::from_value(value).map_err(|e| format!("letter schema violation: {e}"))?;
        letter.validate()?;
        Ok(letter)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != LETTER_VERSION {
            return Err(format!(
                "letter version must be {LETTER_VERSION} (got {})",
                self.version
            ));
        }
        if self.invocation.id.is_empty() || self.invocation.id.len() > 256 {
            return Err("letter invocation.id must be 1..256 chars".to_string());
        }
        if self.invocation.session_id.is_empty() || self.invocation.session_id.len() > 256 {
            return Err("letter invocation.sessionID must be 1..256 chars".to_string());
        }
        if self
            .invocation
            .agent
            .as_deref()
            .map(|s| s.len() > 256)
            .unwrap_or(false)
        {
            return Err("letter invocation.agent exceeds 256 chars".to_string());
        }
        if self.action != "shell" {
            return Err(format!(
                "letter action \"{}\" is outside v1 scope (shell only, ADR-0016 N5)",
                self.action
            ));
        }
        if self.commands.is_empty() || self.commands.len() > 128 {
            return Err("letter commands must be 1..128 entries".to_string());
        }
        for (i, cmd) in self.commands.iter().enumerate() {
            if cmd.index != i as u32 {
                return Err(format!(
                    "letter commands[{}].index is {} (must equal position)",
                    i, cmd.index
                ));
            }
            if cmd.raw.is_empty() || cmd.raw.len() > 8192 {
                return Err(format!("letter commands[{}].raw must be 1..8192 chars", i));
            }
            if cmd.cwd.is_empty() || cmd.cwd.len() > 4096 {
                return Err(format!("letter commands[{}].cwd must be 1..4096 chars", i));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        r#"{"version":1,"invocation":{"id":"m:c","sessionID":"s1","projectDir":"/repo"},
            "action":"shell",
            "commands":[{"index":0,"raw":"git push origin main","cwd":"/repo"}]}"#
            .to_string()
    }

    #[test]
    fn accepts_valid_letter() {
        Letter::from_bytes(sample().as_bytes()).unwrap();
    }

    #[test]
    fn rejects_wrong_version() {
        let s = sample().replace("\"version\":1", "\"version\":2");
        assert!(
            Letter::from_bytes(s.as_bytes())
                .unwrap_err()
                .contains("version")
        );
    }

    #[test]
    fn rejects_foreign_action() {
        let s = sample().replace("\"action\":\"shell\"", "\"action\":\"edit\"");
        let err = Letter::from_bytes(s.as_bytes()).unwrap_err();
        assert!(err.contains("outside v1 scope"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let s = sample().replace("\"raw\":", "\"argv\":[],\"raw\":");
        assert!(
            Letter::from_bytes(s.as_bytes())
                .unwrap_err()
                .contains("schema violation")
        );
    }

    #[test]
    fn rejects_index_mismatch() {
        let s = sample().replace("\"index\":0", "\"index\":3");
        assert!(
            Letter::from_bytes(s.as_bytes())
                .unwrap_err()
                .contains("must equal position")
        );
    }

    #[test]
    fn rejects_multiple_json_values() {
        let s = sample() + "{\"version\":1}";
        assert!(
            Letter::from_bytes(s.as_bytes())
                .unwrap_err()
                .contains("not one JSON value")
        );
    }
}
