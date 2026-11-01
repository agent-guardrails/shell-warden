# shell-warden

Orchestrator engine of the shell-warden permission system (companion of
`opencode-shell-warden-hook`). Speaks wire v1 (`initialize` + `policy/check`)
over stdio; walks configured stages; all decision logic lives in stage tools
(see `agent-guardrails/docs/spec/shell-warden/`, ADR-0008).

Status: sanctioned, not yet implemented — build plan in
`agent-guardrails/docs/spec/shell-warden/HANDOFF-m0.md`.
