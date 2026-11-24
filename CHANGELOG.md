# Release notes

## Unreleased — executable spellings and wrapper coverage

Tracking: https://github.com/agent-guardrails/shell-warden/issues/73
Contract synchronization: https://github.com/agent-guardrails/docs/issues/51
Decision: https://github.com/agent-guardrails/docs/blob/main/adr/0025-explicit-same-name-executable-spellings.md

- Profiles can enroll explicit same-name installation paths, including paths-only
  lists. Complete `node`/`nodejs` and `python`/`python3` basename groups remain valid.
  Selection still compares the full decoded head exactly; no unlisted path gains
  permission, no PATH/filesystem lookup occurs, and raw text is never rewritten.
- **Breaking:** relative and irregular configured executable spellings, ASCII
  controls, and spellings exceeding 4096 UTF-8 bytes fail configuration validation.
  Replace them manually with normalized explicit spellings.
- **Breaking:** specialized analyzer compatibility is checked for every spelling:
  `sed-v1` only models `sed`, `xargs-v1` only models `xargs`, and `export-v1`
  only models the bare `export` builtin. Paths ending in `/export` are rejected
  even without specialized analysis. Enrolled absolute `sed`/`xargs` spellings
  retain their facts and nested relations.
- **Breaking:** `bash`, `sh`, `sudo`, `nohup`, `nice`, `timeout`, and `env` parents
  no longer disappear after child extraction. Like `xargs`, every parent remains
  independently checked. Add explicit parent profiles, option/argument,
  environment, redirect, and nested-part coverage where required. A permitted
  child alone now leaves the invocation at ask; a child deny remains dominant.
- Review raw ask/deny predicates when adding spellings: they intentionally match
  original source. Prefer typed argument/option predicates for shared restrictions.
  There is one active v3 contract, no legacy mode or automatic migration.

The implementation is based on the contextual-parameter v3 contract already
shipped on main under ADR 0026. It preserves dynamic-code blocking, restrictive
uncertainty floors, and unsupported wrapper forms, including `env` assignments
and extra shell operands. Historical v2 artifacts remain unchanged.

Engine and normative schema/spec/fixture changes are coordinated; neither side
alone completes the rollout. No configuration-version or verdict-envelope change
is introduced. The checker never executes the represented commands.
