# Release notes

## Unreleased — quoted parameter option values

Tracking: https://github.com/agent-guardrails/shell-warden/issues/80
Contract: https://github.com/agent-guardrails/docs/issues/60
Hook verification: https://github.com/agent-guardrails/opencode-shell-warden-hook/issues/34

- Add independent allow-only `expansions.optionValues` name grants for supported
  wholly double-quoted values consumed by declared fixed-arity options.
  Explicit arity-one inline forms retain their opt-in requirement.
- Grants still require complete value-independent coverage. Runtime equality,
  regex, and path checks remain unresolved; applicable restrictive predicates
  retain the ask floor. Code-bearing options remain unsupported.
- Review restrictions selecting only `opaque`: supported option values are now
  `parameter` evidence even when no rule grants their variable. Configuration and
  verdict stay v3; older checkers reject policies using the new grant.

## 0.6.0 — configuration and verdict v3

Release tracking: https://github.com/agent-guardrails/shell-warden/issues/78
Companion hook: https://github.com/agent-guardrails/opencode-shell-warden-hook/releases/tag/v0.4.0

### Coordinated upgrade required

- **Breaking:** only configuration `version: 3` and
  `shell-warden.verdict.v3` are supported. Upgrade checker and hook together;
  older configurations are rejected and mixed verdict versions fail closed.
- Contextual parameter permissions independently authorize named variables in
  arguments, redirect targets, and assignment values. They authorize any runtime
  value, not a verified path or environment value; complete coverage is still
  required. Review `complete` and `opaque` classification restrictions when
  migrating. See https://github.com/agent-guardrails/docs/blob/main/spec/shell-warden/12-contextual-parameters.md.
- Repeated `--config` assembles independently valid, disjoint policies without
  override precedence. Conflicts reject the entire set; limits use minima.
- Parsing and matching fixes preserve nested executable evidence, invalid
  classifications, source whitespace, export fact order, deny dominance, and
  decisive three-valued predicate results.

### Executable spellings and wrapper coverage

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

The executable-spelling change itself does not introduce another configuration
version or verdict envelope beyond v3. The checker never executes the represented
commands.

### Open follow-up work

This release contains merged mainline changes only. It does not include the
unmerged Bash startup/script-file work
(https://github.com/agent-guardrails/shell-warden/issues/74), output-budget fixes
(https://github.com/agent-guardrails/shell-warden/issues/59 and
https://github.com/agent-guardrails/shell-warden/issues/60), diagnostic vocabulary
work (https://github.com/agent-guardrails/shell-warden/issues/61), or the earlier
predicate/ordinal follow-ups
(https://github.com/agent-guardrails/shell-warden/issues/53,
https://github.com/agent-guardrails/shell-warden/issues/54, and
https://github.com/agent-guardrails/shell-warden/issues/55).
These open reports are not claims that each historical reproducer still affects
v3. Explicit script-file support is not advertised by this release.
