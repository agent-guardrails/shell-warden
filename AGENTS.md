# agent-guardrails/shell-warden - agent instructions

This repository implements the **engine side** of the shell-warden system. The contract lives in
`agent-guardrails/docs`: `spec/shell-warden/` (normative) and `schemas/` (wire + engine config).
Read them before changing protocol, budgets, config semantics or security behavior.

## Workflow

Per the org rules ([agent-guardrails/.github/AGENTS.md](https://github.com/agent-guardrails/.github/blob/main/AGENTS.md)):
- every non-trivial change starts with a GitHub issue in this repo, linked to the
  ["Agent Guardrails Roadmap"](https://github.com/orgs/agent-guardrails/projects/1) project;
- reference the issue in commits and PRs (`Closes #123`) and move the issue to Done on merge;
- **all changes land via pull requests** — never push directly to the default branch.

## Sync duties (part of Definition of Done)

- **Changed anything the spec describes** (wire protocol, budgets/clamps, config validation,
  security invariants, cache/verdict application) -> update
  `agent-guardrails/docs/spec/shell-warden/` and `schemas/` **in the same change**; mention
  `docs:` in the commit message.
- **Made an architectural choice** (options were weighed) -> new ADR in `agent-guardrails/docs/adr/`
  (next number, MADR structure, `Status: Accepted`).
- **Milestone boundary** (M0...M4 per `spec/shell-warden/11-roadmap.md`) -> update the matching item
  in the org project "Agent Guardrails Roadmap".
- **Publishing a release** -> follow the release artifact convention (see
  `agent-guardrails/homebrew-tap` README, "Release artifact convention"): versioned archives for
  darwin/linux on arm64/amd64 + `checksums.txt`, tag `v<semver>`.

## Constraints

- Fail-closed everywhere: never synthesize `allow`; `onEngineError` is `ask` or `deny` (spec invariant I3).
- Language: Rust (ADR-0015).
- The engine stays an orchestrator: decision logic lives in stage tools (ADR-0008), not here.
- Tests: `cargo test`, `cargo fmt --check` and `cargo clippy` must pass before push.
