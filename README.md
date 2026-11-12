# shell-warden

Decision binary of the shell-warden permission system (companion of the
`opencode-shell-warden-hook` shim). Per ADR-0016 the canonical `shell-warden`
binary is the **one-shot letter checker**: a permission letter on stdin, one
verdict JSON on stdout, process exits. Must be spawned per check — no server,
no long-lived process.

- **Parser**: `src/checker/` — shell-structure parser + recursive executable-part
  extraction, closed relation enum
  (`chain`/`pipeline`/`wrapper`/`commandSubstitution`/`analyzerCommand`), and
  typed evidence states (`complete`/`opaque`/`invalid`).
- **Policy**: config **v2** — monotonic command profiles (per-executable
  option grammar + typed-evidence rules). An `allow` is a full coverage proof;
  every emitted vote reduces by the fixed lattice `deny > ask > allow`. See the
  accepted design `agent-guardrails/docs/design/shell-warden-config-v2.md` and
  the normative specs in `agent-guardrails/docs/spec/shell-warden/`.

## Usage

```
shell-warden [--config FILE]
# letter JSON (schemas/shell-warden.letter.v1.schema.json) on stdin,
# verdict v2 envelope (schemas/shell-warden.verdict.v2.schema.json) on stdout:
# {"protocol":"shell-warden.verdict.v2","result":{...}} — ADR-0023, v2 only
# exit: 0 verdict written; 1 usage failure; 2 config invalid
```

- Default config path: `$XDG_CONFIG_HOME/shell-warden/config.jsonc`
  (fallback `~/.config/shell-warden/config.jsonc`). `--config` also accepts
  `{env:NAME}` substitution toward an absolute path.
- Verdicts fail closed: `invalid`/`opaque` evidence and any limit overflow can
  never produce `allow`; the hook mapping stays `allow → once`,
  `deny → reject`, `ask → silence`.

`shell-warden-serve` (binary kept as reference, never shipped) is the retired
JSON-RPC orchestrator; `warden-test-tool.exe`-style helpers are test-only.

## Tests

`cargo test` runs unit + scenario-golden suites; `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings` gate PRs (see `ci/pr-tests-linters`).
