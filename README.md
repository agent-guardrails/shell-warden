# shell-warden

Decision binary of the shell-warden permission system (companion of the
`opencode-shell-warden-hook` shim). Per ADR-0016 the canonical `shell-warden`
binary is the **one-shot letter checker**: a permission letter on stdin, one
verdict JSON on stdout, process exits. Must be spawned per check — no server,
no long-lived process.

- **Parser**: `src/checker/` — shell-structure parser + recursive executable-part
  extraction, closed relation enum
  (`chain`/`pipeline`/`wrapper`/`command-substitution`/`analyzer-command`), and
  typed evidence states (`complete`/`parameter`/`opaque`/`invalid`).
- **Policy**: config **v3** — command profiles (per-executable
  option grammar + typed-evidence rules). An `allow` is a full coverage proof;
  every emitted vote reduces by the fixed lattice `deny > ask > allow`. See the
  accepted design `agent-guardrails/docs/design/shell-warden-config-v2.md` and
  the normative specs in `agent-guardrails/docs/spec/shell-warden/`.

- **Examples & policy tooling**: `examples/configs/` —
  `shell-warden.example.jsonc` (reference policy, exercised by the golden
  tests), `policy-builder.cjs` (build a v3 policy from composable helpers —
  run `node policy-builder.cjs policy.jsonc`), `verdict-battery.cjs`
  (`node verdict-battery.cjs --config POLICY --battery BATTERY` — spawn-based
  verdict battery; `SHELL_WARDEN_BIN` selects the checker), and
  `example-battery.json` (the example policy's verdicts, run in CI before
  merges that touch `examples/configs/**`).

## Usage

### Install and upgrade 0.6.0

Download the archive for your platform and `checksums.txt` from
[v0.6.0](https://github.com/agent-guardrails/shell-warden/releases/tag/v0.6.0).
Verify its SHA-256 against that file before extracting the top-level
`shell-warden` binary. Archives cover macOS/Linux, arm64/amd64.

Pair this release with
[@agent-guardrails/opencode-shell-warden-hook 0.4.0](https://github.com/agent-guardrails/opencode-shell-warden-hook/releases/tag/v0.4.0).
Migrate policies to configuration v3 and review the
[breaking changes](CHANGELOG.md) before activating either component. There is no
automatic migration or v1/v2 compatibility mode. A Homebrew tap may still select
an older release; verify its version rather than assuming it installs this pair.

```
shell-warden [--config FILE]...
# letter JSON (schemas/shell-warden.letter.v1.schema.json) on stdin,
# verdict v3 envelope (schemas/shell-warden.verdict.v3.schema.json) on stdout:
# {"protocol":"shell-warden.verdict.v3","result":{...}} — ADR-0026, v3 only
# exit: 0 verdict written; 1 usage failure; 2 config invalid
```

- Default config path: `$XDG_CONFIG_HOME/shell-warden/config.jsonc`
  (fallback `~/.config/shell-warden/config.jsonc`). `--config` also accepts
  `{env:NAME}` substitution toward an absolute path.
- Repeat `--config` to assemble disjoint profiles, for example:
  `shell-warden --config /policies/git.jsonc --config /policies/rust.jsonc`.
  Explicit files suppress the default config path; there is no implicit project
  discovery. Argument order preserves profile order, not override precedence.
  Every file must be a complete, independently valid v3 policy. Duplicate
  canonical paths (including symlinks), profile IDs, or executable spellings
  reject the set. Defaults must match, and shared redirect-policy names require
  identical definitions. Rules and fallback hints stay profile-local; cross-file
  references are not supported.
- Effective limits are the minimum across files. `configBytes` covers the sum
  of original bytes, including comments; profile/rule caps cover the assembled
  policy. Any invalid file or conflict exits 2 before evaluation with empty
  stdout and source paths on stderr. `shell-warden --help` describes the CLI.
  Design: https://github.com/agent-guardrails/docs/issues/39.
  Tracking: https://github.com/agent-guardrails/shell-warden/issues/51.
- Verdicts fail closed: `invalid`/`opaque` evidence and any limit overflow can
  never produce `allow`; the hook mapping stays `allow → once`,
  `deny → reject`, `ask → silence`.

`shell-warden-serve` (binary kept as reference, never shipped) is the retired
JSON-RPC orchestrator; `warden-test-tool.exe`-style helpers are test-only.

## Contextual variable permissions

`expansions` on an allow rule independently permits variable names in `arguments`,
`redirectTargets`, and `assignmentValues`. Omitted lists grant nothing. Supported
words have one leading simple reference and a literal suffix. Arguments require a
literal `--` boundary and value-independent coverage. Assignment destinations,
every redirect occurrence, tracked unresolved paths, facts, and nested parts still
require coverage.

This authorizes **any runtime value**, not a verified HOME or path confinement.
Unknown applicable ask/deny comparisons establish an ask floor; an unprovable
allow proof does not veto another qualifying allow. The checker never reads HOME.

See [the opt-in example](https://github.com/agent-guardrails/shell-warden/blob/main/examples/configs/contextual-variables.jsonc)
and [the v3 contract](https://github.com/agent-guardrails/docs/blob/main/spec/shell-warden/12-contextual-parameters.md).
The existing reference policy and builder remain literal-only unless explicitly
changed. Upgrade checker and hook together: retired versions fail closed, with no
fallback. A `complete` classification filter remains literal-only; omit it or use
`parameter` when configuring the new gates and coverage.

## Executable spellings and wrappers

Executable lists enroll exact decoded head spellings, for example
`["tool", "/opt/tools/tool"]`, never every path with that basename.
Bare names are optional. Different-name lists must form one complete catalog
group (`node`/`nodejs` or `python`/`python3`). Relative/irregular configured
spellings and incompatible specialized analyzers are configuration errors.
Every executable wrapper now needs its own profile and full coverage as well
as an independently permitted child. Raw predicates retain original source;
review them when adding a spelling rather than assuming typed-deny equivalence.
See [`examples/configs/executable-spellings.jsonc`](examples/configs/executable-spellings.jsonc)
and [`CHANGELOG.md`](CHANGELOG.md) for the breaking contract changes.

## Tests

`cargo test` runs unit + scenario-golden suites; `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings` gate PRs (see `ci/pr-tests-linters`).
