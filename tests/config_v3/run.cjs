#!/usr/bin/env node
// Release-binary acceptance of the canonical full v3 policy vectors.
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { spawnSync } = require("node:child_process")
const at = process.argv.indexOf("--fixtures")
assert.ok(at >= 0 && process.argv[at + 1], "--fixtures is required")
const root = path.resolve(process.argv[at + 1])
const binary = process.env.SHELL_WARDEN_BIN
assert.ok(binary && path.isAbsolute(binary), "SHELL_WARDEN_BIN must be absolute")
const { fixtures } = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"))
const letter = {
  version: 1, invocation: { id: "config:conformance", sessionID: "test" }, action: "shell",
  commands: [{ index: 0, raw: 'ls -- "$HOME"', cwd: "/repo" }],
}
for (const fixture of fixtures) {
  const output = spawnSync(binary, ["--config", path.join(root, fixture.path)], {
    encoding: "utf8", input: JSON.stringify(letter), timeout: 5000,
  })
  assert.ifError(output.error)
  assert.equal(output.status, fixture.valid ? 0 : 2, `${fixture.path}: ${output.stderr}`)
  if (fixture.valid) {
    const envelope = JSON.parse(output.stdout)
    assert.equal(envelope.protocol, "shell-warden.verdict.v3")
    assert.equal(envelope.result.invocationId, letter.invocation.id)
  } else {
    assert.equal(output.stdout, "", fixture.path)
    assert.match(output.stderr, /config invalid/)
  }
}
console.log(`${fixtures.length} full v3 policies verified with the real checker.`)
