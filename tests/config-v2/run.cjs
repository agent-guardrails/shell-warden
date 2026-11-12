#!/usr/bin/env node
"use strict"

const { spawnSync } = require("node:child_process")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const { wrapControl, wrapFixture } = require("./adapters.cjs")
const { PROBES } = require("./probes.cjs")

const EXPECTED_FILES = Object.freeze({ valid: 33, invalid: 18 })
const EXPECTED_SEMANTIC_REJECTIONS = new Set(["integer", "number", "boolean", "path"])
const VALID_VERDICTS = new Set(["allow", "ask", "deny"])

function usage(message) {
  if (message) console.error(`error: ${message}`)
  console.error("usage: SHELL_WARDEN_BIN=/absolute/path node tests/config-v2/run.cjs --fixtures /absolute/path")
  process.exit(2)
}

function parseArgs(argv) {
  let fixtures
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] !== "--fixtures") usage(`unknown argument ${argv[index]}`)
    if (fixtures !== undefined) usage("--fixtures may be specified only once")
    fixtures = argv[index + 1]
    index += 1
  }
  if (!fixtures) usage("--fixtures is required")
  if (!process.env.SHELL_WARDEN_BIN) usage("SHELL_WARDEN_BIN is required")
  return {
    fixtures: path.resolve(fixtures),
    binary: path.resolve(process.env.SHELL_WARDEN_BIN),
  }
}

function discover(fixtures, kind) {
  const root = path.join(fixtures, kind)
  const files = []
  for (const definition of fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()) {
    const directory = path.join(root, definition)
    for (const name of fs.readdirSync(directory)
      .filter((entry) => entry.endsWith(".json"))
      .sort()) {
      files.push({ definition, absolute: path.join(directory, name), file: `${kind}/${definition}/${name}` })
    }
  }
  if (files.length !== EXPECTED_FILES[kind]) {
    throw new Error(`${kind} fixture file count drift: expected ${EXPECTED_FILES[kind]}, found ${files.length}`)
  }
  return files
}

function letter(raw) {
  return JSON.stringify({
    version: 1,
    invocation: { id: "config-v2-conformance", sessionID: "config-v2-conformance" },
    action: "shell",
    commands: [{ index: 0, cwd: "/tmp", raw }],
  })
}

function execute(binary, configValue, raw) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "shell-warden-config-v2-"))
  try {
    const configPath = path.join(directory, "config.json")
    fs.writeFileSync(configPath, `${JSON.stringify(configValue, null, 2)}\n`, "utf8")
    const result = spawnSync(binary, ["--config", configPath], {
      encoding: "utf8",
      input: letter(raw),
      timeout: 15_000,
    })
    return {
      status: result.status,
      signal: result.signal,
      error: result.error,
      stdout: result.stdout || "",
      stderr: result.stderr || "",
    }
  } finally {
    fs.rmSync(directory, { recursive: true })
  }
}

function describe(result) {
  const error = result.error ? ` error=${result.error.message}` : ""
  const signal = result.signal ? ` signal=${result.signal}` : ""
  return `exit=${result.status}${signal}${error} stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`
}

function verdictOutcome(result) {
  if (result.error || result.status !== 0) return { ok: false, detail: describe(result) }
  let parsed
  try {
    parsed = JSON.parse(result.stdout)
  } catch (error) {
    return { ok: false, detail: `exit=0 unparsable-verdict=${error.message} stdout=${JSON.stringify(result.stdout)}` }
  }
  // verdict v2 only (ADR-0023): the checker emits exactly {protocol, result}
  const verdict = parsed && parsed.result && parsed.result.verdict
  if (!VALID_VERDICTS.has(verdict)) {
    return { ok: false, detail: `exit=0 invalid-verdict=${JSON.stringify(parsed)}` }
  }
  return { ok: true, detail: `exit=0 verdict=${verdict}` }
}

function invalidOutcome(result) {
  const acceptedError = !result.error || (result.error.code === "EPIPE" && result.status === 2)
  const ok = acceptedError && result.status === 2 && result.stdout === "" && result.stderr.includes("config invalid")
  const epipe = result.error ? " epipe=accepted" : ""
  return { ok, detail: ok ? `exit=2${epipe} stdout=empty stderr=${JSON.stringify(result.stderr.trim())}` : describe(result) }
}

function semanticRejectionOutcome(result, arm) {
  const invalid = invalidOutcome(result)
  const diagnostic = `typed fact selector \`${arm}\` applies only to ${arm} facts (catalog type Str)`
  const ok = invalid.ok && result.stderr.includes(diagnostic)
  return {
    ok,
    detail: ok ? `${invalid.detail} expected-semantic-rejection=${arm}` : describe(result),
  }
}

function report(label, outcome) {
  const prefix = outcome.ok ? "PASS" : "FAIL"
  console.error(`${prefix} ${label} ${outcome.detail}`)
  return outcome.ok ? 0 : 1
}

function fixtureCases(file) {
  const document = JSON.parse(fs.readFileSync(file.absolute, "utf8"))
  return Array.isArray(document) ? document : [document]
}

function runFixtures(binary, files, kind) {
  let failures = 0
  let cases = 0
  let semanticRejections = 0
  for (const file of files) {
    for (const [index, value] of fixtureCases(file).entries()) {
      cases += 1
      const meta = { kind, definition: file.definition, file: file.file, index }
      const label = `fixture ${file.file}[${index}]`
      try {
        if (kind === "invalid") {
          const control = execute(binary, wrapControl(meta), "probe")
          failures += report(`control ${file.file}[${index}]`, verdictOutcome(control))
        }
        const result = execute(binary, wrapFixture(value, meta), "probe")
        const arms = Object.keys(value)
        const semanticArm = kind === "valid" && file.definition === "TypedValueSelector" && arms.length === 1 &&
          EXPECTED_SEMANTIC_REJECTIONS.has(arms[0]) ? arms[0] : undefined
        if (semanticArm !== undefined) semanticRejections += 1
        const outcome = semanticArm === undefined
          ? kind === "valid" ? verdictOutcome(result) : invalidOutcome(result)
          : semanticRejectionOutcome(result, semanticArm)
        failures += report(label, outcome)
      } catch (error) {
        failures += report(label, { ok: false, detail: `harness-error=${error.stack || error.message}` })
      }
    }
  }
  return { failures, cases, semanticRejections }
}

function runProbes(binary) {
  let failures = 0
  for (const probe of PROBES) {
    const result = execute(binary, probe.config, probe.raw)
    if (probe.expectConfigInvalid) {
      failures += report(`probe ${probe.name}`, invalidOutcome(result))
      continue
    }
    const outcome = verdictOutcome(result)
    if (outcome.ok && outcome.detail !== `exit=0 verdict=${probe.expect}`) {
      outcome.ok = false
      outcome.detail += ` expected=${probe.expect}`
    }
    failures += report(`probe ${probe.name}`, outcome)
  }
  return { failures, cases: PROBES.length }
}

function main() {
  const { binary, fixtures } = parseArgs(process.argv)
  const validFiles = discover(fixtures, "valid")
  const invalidFiles = discover(fixtures, "invalid")
  console.error(`DISCOVER valid-files=${validFiles.length} invalid-files=${invalidFiles.length}`)
  const valid = runFixtures(binary, validFiles, "valid")
  const invalid = runFixtures(binary, invalidFiles, "invalid")
  const probes = runProbes(binary)
  const rejectionCount = {
    ok: valid.semanticRejections === EXPECTED_SEMANTIC_REJECTIONS.size,
    detail: `expected=${EXPECTED_SEMANTIC_REJECTIONS.size} actual=${valid.semanticRejections}`,
  }
  const failures = valid.failures + invalid.failures + probes.failures +
    report("expected semantic rejection count", rejectionCount)
  console.error(
    `SUMMARY fixture-cases=${valid.cases + invalid.cases} probes=${probes.cases} ` +
      `expected-semantic-rejections=${valid.semanticRejections} failures=${failures}`,
  )
  process.exit(failures === 0 ? 0 : 1)
}

try {
  main()
} catch (error) {
  console.error(`FATAL ${error.stack || error.message}`)
  process.exit(1)
}
