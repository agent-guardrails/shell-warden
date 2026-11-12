#!/usr/bin/env node
// Verdict battery runner: check a policy against a list of (command, expected verdict) cases.
// usage: node verdict-battery.cjs --config policy.jsonc --battery battery.json
// (paths may be relative; the battery resolves them to absolute — engine I2
// requires an absolute --config member)
// SHELL_WARDEN_BIN overrides the checker binary (default: discovery PATH -> homebrew fallback).
const { execFileSync } = require("node:child_process")
const path = require("node:path")

function parseArgs(argv) {
  const args = {}
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--config" || argv[i] === "--battery") args[argv[i].slice(2)] = argv[++i]
  }
  if (args.config) args.config = path.resolve(args.config)
  if (args.battery) args.battery = path.resolve(args.battery)
  if (!args.config || !args.battery) {
    console.error("usage: node verdict-battery.mjs --config policy.jsonc --battery battery.json")
    process.exit(2)
  }
  return args
}

function checkerBin() {
  if (process.env.SHELL_WARDEN_BIN) return process.env.SHELL_WARDEN_BIN
  for (const p of ["/opt/homebrew/bin/shell-warden"]) {
    try { require("node:fs").accessSync(p); return p } catch { /* next */ }
  }
  return "shell-warden"
}

function runCase(cfg, { raw }) {
  const letter = { version: 1, invocation: { id: "battery", sessionID: "battery" }, action: "shell", commands: [{ index: 0, cwd: process.cwd(), raw }] }
  // verdict v2 only (ADR-0023): the checker emits exactly {protocol, result}
  return JSON.parse(execFileSync(checkerBin(), ["--config", cfg], { encoding: "utf8", input: JSON.stringify(letter), timeout: 15_000 })).result
}

const { config, battery } = parseArgs(process.argv)
const { cases } = JSON.parse(require("node:fs").readFileSync(battery, "utf8"))
let fails = 0
for (const { raw, expect } of cases) {
  let verdict
  try {
    verdict = runCase(config, { raw }).verdict
  } catch (e) {
    verdict = "CONFIG_ERROR: " + String(e.stderr || e.message).trim().slice(0, 160)
  }
  if (verdict !== expect) {
    fails++
    console.error(`FAIL want=${expect} got=${verdict.padEnd(13)} | ${raw}`)
  }
}
console.error(`${cases.length - fails}/${cases.length} passed`)
process.exit(fails === 0 ? 0 : 1)
