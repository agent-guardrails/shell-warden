"use strict"

const NO_REDIRECTS = { redirects: { none: true }, paths: { none: true } }

function config(profiles) {
  return {
    version: 2,
    defaults: { action: "ask", redirectPolicy: "no-redirects" },
    redirectPolicies: { "no-redirects": NO_REDIRECTS },
    profiles,
  }
}

function allow(id, argumentsPolicy, optionsPolicy, facts = { none: true }) {
  return {
    id,
    action: "allow",
    match: {
      classification: "complete",
      arguments: argumentsPolicy,
      options: optionsPolicy,
      environment: { none: true },
      paths: { none: true },
      facts,
      nestedParts: { none: true },
    },
  }
}

const COMMAND_CONFIG = config([
  {
    id: "ls", executables: ["ls"], options: {},
    rules: [allow("ls/tmp", { exact: ["/tmp"] }, { none: true })],
  },
  {
    id: "cat", executables: ["cat"], options: {},
    rules: [allow("cat/two", { exact: ["/tmp/x", "/tmp/y"] }, { none: true })],
  },
  {
    id: "npm", executables: ["npm"],
    options: { depth: { aliases: ["--depth"], arity: 1 } },
    rules: [allow("npm/ls", { exact: ["ls"] }, {
      allowed: [{ option: "depth", required: true, repeatable: false, values: { each: { oneOf: ["0"] } } }],
    })],
  },
  {
    id: "git", executables: ["git"], options: {},
    rules: [{ id: "git/deny-push", action: "deny", match: { arguments: { exact: ["push", "origin", "main"] } } }],
  },
])

const OPTION_CONFIG = config([{
  id: "cargo",
  executables: ["cargo"],
  options: {
    file: { aliases: ["--file"], arity: 1 },
    name: { aliases: ["--name"], arity: 1, inline: true },
    rename: { aliases: ["--rename"], arity: 2 },
  },
  rules: [allow("cargo/init", { exact: ["init"] }, {
    allowed: [
      { option: "file", required: false, repeatable: true, values: { each: { oneOf: ["a", "b"] } } },
      { option: "name", required: false, repeatable: false, values: { each: { oneOf: ["one"] } } },
      {
        option: "rename", required: false, repeatable: false,
        values: { byPosition: [{ oneOf: ["old"] }, { path: { within: "/work/project" } }] },
      },
    ],
  })],
}])

const SED_OPTIONS = {
  noPrint: { aliases: ["-n"], arity: 0 },
  extendedRegexp: { aliases: ["-E"], arity: 0 },
  inPlace: { aliases: ["-i"], arity: 0 },
  expression: { aliases: ["-e"], arity: 1 },
  file: { aliases: ["-f"], arity: 1 },
}

const READ_ONLY = {
  all: [
    { analyzer: "sed-v1", version: "1", name: "executionPrimitive", occurrence: "all", value: { exact: "readOnly" } },
    { analyzer: "sed-v1", version: "1", name: "programForm", occurrence: "all", value: { exact: "positional" } },
  ],
}

const SED_CONFIG = config([{
  id: "sed", executables: ["sed"], options: SED_OPTIONS, analyzer: "sed-v1",
  rules: [
    {
      id: "sed/deny-inplace", action: "deny",
      match: { facts: { any: [{ name: "executionPrimitive", value: { exact: "inPlace" } }] } },
    },
    allow("sed/n", { exact: ["1,5p", "file"] }, {
      allowed: [{ option: "noPrint", required: true, repeatable: false }],
    }, READ_ONLY),
    allow("sed/ere", { exact: ["s/a/b/", "file"] }, {
      allowed: [{ option: "extendedRegexp", required: true, repeatable: false }],
    }, READ_ONLY),
  ],
}])

const SED_UNCOVERED = config([{
  id: "sed", executables: ["sed"], options: {}, analyzer: "sed-v1",
  rules: [allow("sed/uncovered", { exact: ["s/a/b/", "file"] }, { none: true }, {
    all: [{ analyzer: "sed-v1", version: "1", name: "programForm", occurrence: "all", value: { exact: "positional" } }],
  })],
}])

const SED_WRONG_TYPE = config([{
  id: "sed", executables: ["sed"], options: {}, analyzer: "sed-v1",
  rules: [allow("sed/wrong-type", { exact: ["s/a/b/", "file"] }, { none: true }, {
    all: [{ analyzer: "sed-v1", version: "1", name: "executionPrimitive", occurrence: "all", value: { boolean: true } }],
  })],
}])

const PROBES = Object.freeze([
  { name: "command ls /tmp", config: COMMAND_CONFIG, raw: "ls /tmp", expect: "allow" },
  { name: "command cat two paths", config: COMMAND_CONFIG, raw: "cat /tmp/x /tmp/y", expect: "allow" },
  { name: "command npm fixed option", config: COMMAND_CONFIG, raw: "npm ls --depth 0", expect: "allow" },
  { name: "command git push", config: COMMAND_CONFIG, raw: "git push origin main", expect: "deny" },
  { name: "command node expression", config: COMMAND_CONFIG, raw: "node -e \"console.log(1)\"", expect: "ask" },
  { name: "option fixed arity covered", config: OPTION_CONFIG, raw: "cargo init --rename old /work/project/new", expect: "allow" },
  { name: "option fixed arity missing", config: OPTION_CONFIG, raw: "cargo init --rename old", expect: "ask" },
  { name: "option repeated each covered", config: OPTION_CONFIG, raw: "cargo init --file a --file b", expect: "allow" },
  { name: "option repeated each uncovered", config: OPTION_CONFIG, raw: "cargo init --file a --file x", expect: "ask" },
  { name: "option each missing value", config: OPTION_CONFIG, raw: "cargo init --file", expect: "ask" },
  { name: "option inline arity one covered", config: OPTION_CONFIG, raw: "cargo init --name=one", expect: "allow" },
  { name: "option inline arity one uncovered", config: OPTION_CONFIG, raw: "cargo init --name=two", expect: "ask" },
  { name: "option byPosition uncovered", config: OPTION_CONFIG, raw: "cargo init --rename new /work/project/old", expect: "ask" },
  { name: "fact sed -n read", config: SED_CONFIG, raw: "sed -n '1,5p' file", expect: "allow" },
  { name: "fact sed -E read", config: SED_CONFIG, raw: "sed -E s/a/b/ file", expect: "allow" },
  { name: "fact sed -i", config: SED_CONFIG, raw: "sed -i 's/a/b/' file", expect: "deny" },
  { name: "fact unknown option", config: SED_CONFIG, raw: "sed -x s/a/b/ file", expect: "ask" },
  { name: "fact missing safety coverage", config: SED_UNCOVERED, raw: "sed s/a/b/ file", expect: "ask" },
  { name: "fact wrong typed selector config", config: SED_WRONG_TYPE, raw: "sed s/a/b/ file", expectConfigInvalid: true },
])

module.exports = { PROBES }
