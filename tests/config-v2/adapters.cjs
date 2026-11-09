"use strict"

const NO_REDIRECTS = { redirects: { none: true }, paths: { none: true } }

function allowMatch(overrides = {}) {
  return {
    classification: "complete",
    arguments: { exact: [] },
    options: { none: true },
    environment: { none: true },
    paths: { none: true },
    facts: { none: true },
    nestedParts: { none: true },
    ...overrides,
  }
}

function profile(overrides = {}) {
  return { id: "probe", executables: ["probe"], options: {}, rules: [], ...overrides }
}

function config(primary, redirectPolicies = {}) {
  return {
    version: 2,
    defaults: { action: "ask", redirectPolicy: "no-redirects" },
    redirectPolicies: { "no-redirects": NO_REDIRECTS, ...redirectPolicies },
    profiles: [primary],
  }
}

function withRule(rule, overrides = {}) {
  return config(profile({ rules: [rule], ...overrides }))
}

function ordinary(dimension, value, overrides = {}) {
  return withRule(
    { id: "probe/rule", action: "ask", match: { [dimension]: value } },
    overrides,
  )
}

function allowing(dimension, value, overrides = {}) {
  return withRule(
    { id: "probe/allow", action: "allow", match: allowMatch({ [dimension]: value }) },
    overrides,
  )
}

function nestedHost(rule) {
  const wrapped = config(profile({
    id: "xargs", executables: ["xargs"], analyzer: "xargs-v1", rules: [rule],
  }))
  wrapped.profiles.push(profile({ id: "rm-safe", executables: ["rm"] }))
  return wrapped
}

function sedHost(rule, overrides = {}) {
  return config(profile({
    id: "sed", executables: ["sed"], analyzer: "sed-v1", rules: [rule], ...overrides,
  }))
}

function definitionError(meta, arm) {
  throw new Error(
    `unsupported fixture arm kind=${meta.kind} definition=${meta.definition} ` +
      `file=${meta.file} index=${meta.index} arm=${arm}`,
  )
}

function pathCoordinate(value, meta) {
  const arms = Object.keys(value)
  const known = new Set(["argument", "optionValue", "environment", "redirect", "analyzerFact"])
  if (!arms.every((arm) => known.has(arm))) definitionError(meta, arms.join(",") || "empty")
  if (arms.length === 1 && arms[0] === "redirect") {
    const policy = { redirects: { none: true }, paths: { all: [{ coordinate: value, within: "/tmp" }] } }
    return config(profile(), { fixture: policy })
  }
  return config(profile({
    executables: ["sed"],
    analyzer: "sed-v1",
    options: { file: { aliases: ["--file"], arity: 1 } },
    pathSources: [value],
  }))
}

function typedSelector(value, meta) {
  const arms = Object.keys(value)
  const known = new Set(["any", "exact", "string", "integer", "number", "boolean", "path"])
  if (arms.length !== 1 || !known.has(arms[0])) definitionError(meta, arms.join(",") || "empty")
  const fact = {
    analyzer: "sed-v1", version: "1", name: "executionPrimitive", occurrence: "all", value,
  }
  return sedHost({
    id: "sed/allow", action: "allow", match: allowMatch({ facts: { all: [fact] } }),
  })
}

const ADAPTERS = Object.freeze({
  AllowMatch: (value) => {
    const wrapped = sedHost(
      { id: "sed/allow", action: "allow", match: value },
      {
        options: { file: { aliases: ["--file"], arity: 1 } },
        pathSources: [{ argument: { index: 1 } }],
      },
    )
    wrapped.profiles.push(profile({ id: "rm-safe", executables: ["rm"] }))
    return wrapped
  },
  ArgumentsMatcher: (value) => ordinary("arguments", value),
  Config: (value) => value,
  EnvironmentMatcher: (value) => ordinary("environment", value),
  EnvironmentPolicy: (value) => allowing("environment", { all: [value] }),
  FactPolicy: (value) => sedHost({
    id: "sed/allow", action: "allow", match: allowMatch({ facts: { all: [value] } }),
  }),
  FactsMatcher: (value) => sedHost({ id: "sed/ask", action: "ask", match: { facts: value } }),
  NestedPartPolicy: (value) => nestedHost({
    id: "xargs/allow", action: "allow", match: allowMatch({ nestedParts: { all: [value] } }),
  }),
  NestedPartsMatcher: (value) => nestedHost({
    id: "xargs/ask", action: "ask", match: { nestedParts: value },
  }),
  OptionCoverage: (value) => allowing("options", { allowed: [value] }, {
    options: { verbose: { aliases: ["--verbose"], arity: 0 } },
  }),
  OptionSpec: (value) => config(profile({ options: { specimen: value } })),
  OptionValueCoverage: (value) => allowing("options", {
    allowed: [{ option: "rename", required: false, repeatable: true, values: value }],
  }, { options: { rename: { aliases: ["--rename"], arity: 2 } } }),
  OptionsCoverage: (value) => allowing("options", value, {
    options: {
      verbose: { aliases: ["--verbose"], arity: 0 },
      file: { aliases: ["--file"], arity: 1 },
    },
  }),
  OptionsMatcher: (value) => ordinary("options", value, {
    options: {
      dryRun: { aliases: ["--dry-run"], arity: 0 },
      verbose: { aliases: ["--verbose"], arity: 0 },
      quiet: { aliases: ["--quiet"], arity: 0 },
      force: { aliases: ["--force"], arity: 0 },
      format: { aliases: ["--format"], arity: 1 },
    },
  }),
  PathCoordinateSelector: pathCoordinate,
  PathSelector: (value) => allowing("arguments", {
    prefix: [], remainder: { each: { path: value } },
  }),
  PathsMatcher: (value) => ordinary("paths", value, {
    pathSources: [{ argument: { index: 1 } }],
  }),
  PositiveArityOptionCoverage: (value) => allowing("options", { allowed: [value] }, {
    options: { file: { aliases: ["--file"], arity: 1 } },
  }),
  PositionalCoordinate: (value) => config(profile({ pathSources: [{ argument: value }] })),
  RedirectMatcher: (value) => ordinary("redirects", value),
  RedirectPolicy: (value) => ({
    version: 2,
    defaults: { action: "ask", redirectPolicy: "fixture" },
    redirectPolicies: { fixture: value },
    profiles: [],
  }),
  RedirectPolicyOverride: (value) => config(
    profile({ redirectPolicy: value }),
    { "safe-local-io": NO_REDIRECTS },
  ),
  RemainderPolicy: (value) => allowing("arguments", { prefix: [], remainder: value }),
  Rule: (value, meta) => {
    if (value.action !== "ask" && value.action !== "deny" && value.action !== "allow") {
      definitionError(meta, String(value.action))
    }
    return withRule(value, { options: { force: { aliases: ["--force"], arity: 0 } } })
  },
  StringValueSelector: (value) => ordinary("options", { values: { format: value } }, {
    options: { format: { aliases: ["--format"], arity: 1 } },
  }),
  TokenSelector: (value) => allowing("arguments", { prefix: [], remainder: { each: value } }),
  TypedValueSelector: typedSelector,
})

const CONTROLS = Object.freeze({
  AllowMatch: allowMatch(), ArgumentsMatcher: { prefix: ["ok"] },
  Config: config(profile()), EnvironmentMatcher: { none: true },
  EnvironmentPolicy: { name: "LANG", prefix: true, occurrence: "all" },
  FactPolicy: { analyzer: "sed-v1", version: "1", name: "executionPrimitive", occurrence: "all", value: { any: true } },
  FactsMatcher: { none: true },
  NestedPartPolicy: { relation: "analyzer-command", occurrence: 1, profile: "rm-safe", classification: "complete", verdict: "ask" },
  NestedPartsMatcher: { none: true },
  OptionCoverage: { option: "verbose", required: false, repeatable: false },
  OptionSpec: { aliases: ["--specimen"], arity: 0 },
  OptionValueCoverage: { byPosition: [{ any: true }, { any: true }] },
  OptionsCoverage: { none: true }, OptionsMatcher: { none: true },
  PathCoordinateSelector: { argument: { index: 0 } }, PathSelector: { within: "/tmp" },
  PathsMatcher: { none: true },
  PositiveArityOptionCoverage: { option: "file", required: false, repeatable: true, values: { each: { any: true } } },
  PositionalCoordinate: { index: 0 }, RedirectMatcher: { none: true },
  RedirectPolicy: NO_REDIRECTS, RedirectPolicyOverride: { mode: "inherit" },
  RemainderPolicy: { none: true },
  Rule: { id: "probe/ask", action: "ask", match: { classification: "complete" } },
  StringValueSelector: { any: true }, TokenSelector: { any: true }, TypedValueSelector: { any: true },
})

function adapterFor(definition, meta) {
  const adapter = ADAPTERS[definition]
  if (adapter === undefined) definitionError(meta, "definition")
  return adapter
}

function wrapFixture(value, meta) {
  return adapterFor(meta.definition, meta)(value, meta)
}

function wrapControl(meta) {
  const control = CONTROLS[meta.definition]
  if (control === undefined) definitionError(meta, "control")
  return adapterFor(meta.definition, meta)(control, meta)
}

module.exports = { wrapControl, wrapFixture }
