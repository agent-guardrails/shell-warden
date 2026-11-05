#!/usr/bin/env node
// Shell-warden config v2 policy builder — builds a policies JSON document from
// composable helpers and profile factories. usage:
//   node policy-builder.mjs [out.jsonc]
// See design/shell-warden-config-v2.md in agent-guardrails/docs for the coverage
// model. Verified against engine 0.3.0 (2026-11-05; 131/132 battery).
//
// Coverage-model notes worth remembering (proven empirically):
// - allow = a total coverage proof (classification complete + every dimension
//   covered + redirect policy). A flag alone never carries an allow.
// - optionCoverage.values.each is LITERAL equality (no glob support) — a
//   free-form value (paths, names, messages) cannot be enumerated, hence the
//   arity-0 workaround: declare the option arity 0 so its value becomes a
//   positional argument covered by "remainder". Engine-side fix is tracked in
//   agent-guardrails/shell-warden issue 32: https://github.com/agent-guardrails/shell-warden/issues/32
// - remainder JSON is externally tagged with TWO levels:
//   {"none":{"none":true}} / {"each":{"each":{"within":root}}}
//   (the published schema lagged; grammar.rs is the ground truth).
const fs = require("node:fs")

// ── coverage helpers ─────────────────────────────────────────────────────────
const cov = (option) => ({ option, required: false, repeatable: false })
const valCov = (option, values) => ({ option, required: false, repeatable: false, values: { each: values } })
const rem = (within) => ({ each: { each: { within } } })
const NO_MORE = { none: { none: true } }
const ALLOW_TAIL = { environment: { none: true }, paths: { none: true }, facts: { none: true }, nestedParts: { none: true } }

const allowRule = (id, prefix, optionCoverage, root = "/") => ({
  id,
  action: "allow",
  match: {
    classification: "complete",
    arguments: { prefix, remainder: rem(root) },
    options: optionCoverage.length ? { allowed: optionCoverage.map((x) => (typeof x === "string" ? cov(x) : x)) } : { none: true },
    ...ALLOW_TAIL,
  },
})
const denyRule = (id, message, match) => ({ id, action: "deny", message, match })
const profile = (id, executables, options, rules) => ({ id, executables, options, rules, analyzer: "generic-v1" })

// version/help bare rule + per-subcommand allows sharing one coverage table
const subProfile = (exe, subs, options, coverage) => {
  const rules = [
    {
      id: exe + "/allow-bare",
      action: "allow",
      redirectPolicy: { mode: "replace", policies: ["no-redirects"] },
      match: { classification: "complete", arguments: { exact: [] }, options: { allowed: (coverage || []).map((x) => (typeof x === "string" ? cov(x) : x)) }, ...ALLOW_TAIL },
    },
  ]
  for (const sub of subs) rules.push(allowRule(exe + "/allow-" + sub, [sub], coverage))
  return profile(exe, [exe], options, rules)
}

// ── the policy payload (a real production policy, ported from v1) ────────────
const readers = ["ls", "cat", "head", "tail", "grep", "rg", "pwd", "which", "wc", "sort", "uniq", "cut", "diff", "jq", "yq", "file", "stat", "strings", "base64", "md5", "shasum", "column", "du", "df", "tree"]

const config = {
  version: 2,
  defaults: {
    action: "ask",
    message: "command not pre-approved by shell-warden — ask the human",
    redirectPolicy: "agent-writes",
  },
  redirectPolicies: {
    "agent-writes": {
      redirects: {
        all: [
          { sourceFd: "default", operator: ">", occurrence: "all", target: { kind: "literalPath" } },
          { sourceFd: "default", operator: ">>", occurrence: "all", target: { kind: "literalPath" } },
          { sourceFd: 2, operator: ">", occurrence: "all", target: { kind: "literalPath" } },
          { sourceFd: 2, operator: ">&", occurrence: "all", target: { kind: "fd" } },
        ],
      },
      paths: {
        all: [
          { coordinate: { redirect: { operator: ">", sourceFd: "default", occurrence: "all" } }, within: "/" },
          { coordinate: { redirect: { operator: ">>", sourceFd: "default", occurrence: "all" } }, within: "/" },
          { coordinate: { redirect: { operator: ">", sourceFd: 2, occurrence: "all" } }, within: "/" },
        ],
      },
    },
    "no-redirects": { redirects: { none: true }, paths: { none: true } },
  },
  profiles: [
    // readers: one profile per executable (v2 hard rule: a multi-exe profile
    // list must equal an implementation-owned alias catalog)
    ...readers.map((exe) =>
      profile("r-" + exe, [exe], {
        long: { aliases: ["-l", "-la", "-lah", "-lh", "-lt", "-lr"], arity: 0 },
        all: { aliases: ["-a"], arity: 0 },
        reverse: { aliases: ["-r"], arity: 0 },
        human: { aliases: ["-h"], arity: 0 },
        verbose: { aliases: ["-v"], arity: 0 },
        count: { aliases: ["-c"], arity: 0 },
        lines: { aliases: ["-n", "-1", "-2", "-3", "-4", "-5", "-10", "-15", "-20"], arity: 0 },
        ignoreCase: { aliases: ["-i"], arity: 0 },
        extended: { aliases: ["-E"], arity: 0 },
        quiet: { aliases: ["-q"], arity: 0 },
        recursive: { aliases: ["-R"], arity: 0 },
        squeeze: { aliases: ["-s"], arity: 0 },
        delim: { aliases: ["-d"], arity: 0 },
        delimColon: { aliases: ["-d:"], arity: 0 },
        fields: { aliases: ["-f"], arity: 0 },
        fieldsOne: { aliases: ["-f1", "-f2", "-f3", "-f4", "-f1-3", "-f2-"], arity: 0 },
        grepCombos: { aliases: ["-rn", "-rni", "-ri", "-in", "-lni", "-rnE", "-rEF", "-rnF", "-L", "-w", "-o"], arity: 0 },
      }, [
        allowRule("r-" + exe + "/allow", [], [
          cov("long"), cov("all"), cov("reverse"), cov("human"), cov("verbose"), cov("count"),
          cov("lines"), cov("ignoreCase"), cov("extended"), cov("quiet"), cov("recursive"),
          cov("squeeze"), cov("delim"), cov("delimColon"), cov("fields"), cov("fieldsOne"),
          cov("grepCombos"),
        ]),
      ])),
    // bare form allows
    ...["echo", "printf", "sleep", "true", "false", "cd"].map((exe) =>
      profile("s-" + exe, [exe], {}, [allowRule("s-" + exe + "/allow", [], [])])),
    profile("date", ["date"], { utc: { aliases: ["-u"], arity: 0 } }, [allowRule("date/allow", [], ["utc"])]),
    profile("mkdir", ["mkdir"], { parents: { aliases: ["-p"], arity: 0 } }, [allowRule("mkdir/allow", [], [cov("parents")])]),
    profile("ps", ["ps"], { every: { aliases: ["-e", "-ef", "-aux"], arity: 0 }, full: { aliases: ["-f"], arity: 0 } }, [allowRule("ps/allow", [], ["every", "full"])]),
    profile("lsof", ["lsof"], { tcp: { aliases: ["-i"], arity: 0 }, numeric: { aliases: ["-n"], arity: 0 }, ports: { aliases: ["-P"], arity: 0 } }, [allowRule("lsof/allow", [], ["tcp", "numeric", "ports"])]),
    profile("openspec", ["openspec"], { strict: { aliases: ["--strict"], arity: 0 }, json: { aliases: ["--json"], arity: 0 }, help: { aliases: ["--help"], arity: 0 } }, [allowRule("openspec/allow", [], ["strict", "json", "help"])]),
    // git: deny rules first, per-subcommand allows with generous flag coverage
    profile("git", ["git"], {
      m: { aliases: ["-m"], arity: 0 },
      force: { aliases: ["--force", "-f"], arity: 0 },
      forceLease: { aliases: ["--force-with-lease"], arity: 0 },
      dryRun: { aliases: ["--dry-run"], arity: 0 },
      oneline: { aliases: ["--oneline"], arity: 0 },
      nums: { aliases: ["-1", "-2", "-3", "-4", "-5", "-8", "-9", "-10", "-20", "-30", "-50"], arity: 0 },
      showToplevel: { aliases: ["--show-toplevel"], arity: 0 },
      abbrev: { aliases: ["--abbrev-ref"], arity: 0 },
      short: { aliases: ["--short"], arity: 0 },
      stat: { aliases: ["--stat"], arity: 0 },
      graph: { aliases: ["--graph"], arity: 0 },
      numstat: { aliases: ["--numstat"], arity: 0 },
      porcelain: { aliases: ["--porcelain"], arity: 0 },
      nameOnly: { aliases: ["--name-only"], arity: 0 },
      decorate: { aliases: ["--decorate"], arity: 0 },
      quiet: { aliases: ["-q", "--quiet"], arity: 0 },
      b: { aliases: ["-b"], arity: 0 },
      amend: { aliases: ["--amend"], arity: 0 },
      all: { aliases: ["-a", "-A", "--all"], arity: 0 },
      delete: { aliases: ["-d", "-D", "--delete"], arity: 0 },
    }, [
      denyRule("git/deny-force-push", "git push --force rewrites remote history — forbidden",
        { arguments: { prefix: ["push"] }, options: { presentAny: ["force", "forceLease"] } }),
      denyRule("git/deny-push-delete", "deleting remote branches is forbidden",
        { arguments: { prefix: ["push"] }, options: { presentAny: ["delete"] } }),
      denyRule("git/deny-push-main-refspec", "pushing the default branch (main/master) from an agent is forbidden",
        { arguments: { prefix: ["push"], containsAny: ["main", "master", ":main", ":master"] } }),
      allowRule("git/allow-status", ["status"], ["short", "porcelain", "nameOnly", "quiet"]),
      allowRule("git/allow-log", ["log"], ["oneline", "stat", "graph", "numstat", "nameOnly", "decorate", "quiet", "nums"]),
      allowRule("git/allow-diff", ["diff"], ["stat", "numstat", "nameOnly", "quiet"]),
      allowRule("git/allow-show", ["show"], ["oneline", "stat", "nameOnly", "quiet"]),
      allowRule("git/allow-rev-parse", ["rev-parse"], ["quiet", "showToplevel", "abbrev"]),
      allowRule("git/allow-ls-files", ["ls-files"], []),
      allowRule("git/allow-blame", ["blame"], []),
      allowRule("git/allow-branch-list", ["branch"], ["quiet"]),
      allowRule("git/allow-add", ["add"], ["all"]),
      // arity-0 "-m": the commit message becomes a positional covered by
      // remainder (free-form values cannot be enumerated;
      // engine-side fix: https://github.com/agent-guardrails/shell-warden/issues/32)
      allowRule("git/allow-commit", ["commit"], ["m", "amend", "all", "quiet"]),
      allowRule("git/allow-fetch", ["fetch"], ["quiet"]),
      allowRule("git/allow-stash", ["stash"], []),
      allowRule("git/allow-switch", ["switch"], []),
      allowRule("git/allow-checkout-new", ["checkout"], ["b", "quiet"]),
      allowRule("git/allow-clone", ["clone"], ["quiet"]),
      {
        id: "git/allow-push-simple",
        action: "allow",
        redirectPolicy: { mode: "replace", policies: ["no-redirects"] },
        match: { classification: "complete", arguments: { prefix: ["push"], remainder: rem("/") }, options: { allowed: ["quiet", "dryRun"].map(cov) }, ...ALLOW_TAIL },
      },
    ]),
    // rm: deny home/system first, then tmp-class allows on disjoint roots
    profile("rm", ["rm"], {
      force: { aliases: ["-f"], arity: 0 },
      recursive: { aliases: ["-r", "-R"], arity: 0 },
      recursiveForce: { aliases: ["-rf", "-fr"], arity: 0 },
      verbose: { aliases: ["-v"], arity: 0 },
    }, [
      denyRule("rm/deny-root-dir", "removing the filesystem root is forbidden", { arguments: { containsAny: ["/"] } }),
      denyRule("rm/deny-home", "removing $HOME parts is forbidden", { arguments: { containsAny: ["~", "~/*", "/Users/*"] } }),
      denyRule("rm/deny-system", "removing system paths is forbidden",
        { arguments: { containsAny: ["/etc/*", "/usr/*", "/bin/*", "/sbin/*", "/System/*", "/Library/*", "/Applications/*", "/opt/*", "/dev/*", "/Volumes/*"] } }),
      {
        id: "rm/allow-tmp",
        action: "allow",
        redirectPolicy: { mode: "replace", policies: ["no-redirects"] },
        match: { classification: "complete", arguments: { prefix: [], remainder: rem("/tmp") }, options: { allowed: ["force", "recursive", "recursiveForce", "verbose"].map(cov) }, ...ALLOW_TAIL },
      },
      {
        id: "rm/allow-var-folders",
        action: "allow",
        redirectPolicy: { mode: "replace", policies: ["no-redirects"] },
        match: { classification: "complete", arguments: { prefix: [], remainder: rem("/private/var/folders") }, options: { allowed: ["force", "recursive", "recursiveForce", "verbose"].map(cov) }, ...ALLOW_TAIL },
      },
    ]),
    // gh: read-only subcommands; mutating gh api stays with the human
    {
      id: "find", executables: ["find"], analyzer: "generic-v1",
      options: {
        name: { aliases: ["-name"], arity: 0 }, iname: { aliases: ["-iname"], arity: 0 },
        type: { aliases: ["-type"], arity: 0 }, maxDepth: { aliases: ["-maxdepth"], arity: 0 },
        minDepth: { aliases: ["-mindepth"], arity: 0 }, print: { aliases: ["-print"], arity: 0 },
        mtime: { aliases: ["-mtime"], arity: 0 }, size: { aliases: ["-size"], arity: 0 },
        not: { aliases: ["-not", "!"], arity: 0 }
      },
      rules: [allowRule("find/allow-read", [], ["name", "iname", "type", "maxDepth", "minDepth", "print", "mtime", "size", "not"])],
    },
    profile("awk", ["awk"], { program: { aliases: ["-f"], arity: 0 }, separator: { aliases: ["-F"], arity: 0 }, assign: { aliases: ["-v"], arity: 0 } }, [allowRule("awk/allow", [], ["program", "separator", "assign"])]),
    profile("gh", ["gh"], {
      repo: { aliases: ["-R", "--repo"], arity: 0 },
      limit: { aliases: ["-L", "--limit"], arity: 0 },
      json: { aliases: ["--json"], arity: 0 },
      jq: { aliases: ["--jq"], arity: 0 },
      field: { aliases: ["-f", "--field"], arity: 0 },
      rawField: { aliases: ["-F"], arity: 0 },
      input: { aliases: ["--input"], arity: 0 },
      method: { aliases: ["-X", "--method"], arity: 0 },
      template: { aliases: ["-t", "--template"], arity: 0 },
      quiet: { aliases: ["-q"], arity: 0 },
    }, [
      allowRule("gh/allow-auth-status", ["auth", "status"], []),
      allowRule("gh/allow-pr-view", ["pr", "view"], ["repo", "json", "jq", "template"]),
      allowRule("gh/allow-pr-list", ["pr", "list"], ["repo", "limit", "json"]),
      allowRule("gh/allow-pr-diff", ["pr", "diff"], ["repo"]),
      allowRule("gh/allow-issue-view", ["issue", "view"], ["repo", "json", "jq"]),
      allowRule("gh/allow-issue-list", ["issue", "list"], ["repo", "limit"]),
      allowRule("gh/allow-release-view", ["release", "view"], ["repo"]),
      allowRule("gh/allow-release-list", ["release", "list"], ["repo", "limit"]),
      allowRule("gh/allow-run-list", ["run", "list"], ["repo", "limit"]),
      allowRule("gh/allow-run-view", ["run", "view"], ["repo", "json"]),
      allowRule("gh/allow-api-get", ["api"], ["jq", "quiet"]),
    ]),
    // dev tools: bare version/help plus safe subcommands (own profile each)
    {
      id: "node", executables: ["node"], analyzer: "generic-v1",
      options: { version: { aliases: ["--version", "-V"], arity: 0 }, help: { aliases: ["--help", "-h"], arity: 0 }, test: { aliases: ["--test"], arity: 0 } },
      rules: [{
        id: "node/allow-bare", action: "allow",
        redirectPolicy: { mode: "replace", policies: ["no-redirects"] },
        match: { classification: "complete", arguments: { exact: [] }, options: { allowed: [cov("version"), cov("help"), cov("test")] }, ...ALLOW_TAIL },
      }],
    },
    subProfile("npm", ["test", "view", "info", "list", "search", "ping", "tree"], {
      version: { aliases: ["--version", "-v", "-V"], arity: 0 },
      help: { aliases: ["--help", "-h"], arity: 0 },
      global: { aliases: ["-g"], arity: 0 },
      json: { aliases: ["--json"], arity: 0 },
      quiet: { aliases: ["--silent", "-s"], arity: 0 },
    }, ["version", "help", "global", "json", "quiet"]),
    subProfile("pnpm", ["list"], {
      version: { aliases: ["--version", "-v", "-V"], arity: 0 },
      help: { aliases: ["--help", "-h"], arity: 0 },
      depth: { aliases: ["--depth"], arity: 0 },
    }, ["version", "help", "depth"]),
    subProfile("bun", [], {
      version: { aliases: ["--version", "-v", "-V"], arity: 0 },
      help: { aliases: ["--help", "-h"], arity: 0 },
    }, ["version", "help"]),
    subProfile("cargo", ["build", "check", "clippy", "fmt", "test", "init", "metadata", "locate-project", "tree"], {
      version: { aliases: ["--version", "-V"], arity: 0 },
      help: { aliases: ["--help", "-h"], arity: 0 },
      quiet: { aliases: ["-q", "--quiet"], arity: 0 },
      release: { aliases: ["--release"], arity: 0 },
      name: { aliases: ["--name"], arity: 0 },
      manifest: { aliases: ["--manifest-path"], arity: 0 },
      offline: { aliases: ["--offline"], arity: 0 },
    }, ["version", "help", "quiet", "release", "name", "manifest", "offline"]),
    {
      id: "go", executables: ["go"], analyzer: "generic-v1",
      options: { verbose: { aliases: ["-v"], arity: 0 } },
      rules: [
        {
          id: "go/allow-version", action: "allow",
          redirectPolicy: { mode: "replace", policies: ["no-redirects"] },
          match: { classification: "complete", arguments: { prefix: ["version"], remainder: NO_MORE }, options: { none: true }, ...ALLOW_TAIL },
        },
        allowRule("go/allow-build", ["build"], ["verbose"]),
        allowRule("go/allow-fmt", ["fmt"], ["verbose"]),
        allowRule("go/allow-test", ["test"], ["verbose"]),
        allowRule("go/allow-vet", ["vet"], ["verbose"]),
      ],
    },
    profile("sed", ["sed"], { inPlace: { aliases: ["-i"], arity: 0 }, expression: { aliases: ["-e"], arity: 0 }, file: { aliases: ["-f"], arity: 0 } }, [
      denyRule("sed/deny-inplace-system", "in-place edits of system paths are forbidden",
        { arguments: { containsAny: ["/etc", "/etc/*", "/usr/*", "/System/*", "/Library/*", "/Applications/*", "/private/etc*"] } }),
      // NOTE: sed-v1 analyzer has a closed option table — bare "sed script file"
      // is allowed; "sed -n" reads degrade to ask until
      // https://github.com/agent-guardrails/shell-warden/issues/32 lands
      allowRule("sed/allow", [], ["inPlace", "expression"]),
    ]),
  ],
}

const out = process.argv[2] || "policy.jsonc"
fs.writeFileSync(out, JSON.stringify(config, null, 1))
const ruleCount = config.profiles.reduce((n, p) => n + p.rules.length, 0)
console.log("policy written: " + out + " (profiles: " + config.profiles.length + ", rules: " + ruleCount + ")")
