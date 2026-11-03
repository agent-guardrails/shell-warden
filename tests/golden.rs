// Golden suite: letter checker CLI — legacy letter JSON in, verdict JSON out.
// Repointed to the shell-warden-letter bin (see #16); migrating the golden
// table to the orchestrator `check --file` single-shot mode per 10-testing
// §10.2 is tracked separately.
// JSON out, subset diffed against the case's `expect`. Every case lives in
// tests/golden/cases/*.json referencing examples/configs. Spawn latency is
// recorded per case (10 §10.6); the 10 ms p95 gate is checked on the runner
// host before the M1 merge — this suite only guards gross drift in CI.

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

const BIN: &str = env!("CARGO_BIN_EXE_shell-warden-letter");
const CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/configs/shell-warden.example.jsonc"
);

fn run_case(name: &str, case: &Value) -> Value {
    let letter = format!("{}\n", serde_json::to_string(&case["letter"]).unwrap());
    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(CONFIG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shell-warden");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(letter.as_bytes())
        .unwrap();
    let started = Instant::now();
    let out = child.wait_with_output().expect("wait");
    let ms = started.elapsed().as_millis();
    eprintln!("case {name}: spawnMs={ms}");
    if !out.status.success() {
        panic!(
            "case {name}: checker exited non-zero: {:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("case {name}: verdict not one JSON value: {e}"))
}

/// Subset semantics (10 §10.2): every field present in `expect` must match the
/// actual; extra fields on the actual are ignored. Array expectations declare
/// their element by its `index` field.
fn subset_matches(actual: &Value, expect: &Value) -> bool {
    match (actual, expect) {
        (Value::Object(a), Value::Object(e)) => e
            .iter()
            .all(|(k, ev)| a.get(k).map(|av| subset_matches(av, ev)).unwrap_or(false)),
        (Value::Array(a), Value::Array(e)) => {
            // element-wise; an expect element declaring `index` anchors to the
            // actual element at that position (10 §10.2)
            e.iter()
                .all(|ev| match ev.get("index").and_then(Value::as_u64) {
                    Some(i) => a
                        .get(i as usize)
                        .map(|item| subset_matches(item, ev))
                        .unwrap_or(false),
                    None => a.iter().any(|item| subset_matches(item, ev)),
                })
        }
        (a, e) => a == e,
    }
}

/// expect.message supports a `contains:` prefix (substring comparison, 10 §10.2
/// runner behavior documented in tests/golden/_schema.txt).
fn case_matches(actual: &Value, expect: &Value) -> bool {
    if let Some(msg) = expect.get("message").and_then(Value::as_str) {
        if let Some(needle) = msg.strip_prefix("contains:") {
            let ok = actual["message"]
                .as_str()
                .map(|m| m.contains(needle))
                .unwrap_or(false);
            let mut e2 = expect.clone();
            e2.as_object_mut().unwrap().remove("message");
            return ok && subset_matches(actual, &e2);
        }
    }
    subset_matches(actual, expect)
}

#[test]
fn version_flag_matches_crate() {
    let out = Command::new(BIN)
        .arg("--version")
        .output()
        .expect("spawn shell-warden --version");
    assert!(out.status.success(), "--version must exit 0");
    let line = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        line,
        format!("shell-warden {}\n", env!("CARGO_PKG_VERSION")),
        "--version must print exactly \"shell-warden <crate version>\"; the tap formula test matches on this"
    );
}

#[test]
fn golden_cases() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/cases");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("golden cases directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no golden cases found");

    for path in entries {
        let name = path.display().to_string();
        let case: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("case {name} is not one JSON value: {e}"));
        let actual = run_case(&name, &case);
        let expect = &case["expect"];
        if !case_matches(&actual, expect) {
            panic!(
                "case {name}\nactual: {}\nexpected subset: {}",
                serde_json::to_string_pretty(&actual).unwrap(),
                serde_json::to_string_pretty(expect).unwrap()
            );
        }
    }
}
