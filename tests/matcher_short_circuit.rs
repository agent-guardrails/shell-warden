use serde_json::{Value, json};
use shell_warden::checker::verdict::VerdictEnvelope;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn policy(restriction: Value) -> Value {
    json!({
        "version":3,
        "defaults":{"action":"ask","redirectPolicy":"none"},
        "redirectPolicies":{"none":{"redirects":{"none":true},"paths":{"none":true}}},
        "profiles":[{
            "id":"echo","executables":["echo"],"options":{},"analyzer":"generic-v1",
            "rules":[
                {"id":"restriction","action":"deny","message":"Restricted command.",
                    "match":restriction},
                {"id":"allow","action":"allow","match":{
                    "arguments":{"prefix":[],"remainder":{"each":{"any":true}}},
                    "options":{"none":true},"environment":{"none":true},
                    "paths":{"none":true},"facts":{"none":true},"nestedParts":{"none":true}
                }}
            ]
        }]
    })
}

fn timed_cli(config: &Value, raw: &str) -> Value {
    struct ConfigFile(std::path::PathBuf);
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.0.join("config.json")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }
    struct Process(Option<Child>);
    impl Drop for Process {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sw-matcher-short-circuit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    let file = ConfigFile(dir);
    std::fs::write(file.0.join("config.json"), config.to_string()).unwrap();
    let input = json!({
        "version":1,"invocation":{"id":"matcher:deadline","sessionID":"test"},
        "action":"shell","commands":[{"index":0,"raw":raw,"cwd":"/repo"}]
    });
    // The checker only analyzes this text; no submitted command is executed.
    let mut process = Process(Some(
        Command::new(env!("CARGO_BIN_EXE_shell-warden"))
            .arg("--config")
            .arg(file.0.join("config.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    process
        .0
        .as_mut()
        .unwrap()
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let started = Instant::now();
    loop {
        if process.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "checker exceeded two seconds for {raw}; restriction: {}",
            config["profiles"][0]["rules"][0]["match"]
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // This single-command test produces a small, bounded verdict.
    let output = process.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope: VerdictEnvelope = serde_json::from_slice(&output.stdout).unwrap();
    envelope.validate_against("matcher:deadline", 1).unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

fn costly_glob() -> String {
    format!("{}b", "*a".repeat(22))
}

#[test]
fn classification_no_match_skips_the_later_raw_glob_in_the_real_cli() {
    let config = policy(json!({"classification":"opaque","raw":costly_glob()}));
    let output = timed_cli(&config, &format!("echo {}", "a".repeat(44)));
    assert_eq!(output["result"]["verdict"], "allow");
    assert_eq!(output["result"]["commands"][0]["classification"], "static");

    let applicable = policy(json!({"classification":"complete","raw":"echo *"}));
    assert_eq!(
        timed_cli(&applicable, "echo safe")["result"]["verdict"],
        "deny"
    );
}

#[test]
fn argument_no_match_skips_later_contains_any_globs_in_the_real_cli() {
    for mismatch in [
        json!({"prefix":["different"]}),
        json!({"exact":["different"]}),
        json!({"prefix":["too","many"]}),
    ] {
        let mut arguments = mismatch;
        arguments["containsAny"] = json!([costly_glob()]);
        let config = policy(json!({"arguments":arguments}));
        let output = timed_cli(&config, &format!("echo {}", "a".repeat(44)));
        assert_eq!(output["result"]["verdict"], "allow");
    }
}
