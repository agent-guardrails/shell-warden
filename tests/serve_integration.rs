// Contract test: drives the engine exactly like the shim does (02 §2.10) —
// NDJSON requests on stdin, responses read back with the same ids. Wire shapes
// are held against the shim's expectations (opencode-shell-warden-hook,
// test/helpers/mock-engine.mjs and src/supervisor.ts route()).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

struct Engine {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: BufReader<std::process::ChildStdout>,
    _config: TempDirGuard,
}

/// Owns a temp dir with the engine config; removes it on drop.
struct TempDirGuard {
    dir: std::path::PathBuf,
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write_config(body: &str) -> TempDirGuard {
    let dir = std::env::temp_dir().join(format!(
        "shell-warden-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    std::fs::write(dir.join("config.jsonc"), body).expect("write config");
    TempDirGuard { dir }
}

impl Engine {
    fn spawn(config: TempDirGuard) -> Engine {
        let config_path = config.dir.join("config.jsonc");
        let mut child = Command::new(env!("CARGO_BIN_EXE_shell-warden"))
            .arg("serve")
            .arg("--config")
            .arg(&config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn engine");
        let stdin = child.stdin.take().unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        Engine { child, stdin: Some(stdin), reader, _config: config }
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn send_value(&mut self, v: &Value) {
        self.send(&serde_json::to_string(v).unwrap());
    }

    /// Read one response line. Panics with the engine's stderr when stdout is
    /// empty — that usually means the engine crashed.
    fn read(&mut self) -> Value {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).expect("read stdout");
        if n == 0 {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("engine stdout closed early; stderr:\n{stderr}");
        }
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("non-JSON line `{line}`: {e}"))
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send_value(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        self.read()
    }

    /// Close stdin and reap the process (clean-EOF path).
    fn wait_after_eof(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("wait")
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const VALID_CONFIG: &str = r#"{
    // user-global stage config (06 §6.1)
    "version": 1,
    "stages": [
        { "id": "s1", "type": "tool", "tool": { "command": ["/bin/echo"], "timeoutMs": 1000 } },
    ],
}"#;

const INVALID_CONFIG: &str = r#"{ "version": 2, "stages": [] }"#;

fn check_params(raw: &str) -> Value {
    json!({
        "invocation": { "id": "msg_1:call_1", "sessionID": "ses_1", "agent": "build", "hook": "permission.evaluate" },
        "action": "shell",
        "commands": [ { "index": 0, "raw": raw, "cwd": "/work/repo" } ]
    })
}

#[test]
fn handshake_and_check_follow_the_wire_contract() {
    let mut eng = Engine::spawn(write_config(VALID_CONFIG));

    // initialize (02 §2.3): config echo reflects the active file (05 §5.3)
    let reply = eng.request(1, "initialize", json!({ "protocolVersion": 1, "client": { "name": "opencode-shell-warden-hook", "version": "0.1.0", "opencode": "2.4.1" } }));
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["protocolVersion"], 1);
    assert_eq!(reply["result"]["engine"]["name"], "shell-warden");
    assert!(reply["result"]["capabilities"].is_object());
    assert_eq!(reply["result"]["config"]["stages"], json!(["s1"]));
    assert!(reply["result"]["config"]["source"].as_str().unwrap().ends_with("config.jsonc"));
    assert!(reply["result"]["config"]["loadedAt"].as_str().unwrap().ends_with('Z'));

    // policy/check (02 §2.4): interim fail-closed verdict ask, same id
    let reply = eng.request(7, "policy/check", check_params("git push origin main"));
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"]["invocationId"], "msg_1:call_1");
    assert_eq!(reply["result"]["verdict"], "ask");
    assert_eq!(reply["result"]["commands"][0]["index"], 0);
    assert_eq!(reply["result"]["commands"][0]["verdict"], "ask");
    assert!(reply["result"]["engine"]["checkMs"].is_number());
}

#[test]
fn invalid_config_is_fatal_but_never_fail_open() {
    let mut eng = Engine::spawn(write_config(INVALID_CONFIG));

    // Handshake still succeeds (05 §5.3: "start anyway").
    let reply = eng.request(1, "initialize", json!({ "protocolVersion": 1, "client": { "name": "hook", "version": "0.1.0" } }));
    assert_eq!(reply["result"]["protocolVersion"], 1);
    assert_eq!(reply["result"]["config"]["stages"], json!([]));

    // Every policy/check is answered -32001 with data.fatal=true.
    let reply = eng.request(2, "policy/check", check_params("ls"));
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["error"]["code"], -32001);
    assert_eq!(reply["error"]["data"]["fatal"], true);

    // Engine stays alive: a later request still gets an answer.
    let reply = eng.request(3, "ping", json!({}));
    assert_eq!(reply["id"], 3);
    assert!(reply["result"]["uptimeMs"].is_number());
}

#[test]
fn notifications_are_not_answered_and_unknown_methods_are_32601() {
    let mut eng = Engine::spawn(write_config(VALID_CONFIG));

    // Notification (no id): MUST NOT be answered (02 §2.2). The next line we
    // read must therefore be the response to the *following* request.
    eng.send_value(&json!({ "jsonrpc": "2.0", "method": "session/ended", "params": { "sessionID": "ses_1" } }));
    eng.send_value(&json!({ "jsonrpc": "2.0", "method": "totally/unknown", "params": {} }));
    let reply = eng.request(2, "ping", json!({}));
    assert_eq!(reply["id"], 2);
    assert!(reply["result"]["uptimeMs"].is_number());
    assert!(reply.get("error").is_none(), "unknown notifications are tolerated, replies stay ordered");
}

#[test]
fn malformed_lines_map_to_error_codes() {
    let mut eng = Engine::spawn(write_config(VALID_CONFIG));

    // Unparseable line → -32700 with id null (02 §2.8).
    eng.send("not json at all");
    let reply = eng.read();
    assert_eq!(reply["id"], Value::Null);
    assert_eq!(reply["error"]["code"], -32700);

    // Wrong jsonrpc version with valid id → -32600 echoing the id.
    eng.send(r#"{"jsonrpc":"1.0","id":9,"method":"ping"}"#);
    let reply = eng.read();
    assert_eq!(reply["id"], 9);
    assert_eq!(reply["error"]["code"], -32600);

    // Unknown method → -32601.
    let reply = eng.request(3, "config/reload", json!({}));
    assert_eq!(reply["error"]["code"], -32601);

    // Schema violation in params → -32602 (missing required cwd).
    eng.send_value(&json!({ "jsonrpc": "2.0", "id": 4, "method": "policy/check", "params": {
        "invocation": { "id": "m:c", "sessionID": "s", "hook": "permission.evaluate" },
        "action": "shell",
        "commands": [ { "index": 0, "raw": "ls" } ] } }));
    let reply = eng.read();
    assert_eq!(reply["id"], 4);
    assert_eq!(reply["error"]["code"], -32602);
}

#[test]
fn clean_eof_exits_zero() {
    let mut eng = Engine::spawn(write_config(VALID_CONFIG));
    eng.send_value(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": 1, "client": { "name": "hook", "version": "0.1.0" } } }));
    let reply = eng.read();
    assert_eq!(reply["id"], 1);
    let status = eng.wait_after_eof();
    assert!(status.success(), "clean EOF must exit 0, got {status}");
}
