// Test-only stage tool used by the runtime contract tests of the engine
// (`tests/stagetools_runtime.rs`). Modes cover the outcome classes of
// 06 §6.4.4: valid verdicts, garbage, exit≠0, oversize, slow answers and a
// persistent answering loop. Not part of the engine's surface.

use std::io::{BufRead, Write};
use std::time::Duration;

fn pid() -> u32 {
    std::process::id()
}

/// Real stage tools read their letter (06 §6.4.1: the engine writes one line
/// and closes stdin). Reading it first pins this binary behind the spawn
/// write on every platform, so the contract races below stay deterministic.
fn read_letter() {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn answer_with_pid() {
    let json = format!("{{\"verdict\":\"allow\",\"reason\":\"pid:{}\"}}", pid());
    println!("{json}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("answer");
    let arg = args.get(1).and_then(|a| a.parse::<u64>().ok());

    // One-shot modes: consume the letter, then produce their outcome.
    match mode {
        // One JSON verdict, then exit 0.
        "answer" => {
            read_letter();
            answer_with_pid();
        }
        // Valid JSON, but the tool reports its own failure (06 §6.4.4 row 2).
        "exit-code" => {
            read_letter();
            answer_with_pid();
            let code = arg.unwrap_or(3) as i32;
            std::process::exit(code);
        }
        // Deadline breaker: answer, but too late.
        "sleep-answer" => {
            read_letter();
            let ms = arg.unwrap_or(5_000);
            std::thread::sleep(Duration::from_millis(ms));
            answer_with_pid();
        }
        // Unparseable stdout.
        "garbage" => {
            read_letter();
            println!("not json at all");
        }
        // Oversize unparsable output (maxOutputBytes breach).
        "oversize" => {
            read_letter();
            let bytes = arg.unwrap_or(200_000) as usize;
            let line: String = "x".repeat(bytes);
            println!("{line}");
        }
        // Contract breach: a response carrying a foreign protocolVersion.
        "foreign-pv" => {
            read_letter();
            println!(r#"{{"protocolVersion":2,"verdict":"allow"}}"#);
        }
        // Over-long message field (cap I6).
        "long-message" => {
            read_letter();
            let m = "x".repeat(513);
            println!(r#"{{"verdict":"allow","message":"{m}"}}"#);
        }
        // Persistent contract: one line in → one verdict out, forever.
        "loop" | "banner-loop" => {
            if mode == "banner-loop" {
                println!("banner"); // unsolicited startup output
            }
            let stdin = std::io::stdin();
            let mut out = std::io::stdout();
            for line in stdin.lock().lines() {
                let Ok(_) = line else { break };
                let json = format!("{{\"verdict\":\"allow\",\"reason\":\"pid:{}\"}}", pid());
                if out.write_all((json + "\n").as_bytes()).is_err() {
                    break; // parent closed the pipe
                }
                let _ = out.flush();
            }
        }
        // Answer one stdin line, linger, then exit: an observable "persistent
        // tool that quits after answering" with no answer/exit race.
        "answer-linger" => {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            answer_with_pid();
            let ms = arg.unwrap_or(400);
            std::thread::sleep(Duration::from_millis(ms));
        }
        other => {
            eprintln!("warden-test-tool: unknown mode {other}");
            std::process::exit(2);
        }
    }
}
