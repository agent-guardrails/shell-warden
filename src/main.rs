// shell-warden — orchestrator engine (ADR-0008 rev; decisions live in stage tools).
// M0 skeleton: modes stub per spec 06 §6.8. Implementation continues per
// agent-guardrails/docs/spec/shell-warden/HANDOFF-m0.md.

const VERSION: &str = "0.1.0";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        Some("check") => check(),
        Some(other) => {
            eprintln!("unknown mode: {other}; expected: serve | check");
            std::process::exit(2);
        }
    }
}

fn serve() {
    eprintln!("shell-warden v{VERSION}: serve mode — implementation pending (HANDOFF-m0 step 1)");
    std::process::exit(1);
}

fn check() {
    eprintln!("shell-warden v{VERSION}: check mode — implementation pending (HANDOFF-m0 step 1)");
    std::process::exit(1);
}
