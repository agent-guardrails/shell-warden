// shell-warden — the one-shot decision binary (02-letter-verdict.md).
// Letter in on stdin, verdict out on stdout. Exit codes: 0 verdict; 1 usage
// failure; 2 config invalid (message on stderr; stdout stays empty).

use shell_warden::checker;
use std::io::Read;
use std::io::Write;

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    // Explicit files assemble disjoint profiles, never last-file-wins.
    let mut config_paths = Vec::new();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => match args.next() {
                Some(p) => config_paths.push(p),
                None => {
                    eprintln!("--config requires a path");
                    return 1;
                }
            },
            "--help" | "-h" => {
                println!(
                    "Usage: shell-warden [--config FILE]...\n\
                     Read a letter from stdin and write a {protocol} envelope.\n\n\
                     --config FILE  Repeat to assemble disjoint profiles in argument order.\n\
                                    No override precedence: conflicting profiles/executables fail.\n\
                                    Defaults must match; shared redirect policies must be identical.\n\
                                    Limits use minima and cover the complete input set.\n\
                                    Paths must be absolute after {{env:NAME}} expansion.\n\
                                    Explicit files suppress the XDG/HOME default config path.\n\
                                    Any invalid file rejects the whole set (exit 2, empty stdout).\n\
                     --version      Print version.\n\
                     --help, -h     Print help.",
                    protocol = checker::verdict::PROTOCOL,
                );
                return 0;
            }
            "--version" => {
                println!("shell-warden {}", env!("CARGO_PKG_VERSION"));
                return 0;
            }
            other => {
                eprintln!("unknown argument \"{other}\" — usage: shell-warden [--config FILE]...");
                return 1;
            }
        }
    }

    // config: strict, fail-closed (06 §6.1; invalid ⇒ 2, no stdout)
    let paths = if config_paths.is_empty() {
        match checker::config::default_config_path() {
            Some(p) => vec![p],
            None => {
                eprintln!("no config path: HOME/XDG_CONFIG_HOME unset");
                return 2;
            }
        }
    } else {
        match config_paths
            .iter()
            .map(|p| checker::config::expand_env(p))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("{e}");
                return 2;
            }
        }
    };
    let config = match checker::config::load_paths(&paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    // letter on stdin (02 §2.2); oversize/invalid ⇒ usage failure (exit 1)
    let mut buf = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
        eprintln!("letter unreadable: {e}");
        return 1;
    }
    let letter = match checker::letter::Letter::from_bytes(&buf) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    // verdict out, exactly one JSON value then EOF (02 §2.7): the closed v3
    // envelope, self-validated per 08 §8.9 before any byte reaches stdout.
    // A serialization or validation failure is a checker anomaly — exit 1,
    // stdout stays empty (fail closed; the hook degrades via onCheckerError).
    let verdict = checker::pipeline::evaluate(&config, &letter);
    let envelope = checker::verdict::VerdictEnvelope::new(verdict);
    if let Err(e) = envelope.validate_against(&letter.invocation.id, letter.commands.len()) {
        eprintln!("{} self-validation failed: {e}", checker::verdict::PROTOCOL);
        return 1;
    }
    let out = match envelope.to_wire() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if std::io::stdout().write_all(&out).is_err() {
        eprintln!("verdict write failed");
        return 1;
    }
    0
}
