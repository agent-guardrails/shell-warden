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
    // options: [--config FILE] (absolute path after hook validation, 04 §4.2)
    let mut config_path = None;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => match args.next() {
                Some(p) => config_path = Some(p),
                None => {
                    eprintln!("--config requires a path");
                    return 1;
                }
            },
            "--version" => {
                println!("shell-warden {}", env!("CARGO_PKG_VERSION"));
                return 0;
            }
            other => {
                eprintln!("unknown argument \"{other}\" — usage: shell-warden [--config FILE]");
                return 1;
            }
        }
    }

    // config: strict, fail-closed (06 §6.1; invalid ⇒ 2, no stdout)
    let path = match config_path.map(|p| checker::config::expand_env(&p)) {
        Some(Ok(p)) => p,
        Some(Err(e)) => {
            eprintln!("{e}");
            return 2;
        }
        None => match checker::config::default_config_path() {
            Some(p) => p,
            None => {
                eprintln!("no config path: HOME/XDG_CONFIG_HOME unset");
                return 2;
            }
        },
    };
    let config = match checker::config::load_path(&path) {
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

    // verdict out, exactly one JSON value then EOF (02 §2.3)
    let verdict = checker::pipeline::evaluate(&config, &letter);
    let out = match verdict.to_wire() {
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
