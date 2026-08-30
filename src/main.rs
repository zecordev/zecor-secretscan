// SPDX-License-Identifier: Apache-2.0
//! `zecor-secretscan` -- secret / high-entropy / injection scanning.
//!
//!   zecor-secretscan text [FILE]   scan a file (or stdin)
//!   zecor-secretscan diff          scan `git diff` output on stdin
//!   zecor-secretscan path DIR      walk a tree (gitignore-aware, parallel)
//!   zecor-secretscan baseline DIR  print a baseline of every current finding
//!
//! Shared flags: --format json|sarif|text (default json), --baseline FILE,
//! --injection (add the prompt-injection pack), --no-gitignore, --max-bytes N.
//!
//! Exit 1 if any finding remains after the baseline, 0 if clean, 2 on a usage error.

use std::collections::HashSet;
use std::io::{self, Read};
use zecor_secretscan::{
    apply_baseline, parse_baseline, sarif::to_sarif, scan_diff, scan_path, scan_text_opts, Finding,
    ScanOpts,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str);

    let mut opts = ScanOpts::default();
    if flag_present(&args, "--injection") {
        opts.injection = true;
    }
    if flag_present(&args, "--no-gitignore") {
        opts.respect_gitignore = false;
    }
    if let Some(n) = flag_value(&args, "--max-bytes").and_then(|s| s.parse().ok()) {
        opts.max_bytes = n;
    }
    let format = flag_value(&args, "--format").unwrap_or_else(|| "json".into());
    let baseline: HashSet<String> = flag_value(&args, "--baseline")
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse_baseline(&t))
        .unwrap_or_default();

    let positional: Vec<&String> = args
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(i, a)| !a.starts_with("--") && !preceded_by_value_flag(&args, *i))
        .map(|(_, a)| a)
        .collect();

    let mut findings: Vec<Finding> = match mode {
        Some("text") => {
            let (text, file) = match positional.first() {
                Some(path) => match std::fs::read_to_string(path.as_str()) {
                    Ok(s) => (s, (*path).clone()),
                    Err(e) => fail(&format!("{path}: {e}")),
                },
                None => (read_stdin(), "<stdin>".to_string()),
            };
            scan_text_opts(&text, &file, &opts)
        }
        Some("diff") => scan_diff(&read_stdin()),
        Some("path") | Some("baseline") => {
            let root = positional.first().map(|s| s.as_str()).unwrap_or(".");
            scan_path(std::path::Path::new(root), &opts)
        }
        _ => {
            eprintln!(
                "usage: zecor-secretscan <text [FILE] | diff | path DIR | baseline DIR> \
                 [--format json|sarif|text] [--baseline FILE] [--injection] [--no-gitignore]"
            );
            std::process::exit(2);
        }
    };

    if mode == Some("baseline") {
        // Emit each current finding's fingerprint -- the file to pass back as --baseline.
        println!(
            "# zecor-secretscan baseline -- {} finding(s) accepted",
            findings.len()
        );
        let mut seen = HashSet::new();
        for f in &findings {
            let fp = f.fingerprint();
            if seen.insert(fp.clone()) {
                println!("{fp}  # {} {}:{}", f.rule, f.file, f.line);
            }
        }
        return;
    }

    findings = apply_baseline(findings, &baseline);

    match format.as_str() {
        "sarif" => println!("{}", to_sarif(&findings, VERSION)),
        "text" => {
            for f in &findings {
                println!("{:22} {}:{}  {}", f.rule, f.file, f.line, f.hint);
            }
            eprintln!(
                "{}",
                if findings.is_empty() {
                    "clean".into()
                } else {
                    format!("{} finding(s)", findings.len())
                }
            );
        }
        _ => println!(
            "{}",
            serde_json::to_string(&findings).expect("findings serialize")
        ),
    }
    std::process::exit(if findings.is_empty() { 0 } else { 1 });
}

fn read_stdin() -> String {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).ok();
    s
}

const VALUE_FLAGS: &[&str] = &["--format", "--baseline", "--max-bytes"];

fn flag_present(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// True if `args[idx]` is the value token immediately following a value-taking flag.
fn preceded_by_value_flag(args: &[String], idx: usize) -> bool {
    idx > 0 && VALUE_FLAGS.contains(&args[idx - 1].as_str())
}

fn fail(msg: &str) -> ! {
    eprintln!("zecor-secretscan: {msg}");
    std::process::exit(2);
}
