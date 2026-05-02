//! PSAR demo binary (issue #680).
//!
//! Wraps `dark_psar::report::run_demo`. Spins up an in-process ASP,
//! boards `K` synthetic users with horizon `N`, advances every epoch,
//! verifies every per-user renewal signature, and writes a structured
//! JSON [`dark_psar::RunReport`] to `--report-path` (`-` for stdout).
//!
//! Built only with `--features demo`; the library does not pull in
//! `clap` or `tracing-subscriber` for normal consumers.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "psar-demo",
    about = "End-to-end PSAR demo with metrics + tracing."
)]
struct Args {
    /// Cohort size.
    #[arg(long, default_value_t = 100)]
    k: u32,
    /// Hibernation horizon.
    #[arg(long, default_value_t = 12)]
    n: u32,
    /// RNG seed for deterministic keypair generation.
    #[arg(long, default_value_t = 0xDE5C_DA7A_5EED_2026_u64)]
    seed: u64,
    /// Where to write the JSON report. `-` writes to stdout (default).
    #[arg(long, default_value = "-")]
    report_path: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Default to `info` so the three required spans (psar.boarding /
    // psar.epoch{t} / psar.aggregate) emit; override via `RUST_LOG`.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let report = match dark_psar::run_demo(args.k, args.n, args.seed) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("psar-demo: run_demo failed: {e}");
            return ExitCode::from(2);
        }
    };

    let body = match serde_json::to_string_pretty(&report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("psar-demo: serialise RunReport: {e}");
            return ExitCode::from(3);
        }
    };

    if args.report_path == "-" {
        println!("{body}");
    } else {
        let path = PathBuf::from(&args.report_path);
        match std::fs::File::create(&path).and_then(|mut f| f.write_all(body.as_bytes())) {
            Ok(()) => {
                eprintln!("psar-demo: wrote report to {}", path.display());
            }
            Err(e) => {
                eprintln!("psar-demo: write {}: {e}", path.display());
                return ExitCode::from(4);
            }
        }
    }

    if !report.aggregate.all_verify {
        eprintln!("psar-demo: at least one renewal signature failed verification");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
