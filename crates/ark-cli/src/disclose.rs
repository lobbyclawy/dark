//! Subcommands for assembling and verifying compliance bundles.
//!
//! Two actions are exposed:
//!
//! - `disclose <vtxo_id>` — assembles a bundle of one or more compliance
//!   proofs about the targeted VTXO and writes the bundle to stdout (or to
//!   the file passed via `--out`). The set of proofs is opt-in: pass
//!   `--selective-reveal`, `--bounded-range`, and/or `--source-of-funds`
//!   in any combination.
//! - `verify <bundle>` — reads a bundle from `--in <path>` (or stdin),
//!   runs each contained proof's verifier, and exits 0 only if every
//!   proof verifies.
//!
//! # Stubs
//!
//! The proof bundle codec (#562) and the proof types themselves (#565
//! VTXO reveal, #566 bounded range, #567 source-of-funds) are still in
//! flight. Until they land, this module defines minimal local stand-ins
//! with the same shape so the CLI compiles and so end-to-end JSON
//! round-trips are testable. Each stub is annotated with a
//! `TODO(#NNN)` pointing to the upstream issue.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};

/// CLI arguments for the `disclose` subcommand.
///
/// The user picks a VTXO and toggles on the proofs they want to include.
/// At least one disclosure flag is required; otherwise we'd be writing
/// an empty (and useless) bundle.
#[derive(Args, Debug)]
pub struct DiscloseArgs {
    /// VTXO selector — the VTXO that the bundle proves statements about.
    /// Typically a `<txid>:<vout>` style identifier.
    pub vtxo_id: String,

    /// Include a selective-reveal proof: opens the VTXO's amount
    /// commitment so a verifier can confirm the on-chain commitment
    /// without learning anything else about related VTXOs.
    #[arg(long)]
    pub selective_reveal: bool,

    /// Include a bounded-range proof: prove `lower <= amount <= upper`
    /// without revealing the amount. Both bounds must be supplied
    /// together.
    #[arg(long, requires = "upper")]
    pub lower: Option<u64>,

    /// Upper bound for the bounded-range proof. See `--lower`.
    #[arg(long, requires = "lower")]
    pub upper: Option<u64>,

    /// Include a source-of-funds proof: prove the VTXO descends from a
    /// known root VTXO without revealing intermediate amounts.
    #[arg(long, value_name = "ROOT_VTXO_ID")]
    pub source_of_funds: Option<String>,

    /// Write the bundle to this path instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// CLI arguments for the `verify` subcommand.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Read the bundle from this path. If omitted, reads from stdin.
    #[arg(long = "in", value_name = "PATH")]
    pub input: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Stub bundle / proof types
//
// Once #562 (bundle codec) and #565/#566/#567 (proof types) land, replace
// these with re-exports from `dark-confidential::disclosure`. The shapes
// here are deliberately minimal — just enough for the CLI to round-trip a
// bundle through JSON and report per-proof pass/fail.
// ---------------------------------------------------------------------------

const BUNDLE_VERSION: u32 = 1;

/// A single compliance proof inside a bundle.
///
/// TODO(#562): replace with the canonical bundle envelope (CBOR, version,
/// proof_type enum, payload, issuer signature).
/// TODO(#565): replace `SelectiveReveal` payload with the real VtxoReveal
/// proof from `dark_confidential::disclosure`.
/// TODO(#566): replace `BoundedRange` payload with the real BoundedRangeProof.
/// TODO(#567): replace `SourceOfFunds` payload with the real SourceOfFundsProof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProofEntry {
    SelectiveReveal {
        vtxo_id: String,
    },
    BoundedRange {
        vtxo_id: String,
        lower: u64,
        upper: u64,
    },
    SourceOfFunds {
        vtxo_id: String,
        root: String,
    },
}

impl ProofEntry {
    /// Short human label used in summaries.
    fn label(&self) -> &'static str {
        match self {
            ProofEntry::SelectiveReveal { .. } => "selective-reveal",
            ProofEntry::BoundedRange { .. } => "bounded-range",
            ProofEntry::SourceOfFunds { .. } => "source-of-funds",
        }
    }

    /// Description of what this proof claims, for the verify summary.
    fn scope(&self) -> String {
        match self {
            ProofEntry::SelectiveReveal { vtxo_id } => {
                format!("opens commitment for vtxo {}", vtxo_id)
            }
            ProofEntry::BoundedRange {
                vtxo_id,
                lower,
                upper,
            } => format!("amount of vtxo {} is in [{}, {}]", vtxo_id, lower, upper),
            ProofEntry::SourceOfFunds { vtxo_id, root } => {
                format!("vtxo {} descends from root {}", vtxo_id, root)
            }
        }
    }

    /// Run the proof's verifier and return `Ok(())` on success.
    ///
    /// TODO(#565/#566/#567): delegate to the real verifiers in
    /// `dark_confidential::disclosure` once those land. The current stub
    /// rejects obviously-malformed payloads (empty IDs, inverted bounds)
    /// so the negative tests in this crate exercise a real failure path.
    fn verify(&self) -> Result<()> {
        match self {
            ProofEntry::SelectiveReveal { vtxo_id } => {
                if vtxo_id.is_empty() {
                    return Err(anyhow!("selective-reveal: vtxo_id is empty"));
                }
                Ok(())
            }
            ProofEntry::BoundedRange {
                vtxo_id,
                lower,
                upper,
            } => {
                if vtxo_id.is_empty() {
                    return Err(anyhow!("bounded-range: vtxo_id is empty"));
                }
                if lower > upper {
                    return Err(anyhow!(
                        "bounded-range: lower ({}) exceeds upper ({})",
                        lower,
                        upper
                    ));
                }
                Ok(())
            }
            ProofEntry::SourceOfFunds { vtxo_id, root } => {
                if vtxo_id.is_empty() {
                    return Err(anyhow!("source-of-funds: vtxo_id is empty"));
                }
                if root.is_empty() {
                    return Err(anyhow!("source-of-funds: root is empty"));
                }
                Ok(())
            }
        }
    }
}

/// A versioned envelope wrapping one or more compliance proofs.
///
/// TODO(#562): replace with the canonical CBOR envelope. Until then,
/// the JSON representation here mirrors the eventual field layout
/// (version + ordered proof list) so the CLI surface and tests stay
/// stable across the swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceBundle {
    pub version: u32,
    pub proofs: Vec<ProofEntry>,
}

impl ComplianceBundle {
    fn new(proofs: Vec<ProofEntry>) -> Self {
        Self {
            version: BUNDLE_VERSION,
            proofs,
        }
    }

    fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("failed to encode bundle as JSON")
    }

    fn from_json(input: &str) -> Result<Self> {
        let bundle: ComplianceBundle =
            serde_json::from_str(input).context("failed to decode bundle from JSON")?;
        if bundle.version != BUNDLE_VERSION {
            return Err(anyhow!(
                "unsupported bundle version: got {}, expected {}",
                bundle.version,
                BUNDLE_VERSION
            ));
        }
        Ok(bundle)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub fn handle_disclose(args: &DiscloseArgs) -> Result<()> {
    let proofs = collect_proofs(args)?;
    let bundle = ComplianceBundle::new(proofs);
    let encoded = bundle.to_json()?;
    write_bundle(&encoded, args.out.as_deref())
}

pub fn handle_verify(args: &VerifyArgs) -> Result<()> {
    let input = read_bundle(args.input.as_deref())?;
    let bundle = ComplianceBundle::from_json(&input)?;
    let report = run_verifications(&bundle);
    print_summary(&report);
    if report.all_passed() {
        Ok(())
    } else {
        Err(anyhow!(
            "{} of {} proofs failed verification",
            report.failed_count(),
            report.total()
        ))
    }
}

fn collect_proofs(args: &DiscloseArgs) -> Result<Vec<ProofEntry>> {
    let mut proofs = Vec::new();

    if args.selective_reveal {
        proofs.push(ProofEntry::SelectiveReveal {
            vtxo_id: args.vtxo_id.clone(),
        });
    }

    if let (Some(lower), Some(upper)) = (args.lower, args.upper) {
        if lower > upper {
            return Err(anyhow!(
                "--lower ({}) must not exceed --upper ({})",
                lower,
                upper
            ));
        }
        proofs.push(ProofEntry::BoundedRange {
            vtxo_id: args.vtxo_id.clone(),
            lower,
            upper,
        });
    }

    if let Some(root) = &args.source_of_funds {
        proofs.push(ProofEntry::SourceOfFunds {
            vtxo_id: args.vtxo_id.clone(),
            root: root.clone(),
        });
    }

    if proofs.is_empty() {
        return Err(anyhow!(
            "no disclosure types selected; pass at least one of \
             --selective-reveal, --lower/--upper, --source-of-funds"
        ));
    }

    Ok(proofs)
}

fn write_bundle(encoded: &str, out: Option<&std::path::Path>) -> Result<()> {
    match out {
        Some(path) => fs::write(path, encoded)
            .with_context(|| format!("failed to write bundle to {}", path.display())),
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(encoded.as_bytes())?;
            handle.write_all(b"\n")?;
            Ok(())
        }
    }
}

fn read_bundle(input: Option<&std::path::Path>) -> Result<String> {
    match input {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read bundle from {}", path.display())),
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read bundle from stdin")?;
            Ok(buf)
        }
    }
}

/// Outcome of verifying a single proof inside a bundle.
struct ProofResult {
    label: &'static str,
    scope: String,
    outcome: Result<()>,
}

/// Aggregated outcome of verifying every proof in a bundle.
struct VerificationReport {
    results: Vec<ProofResult>,
}

impl VerificationReport {
    fn total(&self) -> usize {
        self.results.len()
    }

    fn failed_count(&self) -> usize {
        self.results.iter().filter(|r| r.outcome.is_err()).count()
    }

    fn all_passed(&self) -> bool {
        self.failed_count() == 0
    }
}

fn run_verifications(bundle: &ComplianceBundle) -> VerificationReport {
    let results = bundle
        .proofs
        .iter()
        .map(|proof| ProofResult {
            label: proof.label(),
            scope: proof.scope(),
            outcome: proof.verify(),
        })
        .collect();
    VerificationReport { results }
}

fn print_summary(report: &VerificationReport) {
    println!("Compliance bundle verification");
    println!("───────────────────────────────────────");
    for result in &report.results {
        match &result.outcome {
            Ok(()) => println!("  PASS  {} — {}", result.label, result.scope),
            Err(err) => println!("  FAIL  {} — {} ({})", result.label, result.scope, err),
        }
    }
    println!("───────────────────────────────────────");
    println!(
        "  {} of {} proofs verified",
        report.total() - report.failed_count(),
        report.total()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn args_for(vtxo_id: &str, out: Option<PathBuf>) -> DiscloseArgs {
        DiscloseArgs {
            vtxo_id: vtxo_id.to_string(),
            selective_reveal: true,
            lower: Some(100),
            upper: Some(1_000),
            source_of_funds: Some("root-vtxo".to_string()),
            out,
        }
    }

    #[test]
    fn collect_proofs_returns_one_entry_per_enabled_disclosure() {
        let args = args_for("vtxo-1", None);
        let proofs = collect_proofs(&args).expect("collect");
        assert_eq!(proofs.len(), 3);
        assert!(matches!(proofs[0], ProofEntry::SelectiveReveal { .. }));
        assert!(matches!(proofs[1], ProofEntry::BoundedRange { .. }));
        assert!(matches!(proofs[2], ProofEntry::SourceOfFunds { .. }));
    }

    #[test]
    fn collect_proofs_rejects_empty_request() {
        let args = DiscloseArgs {
            vtxo_id: "vtxo-1".to_string(),
            selective_reveal: false,
            lower: None,
            upper: None,
            source_of_funds: None,
            out: None,
        };
        let err = collect_proofs(&args).unwrap_err().to_string();
        assert!(err.contains("no disclosure types selected"));
    }

    #[test]
    fn collect_proofs_rejects_inverted_range() {
        let args = DiscloseArgs {
            vtxo_id: "vtxo-1".to_string(),
            selective_reveal: false,
            lower: Some(500),
            upper: Some(100),
            source_of_funds: None,
            out: None,
        };
        let err = collect_proofs(&args).unwrap_err().to_string();
        assert!(err.contains("must not exceed"));
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let bundle = ComplianceBundle::new(vec![ProofEntry::SelectiveReveal {
            vtxo_id: "vtxo-1".to_string(),
        }]);
        let encoded = bundle.to_json().expect("encode");
        let decoded = ComplianceBundle::from_json(&encoded).expect("decode");
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn bundle_decode_rejects_unknown_version() {
        let json = r#"{"version":99,"proofs":[]}"#;
        let err = ComplianceBundle::from_json(json).unwrap_err().to_string();
        assert!(err.contains("unsupported bundle version"));
    }

    /// Round-trip: write a bundle to disk, read it back, verify it.
    #[test]
    fn disclose_then_verify_succeeds_for_valid_bundle() {
        let bundle_file = NamedTempFile::new().expect("temp file");
        let disclose_args = args_for("vtxo-roundtrip", Some(bundle_file.path().to_path_buf()));
        handle_disclose(&disclose_args).expect("disclose succeeds");

        let verify_args = VerifyArgs {
            input: Some(bundle_file.path().to_path_buf()),
        };
        handle_verify(&verify_args).expect("verify succeeds for honest bundle");
    }

    /// Negative test: hand-edit the bundle on disk and prove that
    /// verification surfaces a non-zero outcome.
    #[test]
    fn verify_rejects_tampered_bundle() {
        let bundle_file = NamedTempFile::new().expect("temp file");
        let disclose_args = DiscloseArgs {
            vtxo_id: "vtxo-tamper".to_string(),
            selective_reveal: false,
            lower: Some(10),
            upper: Some(1_000),
            source_of_funds: None,
            out: Some(bundle_file.path().to_path_buf()),
        };
        handle_disclose(&disclose_args).expect("disclose succeeds");

        // Swap the bounds so `lower > upper` — the verifier must reject.
        let original = fs::read_to_string(bundle_file.path()).expect("read bundle");
        let tampered = original
            .replace("\"lower\": 10", "\"lower\": 9999")
            .replace("\"upper\": 1000", "\"upper\": 5");
        fs::write(bundle_file.path(), tampered).expect("write tampered bundle");

        let verify_args = VerifyArgs {
            input: Some(bundle_file.path().to_path_buf()),
        };
        let err =
            handle_verify(&verify_args).expect_err("verification must fail for tampered bundle");
        assert!(
            err.to_string().contains("failed verification"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn verify_rejects_unparseable_bundle() {
        let bundle_file = NamedTempFile::new().expect("temp file");
        fs::write(bundle_file.path(), "not json").expect("write");

        let verify_args = VerifyArgs {
            input: Some(bundle_file.path().to_path_buf()),
        };
        let err = handle_verify(&verify_args).unwrap_err().to_string();
        assert!(err.contains("failed to decode bundle"));
    }
}
