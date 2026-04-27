//! `ark-cli balance` — print confidential-aware spendable balance.
//!
//! Sums plaintext amounts the wallet has openings for. Confidential
//! VTXOs the wallet only observed (no opening) cannot contribute.
//!
//! ## Cache wiring — TODO(#574)
//!
//! The real implementation will pull owned VTXOs from the local
//! confidential cache (#574). Until that lands on main, this command
//! returns `0` from an empty in-memory source, and emits a
//! `note: cache not available` line so users understand why.
//!
//! ## Closes #575

use anyhow::Result;
use dark_client::{balance, InMemoryOwnedVtxos, OwnedVtxoSource};

/// Note shown to humans whenever the underlying source is empty —
/// callers should be aware the `0` may simply mean "cache not wired".
const EMPTY_SOURCE_NOTE: &str = "no owned VTXOs cached locally (TODO(#574): wire cache)";

pub fn handle(json: bool) -> Result<()> {
    let source = owned_vtxo_source();
    print_balance(&source, json)
}

fn owned_vtxo_source() -> impl OwnedVtxoSource {
    // TODO(#574): swap for the real confidential cache once available.
    InMemoryOwnedVtxos::new()
}

fn print_balance<S: OwnedVtxoSource>(source: &S, json: bool) -> Result<()> {
    let total = balance(source);
    let owned_count = source.owned_vtxos().len();

    if json {
        let mut out = serde_json::json!({
            "balance_sats": total,
            "owned_vtxo_count": owned_count,
        });
        if owned_count == 0 {
            out["note"] = serde_json::Value::String(EMPTY_SOURCE_NOTE.into());
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Balance: {} sats", total);
        if owned_count == 0 {
            println!("  ({})", EMPTY_SOURCE_NOTE);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_does_not_panic_for_text_output() {
        handle(false).expect("text output should succeed");
    }

    #[test]
    fn handle_does_not_panic_for_json_output() {
        handle(true).expect("json output should succeed");
    }
}
