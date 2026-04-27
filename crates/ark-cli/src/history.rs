//! `ark-cli history` — print confidential-aware activity history.
//!
//! Each entry shows the plaintext amount when known, otherwise the
//! literal string `confidential` (see
//! [`dark_client::CONFIDENTIAL_AMOUNT_LABEL`]).
//!
//! ## Cache wiring — TODO(#574)
//!
//! The real implementation will pull owned and observed VTXOs from
//! the confidential cache (#574). Until that lands, this command runs
//! against empty in-memory sources and emits a `note: cache not
//! available` line.
//!
//! ## Closes #575

use anyhow::Result;
use dark_client::{
    history, HistoryEntry, InMemoryObservedVtxos, InMemoryOwnedVtxos, ObservedVtxoSource,
    OwnedVtxoSource,
};

const EMPTY_SOURCES_NOTE: &str = "no VTXOs cached locally (TODO(#574): wire confidential cache)";

pub fn handle(json: bool) -> Result<()> {
    let owned = owned_vtxo_source();
    let observed = observed_vtxo_source();
    print_history(&owned, &observed, json)
}

fn owned_vtxo_source() -> impl OwnedVtxoSource {
    // TODO(#574): swap for the real confidential cache once available.
    InMemoryOwnedVtxos::new()
}

fn observed_vtxo_source() -> impl ObservedVtxoSource {
    // TODO(#574): swap for the real confidential cache once available.
    InMemoryObservedVtxos::new()
}

fn print_history<O, X>(owned: &O, observed: &X, json: bool) -> Result<()>
where
    O: OwnedVtxoSource,
    X: ObservedVtxoSource,
{
    let entries = history(owned, observed);

    if json {
        print_json(&entries)?;
        return Ok(());
    }

    if entries.is_empty() {
        println!("No history entries.");
        println!("  ({})", EMPTY_SOURCES_NOTE);
        return Ok(());
    }

    print_table(&entries);
    Ok(())
}

fn print_json(entries: &[HistoryEntry]) -> Result<()> {
    let mut out = serde_json::json!({ "entries": entries });
    if entries.is_empty() {
        out["note"] = serde_json::Value::String(EMPTY_SOURCES_NOTE.into());
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_table(entries: &[HistoryEntry]) {
    println!("  VTXO                     KIND     AMOUNT         STATUS     TIMESTAMP");
    let separator = "-".repeat(72);
    println!("  {separator}");
    for entry in entries {
        println!(
            "  {:<24} {:<8} {:<14} {:<10} {}",
            truncate(&entry.vtxo_id, 24),
            format!("{:?}", entry.kind).to_lowercase(),
            entry.amount_display(),
            format!("{:?}", entry.status).to_lowercase(),
            entry.timestamp,
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
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

    #[test]
    fn truncate_keeps_short_strings_intact() {
        assert_eq!(truncate("short", 24), "short");
    }

    #[test]
    fn truncate_shortens_long_strings_with_ellipsis() {
        let truncated = truncate("0123456789012345678901234567890", 10);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.len(), 10);
    }
}
