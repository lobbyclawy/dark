//! Confidential-aware activity history.
//!
//! For confidential VTXOs the wallet shows plaintext amounts only for
//! the ones it actually owns; observed-but-not-owned VTXOs surface as
//! entries with [`HistoryEntry::amount`] == `None`, which CLIs render
//! as the literal string `confidential` (see
//! [`HistoryEntry::amount_display`]).
//!
//! ## Stubbed cache trait — TODO(#574)
//!
//! The local VTXO cache (#574) is the source of plaintext amounts.
//! While that issue is in flight, this module relies on the minimal
//! [`crate::balance::OwnedVtxoSource`] trait defined in the
//! [`crate::balance`](mod@crate::balance) module. The observed-but-not-owned set is supplied
//! through [`ObservedVtxoSource`] — a deliberately tiny shim so tests
//! and CLIs can stand it up in-memory.
//!
//! ## Closes #575

use serde::{Deserialize, Serialize};

use crate::balance::{OwnedVtxo, OwnedVtxoSource};

/// What this history entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryEntryKind {
    /// VTXO landed in our wallet (incoming).
    Receive,
    /// VTXO left our wallet (outgoing).
    Send,
    /// VTXO observed in a settlement round (counterparty traffic).
    Round,
    /// Operator-driven sweep of an expired VTXO.
    Sweep,
}

/// Lifecycle status of the underlying VTXO at the time of report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryStatus {
    /// VTXO is still spendable.
    Spendable,
    /// VTXO has been spent.
    Spent,
    /// VTXO has been swept by the operator after expiry.
    Swept,
}

/// A single entry in the wallet's activity history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// VTXO this entry is about.
    pub vtxo_id: String,
    /// What kind of activity this entry records.
    pub kind: HistoryEntryKind,
    /// Plaintext amount in satoshis if known, `None` for confidential VTXOs.
    pub amount: Option<u64>,
    /// Unix timestamp the entry was observed at.
    pub timestamp: i64,
    /// Lifecycle status at report time.
    pub status: HistoryStatus,
}

/// Literal string used by CLIs/UIs when an amount is hidden.
pub const CONFIDENTIAL_AMOUNT_LABEL: &str = "confidential";

impl HistoryEntry {
    /// Render the amount for human consumption: digits if known,
    /// otherwise the literal `"confidential"`.
    pub fn amount_display(&self) -> String {
        match self.amount {
            Some(sats) => sats.to_string(),
            None => CONFIDENTIAL_AMOUNT_LABEL.to_string(),
        }
    }
}

/// A VTXO the wallet has observed on-network but cannot open.
///
/// This is the deliberately-small surface needed to render history
/// entries; richer metadata (round id, ephemeral pubkey, etc.) would
/// live alongside it in the real cache once #574 lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedVtxo {
    pub vtxo_id: String,
    pub kind: HistoryEntryKind,
    pub timestamp: i64,
    pub status: HistoryStatus,
}

/// Source of observed-but-not-owned VTXOs.
///
/// TODO(#574): fold into the canonical cache trait once #574 is on main.
pub trait ObservedVtxoSource {
    fn observed_vtxos(&self) -> Vec<ObservedVtxo>;
}

/// Build the wallet's activity history.
///
/// Owned VTXOs (from `owned`) yield entries with concrete plaintext
/// amounts; observed-only VTXOs (from `observed`) yield entries with
/// `amount = None`, which downstream renderers print as
/// [`CONFIDENTIAL_AMOUNT_LABEL`].
///
/// Entries are returned newest-first by timestamp; ties are broken by
/// `vtxo_id` for deterministic ordering. If both sources include the
/// same `vtxo_id`, the owned entry wins (we have the plaintext).
pub fn history<O, X>(owned: &O, observed: &X) -> Vec<HistoryEntry>
where
    O: OwnedVtxoSource + ?Sized,
    X: ObservedVtxoSource + ?Sized,
{
    let owned_entries = owned.owned_vtxos().into_iter().map(owned_to_entry);
    let known_ids: std::collections::HashSet<String> =
        owned.owned_vtxos().into_iter().map(|v| v.vtxo_id).collect();
    let observed_entries = observed
        .observed_vtxos()
        .into_iter()
        .filter(|v| !known_ids.contains(&v.vtxo_id))
        .map(observed_to_entry);

    let mut entries: Vec<HistoryEntry> = owned_entries.chain(observed_entries).collect();
    entries.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.vtxo_id.cmp(&b.vtxo_id))
    });
    entries
}

fn owned_to_entry(vtxo: OwnedVtxo) -> HistoryEntry {
    let status = if vtxo.is_swept {
        HistoryStatus::Swept
    } else if vtxo.is_spent {
        HistoryStatus::Spent
    } else {
        HistoryStatus::Spendable
    };
    let kind = match status {
        HistoryStatus::Spendable => HistoryEntryKind::Receive,
        HistoryStatus::Spent => HistoryEntryKind::Send,
        HistoryStatus::Swept => HistoryEntryKind::Sweep,
    };
    HistoryEntry {
        vtxo_id: vtxo.vtxo_id,
        kind,
        amount: Some(vtxo.amount),
        timestamp: 0,
        status,
    }
}

fn observed_to_entry(vtxo: ObservedVtxo) -> HistoryEntry {
    HistoryEntry {
        vtxo_id: vtxo.vtxo_id,
        kind: vtxo.kind,
        amount: None,
        timestamp: vtxo.timestamp,
        status: vtxo.status,
    }
}

/// In-memory placeholder source used by `ark-cli` and tests until the
/// real confidential cache (#574) is on main.
///
/// TODO(#574): drop in favour of the cache impl once #574 lands.
#[derive(Debug, Default, Clone)]
pub struct InMemoryObservedVtxos {
    vtxos: Vec<ObservedVtxo>,
}

impl InMemoryObservedVtxos {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style insert; returns `self` for chaining.
    pub fn with(mut self, vtxo: ObservedVtxo) -> Self {
        self.vtxos.push(vtxo);
        self
    }

    /// Direct insert.
    pub fn push(&mut self, vtxo: ObservedVtxo) {
        self.vtxos.push(vtxo);
    }
}

impl ObservedVtxoSource for InMemoryObservedVtxos {
    fn observed_vtxos(&self) -> Vec<ObservedVtxo> {
        self.vtxos.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balance::{InMemoryOwnedVtxos, OwnedVtxo};

    fn owned(id: &str, amount: u64) -> OwnedVtxo {
        OwnedVtxo {
            vtxo_id: id.into(),
            amount,
            is_spent: false,
            is_swept: false,
        }
    }

    fn observed(id: &str, kind: HistoryEntryKind, ts: i64) -> ObservedVtxo {
        ObservedVtxo {
            vtxo_id: id.into(),
            kind,
            timestamp: ts,
            status: HistoryStatus::Spendable,
        }
    }

    #[test]
    fn empty_sources_yield_empty_history() {
        let owned = InMemoryOwnedVtxos::new();
        let observed = InMemoryObservedVtxos::new();
        assert!(history(&owned, &observed).is_empty());
    }

    #[test]
    fn owned_vtxos_carry_plaintext_amount() {
        let owned = InMemoryOwnedVtxos::new().with(owned("v1", 12_345));
        let observed = InMemoryObservedVtxos::new();

        let entries = history(&owned, &observed);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].amount, Some(12_345));
        assert_eq!(entries[0].amount_display(), "12345");
        assert_eq!(entries[0].kind, HistoryEntryKind::Receive);
    }

    #[test]
    fn observed_only_vtxos_render_as_confidential() {
        let owned = InMemoryOwnedVtxos::new();
        let observed =
            InMemoryObservedVtxos::new().with(observed("v9", HistoryEntryKind::Round, 100));

        let entries = history(&owned, &observed);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].amount.is_none());
        assert_eq!(entries[0].amount_display(), CONFIDENTIAL_AMOUNT_LABEL);
        assert_eq!(entries[0].kind, HistoryEntryKind::Round);
    }

    #[test]
    fn owned_entry_wins_when_id_appears_in_both_sources() {
        let owned = InMemoryOwnedVtxos::new().with(owned("dup", 9_000));
        let observed =
            InMemoryObservedVtxos::new().with(observed("dup", HistoryEntryKind::Round, 50));

        let entries = history(&owned, &observed);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].amount, Some(9_000));
    }

    #[test]
    fn entries_are_sorted_newest_first() {
        let owned = InMemoryOwnedVtxos::new();
        let observed = InMemoryObservedVtxos::new()
            .with(observed("a", HistoryEntryKind::Round, 100))
            .with(observed("b", HistoryEntryKind::Round, 300))
            .with(observed("c", HistoryEntryKind::Round, 200));

        let entries = history(&owned, &observed);
        let timestamps: Vec<i64> = entries.iter().map(|e| e.timestamp).collect();
        assert_eq!(timestamps, vec![300, 200, 100]);
    }

    #[test]
    fn spent_owned_vtxo_records_send_kind() {
        let mut spent = owned("v1", 1_000);
        spent.is_spent = true;
        let owned_src = InMemoryOwnedVtxos::new().with(spent);

        let entries = history(&owned_src, &InMemoryObservedVtxos::new());
        assert_eq!(entries[0].kind, HistoryEntryKind::Send);
        assert_eq!(entries[0].status, HistoryStatus::Spent);
    }

    #[test]
    fn swept_owned_vtxo_records_sweep_kind() {
        let mut swept = owned("v1", 1_000);
        swept.is_swept = true;
        let owned_src = InMemoryOwnedVtxos::new().with(swept);

        let entries = history(&owned_src, &InMemoryObservedVtxos::new());
        assert_eq!(entries[0].kind, HistoryEntryKind::Sweep);
        assert_eq!(entries[0].status, HistoryStatus::Swept);
    }
}
