//! Confidential-aware spendable balance.
//!
//! For confidential VTXOs we only know the plaintext amount of the ones
//! the wallet actually owns (the openings sit in the local cache). For
//! everything else — VTXOs the wallet has *observed* on the network but
//! cannot open — the amount is hidden, so it cannot contribute to the
//! local spendable balance.
//!
//! [`balance`] simply sums the plaintext amounts of the locally-owned,
//! still-spendable VTXOs returned by an [`OwnedVtxoSource`].
//!
//! ## Cache trait — TODO(#574)
//!
//! Issue #574 ("local VTXO cache for confidential openings") defines the
//! authoritative cache trait. Until that lands on main, this module
//! exposes a minimal [`OwnedVtxoSource`] surface with the single method
//! [`OwnedVtxoSource::owned_vtxos`]. When #574 merges, this trait should
//! be replaced by — or made an alias for — its richer cache trait.
//!
//! ## Closes #575
//! Used by `ark-cli balance` and by [`crate::history`](mod@crate::history) to
//! resolve plaintext amounts.

use crate::types::Vtxo;

/// A locally-known VTXO opening — i.e. one we own and have plaintext for.
///
/// The `amount` field is the cleartext value in satoshis recovered from
/// the Pedersen commitment opening; this is what makes the VTXO
/// "non-confidential to us".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedVtxo {
    /// Stable VTXO identifier (matches [`Vtxo::id`]).
    pub vtxo_id: String,
    /// Plaintext amount in satoshis.
    pub amount: u64,
    /// Whether the VTXO has been spent locally or on the network.
    pub is_spent: bool,
    /// Whether the operator has swept the VTXO post-expiry.
    pub is_swept: bool,
}

impl OwnedVtxo {
    /// True when the VTXO is still spendable: not spent, not swept.
    pub fn is_spendable(&self) -> bool {
        !self.is_spent && !self.is_swept
    }
}

/// Source of locally-owned VTXO openings.
///
/// TODO(#574): replace with the canonical confidential-cache trait
/// introduced by issue #574. Until that lands, this minimal surface is
/// what `balance` and `history` rely on.
pub trait OwnedVtxoSource {
    /// Return all VTXOs the wallet owns the plaintext opening for.
    ///
    /// Both spendable and already-spent entries should be returned;
    /// callers (like [`balance`]) are responsible for filtering.
    fn owned_vtxos(&self) -> Vec<OwnedVtxo>;
}

/// Sum the plaintext amounts of all spendable, locally-owned VTXOs.
///
/// VTXOs the wallet has merely *observed* but cannot open are
/// confidential to us, so they cannot contribute — see [`history`] for
/// how those surface in the activity log instead.
///
/// [`history`]: crate::history::history
pub fn balance<S: OwnedVtxoSource + ?Sized>(source: &S) -> u64 {
    source
        .owned_vtxos()
        .iter()
        .filter(|vtxo| vtxo.is_spendable())
        .map(|vtxo| vtxo.amount)
        .sum()
}

/// Convenience helper for the common case where the caller already
/// holds a slice of [`Vtxo`]s and wants to compute a confidential-aware
/// balance over only the ones with known plaintext amounts.
pub fn balance_from_vtxos(vtxos: &[Vtxo]) -> u64 {
    vtxos
        .iter()
        .filter(|vtxo| !vtxo.is_spent && !vtxo.is_swept)
        .map(|vtxo| vtxo.amount)
        .sum()
}

/// In-memory placeholder source used by `ark-cli` and tests until the
/// real confidential cache (#574) is on main.
///
/// TODO(#574): drop in favour of the cache impl once #574 lands.
#[derive(Debug, Default, Clone)]
pub struct InMemoryOwnedVtxos {
    vtxos: Vec<OwnedVtxo>,
}

impl InMemoryOwnedVtxos {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style insert; returns `self` for chaining.
    pub fn with(mut self, vtxo: OwnedVtxo) -> Self {
        self.vtxos.push(vtxo);
        self
    }

    /// Direct insert.
    pub fn push(&mut self, vtxo: OwnedVtxo) {
        self.vtxos.push(vtxo);
    }
}

impl OwnedVtxoSource for InMemoryOwnedVtxos {
    fn owned_vtxos(&self) -> Vec<OwnedVtxo> {
        self.vtxos.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(id: &str, amount: u64) -> OwnedVtxo {
        OwnedVtxo {
            vtxo_id: id.into(),
            amount,
            is_spent: false,
            is_swept: false,
        }
    }

    #[test]
    fn empty_source_yields_zero_balance() {
        let source = InMemoryOwnedVtxos::new();
        assert_eq!(balance(&source), 0);
    }

    #[test]
    fn balance_sums_only_spendable_vtxos() {
        let mut spent = owned("v2", 5_000);
        spent.is_spent = true;

        let mut swept = owned("v3", 7_000);
        swept.is_swept = true;

        let source = InMemoryOwnedVtxos::new()
            .with(owned("v1", 10_000))
            .with(spent)
            .with(swept)
            .with(owned("v4", 3_000));

        assert_eq!(balance(&source), 13_000);
    }

    #[test]
    fn balance_from_vtxos_skips_spent_and_swept() {
        fn vtxo(id: &str, amount: u64, is_spent: bool, is_swept: bool) -> Vtxo {
            Vtxo {
                id: id.into(),
                txid: id.into(),
                vout: 0,
                amount,
                script: String::new(),
                created_at: 0,
                expires_at: 0,
                is_spent,
                is_swept,
                is_unrolled: false,
                spent_by: String::new(),
                ark_txid: String::new(),
                assets: vec![],
            }
        }

        let vtxos = vec![
            vtxo("a", 1_000, false, false),
            vtxo("b", 2_000, true, false),
            vtxo("c", 4_000, false, true),
            vtxo("d", 8_000, false, false),
        ];

        assert_eq!(balance_from_vtxos(&vtxos), 9_000);
    }
}
