//! Batch protocol state machine for Ark round settlement.
//!
//! Implements the full batch protocol matching the Go SDK's `JoinBatchSession`:
//! 1. RegisterIntent -> get intent_id
//! 2. Subscribe to GetEventStream
//! 3. Process events through state machine
//! 4. MuSig2 nonce generation + partial signing
//! 5. Build, sign, and submit forfeit transactions

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use base64::Engine;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{Amount, OutPoint, ScriptBuf, TapSighashType, TxOut, Txid, XOnlyPublicKey};

use musig2::{BinaryEncoding, KeyAggContext, PubNonce, SecNonce};

use dark_api::proto::ark_v1::round_event;
use dark_api::proto::ark_v1::{
    ark_service_client::ArkServiceClient, GetEventStreamRequest, SubmitSignedForfeitTxsRequest,
    SubmitTreeNoncesRequest, SubmitTreeSignaturesRequest, UpdateStreamTopicsRequest,
};
use dark_bitcoin::ForfeitTx;
use tonic::transport::Channel;

use crate::error::{ClientError, ClientResult};

/// A VTXO that will be spent in this round and needs a signed forfeit tx.
#[derive(Debug, Clone)]
pub struct VtxoInput {
    /// Transaction ID of the VTXO being spent.
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
enum BatchStep {
    Start,
    BatchStarted,
    TreeSigningStarted,
    TreeNoncesAggregated,
    BatchFinalization,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TreeTxNode {
    txid: String,
    tx: String,
    children: HashMap<u32, String>,
}

struct SignerState {
    secret_key: musig2::secp256k1::SecretKey,
    pubkey_hex: String,
    sec_nonces: HashMap<String, SecNonce>,
    pub_nonces: HashMap<String, PubNonce>,
    agg_nonces: HashMap<String, musig2::AggNonce>,
    /// Sweep script merkle root for taproot tweak (set in init_for_signing).
    sweep_merkle_root: Option<[u8; 32]>,
}

impl SignerState {
    fn new(secret_key: musig2::secp256k1::SecretKey) -> Self {
        let secp = musig2::secp256k1::Secp256k1::new();
        let pubkey = musig2::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // Store original pubkey_hex for identification (matching what server stores
        // from RegisterForRound). The server looks up participants by this key.
        let pubkey_hex = hex::encode(pubkey.serialize());

        // Normalize secret key to even parity for MuSig2 nonce generation and signing.
        // The same normalized key must be used for BOTH operations so the SecNonce's
        // embedded pubkey matches what's used during signing.
        let normalized_secret = if pubkey.serialize()[0] == 0x03 {
            secret_key.negate()
        } else {
            secret_key
        };

        Self {
            secret_key: normalized_secret,
            pubkey_hex,
            sec_nonces: HashMap::new(),
            pub_nonces: HashMap::new(),
            agg_nonces: HashMap::new(),
            sweep_merkle_root: None,
        }
    }

    /// Initialize signing state with sweep merkle root computed from ASP pubkey + exit delay.
    fn init_for_signing(&mut self, asp_pubkey: &XOnlyPublicKey, exit_delay: u32) {
        // Build sweep script: <exit_delay> OP_CSV OP_DROP <asp_pubkey> OP_CHECKSIG
        let sweep_script = bitcoin::script::Builder::new()
            .push_int(exit_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(asp_pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let leaf_hash = TapLeafHash::from_script(&sweep_script, LeafVersion::TapScript);
        let merkle_root = TapNodeHash::from_byte_array(leaf_hash.to_byte_array());
        self.sweep_merkle_root = Some(merkle_root.to_byte_array());
    }

    fn generate_nonces(&mut self, tree_txids: &[String]) {
        for txid in tree_txids {
            let msg = txid.as_bytes();
            let (sec_nonce, pub_nonce) = dark_bitcoin::generate_nonce(&self.secret_key, msg);
            self.sec_nonces.insert(txid.clone(), sec_nonce);
            self.pub_nonces.insert(txid.clone(), pub_nonce);
        }
    }

    fn tree_nonces_hex(&self) -> HashMap<String, String> {
        self.pub_nonces
            .iter()
            .map(|(txid, pn)| (txid.clone(), hex::encode(pn.to_bytes())))
            .collect()
    }

    fn aggregate_nonces_for_tx(
        &mut self,
        txid: &str,
        cosigner_nonces: &HashMap<String, String>,
        total_tree_txs: usize,
        tree_nodes: &[TreeTxNode],
    ) -> ClientResult<bool> {
        if self.agg_nonces.contains_key(txid) {
            return Ok(self.agg_nonces.len() >= total_tree_txs);
        }

        // Find this tree node's PSBT to extract the correct cosigner key order
        let node = tree_nodes.iter().find(|n| n.txid == txid);
        let cosigner_keys_from_psbt =
            node.and_then(|n| Self::extract_cosigners_from_psbt_b64(&n.tx));

        // Ensure our own nonce hasn't been tampered with by the server (like Go does)
        let mut nonces = cosigner_nonces.clone();
        let our_xonly_hex = if self.pubkey_hex.len() == 66 {
            self.pubkey_hex[2..].to_string()
        } else {
            self.pubkey_hex.clone()
        };
        if let Some(our_pub_nonce) = self.pub_nonces.get(txid) {
            nonces.insert(our_xonly_hex.clone(), hex::encode(our_pub_nonce.to_bytes()));
        }

        // Aggregate nonces in cosigner key order (matching PSBT fields, like Go does)
        let mut all_pub_nonces = Vec::new();
        if let Some(ref keys) = cosigner_keys_from_psbt {
            for pk_hex in keys {
                // PSBT stores compressed keys (33 bytes); extract x-only (strip prefix)
                let xonly_hex = if pk_hex.len() == 66 {
                    pk_hex[2..].to_string()
                } else {
                    pk_hex.clone()
                };
                let nonce_hex = match nonces.get(&xonly_hex) {
                    Some(h) => h,
                    None => continue, // missing nonce for this cosigner
                };
                let nonce_bytes = hex::decode(nonce_hex).map_err(|e| {
                    ClientError::InvalidResponse(format!("Invalid nonce hex: {}", e))
                })?;
                let pub_nonce = PubNonce::from_bytes(&nonce_bytes).map_err(|e| {
                    ClientError::InvalidResponse(format!("Invalid PubNonce: {}", e))
                })?;
                all_pub_nonces.push(pub_nonce);
            }
        } else {
            // Fallback: iterate all nonces (shouldn't happen with well-formed PSBTs)
            for nonce_hex in nonces.values() {
                let nonce_bytes = hex::decode(nonce_hex).map_err(|e| {
                    ClientError::InvalidResponse(format!("Invalid nonce hex: {}", e))
                })?;
                let pub_nonce = PubNonce::from_bytes(&nonce_bytes).map_err(|e| {
                    ClientError::InvalidResponse(format!("Invalid PubNonce: {}", e))
                })?;
                all_pub_nonces.push(pub_nonce);
            }
        }

        if all_pub_nonces.len() < 2 {
            return Ok(false);
        }

        let agg_nonce = dark_bitcoin::aggregate_nonces(&all_pub_nonces);
        self.agg_nonces.insert(txid.to_string(), agg_nonce);

        Ok(self.agg_nonces.len() >= total_tree_txs)
    }

    /// Sign tree transactions with proper BIP-341 sighash and taproot-tweaked MuSig2.
    ///
    /// Extracts cosigner keys from each tree node's PSBT (matching the Go
    /// reference), so the `KeyAggContext` includes ALL cosigners (including ASP).
    fn sign_tree(
        &mut self,
        tree_nodes: &[TreeTxNode],
        _cosigner_pubkeys: &[String],
    ) -> ClientResult<HashMap<String, Vec<u8>>> {
        let sweep_merkle_root = self.sweep_merkle_root.ok_or_else(|| {
            ClientError::Rpc("Signing state not initialized (missing sweep_merkle_root)".into())
        })?;

        // Build output map for prevout fetching
        let output_map = Self::build_tree_output_map(tree_nodes)?;

        let mut sigs = HashMap::new();

        for node in tree_nodes {
            if node.tx.is_empty() {
                continue;
            }

            let agg_nonce = match self.agg_nonces.get(&node.txid) {
                Some(n) => n,
                None => continue, // Not our txid
            };

            let sec_nonce = match self.sec_nonces.remove(&node.txid) {
                Some(n) => n,
                None => {
                    return Err(ClientError::Rpc(format!(
                        "Missing secret nonce for txid {} (already consumed?)",
                        node.txid
                    )));
                }
            };

            // Extract cosigner keys from this node's PSBT (like Go does).
            // The PSBT's 0xDE cosigner fields include ALL cosigners (ASP + users).
            let psbt_cosigner_hexes =
                Self::extract_cosigners_from_psbt_b64(&node.tx).ok_or_else(|| {
                    ClientError::Rpc(format!(
                        "Failed to extract cosigner keys from PSBT for txid {}",
                        node.txid
                    ))
                })?;

            // Build KeyAggContext with even-parity normalized pubkeys (per-node)
            let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = Vec::new();
            for pk_hex in &psbt_cosigner_hexes {
                let pk_bytes = hex::decode(pk_hex)
                    .map_err(|e| ClientError::Rpc(format!("Invalid cosigner pubkey hex: {}", e)))?;
                let pk = musig2::secp256k1::PublicKey::from_slice(&pk_bytes)
                    .map_err(|e| ClientError::Rpc(format!("Invalid cosigner pubkey: {}", e)))?;
                // Normalize to even parity (0x02 prefix) to match tree builder
                let mut even_bytes = [0u8; 33];
                even_bytes[0] = 0x02;
                even_bytes[1..].copy_from_slice(&pk.serialize()[1..]);
                let even_pk = musig2::secp256k1::PublicKey::from_slice(&even_bytes)
                    .map_err(|e| ClientError::Rpc(format!("Even-parity pubkey failed: {}", e)))?;
                musig_pubkeys.push(even_pk);
            }
            musig_pubkeys.sort();

            // Build KeyAggContext with taproot tweak
            let key_agg_ctx = KeyAggContext::new(musig_pubkeys)
                .map_err(|e| ClientError::Rpc(format!("MuSig2 key aggregation failed: {}", e)))?
                .with_taproot_tweak(&sweep_merkle_root)
                .map_err(|e| ClientError::Rpc(format!("Taproot tweak failed: {}", e)))?;

            // Compute real BIP-341 sighash from PSBT
            let sighash = Self::compute_tree_psbt_sighash(&node.tx, &output_map)?;

            // Create partial signature
            let partial_sig = dark_bitcoin::create_partial_sig(
                &key_agg_ctx,
                &self.secret_key,
                sec_nonce,
                agg_nonce,
                &sighash,
            )
            .map_err(|e| ClientError::Rpc(format!("MuSig2 partial signing failed: {}", e)))?;

            sigs.insert(node.txid.clone(), partial_sig.serialize().to_vec());
        }

        Ok(sigs)
    }

    /// Extract cosigner compressed pubkey hex strings from a base64-encoded PSBT.
    ///
    /// Reads the custom 0xDE "cosigner" fields from input[0], matching the
    /// format used by the tree builder and the Go SDK's
    /// `ParseCosignerKeysFromArkPsbt`. Returns `None` if the PSBT cannot be
    /// parsed or has no cosigner fields.
    fn extract_cosigners_from_psbt_b64(psbt_b64: &str) -> Option<Vec<String>> {
        use base64::Engine;
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .ok()?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).ok()?;
        if psbt.inputs.is_empty() {
            return None;
        }
        let mut cosigners: Vec<(u32, String)> = Vec::new();
        for (raw_key, value) in &psbt.inputs[0].unknown {
            if raw_key.type_value != 0xDE {
                continue;
            }
            // key layout: "cosigner" (8 bytes) + index (4 bytes BE)
            if raw_key.key.len() != 12 {
                continue;
            }
            if &raw_key.key[..8] != b"cosigner" {
                continue;
            }
            if value.len() != 33 {
                continue;
            }
            let idx = u32::from_be_bytes([
                raw_key.key[8],
                raw_key.key[9],
                raw_key.key[10],
                raw_key.key[11],
            ]);
            cosigners.push((idx, hex::encode(value)));
        }
        if cosigners.is_empty() {
            return None;
        }
        // Sort by index to preserve insertion order
        cosigners.sort_by_key(|(idx, _)| *idx);
        Some(cosigners.into_iter().map(|(_, hex)| hex).collect())
    }

    /// Build txid -> TxOut vec map from tree nodes for prevout fetching.
    fn build_tree_output_map(
        tree_nodes: &[TreeTxNode],
    ) -> ClientResult<HashMap<String, Vec<TxOut>>> {
        let mut map = HashMap::new();
        for node in tree_nodes {
            if node.tx.is_empty() {
                continue;
            }
            let psbt_bytes = base64::engine::general_purpose::STANDARD
                .decode(&node.tx)
                .map_err(|e| ClientError::Rpc(format!("Invalid base64 PSBT: {}", e)))?;
            let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
                .map_err(|e| ClientError::Rpc(format!("Invalid PSBT: {}", e)))?;
            map.insert(node.txid.clone(), psbt.unsigned_tx.output.clone());
        }
        Ok(map)
    }

    /// Compute BIP-341 taproot key-spend sighash for input 0 of a tree PSBT.
    fn compute_tree_psbt_sighash(
        psbt_b64: &str,
        output_map: &HashMap<String, Vec<TxOut>>,
    ) -> ClientResult<[u8; 32]> {
        use bitcoin::hashes::Hash;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};

        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .map_err(|e| ClientError::Rpc(format!("Invalid base64 PSBT: {}", e)))?;
        let mut psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
            .map_err(|e| ClientError::Rpc(format!("Invalid PSBT: {}", e)))?;

        // Ensure witness_utxo is set for each input
        for (idx, input_tx) in psbt.unsigned_tx.input.iter().enumerate() {
            if psbt.inputs[idx].witness_utxo.is_some() {
                continue;
            }
            let parent_txid = input_tx.previous_output.txid.to_string();
            let parent_vout = input_tx.previous_output.vout as usize;
            if let Some(outputs) = output_map.get(&parent_txid) {
                if parent_vout < outputs.len() {
                    psbt.inputs[idx].witness_utxo = Some(outputs[parent_vout].clone());
                }
            }
        }

        // Collect prevouts for sighash computation
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .filter_map(|input| input.witness_utxo.clone())
            .collect();

        if prevouts.len() != psbt.unsigned_tx.input.len() {
            return Err(ClientError::Rpc(
                "Missing witness_utxo for some inputs".into(),
            ));
        }

        // Compute BIP-341 taproot key-spend sighash for input 0
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|e| ClientError::Rpc(format!("Sighash computation failed: {}", e)))?;

        Ok(sighash.to_byte_array())
    }
}

/// Execute the full batch protocol for settle().
///
/// When `vtxos_to_forfeit` is non-empty, the client will build and sign forfeit
/// transactions during `BatchFinalization` (one per VTXO, paired with connector
/// tree leaves) and submit them via `SubmitSignedForfeitTxs`.
#[allow(dead_code)]
pub(crate) async fn run_batch_protocol(
    client: &mut ArkServiceClient<Channel>,
    intent_id: &str,
    secret_key: &bitcoin::secp256k1::SecretKey,
    vtxos_to_forfeit: &[VtxoInput],
    asp_forfeit_pubkey: Option<XOnlyPublicKey>,
) -> ClientResult<String> {
    let stream = client
        .get_event_stream(GetEventStreamRequest { topics: vec![] })
        .await
        .map_err(|e| ClientError::Rpc(format!("GetEventStream failed: {}", e)))?
        .into_inner();

    run_batch_protocol_with_stream_impl(
        client,
        intent_id,
        secret_key,
        vtxos_to_forfeit,
        asp_forfeit_pubkey,
        stream,
    )
    .await
}

/// Execute the full batch protocol using a pre-existing event stream.
///
/// This variant allows the caller to subscribe to the event stream BEFORE
/// registering the intent, avoiding the race where `BatchStarted` is emitted
/// between registration and subscription.
pub(crate) async fn run_batch_protocol_with_stream(
    client: &mut ArkServiceClient<Channel>,
    intent_id: &str,
    secret_key: &bitcoin::secp256k1::SecretKey,
    vtxos_to_forfeit: &[VtxoInput],
    asp_forfeit_pubkey: Option<XOnlyPublicKey>,
    stream: tonic::Streaming<dark_api::proto::ark_v1::RoundEvent>,
) -> ClientResult<String> {
    run_batch_protocol_with_stream_impl(
        client,
        intent_id,
        secret_key,
        vtxos_to_forfeit,
        asp_forfeit_pubkey,
        stream,
    )
    .await
}

/// Wait for a `BatchFinalized` event matching the given intent, without MuSig2 signing.
///
/// This is the simplified variant for note redemptions where the server handles
/// signing. It:
/// 1. Waits for `BatchStarted` containing our intent hash.
/// 2. Confirms registration.
/// 3. Waits for `BatchFinalized` and returns the `commitment_txid`.
pub(crate) async fn wait_for_batch_finalized(
    client: &mut ArkServiceClient<Channel>,
    intent_id: &str,
    mut stream: tonic::Streaming<dark_api::proto::ark_v1::RoundEvent>,
) -> ClientResult<String> {
    let intent_hash = {
        let hash = Sha256::digest(intent_id.as_bytes());
        hex::encode(hash)
    };

    let mut batch_session_id = String::new();

    loop {
        let event = stream
            .message()
            .await
            .map_err(|e| ClientError::Rpc(format!("Event stream error: {}", e)))?
            .ok_or_else(|| ClientError::Rpc("Event stream closed unexpectedly".into()))?;

        let round_event = match event.event {
            Some(e) => e,
            None => continue,
        };

        match round_event {
            round_event::Event::StreamStarted(_) | round_event::Event::Heartbeat(_) => {}

            round_event::Event::BatchStarted(e) => {
                if !batch_session_id.is_empty() {
                    continue;
                }
                let found = e.intent_id_hashes.iter().any(|h| h == &intent_hash);
                if !found {
                    continue;
                }
                // Confirm registration in a background task (same pattern as
                // run_batch_protocol_with_stream_impl).
                {
                    let mut bg_client = client.clone();
                    let bg_intent = intent_id.to_string();
                    tokio::spawn(async move {
                        let _ = bg_client
                            .confirm_registration(
                                dark_api::proto::ark_v1::ConfirmRegistrationRequest {
                                    intent_id: bg_intent,
                                },
                            )
                            .await;
                    });
                }
                batch_session_id = e.id.clone();
            }

            round_event::Event::BatchFinalized(e) => {
                if !batch_session_id.is_empty() && e.id == batch_session_id {
                    return Ok(e.commitment_txid);
                }
            }

            round_event::Event::BatchFailed(e) => {
                if !batch_session_id.is_empty() && e.id == batch_session_id {
                    return Err(ClientError::Rpc(format!("Batch failed: {}", e.reason)));
                }
            }

            // Ignore all other events (TreeTx, TreeSigningStarted, etc.)
            _ => {}
        }
    }
}

/// Execute the full batch protocol using a pre-existing event stream (core impl).
///
/// Accepts optional forfeit params for VTXOs being spent in this round.
pub(crate) async fn run_batch_protocol_with_stream_impl(
    client: &mut ArkServiceClient<Channel>,
    intent_id: &str,
    secret_key: &bitcoin::secp256k1::SecretKey,
    vtxos_to_forfeit: &[VtxoInput],
    asp_forfeit_pubkey: Option<XOnlyPublicKey>,
    mut stream: tonic::Streaming<dark_api::proto::ark_v1::RoundEvent>,
) -> ClientResult<String> {
    let sk_bytes = secret_key.secret_bytes();
    let musig_sk = musig2::secp256k1::SecretKey::from_byte_array(sk_bytes)
        .map_err(|e| ClientError::Wallet(format!("Invalid secret key for MuSig2: {}", e)))?;

    let mut signer = SignerState::new(musig_sk);
    let mut step = BatchStep::Start;

    let intent_hash = {
        let hash = Sha256::digest(intent_id.as_bytes());
        hex::encode(hash)
    };

    let mut flat_vtxo_tree: Vec<TreeTxNode> = Vec::new();
    let mut flat_connector_tree: Vec<TreeTxNode> = Vec::new();
    let mut vtxo_tree_txids: Vec<String> = Vec::new();
    let mut cosigner_pubkeys: Vec<String> = Vec::new();
    let mut batch_session_id = String::new();
    let mut stream_id = String::new();
    let mut _commitment_tx = String::new();

    loop {
        let event = stream
            .message()
            .await
            .map_err(|e| ClientError::Rpc(format!("Event stream error: {}", e)))?
            .ok_or_else(|| ClientError::Rpc("Event stream closed unexpectedly".into()))?;

        let round_event = match event.event {
            Some(e) => e,
            None => continue,
        };

        match round_event {
            round_event::Event::StreamStarted(ref started) => {
                stream_id = started.id.clone();
                continue;
            }
            round_event::Event::Heartbeat(_) => {}

            round_event::Event::BatchStarted(e) => {
                if step > BatchStep::Start {
                    continue;
                }
                let found = e.intent_id_hashes.iter().any(|h| h == &intent_hash);
                if !found {
                    continue;
                }
                // Fire-and-forget: confirm registration and update topics in
                // a background task so the event loop can immediately process
                // TreeTx and TreeSigningStarted events.  These RPCs would
                // otherwise block while finalize_round() holds the write lock
                // on the server, delaying nonce submission and risking a
                // signing timeout.
                {
                    let mut bg_client = client.clone();
                    let bg_intent = intent_id.to_string();
                    let bg_pubkey = signer.pubkey_hex.clone();
                    // Subscribe with both compressed (66-char) and x-only
                    // (64-char) pubkey formats.  TreeTx events carry
                    // compressed-pubkey topics while TreeNonces events carry
                    // x-only-pubkey topics (the server strips the prefix
                    // when forwarding nonces).  Without both formats the
                    // topic filter would drop one of the two event types.
                    let bg_xonly = if bg_pubkey.len() == 66 {
                        bg_pubkey[2..].to_string()
                    } else {
                        bg_pubkey.clone()
                    };
                    let bg_stream_id = stream_id.clone();
                    tokio::spawn(async move {
                        let _ = bg_client
                            .confirm_registration(
                                dark_api::proto::ark_v1::ConfirmRegistrationRequest {
                                    intent_id: bg_intent,
                                },
                            )
                            .await;
                        let _ = bg_client
                            .update_stream_topics(UpdateStreamTopicsRequest {
                                stream_id: bg_stream_id,
                                topics_change: Some(
                                    dark_api::proto::ark_v1::update_stream_topics_request::TopicsChange::Overwrite(
                                        dark_api::proto::ark_v1::OverwriteTopics {
                                            topics: vec![bg_pubkey, bg_xonly],
                                        },
                                    ),
                                ),
                            })
                            .await;
                    });
                }
                batch_session_id = e.id.clone();
                // Capture batch_expiry for sweep script construction
                let batch_expiry_secs = e.batch_expiry as u32;
                if let Some(asp_pk) = asp_forfeit_pubkey {
                    signer.init_for_signing(&asp_pk, batch_expiry_secs);
                }
                step = BatchStep::BatchStarted;
            }

            round_event::Event::TreeTx(e) => {
                if step != BatchStep::BatchStarted && step != BatchStep::TreeNoncesAggregated {
                    continue;
                }
                let node = TreeTxNode {
                    txid: e.txid.clone(),
                    tx: e.tx.clone(),
                    children: e.children,
                };
                if e.batch_index == 0 {
                    flat_vtxo_tree.push(node);
                } else {
                    flat_connector_tree.push(node);
                }
            }

            round_event::Event::TreeSigningStarted(e) => {
                if step != BatchStep::BatchStarted {
                    continue;
                }
                let found = e
                    .cosigners_pubkeys
                    .iter()
                    .any(|pk| pk == &signer.pubkey_hex);
                if !found {
                    continue;
                }
                cosigner_pubkeys = e.cosigners_pubkeys.clone();
                vtxo_tree_txids = flat_vtxo_tree.iter().map(|n| n.txid.clone()).collect();
                signer.generate_nonces(&vtxo_tree_txids);
                let tree_nonces: HashMap<String, String> = signer.tree_nonces_hex();
                client
                    .submit_tree_nonces(SubmitTreeNoncesRequest {
                        batch_id: e.id.clone(),
                        pubkey: signer.pubkey_hex.clone(),
                        tree_nonces,
                    })
                    .await
                    .map_err(|e| ClientError::Rpc(format!("SubmitTreeNonces failed: {}", e)))?;
                step = BatchStep::TreeSigningStarted;
            }

            round_event::Event::TreeNonces(e) => {
                if step != BatchStep::TreeSigningStarted {
                    continue;
                }
                let cosigner_nonces: HashMap<String, String> = e
                    .nonces
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let all_aggregated = signer.aggregate_nonces_for_tx(
                    &e.txid,
                    &cosigner_nonces,
                    vtxo_tree_txids.len(),
                    &flat_vtxo_tree,
                )?;
                if all_aggregated {
                    let sigs = signer.sign_tree(&flat_vtxo_tree, &cosigner_pubkeys)?;
                    client
                        .submit_tree_signatures(SubmitTreeSignaturesRequest {
                            batch_id: e.id.clone(),
                            pubkey: signer.pubkey_hex.clone(),
                            tree_signatures: sigs,
                        })
                        .await
                        .map_err(|e| {
                            ClientError::Rpc(format!("SubmitTreeSignatures failed: {}", e))
                        })?;
                    step = BatchStep::TreeNoncesAggregated;
                }
            }

            round_event::Event::TreeNoncesAggregated(_) | round_event::Event::TreeSignature(_) => {}

            round_event::Event::BatchFinalization(e) => {
                if step != BatchStep::TreeNoncesAggregated {
                    continue;
                }
                _commitment_tx = e.commitment_tx.clone();

                // Build and sign forfeit transactions for VTXOs being spent.
                let signed_forfeit_txs = if !vtxos_to_forfeit.is_empty() {
                    let asp_pk = asp_forfeit_pubkey.ok_or_else(|| {
                        ClientError::InvalidResponse(
                            "VTXOs to forfeit but no ASP forfeit pubkey provided".into(),
                        )
                    })?;

                    // Collect connector tree leaves (nodes with no children).
                    let connector_leaves: Vec<&TreeTxNode> = flat_connector_tree
                        .iter()
                        .filter(|n| n.children.is_empty())
                        .collect();

                    if connector_leaves.len() < vtxos_to_forfeit.len() {
                        return Err(ClientError::InvalidResponse(format!(
                            "Not enough connector leaves ({}) for VTXOs to forfeit ({})",
                            connector_leaves.len(),
                            vtxos_to_forfeit.len(),
                        )));
                    }

                    build_and_sign_forfeits(
                        secret_key,
                        vtxos_to_forfeit,
                        &connector_leaves,
                        asp_pk,
                    )?
                } else {
                    vec![]
                };

                // Sign the commitment tx if it contains boarding inputs
                // that belong to us. The server needs our signature on those
                // inputs before it can broadcast the commitment tx.
                let signed_commitment = sign_commitment_tx(secret_key, &_commitment_tx);

                client
                    .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                        signed_forfeit_txs,
                        signed_commitment_tx: signed_commitment,
                    })
                    .await
                    .map_err(|e| {
                        ClientError::Rpc(format!("SubmitSignedForfeitTxs failed: {}", e))
                    })?;
                step = BatchStep::BatchFinalization;
            }

            round_event::Event::BatchFinalized(e) => {
                // Accept BatchFinalized at any step once we know our batch.
                // When the server has zero cosigners it auto-completes the
                // round (skipping tree signing), so the client may still be
                // at BatchStarted when BatchFinalized arrives.
                if !batch_session_id.is_empty() && e.id == batch_session_id {
                    return Ok(e.commitment_txid);
                }
            }

            round_event::Event::BatchFailed(e) => {
                if !batch_session_id.is_empty() && e.id == batch_session_id {
                    return Err(ClientError::Rpc(format!("Batch failed: {}", e.reason)));
                }
            }
        }
    }
}

/// Sign the commitment tx PSBT with our key for any inputs we own.
///
/// The server sends us the commitment PSBT during BatchFinalization. This
/// function handles two spend paths:
///
/// 1. **VTXO inputs (key-path spend):** The user key IS the tweaked internal
///    key. We sign with a standard taproot key-path spend.
///
/// 2. **Boarding inputs (script-path spend):** The internal key is the BIP-341
///    unspendable key, and the PSBT input contains `tap_scripts` with the
///    cooperative leaf (`<user> OP_CHECKSIGVERIFY <asp> OP_CHECKSIG`). We
///    sign using `taproot_script_spend_signature_hash` and populate
///    `tap_script_sigs`.
///
/// Returns the signed PSBT as base64, or an empty string if signing fails
/// (e.g. the PSBT is empty or cannot be parsed).
fn sign_commitment_tx(
    secret_key: &bitcoin::secp256k1::SecretKey,
    commitment_psbt_b64: &str,
) -> String {
    use base64::Engine;

    if commitment_psbt_b64.is_empty() {
        return String::new();
    }

    let psbt_bytes = match base64::engine::general_purpose::STANDARD.decode(commitment_psbt_b64) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };

    let mut psbt = match bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (our_xonly, _parity) = keypair.x_only_public_key();
    // Key-path tweaked pubkey for VTXO inputs (no script tree).
    let (tweaked_pk, _) = our_xonly.tap_tweak(&secp, None);
    let our_p2tr = ScriptBuf::new_p2tr_tweaked(tweaked_pk);

    // Serialized x-only key bytes for matching inside tap leaf scripts.
    let our_xonly_bytes = our_xonly.serialize();

    // Collect prevouts for sighash computation.
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|inp| {
            inp.witness_utxo.clone().unwrap_or(TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            })
        })
        .collect();

    let mut signed_any = false;
    for (i, psbt_input) in psbt.inputs.iter_mut().enumerate() {
        // Skip inputs that already have a key-path signature.
        if psbt_input.tap_key_sig.is_some() {
            continue;
        }

        // ── Boarding inputs: script-path spend via cooperative leaf ──
        //
        // Boarding inputs have tap_scripts populated by the server and use an
        // unspendable internal key. Detect them by checking that tap_scripts
        // is non-empty AND the internal key (if present) is NOT our key.
        let is_boarding = !psbt_input.tap_scripts.is_empty()
            && psbt_input
                .tap_internal_key
                .map(|ik| ik != our_xonly)
                .unwrap_or(true);

        if is_boarding {
            // Find the cooperative leaf: the one whose script contains our
            // x-only pubkey bytes. The cooperative script format is:
            //   <user_xonly> OP_CHECKSIGVERIFY <asp_xonly> OP_CHECKSIG
            let leaf =
                psbt_input
                    .tap_scripts
                    .iter()
                    .find(|(_control_block, (script, _version))| {
                        let script_bytes = script.as_bytes();
                        // Cooperative leaf: <user_xonly(32)> OP_CHECKSIGVERIFY <asp_xonly(32)> OP_CHECKSIG
                        //   = 1 + 32 + 1 + 1 + 32 + 1 = 68 bytes
                        // CSV exit leaf:    push_int(delay) OP_CSV OP_DROP <user_xonly(32)> OP_CHECKSIG
                        //   ≈ 3 + 1 + 1 + 1 + 32 + 1 = 39 bytes (for typical CSV delays)
                        //
                        // The cooperative leaf is always LONGER than the CSV exit leaf.
                        // Also, the cooperative leaf starts with 0x20 (push 32 bytes) followed
                        // immediately by our key, whereas the CSV leaf starts with the delay integer.
                        //
                        // Use length as the primary discriminator — much more reliable than
                        // scanning for opcode bytes which may appear in key data.
                        let has_our_key = script_bytes
                            .windows(our_xonly_bytes.len())
                            .any(|w| w == our_xonly_bytes);
                        // Cooperative leaf is exactly 68 bytes for two 32-byte x-only keys
                        let is_coop_length = script_bytes.len() == 68;
                        has_our_key && is_coop_length
                    });

            let (control_block, (leaf_script, leaf_version)) = match leaf {
                Some((cb, (s, v))) => (cb, (s, v)),
                None => continue,
            };

            let leaf_hash = TapLeafHash::from_script(leaf_script, *leaf_version);

            let mut cache = SighashCache::new(&psbt.unsigned_tx);
            let sighash = match cache.taproot_script_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            ) {
                Ok(h) => h,
                Err(_) => continue,
            };

            let msg = Message::from_digest(sighash.to_byte_array());
            // Script-path spend: sign with the untweaked keypair.
            let sig = secp.sign_schnorr(&msg, &keypair);
            let tap_sig = bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            };
            psbt_input
                .tap_script_sigs
                .insert((our_xonly, leaf_hash), tap_sig);

            // Ensure the control block and leaf script are preserved so the
            // finalizer can build the witness stack.
            let _ = control_block; // already in tap_scripts

            signed_any = true;
            continue;
        }

        // ── VTXO inputs: key-path spend ──
        let is_ours = psbt_input
            .witness_utxo
            .as_ref()
            .map(|utxo| utxo.script_pubkey == our_p2tr)
            .unwrap_or(false);

        if !is_ours {
            continue;
        }

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = match cache.taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        ) {
            Ok(h) => h,
            Err(_) => continue,
        };

        let msg = Message::from_digest(sighash.to_byte_array());
        let tweaked_keypair = keypair.tap_tweak(&secp, None).to_keypair();
        let sig = secp.sign_schnorr(&msg, &tweaked_keypair);
        psbt_input.tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        });
        signed_any = true;
    }

    if !signed_any {
        return String::new();
    }

    let signed_bytes = psbt.serialize();
    base64::engine::general_purpose::STANDARD.encode(&signed_bytes)
}

/// Build and sign forfeit transactions for each VTXO being refreshed.
///
/// Each VTXO is paired with a connector tree leaf. The forfeit tx spends the
/// VTXO + connector output, paying the combined value (minus fees) to the ASP.
/// The VTXO input is signed with a taproot key-path spend using `secret_key`.
fn build_and_sign_forfeits(
    secret_key: &bitcoin::secp256k1::SecretKey,
    vtxos: &[VtxoInput],
    connector_leaves: &[&TreeTxNode],
    asp_pubkey: XOnlyPublicKey,
) -> ClientResult<Vec<String>> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (client_xonly, _parity) = keypair.x_only_public_key();

    // Derive the tweaked ASP key for P2TR key-path spend (no script tree).
    let (asp_tweaked, _parity) = asp_pubkey.tap_tweak(&secp, None);

    let mut signed_txs = Vec::with_capacity(vtxos.len());

    for (i, vtxo) in vtxos.iter().enumerate() {
        let connector_node = connector_leaves[i];

        // Parse the connector transaction from hex.
        let connector_tx =
            dark_bitcoin::BitcoinTxDecoder::decode_hex(&connector_node.tx).map_err(|e| {
                ClientError::InvalidResponse(format!("Failed to decode connector tx: {}", e))
            })?;

        // Find the first non-anchor output in the connector tx
        // (skip OP_RETURN / anchor outputs).
        let (conn_vout, conn_output) = connector_tx
            .output
            .iter()
            .enumerate()
            .find(|(_idx, out)| !out.script_pubkey.is_op_return() && out.value.to_sat() > 0)
            .ok_or_else(|| {
                ClientError::InvalidResponse(
                    "No usable output in connector tx (all anchor/OP_RETURN)".into(),
                )
            })?;

        let connector_txid = connector_tx.compute_txid();
        let connector_outpoint = OutPoint {
            txid: connector_txid,
            vout: conn_vout as u32,
        };
        let connector_amount = conn_output.value;

        // Parse VTXO outpoint.
        let vtxo_txid = vtxo.txid.parse::<Txid>().map_err(|e| {
            ClientError::InvalidResponse(format!("Invalid VTXO txid '{}': {}", vtxo.txid, e))
        })?;
        let vtxo_outpoint = OutPoint {
            txid: vtxo_txid,
            vout: vtxo.vout,
        };
        let vtxo_amount = Amount::from_sat(vtxo.amount);

        // Build the unsigned forfeit transaction (2 sat/vB fee rate).
        let forfeit_tx = ForfeitTx::build(
            vtxo_outpoint,
            vtxo_amount,
            connector_outpoint,
            connector_amount,
            asp_tweaked,
            2,
        )
        .map_err(|e| ClientError::InvalidResponse(format!("Failed to build forfeit tx: {}", e)))?;

        // Compute the taproot key-path sighash for input 0 (the VTXO input).
        let vtxo_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(client_xonly),
        );
        let prevouts = vec![
            TxOut {
                value: vtxo_amount,
                script_pubkey: vtxo_script,
            },
            TxOut {
                value: connector_amount,
                script_pubkey: conn_output.script_pubkey.clone(),
            },
        ];

        let mut cache = SighashCache::new(&forfeit_tx.tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|e| {
                ClientError::InvalidResponse(format!("Forfeit sighash computation failed: {}", e))
            })?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr(&msg, &keypair);

        // Attach the witness (64-byte Schnorr signature) to input 0.
        let mut signed_tx = forfeit_tx.tx.clone();
        signed_tx.input[0].witness.push(sig.as_ref());

        // Serialize the signed transaction to hex.
        let mut buf = Vec::new();
        signed_tx
            .consensus_encode(&mut buf)
            .map_err(|e| ClientError::InvalidResponse(format!("Failed to encode tx: {}", e)))?;
        signed_txs.push(hex::encode(buf));
    }

    Ok(signed_txs)
}
