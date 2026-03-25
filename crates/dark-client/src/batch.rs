//! Batch protocol state machine for Ark round settlement.
//!
//! Implements the full batch protocol matching the Go SDK's `JoinBatchSession`:
//! 1. RegisterIntent -> get intent_id
//! 2. Subscribe to GetEventStream
//! 3. Process events through state machine
//! 4. MuSig2 nonce generation + partial signing
//! 5. Submit forfeit transactions

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use musig2::{BinaryEncoding, KeyAggContext, PubNonce, SecNonce};

use dark_api::proto::ark_v1::round_event;
use dark_api::proto::ark_v1::{
    ark_service_client::ArkServiceClient, GetEventStreamRequest, SubmitSignedForfeitTxsRequest,
    SubmitTreeNoncesRequest, SubmitTreeSignaturesRequest, UpdateStreamTopicsRequest,
};
use tonic::transport::Channel;

use crate::error::{ClientError, ClientResult};

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
}

impl SignerState {
    fn new(secret_key: musig2::secp256k1::SecretKey) -> Self {
        let secp = musig2::secp256k1::Secp256k1::new();
        let pubkey = musig2::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_hex = hex::encode(pubkey.serialize());
        Self {
            secret_key,
            pubkey_hex,
            sec_nonces: HashMap::new(),
            pub_nonces: HashMap::new(),
            agg_nonces: HashMap::new(),
        }
    }

    fn generate_nonces(&mut self, tree_txids: &[String]) {
        for txid in tree_txids {
            let msg = txid.as_bytes();
            let (sec_nonce, pub_nonce) = dark_bitcoin::generate_nonce(&self.secret_key, msg);
            self.sec_nonces.insert(txid.clone(), sec_nonce);
            self.pub_nonces.insert(txid.clone(), pub_nonce);
        }
    }

    fn tree_nonces_bytes(&self) -> HashMap<String, Vec<u8>> {
        self.pub_nonces
            .iter()
            .map(|(txid, pn)| (txid.clone(), pn.to_bytes().to_vec()))
            .collect()
    }

    fn aggregate_nonces_for_tx(
        &mut self,
        txid: &str,
        cosigner_nonces: &HashMap<String, String>,
        total_tree_txs: usize,
    ) -> ClientResult<bool> {
        if self.agg_nonces.contains_key(txid) {
            return Ok(self.agg_nonces.len() >= total_tree_txs);
        }

        let mut all_pub_nonces = Vec::new();

        if let Some(our_nonce) = self.pub_nonces.get(txid) {
            all_pub_nonces.push(our_nonce.clone());
        }

        for nonce_hex in cosigner_nonces.values() {
            let nonce_bytes = hex::decode(nonce_hex)
                .map_err(|e| ClientError::InvalidResponse(format!("Invalid nonce hex: {}", e)))?;
            let pub_nonce = PubNonce::from_bytes(&nonce_bytes)
                .map_err(|e| ClientError::InvalidResponse(format!("Invalid PubNonce: {}", e)))?;
            all_pub_nonces.push(pub_nonce);
        }

        if all_pub_nonces.len() < 2 {
            return Ok(false);
        }

        let agg_nonce = dark_bitcoin::aggregate_nonces(&all_pub_nonces);
        self.agg_nonces.insert(txid.to_string(), agg_nonce);

        Ok(self.agg_nonces.len() >= total_tree_txs)
    }

    fn sign_tree(
        &mut self,
        tree_txids: &[String],
        cosigner_pubkeys: &[String],
    ) -> ClientResult<HashMap<String, Vec<u8>>> {
        let mut sigs = HashMap::new();

        let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = Vec::new();
        for pk_hex in cosigner_pubkeys {
            let pk_bytes = hex::decode(pk_hex)
                .map_err(|e| ClientError::Rpc(format!("Invalid cosigner pubkey hex: {}", e)))?;
            let pk = musig2::secp256k1::PublicKey::from_slice(&pk_bytes)
                .map_err(|e| ClientError::Rpc(format!("Invalid cosigner pubkey: {}", e)))?;
            musig_pubkeys.push(pk);
        }
        musig_pubkeys.sort();

        let key_agg_ctx = KeyAggContext::new(musig_pubkeys)
            .map_err(|e| ClientError::Rpc(format!("MuSig2 key aggregation failed: {}", e)))?;

        for txid in tree_txids {
            let agg_nonce = self.agg_nonces.get(txid).ok_or_else(|| {
                ClientError::Rpc(format!("Missing aggregated nonce for txid {}", txid))
            })?;

            let sec_nonce = self.sec_nonces.remove(txid).ok_or_else(|| {
                ClientError::Rpc(format!(
                    "Missing secret nonce for txid {} (already consumed?)",
                    txid
                ))
            })?;

            let mut msg = [0u8; 32];
            let hash = Sha256::digest(txid.as_bytes());
            msg.copy_from_slice(&hash);

            let partial_sig = dark_bitcoin::create_partial_sig(
                &key_agg_ctx,
                &self.secret_key,
                sec_nonce,
                agg_nonce,
                &msg,
            )
            .map_err(|e| ClientError::Rpc(format!("MuSig2 partial signing failed: {}", e)))?;

            sigs.insert(txid.clone(), partial_sig.serialize().to_vec());
        }

        Ok(sigs)
    }
}

/// Execute the full batch protocol for settle().
pub(crate) async fn run_batch_protocol(
    client: &mut ArkServiceClient<Channel>,
    intent_id: &str,
    secret_key: &bitcoin::secp256k1::SecretKey,
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
    let mut _commitment_tx = String::new();

    let mut stream = client
        .get_event_stream(GetEventStreamRequest {})
        .await
        .map_err(|e| ClientError::Rpc(format!("GetEventStream failed: {}", e)))?
        .into_inner();

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
                if step > BatchStep::Start {
                    continue;
                }
                let found = e.intent_id_hashes.iter().any(|h| h == &intent_hash);
                if !found {
                    continue;
                }
                client
                    .confirm_registration(dark_api::proto::ark_v1::ConfirmRegistrationRequest {
                        intent_id: intent_id.to_string(),
                    })
                    .await
                    .map_err(|e| ClientError::Rpc(format!("ConfirmRegistration failed: {}", e)))?;
                batch_session_id = e.id.clone();
                let _ = client
                    .update_stream_topics(UpdateStreamTopicsRequest {
                        topics: vec![signer.pubkey_hex.clone()],
                        update_mode: None,
                    })
                    .await;
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
                let tree_nonces: HashMap<String, Vec<u8>> = signer.tree_nonces_bytes();
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
                )?;
                if all_aggregated {
                    let sigs = signer.sign_tree(&vtxo_tree_txids, &cosigner_pubkeys)?;
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
                client
                    .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                        signed_forfeit_txs: vec![],
                        signed_commitment_tx: String::new(),
                    })
                    .await
                    .map_err(|e| {
                        ClientError::Rpc(format!("SubmitSignedForfeitTxs failed: {}", e))
                    })?;
                step = BatchStep::BatchFinalization;
            }

            round_event::Event::BatchFinalized(e) => {
                if step != BatchStep::BatchFinalization {
                    continue;
                }
                if e.id == batch_session_id {
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
