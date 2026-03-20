//! SignerService gRPC implementation for the standalone signer binary.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::Network;
use tonic::{Request, Response, Status};
use tracing::{debug, info};

// For TapSighash::to_byte_array
use bitcoin::hashes::Hash as _;

use dark_api::proto::ark_v1::signer_service_server::SignerService;
use dark_api::proto::ark_v1::{
    AggregateKeysRequest, AggregateKeysResponse, GetPublicKeyRequest, GetPublicKeyResponse,
    SignMessageRequest, SignMessageResponse, SignTransactionRequest, SignTransactionResponse,
};

/// In-process signer holding the ASP secret key.
pub struct SignerServiceImpl {
    keypair: Keypair,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    #[allow(dead_code)]
    network: Network,
}

impl SignerServiceImpl {
    /// Build from a hex-encoded 32-byte secret key.
    pub fn from_hex(
        hex_key: &str,
        network: Network,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = hex::decode(hex_key)?;
        let secret_key = SecretKey::from_slice(&bytes)?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        Ok(Self {
            keypair,
            secp,
            network,
        })
    }

    /// Compressed public key hex (for logging).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keypair.public_key().serialize())
    }
}

#[tonic::async_trait]
impl SignerService for SignerServiceImpl {
    /// Return the compressed public key (33 bytes).
    async fn get_public_key(
        &self,
        _request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let pubkey = self.keypair.public_key().serialize().to_vec();
        debug!("GetPublicKey called");
        Ok(Response::new(GetPublicKeyResponse { pubkey }))
    }

    /// Sign a PSBT — iterates over requested inputs and signs with the
    /// signer's keypair using `SIGHASH_DEFAULT` (Schnorr / taproot key-path).
    async fn sign_transaction(
        &self,
        request: Request<SignTransactionRequest>,
    ) -> Result<Response<SignTransactionResponse>, Status> {
        let req = request.into_inner();
        info!(
            inputs = req.input_indexes.len(),
            "SignTransaction request received"
        );

        let mut psbt: bitcoin::Psbt = bitcoin::Psbt::deserialize(&req.psbt)
            .map_err(|e| Status::invalid_argument(format!("invalid PSBT: {e}")))?;

        let indexes: Vec<usize> = if req.input_indexes.is_empty() {
            // Sign all inputs when none specified.
            (0..psbt.inputs.len()).collect()
        } else {
            req.input_indexes.iter().map(|i| *i as usize).collect()
        };

        for idx in &indexes {
            if *idx >= psbt.inputs.len() {
                return Err(Status::invalid_argument(format!(
                    "input index {} out of range (PSBT has {} inputs)",
                    idx,
                    psbt.inputs.len()
                )));
            }

            // Compute the sighash for taproot key-path spend.
            let sighash = {
                let mut prevouts: Vec<bitcoin::TxOut> = Vec::with_capacity(psbt.inputs.len());
                for (i, input) in psbt.inputs.iter().enumerate() {
                    prevouts.push(input.witness_utxo.clone().ok_or_else(|| {
                        Status::invalid_argument(format!("missing witness_utxo for input {i}"))
                    })?);
                }

                let prevouts_ref = bitcoin::sighash::Prevouts::All(&prevouts);
                let mut sighash_cache =
                    bitcoin::sighash::SighashCache::new(psbt.unsigned_tx.clone());
                let hash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        *idx,
                        &prevouts_ref,
                        bitcoin::sighash::TapSighashType::Default,
                    )
                    .map_err(|e| {
                        Status::internal(format!("sighash computation failed for input {idx}: {e}"))
                    })?;
                hash
            };

            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = self.secp.sign_schnorr(&msg, &self.keypair);

            let bitcoin_sig = bitcoin::taproot::Signature {
                signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&sig[..])
                    .map_err(|e| Status::internal(format!("sig conversion: {e}")))?,
                sighash_type: bitcoin::sighash::TapSighashType::Default,
            };

            psbt.inputs[*idx].tap_key_sig = Some(bitcoin_sig);
        }

        let signed = psbt.serialize();
        Ok(Response::new(SignTransactionResponse {
            signed_psbt: signed,
        }))
    }

    /// Sign an arbitrary message with Schnorr (BIP-340).
    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<SignMessageResponse>, Status> {
        let req = request.into_inner();
        debug!(len = req.message.len(), "SignMessage request received");

        if req.message.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "message must be exactly 32 bytes (got {})",
                req.message.len()
            )));
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&req.message);
        let msg = Message::from_digest(digest);
        let sig = self.secp.sign_schnorr(&msg, &self.keypair);

        Ok(Response::new(SignMessageResponse {
            signature: sig[..].to_vec(),
        }))
    }

    /// Aggregate public keys (MuSig2 placeholder).
    ///
    /// Full MuSig2 key aggregation requires a proper library (e.g. `musig2`).
    /// For now we return an error directing callers to a future implementation.
    async fn aggregate_keys(
        &self,
        _request: Request<AggregateKeysRequest>,
    ) -> Result<Response<AggregateKeysResponse>, Status> {
        Err(Status::unimplemented(
            "MuSig2 key aggregation not yet implemented — see dark issue tracker",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> SignerServiceImpl {
        // Deterministic test key
        let hex_key = "0000000000000000000000000000000000000000000000000000000000000001";
        SignerServiceImpl::from_hex(hex_key, Network::Regtest).unwrap()
    }

    #[tokio::test]
    async fn get_public_key_returns_33_bytes() {
        let signer = test_signer();
        let resp = signer
            .get_public_key(Request::new(GetPublicKeyRequest {}))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().pubkey.len(), 33);
    }

    #[tokio::test]
    async fn sign_message_valid() {
        let signer = test_signer();
        let message = vec![0xab; 32];
        let resp = signer
            .sign_message(Request::new(SignMessageRequest {
                message: message.clone(),
            }))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().signature.len(), 64);
    }

    #[tokio::test]
    async fn sign_message_wrong_length_rejected() {
        let signer = test_signer();
        let result = signer
            .sign_message(Request::new(SignMessageRequest {
                message: vec![0u8; 31],
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn aggregate_keys_unimplemented() {
        let signer = test_signer();
        let result = signer
            .aggregate_keys(Request::new(AggregateKeysRequest { pubkeys: vec![] }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unimplemented);
    }
}
