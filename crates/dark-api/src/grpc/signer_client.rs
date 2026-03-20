//! Remote signer gRPC client for key isolation.
//!
//! When `remote_signer_url` is configured, the main dark process delegates
//! all signing operations to a separate signer process via this client.

use tonic::transport::Channel;

use crate::proto::ark_v1::signer_service_client::SignerServiceClient;
use crate::proto::ark_v1::{
    AggregateKeysRequest, GetPublicKeyRequest, SignMessageRequest, SignTransactionRequest,
};

/// Remote signer client wrapping the generated gRPC `SignerServiceClient`.
pub struct RemoteSignerClient {
    inner: SignerServiceClient<Channel>,
}

impl RemoteSignerClient {
    /// Connect to a remote signer at the given gRPC URL.
    pub async fn connect(url: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Channel::from_shared(url.to_string())
            .expect("valid URI")
            .connect()
            .await?;
        Ok(Self {
            inner: SignerServiceClient::new(channel),
        })
    }

    /// Retrieve the signer's public key.
    pub async fn get_public_key(&mut self) -> Result<Vec<u8>, tonic::Status> {
        let resp = self.inner.get_public_key(GetPublicKeyRequest {}).await?;
        Ok(resp.into_inner().pubkey)
    }

    /// Sign a PSBT, optionally restricting to specific input indexes.
    pub async fn sign_transaction(
        &mut self,
        psbt: Vec<u8>,
        input_indexes: Vec<u32>,
    ) -> Result<Vec<u8>, tonic::Status> {
        let resp = self
            .inner
            .sign_transaction(SignTransactionRequest {
                psbt,
                input_indexes,
            })
            .await?;
        Ok(resp.into_inner().signed_psbt)
    }

    /// Sign an arbitrary message (Schnorr).
    pub async fn sign_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>, tonic::Status> {
        let resp = self
            .inner
            .sign_message(SignMessageRequest { message })
            .await?;
        Ok(resp.into_inner().signature)
    }

    /// Aggregate public keys (MuSig2).
    pub async fn aggregate_keys(
        &mut self,
        pubkeys: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, tonic::Status> {
        let resp = self
            .inner
            .aggregate_keys(AggregateKeysRequest { pubkeys })
            .await?;
        Ok(resp.into_inner().aggregated_pubkey)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    use crate::proto::ark_v1;

    #[test]
    fn test_signer_proto_compiles() {
        // Verify all generated signer types are accessible
        let _req = ark_v1::GetPublicKeyRequest {};
        let _resp = ark_v1::GetPublicKeyResponse {
            pubkey: vec![0u8; 33],
        };
        let _sign_req = ark_v1::SignTransactionRequest {
            psbt: vec![],
            input_indexes: vec![0, 1],
        };
        let _sign_resp = ark_v1::SignTransactionResponse {
            signed_psbt: vec![],
        };
        let _msg_req = ark_v1::SignMessageRequest {
            message: vec![0u8; 32],
        };
        let _msg_resp = ark_v1::SignMessageResponse {
            signature: vec![0u8; 64],
        };
        let _agg_req = ark_v1::AggregateKeysRequest { pubkeys: vec![] };
        let _agg_resp = ark_v1::AggregateKeysResponse {
            aggregated_pubkey: vec![],
        };
    }

    #[test]
    fn test_remote_signer_url_config_default_none() {
        let config = crate::ServerConfig::default();
        assert!(
            config.remote_signer_url.is_none(),
            "remote_signer_url should default to None (local signing)"
        );
    }
}
