use crate::{
    client::{R2psClient, Transport},
    error::{R2psError, Result},
    pake::PakeClient,
    types::*,
};
use base64ct::Encoding;

/// Trait matching the FIDO2 rawSign extension API.
///
/// Implementations provide ECDSA signing — either via local FIDO2 rawSign
/// or via R2PS remote signing as a fallback for devices that lack rawSign.
pub trait RawSign {
    /// Generate a new EC key pair, returning the key identifier (`kid`).
    /// The kid is the hex-encoded compressed SEC1 public key point.
    fn generate_key(&mut self) -> Result<Vec<u8>>;

    /// Sign `data` using the key identified by `kid`.
    /// Returns the DER-encoded ECDSA signature.
    fn sign(&mut self, kid: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    /// List keys available in the remote HSM, optionally filtered by curves.
    fn list_keys(&mut self, curves: &[&str]) -> Result<Vec<HsmKeyInfo>>;
}

// --- HSM service type data structures (per r2ps-service-types.md) ---

/// EC key generation request (§1).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HsmEcKeygenRequest {
    pub curve: String,
}

/// EC key generation response (§1).
#[derive(serde::Deserialize)]
pub struct HsmEcKeygenResponse {
    pub created_key: String,
}

/// List HSM keys request (§2).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HsmListKeysRequest {
    pub curve: Vec<String>,
}

/// List HSM keys response (§2).
#[derive(serde::Deserialize)]
pub struct HsmListKeysResponse {
    pub key_info: Vec<HsmKeyInfo>,
}

/// Key info entry from list_keys (§2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HsmKeyInfo {
    /// Key identifier — hex-encoded compressed SEC1 public key point.
    pub kid: String,
    /// EC curve name (e.g. "P-256", "P-384", "P-521").
    pub curve_name: String,
    /// Creation time as Unix timestamp.
    pub creation_time: i64,
    /// SPKI DER-encoded public key (base64).
    pub public_key: String,
}

/// ECDSA sign request (§3).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HsmEcdsaRequest {
    pub kid: String,
    pub tbs_hash: String,
}
// ECDSA response: raw DER signature bytes (not JSON).

/// ECDH request (§4).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HsmEcdhRequest {
    pub kid: String,
    /// SPKI DER-encoded public key of the other party (base64).
    pub public_key: String,
}
// ECDH response: raw shared secret bytes (not JSON).

/// R2PS-backed implementation of [`RawSign`].
///
/// Uses the R2PS HSM service types to perform remote signing as a fallback
/// for devices without FIDO2 rawSign support. Conforms to the service type
/// definitions in `r2ps-service-types.md`.
pub struct R2psRawSign<'a, T: Transport, P: PakeClient> {
    client: &'a mut R2psClient<T, P>,
}

impl<'a, T: Transport, P: PakeClient> R2psRawSign<'a, T, P> {
    pub fn new(client: &'a mut R2psClient<T, P>) -> Self {
        Self { client }
    }

    /// Perform an ECDH key agreement using a remote HSM key.
    /// Returns the raw shared secret bytes.
    pub fn ecdh(&mut self, kid: &str, peer_spki_der_b64: &str) -> Result<Vec<u8>> {
        let req = serde_json::json!({
            "kid": kid,
            "public_key": peer_spki_der_b64,
        });

        let resp = self.client.call_service(TYPE_AGREE_ECDH, &req)?;
        // Response is base64-encoded raw shared secret
        let secret_b64 = resp
            .as_str()
            .ok_or_else(|| R2psError::Protocol("ECDH response is not a string".into()))?;
        base64ct::Base64::decode_vec(secret_b64).map_err(|e| R2psError::Base64(e.to_string()))
    }
}

impl<T: Transport, P: PakeClient> RawSign for R2psRawSign<'_, T, P> {
    fn generate_key(&mut self) -> Result<Vec<u8>> {
        let req = serde_json::json!({ "curve": "P-256" });

        // Step 1: Create the key (response confirms curve only)
        let _resp = self.client.call_service(TYPE_P256_GENERATE, &req)?;

        // Step 2: List keys to find the newly created key's kid
        let list_req = serde_json::json!({ "curve": ["P-256"] });
        let list_resp = self.client.call_service(TYPE_HSM_LIST_KEYS, &list_req)?;
        let list: HsmListKeysResponse = serde_json::from_value(list_resp)?;

        // Return the kid of the most recently created key
        let newest = list
            .key_info
            .into_iter()
            .max_by_key(|k| k.creation_time)
            .ok_or_else(|| R2psError::Protocol("no keys returned after keygen".into()))?;

        Ok(newest.kid.into_bytes())
    }

    fn sign(&mut self, kid: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let kid_str = String::from_utf8(kid.to_vec())
            .map_err(|e| R2psError::Protocol(format!("invalid kid: {e}")))?;

        let req = serde_json::json!({
            "kid": kid_str,
            "tbs_hash": base64ct::Base64::encode_string(data),
        });

        let resp = self.client.call_service(TYPE_SIGN_ECDSA, &req)?;
        // Response is base64-encoded raw DER signature
        let sig_b64 = resp
            .as_str()
            .ok_or_else(|| R2psError::Protocol("ECDSA response is not a string".into()))?;
        base64ct::Base64::decode_vec(sig_b64).map_err(|e| R2psError::Base64(e.to_string()))
    }

    fn list_keys(&mut self, curves: &[&str]) -> Result<Vec<HsmKeyInfo>> {
        let req = serde_json::json!({ "curve": curves });

        let resp = self.client.call_service(TYPE_HSM_LIST_KEYS, &req)?;
        let list: HsmListKeysResponse = serde_json::from_value(resp)?;

        Ok(list.key_info)
    }
}
