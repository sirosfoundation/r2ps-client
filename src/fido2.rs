//! FIDO2/WebAuthn 2FA authentication for R2PS.
//!
//! This module implements the client-side FIDO2 authentication flow as specified
//! in r2ps-service-types.md §4.1.3 (registration) and §4.2.3 (authentication).
//!
//! The actual WebAuthn ceremony (UV gesture, authenticator interaction) is delegated
//! to external code via the [`Fido2Ceremony`] trait.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::{ecdh::EphemeralSecret, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{R2psError, Result};

/// Trait for delegating the WebAuthn ceremony to external code.
///
/// Implementors perform the actual authenticator interaction
/// (credential creation or assertion) using platform WebAuthn APIs.
pub trait Fido2Ceremony {
    /// Perform a WebAuthn credential creation ceremony.
    ///
    /// # Arguments
    /// * `challenge` - The server-provided challenge (base64url-encoded)
    /// * `rp_id` - The Relying Party ID
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// The attestation result to send to the server.
    fn create_credential(
        &self,
        challenge: &str,
        rp_id: &str,
        user_id: &str,
    ) -> Result<RegistrationResult>;

    /// Perform a WebAuthn assertion ceremony.
    ///
    /// # Arguments
    /// * `challenge` - The server-provided challenge (base64url-encoded)
    /// * `rp_id` - The Relying Party ID
    /// * `allow_credentials` - List of allowed credential IDs (base64url)
    ///
    /// # Returns
    /// The assertion result to send to the server.
    fn get_assertion(
        &self,
        challenge: &str,
        rp_id: &str,
        allow_credentials: &[String],
    ) -> Result<AssertionResult>;
}

/// Result of a WebAuthn credential creation ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    /// Base64url-encoded credential identifier
    pub credential_id: String,
    /// Base64url-encoded attestation object
    pub attestation_object: String,
    /// Base64url-encoded clientDataJSON
    pub client_data: String,
}

/// Result of a WebAuthn assertion ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResult {
    /// Base64url-encoded credential identifier
    pub credential_id: String,
    /// Base64url-encoded authenticator data
    pub authenticator_data: String,
    /// Base64url-encoded clientDataJSON
    pub client_data: String,
    /// Base64url-encoded signature
    pub signature: String,
}

/// FIDO2 challenge response from the server.
#[derive(Debug, Clone, Deserialize)]
pub struct Fido2ChallengeResponse {
    pub challenge: String,
    pub token: String,
    pub user_verification: Option<String>,
}

/// FIDO2 auth finalize response from the server.
#[derive(Debug, Clone, Deserialize)]
pub struct Fido2FinalizeResponse {
    pub server_epub: String,
    /// I-D field name.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Legacy field name.
    #[serde(rename = "2fa_session_id", default)]
    pub tfa_session_id: Option<String>,
    pub task: String,
    pub session_expiration_time: i64,
}

/// FIDO2 registration request (state=register).
#[derive(Debug, Clone, Serialize)]
pub struct Fido2RegisterRequest {
    pub credential_id: String,
    pub attestation_object: String,
    pub client_data: String,
}

/// FIDO2 finalize request (state=finalize).
#[derive(Debug, Clone, Serialize)]
pub struct Fido2FinalizeRequest {
    pub client_epub: String,
    pub token: String,
    pub task: String,
    pub assertion: AssertionResult,
}

/// FIDO2 TFA request data wrapper for the R2PS protocol.
/// Used when request is a JSON object rather than base64-encoded bytes.
#[derive(Debug, Clone, Serialize)]
pub struct Fido2TfaRequestData {
    pub protocol: String,
    pub state: String,
    pub request: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
}

/// Derive the FIDO2 session key using HKDF.
///
/// Per spec §4.2.3.2:
/// - ikm = ECDH(own_eprv, peer_epub)
/// - salt = finalize message nonce
/// - info = "r2ps-2fa_authentication-fido2" || SHA256(2fa_mode || client_epub || server_epub || task)
/// - L = 32 bytes
pub fn derive_fido2_session_key(
    shared_secret: &[u8],
    nonce: &[u8],
    client_epub_bytes: &[u8],
    server_epub_bytes: &[u8],
    task: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    use hkdf::Hkdf;

    // Build transcript binding hash
    let mut transcript = Sha256::new();
    transcript.update(b"fido2");
    transcript.update(client_epub_bytes);
    transcript.update(server_epub_bytes);
    transcript.update(task.as_bytes());
    let transcript_hash = transcript.finalize();

    // info = DST || transcript_hash
    let dst = b"r2ps-2fa_authentication-fido2";
    let mut info = Vec::with_capacity(dst.len() + 32);
    info.extend_from_slice(dst);
    info.extend_from_slice(&transcript_hash);

    let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
    let mut session_key = Zeroizing::new(vec![0u8; 32]);
    hk.expand(&info, &mut session_key)
        .map_err(|e| R2psError::Protocol(format!("HKDF expand failed: {e}")))?;

    Ok(session_key)
}

/// Build a SAD task string for signing specific hashes.
///
/// The task format is: "sign:<hex-hash1>,<hex-hash2>,..."
/// This binds the 2FA session to only authorize signing these specific hashes.
pub fn build_sign_task(hashes: &[&[u8]]) -> String {
    let mut task = String::from("sign:");
    for (i, hash) in hashes.iter().enumerate() {
        if i > 0 {
            task.push(',');
        }
        task.push_str(&hex::encode(hash));
    }
    task
}

/// Simple hex encoding (no external dep needed for this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            result.push(HEX_CHARS[(b >> 4) as usize] as char);
            result.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        result
    }
}

/// Generate an ephemeral P-256 key pair for session establishment.
/// Returns (private_key_for_ecdh, uncompressed_public_key_bytes).
pub fn generate_ephemeral_keypair() -> Result<(EphemeralSecret, Vec<u8>)> {
    let secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let public_key = secret.public_key();
    let pub_bytes = public_key.to_sec1_bytes().to_vec();
    Ok((secret, pub_bytes))
}

/// Perform ECDH with the server's ephemeral public key.
pub fn compute_shared_secret(
    client_secret: EphemeralSecret,
    server_epub_bytes: &[u8],
) -> Result<Vec<u8>> {
    let server_pub = PublicKey::from_sec1_bytes(server_epub_bytes)
        .map_err(|e| R2psError::Protocol(format!("invalid server epub: {e}")))?;
    let shared = client_secret.diffie_hellman(&server_pub);
    Ok(shared.raw_secret_bytes().to_vec())
}

/// Encode the registration ceremony result as a base64url-encoded JSON string for the request field.
pub fn encode_register_request(result: &RegistrationResult, _token: &str) -> Result<String> {
    let req = Fido2RegisterRequest {
        credential_id: result.credential_id.clone(),
        attestation_object: result.attestation_object.clone(),
        client_data: result.client_data.clone(),
    };
    let json = serde_json::to_vec(&req)?;
    Ok(Base64UrlUnpadded::encode_string(&json))
}

/// Encode the finalize request as a base64url-encoded JSON string.
pub fn encode_finalize_request(
    client_epub_bytes: &[u8],
    token: &str,
    task: &str,
    assertion: &AssertionResult,
) -> Result<String> {
    let req = Fido2FinalizeRequest {
        client_epub: Base64UrlUnpadded::encode_string(client_epub_bytes),
        token: token.to_string(),
        task: task.to_string(),
        assertion: assertion.clone(),
    };
    let json = serde_json::to_vec(&req)?;
    Ok(Base64UrlUnpadded::encode_string(&json))
}
