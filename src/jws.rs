use base64ct::Encoding;
use josekit::jws::{self as jose_jws, JwsHeader, ES256};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

use crate::error::{R2psError, Result};

/// Protected headers extracted from a JWS without signature verification.
#[derive(Debug, Clone, Default)]
pub struct JwsHeaders {
    pub kid: Option<String>,
    pub typ: Option<String>,
}

/// Create a JWS compact serialization (ES256) of `payload`.
pub fn sign_jws(
    payload: &[u8],
    key: &SigningKey,
    kid: Option<&str>,
    typ: Option<&str>,
) -> Result<String> {
    let mut header = JwsHeader::new();
    header.set_algorithm("ES256");
    if let Some(k) = kid {
        header.set_key_id(k);
    }
    if let Some(t) = typ {
        header.set_token_type(t);
    }

    let sk_der = key
        .to_pkcs8_der()
        .map_err(|e| R2psError::Jws(format!("encode signing key: {e}")))?;
    let signer = ES256
        .signer_from_der(sk_der.as_bytes())
        .map_err(|e| R2psError::Jws(e.to_string()))?;

    jose_jws::serialize_compact(payload, &header, &signer)
        .map_err(|e| R2psError::Jws(e.to_string()))
}

/// Verify a JWS compact serialization (ES256) and return the payload.
pub fn verify_jws(compact: &str, key: &VerifyingKey) -> Result<Vec<u8>> {
    let pk_der = key
        .to_public_key_der()
        .map_err(|e| R2psError::Jws(format!("encode verifying key: {e}")))?;
    let verifier = ES256
        .verifier_from_der(pk_der.as_ref())
        .map_err(|e| R2psError::Jws(e.to_string()))?;

    let (payload, _header) = jose_jws::deserialize_compact(compact, &verifier)
        .map_err(|e| R2psError::Jws(e.to_string()))?;

    Ok(payload)
}

/// Parse JWS protected headers without verifying the signature.
/// Used to extract `kid` for key lookup before verification.
pub fn peek_jws_headers(compact: &str) -> Result<JwsHeaders> {
    let header_b64 = compact
        .split('.')
        .next()
        .ok_or_else(|| R2psError::Jws("empty JWS".into()))?;

    let header = JwsHeader::from_bytes(
        &base64ct::Base64UrlUnpadded::decode_vec(header_b64)
            .map_err(|e| R2psError::Jws(format!("decode header: {e}")))?,
    )
    .map_err(|e| R2psError::Jws(format!("parse header: {e}")))?;

    Ok(JwsHeaders {
        kid: header.key_id().map(String::from),
        typ: header.token_type().map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::Generate;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::generate();
        let vk = VerifyingKey::from(&key);
        let payload = b"hello world";

        let jws = sign_jws(payload, &key, Some("test-kid"), Some("r2ps-request+jwt")).unwrap();
        let recovered = verify_jws(&jws, &vk).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn peek_headers() {
        let key = SigningKey::generate();
        let jws = sign_jws(b"{}", &key, Some("my-kid"), Some("r2ps-request+jwt")).unwrap();
        let headers = peek_jws_headers(&jws).unwrap();
        assert_eq!(headers.kid.as_deref(), Some("my-kid"));
        assert_eq!(headers.typ.as_deref(), Some("r2ps-request+jwt"));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let other_vk = VerifyingKey::from(&other);

        let jws = sign_jws(b"test", &key, None, None).unwrap();
        assert!(verify_jws(&jws, &other_vk).is_err());
    }
}
