use josekit::jwe::{self as jose_jwe, Dir, JweHeader, ECDH_ES_A256KW};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};

use crate::error::{R2psError, Result};

/// Encrypt plaintext using ECDH-ES+A256KW with A256GCM (device mode).
pub fn encrypt_jwe(plaintext: &[u8], recipient_pub: &PublicKey) -> Result<String> {
    let mut header = JweHeader::new();
    header.set_algorithm("ECDH-ES+A256KW");
    header.set_content_encryption("A256GCM");
    header.set_content_type("application/octet-stream");

    let spki_der = recipient_pub
        .to_public_key_der()
        .map_err(|e| R2psError::Jwe(format!("encode recipient public key: {e}")))?;

    let encrypter = ECDH_ES_A256KW
        .encrypter_from_der(spki_der.as_ref())
        .map_err(|e| R2psError::Jwe(e.to_string()))?;

    jose_jwe::serialize_compact(plaintext, &header, &encrypter)
        .map_err(|e| R2psError::Jwe(e.to_string()))
}

/// Decrypt a JWE compact serialization using ECDH-ES+A256KW (device mode).
pub fn decrypt_jwe(compact: &str, recipient_key: &SecretKey) -> Result<Vec<u8>> {
    let pkcs8_der = recipient_key
        .to_pkcs8_der()
        .map_err(|e| R2psError::Jwe(format!("encode recipient private key: {e}")))?;

    let decrypter = ECDH_ES_A256KW
        .decrypter_from_der(pkcs8_der.as_bytes())
        .map_err(|e| R2psError::Jwe(e.to_string()))?;

    let (payload, _header) = jose_jwe::deserialize_compact(compact, &decrypter)
        .map_err(|e| R2psError::Jwe(e.to_string()))?;

    Ok(payload)
}

/// Encrypt plaintext with a symmetric key using dir+A256GCM (user mode).
pub fn encrypt_jwe_symmetric(plaintext: &[u8], key: &[u8; 32]) -> Result<String> {
    let mut header = JweHeader::new();
    header.set_algorithm("dir");
    header.set_content_encryption("A256GCM");
    header.set_content_type("application/octet-stream");

    let encrypter = Dir
        .encrypter_from_bytes(key)
        .map_err(|e| R2psError::Jwe(e.to_string()))?;

    jose_jwe::serialize_compact(plaintext, &header, &encrypter)
        .map_err(|e| R2psError::Jwe(e.to_string()))
}

/// Decrypt a JWE compact serialization with a symmetric key (user mode).
pub fn decrypt_jwe_symmetric(compact: &str, key: &[u8; 32]) -> Result<Vec<u8>> {
    let decrypter = Dir
        .decrypter_from_bytes(key)
        .map_err(|e| R2psError::Jwe(e.to_string()))?;

    let (payload, _header) = jose_jwe::deserialize_compact(compact, &decrypter)
        .map_err(|e| R2psError::Jwe(e.to_string()))?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use rand::rngs::OsRng;

    #[test]
    fn jwe_ecdh_roundtrip() {
        let sk = SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        let plaintext = b"secret payload";

        let jwe = encrypt_jwe(plaintext, &pk).unwrap();
        let recovered = decrypt_jwe(&jwe, &sk).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn jwe_symmetric_roundtrip() {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        let plaintext = b"symmetric secret";

        let jwe = encrypt_jwe_symmetric(plaintext, &key).unwrap();
        let recovered = decrypt_jwe_symmetric(&jwe, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn jwe_wrong_key_fails() {
        let sk = SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        let other = SecretKey::random(&mut OsRng);

        let jwe = encrypt_jwe(b"test", &pk).unwrap();
        assert!(decrypt_jwe(&jwe, &other).is_err());
    }
}
