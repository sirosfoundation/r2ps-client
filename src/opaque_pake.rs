//! Real OPAQUE (RFC 9807) [`PakeClient`] implementation, using the
//! `opaque-ke` crate (P256-SHA256 ciphersuite, matching the R2PS server's
//! `bytemare/opaque` configuration: `OPRF: P256Sha256, AKE: P256Sha256,
//! KDF/MAC/Hash: SHA256`, no key stretching function).
//!
//! `opaque-ke`/`voprf` are built against `elliptic-curve` 0.13, which is
//! semver-incompatible with the `elliptic-curve` 0.14 this crate's own
//! `p256 = "0.14"` dependency (used elsewhere for JWS/ECDSA) depends on -
//! `p256::NistP256` from the two versions are distinct, non-interchangeable
//! types. `p256-opaque`/`sha2-opaque` (renamed deps pinned to the exact
//! versions `opaque-ke` itself is built and tested against) are used here
//! instead, kept entirely internal to this module - [`PakeClient`]'s public
//! boundary is raw bytes only, so this version split never leaks out.

use opaque_ke::{
    ciphersuite::CipherSuite, key_exchange::tripledh::TripleDh, ksf::Identity, ClientLogin,
    ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialResponse, Identifiers, RegistrationResponse,
};
use p256_opaque::NistP256;
use rand_opaque::rngs::OsRng;
use sha2_opaque::Sha256;
use zeroize::Zeroizing;

use crate::error::{R2psError, Result};
use crate::pake::PakeClient;

/// P256-SHA256 OPAQUE ciphersuite, matching the R2PS server's
/// `bytemare/opaque` configuration exactly: OPRF group P256/SHA256, AKE
/// (3DH) over P256/SHA256, no key stretching (the server's `KSF` field is
/// left unset, which `bytemare/opaque` documents as "0 = Identity/no
/// stretching").
struct R2psCipherSuite;

impl CipherSuite for R2psCipherSuite {
    type OprfCs = NistP256;
    type KeyExchange = TripleDh<NistP256, Sha256>;
    type Ksf = Identity;
}

fn pake_err(context: &str, err: impl std::fmt::Display) -> R2psError {
    R2psError::Pake(format!("{context}: {err}"))
}

/// Real OPAQUE client, backed by `opaque-ke`.
///
/// Holds the in-progress registration/login state and the password between
/// the `_init`/`_finalize` call pairs, since [`PakeClient`]'s four methods
/// are called across a network round trip (the server's response arrives
/// in between) and `opaque-ke`'s own `finish()` methods need the original
/// password again.
#[derive(Default)]
pub struct OpaqueClient {
    registration: Option<(Zeroizing<Vec<u8>>, ClientRegistration<R2psCipherSuite>)>,
    login: Option<(Zeroizing<Vec<u8>>, ClientLogin<R2psCipherSuite>)>,
}

impl OpaqueClient {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PakeClient for OpaqueClient {
    fn registration_init(&mut self, password: &[u8]) -> Result<Vec<u8>> {
        let result = ClientRegistration::<R2psCipherSuite>::start(&mut OsRng, password)
            .map_err(|e| pake_err("registration start", e))?;
        self.registration = Some((Zeroizing::new(password.to_vec()), result.state));
        Ok(result.message.serialize().to_vec())
    }

    fn registration_finalize(&mut self, server_resp: &[u8]) -> Result<Vec<u8>> {
        let (password, state) = self
            .registration
            .take()
            .ok_or_else(|| R2psError::Pake("registration not started".into()))?;
        let response = RegistrationResponse::<R2psCipherSuite>::deserialize(server_resp)
            .map_err(|e| pake_err("deserialize registration response", e))?;
        let result = state
            .finish(
                &mut OsRng,
                &password,
                response,
                ClientRegistrationFinishParameters::new(Identifiers::default(), None),
            )
            .map_err(|e| pake_err("registration finish", e))?;
        Ok(result.message.serialize().to_vec())
    }

    fn auth_init(&mut self, password: &[u8]) -> Result<Vec<u8>> {
        let result = ClientLogin::<R2psCipherSuite>::start(&mut OsRng, password)
            .map_err(|e| pake_err("login start", e))?;
        self.login = Some((Zeroizing::new(password.to_vec()), result.state));
        Ok(result.message.serialize().to_vec())
    }

    fn auth_finalize(&mut self, server_resp: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (password, state) = self
            .login
            .take()
            .ok_or_else(|| R2psError::Pake("login not started".into()))?;
        let response = CredentialResponse::<R2psCipherSuite>::deserialize(server_resp)
            .map_err(|e| pake_err("deserialize credential response", e))?;
        let result = state
            .finish(
                &mut OsRng,
                &password,
                response,
                ClientLoginFinishParameters::new(None, Identifiers::default(), None),
            )
            .map_err(|e| pake_err("login finish", e))?;
        Ok((
            result.message.serialize().to_vec(),
            result.session_key.to_vec(),
        ))
    }
}
