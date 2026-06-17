use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::{ecdsa::SigningKey, PublicKey, SecretKey};
use rand::RngCore;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::{
    error::{R2psError, Result},
    fido2::{
        self, Fido2Ceremony, Fido2ChallengeResponse, Fido2FinalizeResponse, Fido2TfaRequestData,
    },
    jws,
    pake::PakeClient,
    types::*,
};

/// HTTP transport for R2PS requests.
pub trait Transport {
    /// Send a signed JWS request body and return the raw response bytes.
    fn send(&self, body: &[u8]) -> Result<Vec<u8>>;
}

/// R2PS protocol client.
pub struct R2psClient<T: Transport, P: PakeClient> {
    client_id: String,
    context: String,
    client_key: SecretKey,
    server_pub: PublicKey,
    transport: T,
    pake: P,

    // Session state
    session_id: Option<String>,
    session_key: Option<Zeroizing<Vec<u8>>>,
}

impl<T: Transport, P: PakeClient> R2psClient<T, P> {
    pub fn new(
        client_id: String,
        context: String,
        client_key: SecretKey,
        server_pub: PublicKey,
        transport: T,
        pake: P,
    ) -> Self {
        Self {
            client_id,
            context,
            client_key,
            server_pub,
            transport,
            pake,
            session_id: None,
            session_key: None,
        }
    }

    /// Perform OPAQUE registration (evaluate + finalize).
    pub fn register(&mut self, password: &[u8]) -> Result<()> {
        // Phase 1: RegistrationInit
        let reg_req = self.pake.registration_init(password)?;

        let tfa_req = TFARequestData {
            tfa_mode: TFA_MODE_OPAQUE.into(),
            state: STATE_EVALUATE.into(),
            authorization: None,
            request: Base64UrlUnpadded::encode_string(&reg_req),
        };

        let resp = self.send_2fa(TYPE_2FA_REGISTRATION, None, &tfa_req)?;

        // Phase 2: RegistrationFinalize
        let resp_bytes = Base64UrlUnpadded::decode_vec(
            resp.response
                .as_deref()
                .ok_or_else(|| R2psError::Protocol("missing response in 2FA response".into()))?,
        )
        .map_err(|e| R2psError::Base64(e.to_string()))?;

        let record = self.pake.registration_finalize(&resp_bytes)?;

        let tfa_req_fin = TFARequestData {
            tfa_mode: TFA_MODE_OPAQUE.into(),
            state: STATE_FINALIZE.into(),
            authorization: None,
            request: Base64UrlUnpadded::encode_string(&record),
        };

        self.send_2fa(TYPE_2FA_REGISTRATION, None, &tfa_req_fin)?;
        Ok(())
    }

    /// Perform OPAQUE authentication (evaluate + finalize).
    /// On success, stores session ID and key for subsequent service calls.
    pub fn authenticate(&mut self, password: &[u8]) -> Result<()> {
        // Phase 1: KE1
        let ke1 = self.pake.auth_init(password)?;

        let tfa_req = TFARequestData {
            tfa_mode: TFA_MODE_OPAQUE.into(),
            state: STATE_EVALUATE.into(),
            authorization: None,
            request: Base64UrlUnpadded::encode_string(&ke1),
        };

        let resp = self.send_2fa_auth(TYPE_2FA_AUTHENTICATE, None, &tfa_req)?;

        let session_id = resp
            .tfa_session_id
            .as_ref()
            .ok_or_else(|| R2psError::Protocol("missing 2fa_session_id".into()))?
            .clone();

        // Phase 2: KE3
        let ke2_bytes = Base64UrlUnpadded::decode_vec(
            resp.response
                .as_deref()
                .ok_or_else(|| R2psError::Protocol("missing response".into()))?,
        )
        .map_err(|e| R2psError::Base64(e.to_string()))?;

        let (ke3, session_key) = self.pake.auth_finalize(&ke2_bytes)?;

        let tfa_req_fin = TFARequestData {
            tfa_mode: TFA_MODE_OPAQUE.into(),
            state: STATE_FINALIZE.into(),
            authorization: None,
            request: Base64UrlUnpadded::encode_string(&ke3),
        };

        self.send_2fa_auth(TYPE_2FA_AUTHENTICATE, Some(&session_id), &tfa_req_fin)?;

        self.session_id = Some(session_id);
        self.session_key = Some(Zeroizing::new(session_key));
        Ok(())
    }

    /// Register a FIDO2 credential (challenge + registration ceremony).
    ///
    /// # Arguments
    /// * `ceremony` - Implementation of the WebAuthn credential creation ceremony
    /// * `rp_id` - Relying Party ID for the WebAuthn ceremony
    pub fn register_fido2(&self, ceremony: &dyn Fido2Ceremony, rp_id: &str) -> Result<()> {
        // Phase 1: Request challenge
        let challenge_req = Fido2TfaRequestData {
            tfa_mode: TFA_MODE_FIDO2.into(),
            state: STATE_CHALLENGE.into(),
            request: serde_json::json!({}),
            authorization: None,
        };

        let resp_payload = self.send_request_raw(TYPE_2FA_REGISTRATION, None, &challenge_req)?;
        let challenge_resp: Fido2ChallengeResponse = serde_json::from_slice(&resp_payload)?;

        // Phase 2: Perform WebAuthn ceremony
        let reg_result =
            ceremony.create_credential(&challenge_resp.challenge, rp_id, &self.client_id)?;

        // Phase 3: Send registration to server
        let register_req = Fido2TfaRequestData {
            tfa_mode: TFA_MODE_FIDO2.into(),
            state: STATE_REGISTER.into(),
            request: serde_json::to_value(&fido2::Fido2RegisterRequest {
                credential_id: reg_result.credential_id,
                attestation_object: reg_result.attestation_object,
                client_data: reg_result.client_data,
            })?,
            authorization: Some(challenge_resp.token),
        };

        self.send_request_raw(TYPE_2FA_REGISTRATION, None, &register_req)?;
        Ok(())
    }

    /// Perform FIDO2 authentication (challenge + assertion + session establishment).
    ///
    /// # Arguments
    /// * `ceremony` - Implementation of the WebAuthn assertion ceremony
    /// * `rp_id` - Relying Party ID for the WebAuthn ceremony
    /// * `task` - Task binding for SAD (e.g., "sign:<hex-hashes>")
    /// * `allow_credentials` - List of allowed credential IDs (base64url)
    ///
    /// On success, stores session ID and key for subsequent service calls.
    pub fn authenticate_fido2(
        &mut self,
        ceremony: &dyn Fido2Ceremony,
        rp_id: &str,
        task: &str,
        allow_credentials: &[String],
    ) -> Result<()> {
        // Phase 1: Request challenge
        let challenge_req = Fido2TfaRequestData {
            tfa_mode: TFA_MODE_FIDO2.into(),
            state: STATE_CHALLENGE.into(),
            request: serde_json::json!({}),
            authorization: None,
        };

        let resp_payload = self.send_request_raw(TYPE_2FA_AUTHENTICATE, None, &challenge_req)?;
        let challenge_resp: Fido2ChallengeResponse = serde_json::from_slice(&resp_payload)?;

        // Phase 2: Perform WebAuthn assertion ceremony
        let assertion =
            ceremony.get_assertion(&challenge_resp.challenge, rp_id, allow_credentials)?;

        // Phase 3: Generate ephemeral key pair for session derivation
        let (client_secret, client_epub_bytes) = fido2::generate_ephemeral_keypair()?;

        // Phase 4: Send finalize request
        let finalize_req_data = fido2::Fido2FinalizeRequest {
            client_epub: Base64UrlUnpadded::encode_string(&client_epub_bytes),
            token: challenge_resp.token,
            task: task.to_string(),
            assertion,
        };

        let finalize_req = Fido2TfaRequestData {
            tfa_mode: TFA_MODE_FIDO2.into(),
            state: STATE_FINALIZE.into(),
            request: serde_json::to_value(&finalize_req_data)?,
            authorization: None,
        };

        // Use the nonce from the finalize request for HKDF salt
        let nonce = random_bytes_vec(16);
        let nonce_b64 = Base64UrlUnpadded::encode_string(&nonce);

        let resp_payload =
            self.send_request_with_nonce(TYPE_2FA_AUTHENTICATE, None, &finalize_req, &nonce_b64)?;
        let finalize_resp: Fido2FinalizeResponse = serde_json::from_slice(&resp_payload)?;

        // Phase 5: Derive session key
        let server_epub_bytes = Base64UrlUnpadded::decode_vec(&finalize_resp.server_epub)
            .map_err(|e| R2psError::Base64(e.to_string()))?;

        let shared_secret = fido2::compute_shared_secret(client_secret, &server_epub_bytes)?;

        let session_key = fido2::derive_fido2_session_key(
            &shared_secret,
            &nonce,
            &client_epub_bytes,
            &server_epub_bytes,
            task,
        )?;

        self.session_id = Some(finalize_resp.tfa_session_id);
        self.session_key = Some(session_key);
        Ok(())
    }

    /// Send a signing request with SAD (Signature Activation Data) binding.
    ///
    /// This method authenticates via FIDO2 with the hash(es) bound to the session,
    /// then performs the sign operation.
    ///
    /// # Arguments
    /// * `ceremony` - FIDO2 ceremony implementation
    /// * `rp_id` - Relying Party ID
    /// * `allow_credentials` - Allowed credential IDs
    /// * `kid` - Key identifier for signing
    /// * `tbs_hash` - The hash to be signed (SHA-256/384/512)
    pub fn sign_with_sad(
        &mut self,
        ceremony: &dyn Fido2Ceremony,
        rp_id: &str,
        allow_credentials: &[String],
        kid: &str,
        tbs_hash: &[u8],
    ) -> Result<Vec<u8>> {
        // Build SAD task binding the session to this specific hash
        let task = fido2::build_sign_task(&[tbs_hash]);

        // Authenticate with FIDO2, binding the session to the hash
        self.authenticate_fido2(ceremony, rp_id, &task, allow_credentials)?;

        // Now sign using the bound session
        let sign_req = serde_json::json!({
            "kid": kid,
            "tbs_hash": Base64UrlUnpadded::encode_string(tbs_hash),
        });

        let resp = self.call_service(TYPE_SIGN_ECDSA, &sign_req)?;

        // Response is base64url-encoded DER signature
        match resp.as_str() {
            Some(sig_b64) => {
                Base64UrlUnpadded::decode_vec(sig_b64).map_err(|e| R2psError::Base64(e.to_string()))
            }
            None => Err(R2psError::Protocol(
                "expected string response for signature".into(),
            )),
        }
    }

    /// Send an authenticated service request using the session key.
    /// Returns the decrypted response data as raw bytes.
    pub fn call_service(
        &self,
        service_type: &str,
        req_data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let session_id = self
            .session_id
            .as_ref()
            .ok_or(R2psError::NotAuthenticated)?;

        let data_raw = RawValue::from_string(serde_json::to_string(req_data)?)
            .map_err(|e| R2psError::Protocol(format!("invalid data JSON: {e}")))?;

        let svc_req = ServiceRequest {
            ver: PROTOCOL_VERSION.into(),
            nonce: Base64UrlUnpadded::encode_string(&random_bytes_vec(16)),
            iat: now_unix(),
            data: data_raw,
            client_id: self.client_id.clone(),
            context: self.context.clone(),
            service_type: service_type.into(),
            tfa_session_id: Some(session_id.clone()),
        };

        let req_json = serde_json::to_vec(&svc_req)?;
        let signing_key = SigningKey::from(&self.client_key);
        let kid = self.client_id.as_str();
        let signed = jws::sign_jws(&req_json, &signing_key, Some(kid), Some(TYP_REQUEST))?;

        let resp_body = self.transport.send(signed.as_bytes())?;

        // Verify and parse response
        let verifying_key = p256::ecdsa::VerifyingKey::from(&self.server_pub);
        let resp_payload = jws::verify_jws(
            std::str::from_utf8(&resp_body)
                .map_err(|e| R2psError::Protocol(format!("response not UTF-8: {e}")))?,
            &verifying_key,
        )?;

        let svc_resp: ServiceResponse = serde_json::from_slice(&resp_payload)?;

        // Data is now direct JSON in the response
        let data: serde_json::Value = serde_json::from_str(svc_resp.data.get())?;
        Ok(data)
    }

    /// Send a 1FA service request (no 2FA session required).
    /// Used for EUDIW attestation types (WKA/WIA) and key generation.
    pub fn call_service_1fa(
        &self,
        service_type: &str,
        req_data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let data_raw = RawValue::from_string(serde_json::to_string(req_data)?)
            .map_err(|e| R2psError::Protocol(format!("invalid data JSON: {e}")))?;

        let svc_req = ServiceRequest {
            ver: PROTOCOL_VERSION.into(),
            nonce: Base64UrlUnpadded::encode_string(&random_bytes_vec(16)),
            iat: now_unix(),
            data: data_raw,
            client_id: self.client_id.clone(),
            context: self.context.clone(),
            service_type: service_type.into(),
            tfa_session_id: None,
        };

        let req_json = serde_json::to_vec(&svc_req)?;
        let signing_key = SigningKey::from(&self.client_key);
        let kid = self.client_id.as_str();
        let signed = jws::sign_jws(&req_json, &signing_key, Some(kid), Some(TYP_REQUEST))?;

        let resp_body = self.transport.send(signed.as_bytes())?;

        let verifying_key = p256::ecdsa::VerifyingKey::from(&self.server_pub);
        let resp_payload = jws::verify_jws(
            std::str::from_utf8(&resp_body)
                .map_err(|e| R2psError::Protocol(format!("response not UTF-8: {e}")))?,
            &verifying_key,
        )?;

        let svc_resp: ServiceResponse = serde_json::from_slice(&resp_payload)?;
        let data: serde_json::Value = serde_json::from_str(svc_resp.data.get())?;
        Ok(data)
    }

    /// Returns the current session ID, if authenticated.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Returns true if the client has an active session.
    pub fn is_authenticated(&self) -> bool {
        self.session_key.is_some()
    }

    fn send_2fa(
        &self,
        req_type: &str,
        session_id: Option<&str>,
        tfa_req: &TFARequestData,
    ) -> Result<TFAResponseData> {
        let resp_payload = self.send_request(req_type, session_id, tfa_req)?;
        let tfa_resp: TFAResponseData = serde_json::from_slice(&resp_payload)?;
        Ok(tfa_resp)
    }

    fn send_2fa_auth(
        &self,
        req_type: &str,
        session_id: Option<&str>,
        tfa_req: &TFARequestData,
    ) -> Result<TFAAuthResponseData> {
        let resp_payload = self.send_request(req_type, session_id, tfa_req)?;
        let tfa_resp: TFAAuthResponseData = serde_json::from_slice(&resp_payload)?;
        Ok(tfa_resp)
    }

    fn send_request<D: serde::Serialize>(
        &self,
        req_type: &str,
        session_id: Option<&str>,
        data: &D,
    ) -> Result<Vec<u8>> {
        let nonce = Base64UrlUnpadded::encode_string(&random_bytes_vec(16));
        self.send_request_with_nonce(req_type, session_id, data, &nonce)
    }

    /// Same as send_request but returns the raw response data bytes.
    /// Used by FIDO2 flows where the response structure varies.
    fn send_request_raw<D: serde::Serialize>(
        &self,
        req_type: &str,
        session_id: Option<&str>,
        data: &D,
    ) -> Result<Vec<u8>> {
        self.send_request(req_type, session_id, data)
    }

    fn send_request_with_nonce<D: serde::Serialize>(
        &self,
        req_type: &str,
        session_id: Option<&str>,
        data: &D,
        nonce: &str,
    ) -> Result<Vec<u8>> {
        let data_json = serde_json::to_string(data)?;
        let data_raw = RawValue::from_string(data_json)
            .map_err(|e| R2psError::Protocol(format!("invalid data JSON: {e}")))?;

        let svc_req = ServiceRequest {
            ver: PROTOCOL_VERSION.into(),
            nonce: nonce.to_string(),
            iat: now_unix(),
            data: data_raw,
            client_id: self.client_id.clone(),
            context: self.context.clone(),
            service_type: req_type.into(),
            tfa_session_id: session_id.map(String::from),
        };

        let req_json = serde_json::to_vec(&svc_req)?;
        let signing_key = SigningKey::from(&self.client_key);
        let kid = self.client_id.as_str();
        let signed = jws::sign_jws(&req_json, &signing_key, Some(kid), Some(TYP_REQUEST))?;

        let resp_body = self.transport.send(signed.as_bytes())?;

        // Verify response JWS
        let verifying_key = p256::ecdsa::VerifyingKey::from(&self.server_pub);
        let resp_payload = jws::verify_jws(
            std::str::from_utf8(&resp_body)
                .map_err(|e| R2psError::Protocol(format!("response not UTF-8: {e}")))?,
            &verifying_key,
        )?;

        let svc_resp: ServiceResponse = serde_json::from_slice(&resp_payload)?;

        // Data is now direct JSON — extract it
        Ok(svc_resp.data.get().as_bytes().to_vec())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_bytes_vec(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}
