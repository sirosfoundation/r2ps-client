use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::{ecdsa::SigningKey, PublicKey, SecretKey};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{
    error::{R2psError, Result},
    jwe, jws,
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
    kid: String,
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
        kid: String,
        context: String,
        client_key: SecretKey,
        server_pub: PublicKey,
        transport: T,
        pake: P,
    ) -> Self {
        Self {
            client_id,
            kid,
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

        let pake_req = PakeRequest {
            protocol: PAKE_PROTOCOL_OPAQUE.into(),
            state: PAKE_STATE_EVALUATE.into(),
            authorization: None,
            task: None,
            session_duration: None,
            req: Base64UrlUnpadded::encode_string(&reg_req),
        };

        let resp = self.send_pake(TYPE_PIN_REGISTRATION, ENC_DEVICE, None, &pake_req)?;

        // Phase 2: RegistrationFinalize
        let resp_bytes = Base64UrlUnpadded::decode_vec(
            resp.resp
                .as_deref()
                .ok_or_else(|| R2psError::Protocol("missing resp in PAKE response".into()))?,
        )
        .map_err(|e| R2psError::Base64(e.to_string()))?;

        let record = self.pake.registration_finalize(&resp_bytes)?;

        let pake_req_fin = PakeRequest {
            protocol: PAKE_PROTOCOL_OPAQUE.into(),
            state: PAKE_STATE_FINALIZE.into(),
            authorization: None,
            task: None,
            session_duration: None,
            req: Base64UrlUnpadded::encode_string(&record),
        };

        self.send_pake(TYPE_PIN_REGISTRATION, ENC_DEVICE, None, &pake_req_fin)?;
        Ok(())
    }

    /// Perform OPAQUE authentication (evaluate + finalize).
    /// On success, stores session ID and key for subsequent service calls.
    pub fn authenticate(&mut self, password: &[u8], task: &str) -> Result<()> {
        // Phase 1: KE1
        let ke1 = self.pake.auth_init(password)?;

        let pake_req = PakeRequest {
            protocol: PAKE_PROTOCOL_OPAQUE.into(),
            state: PAKE_STATE_EVALUATE.into(),
            authorization: None,
            task: Some(task.into()),
            session_duration: None,
            req: Base64UrlUnpadded::encode_string(&ke1),
        };

        let resp = self.send_pake(TYPE_AUTHENTICATE, ENC_DEVICE, None, &pake_req)?;

        let session_id = resp
            .pake_session_id
            .as_ref()
            .ok_or_else(|| R2psError::Protocol("missing pake_session_id".into()))?
            .clone();

        // Phase 2: KE3
        let ke2_bytes = Base64UrlUnpadded::decode_vec(
            resp.resp
                .as_deref()
                .ok_or_else(|| R2psError::Protocol("missing resp".into()))?,
        )
        .map_err(|e| R2psError::Base64(e.to_string()))?;

        let (ke3, session_key) = self.pake.auth_finalize(&ke2_bytes)?;

        let pake_req_fin = PakeRequest {
            protocol: PAKE_PROTOCOL_OPAQUE.into(),
            state: PAKE_STATE_FINALIZE.into(),
            authorization: None,
            task: Some(task.into()),
            session_duration: None,
            req: Base64UrlUnpadded::encode_string(&ke3),
        };

        self.send_pake(
            TYPE_AUTHENTICATE,
            ENC_DEVICE,
            Some(&session_id),
            &pake_req_fin,
        )?;

        self.session_id = Some(session_id);
        self.session_key = Some(Zeroizing::new(session_key));
        Ok(())
    }

    /// Send an authenticated service request using the session key.
    /// Returns the decrypted response data.
    pub fn call_service(&self, service_type: &str, req_data: &[u8]) -> Result<Vec<u8>> {
        let session_key = self
            .session_key
            .as_ref()
            .ok_or(R2psError::NotAuthenticated)?;
        let session_id = self
            .session_id
            .as_ref()
            .ok_or(R2psError::NotAuthenticated)?;

        let sym_key: [u8; 32] = session_key[..32]
            .try_into()
            .map_err(|_| R2psError::Protocol("session key too short".into()))?;

        let enc_data = jwe::encrypt_jwe_symmetric(req_data, &sym_key)?;

        let svc_req = ServiceRequest {
            ver: PROTOCOL_VERSION.into(),
            nonce: Base64UrlUnpadded::encode_string(&random_bytes_vec(16)),
            iat: now_unix(),
            enc: ENC_USER.into(),
            data: enc_data,
            client_id: self.client_id.clone(),
            kid: self.kid.clone(),
            context: self.context.clone(),
            service_type: service_type.into(),
            pake_session_id: Some(session_id.clone()),
        };

        let req_json = serde_json::to_vec(&svc_req)?;
        let signing_key = SigningKey::from(&self.client_key);
        let signed = jws::sign_jws(
            &req_json,
            &signing_key,
            Some(&self.kid),
            Some(TYP_REQUEST),
        )?;

        let resp_body = self.transport.send(signed.as_bytes())?;

        // Verify and parse response
        let verifying_key = p256::ecdsa::VerifyingKey::from(&self.server_pub);
        let resp_payload = jws::verify_jws(
            std::str::from_utf8(&resp_body)
                .map_err(|e| R2psError::Protocol(format!("response not UTF-8: {e}")))?,
            &verifying_key,
        )?;

        let svc_resp: ServiceResponse = serde_json::from_slice(&resp_payload)?;

        jwe::decrypt_jwe_symmetric(&svc_resp.data, &sym_key)
    }

    /// Returns the current session ID, if authenticated.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Returns true if the client has an active session.
    pub fn is_authenticated(&self) -> bool {
        self.session_key.is_some()
    }

    fn send_pake(
        &self,
        req_type: &str,
        enc: &str,
        session_id: Option<&str>,
        pake_req: &PakeRequest,
    ) -> Result<PakeResponse> {
        let pake_json = serde_json::to_vec(pake_req)?;

        // Encrypt PAKE data to server's public key
        let enc_data = jwe::encrypt_jwe(&pake_json, &self.server_pub)?;

        let svc_req = ServiceRequest {
            ver: PROTOCOL_VERSION.into(),
            nonce: Base64UrlUnpadded::encode_string(&random_bytes_vec(16)),
            iat: now_unix(),
            enc: enc.into(),
            data: enc_data,
            client_id: self.client_id.clone(),
            kid: self.kid.clone(),
            context: self.context.clone(),
            service_type: req_type.into(),
            pake_session_id: session_id.map(String::from),
        };

        let req_json = serde_json::to_vec(&svc_req)?;
        let signing_key = SigningKey::from(&self.client_key);
        let signed = jws::sign_jws(
            &req_json,
            &signing_key,
            Some(&self.kid),
            Some(TYP_REQUEST),
        )?;

        let resp_body = self.transport.send(signed.as_bytes())?;

        // Verify response JWS
        let verifying_key = p256::ecdsa::VerifyingKey::from(&self.server_pub);
        let resp_payload = jws::verify_jws(
            std::str::from_utf8(&resp_body)
                .map_err(|e| R2psError::Protocol(format!("response not UTF-8: {e}")))?,
            &verifying_key,
        )?;

        let svc_resp: ServiceResponse = serde_json::from_slice(&resp_payload)?;

        // Decrypt response data using client's private key
        let decrypted = jwe::decrypt_jwe(&svc_resp.data, &self.client_key)?;

        let pake_resp: PakeResponse = serde_json::from_slice(&decrypted)?;
        Ok(pake_resp)
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
