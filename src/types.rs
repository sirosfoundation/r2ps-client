use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// JWS payload for an R2PS service request (draft-santesson-r2ps §4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRequest {
    pub ver: String,
    pub nonce: String,
    pub iat: i64,
    pub data: Box<RawValue>,
    pub client_id: String,
    pub context: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "2fa_session_id", skip_serializing_if = "Option::is_none")]
    pub tfa_session_id: Option<String>,
    /// SHA-256 of JWE protected header (draft-santesson-r2ps §4.2.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwe_hash: Option<String>,
}

/// JWS payload for an R2PS service response (draft-santesson-r2ps §4.2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub ver: String,
    pub nonce: String,
    pub iat: i64,
    pub data: Box<RawValue>,
    /// Success indicator (draft-santesson-r2ps §4.2.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
}

/// Error response returned on failure (draft-santesson-r2ps §4.2.2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

/// 2FA request data (draft-santesson-r2ps §4.3.1).
///
/// Uses I-D field names (`protocol`, `p_data`) as primary.
/// Legacy names (`2fa_mode`, `request`) are accepted on deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFARequestData {
    /// I-D field name for the authentication protocol identifier.
    #[serde(default)]
    pub protocol: String,
    /// Legacy field name — accepted on deserialization, not emitted.
    #[serde(rename = "2fa_mode", default, skip_serializing_if = "String::is_empty")]
    pub tfa_mode: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
    /// I-D field name for protocol-specific data.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub p_data: String,
    /// Legacy field name — accepted on deserialization, not emitted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request: String,
    /// Authorization type (draft-santesson-r2ps §4.3.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_type: Option<String>,
    /// Requested session duration in seconds (draft-santesson-r2ps §4.3.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_duration: Option<i64>,
}

impl TFARequestData {
    /// Returns the protocol identifier, preferring I-D field over legacy.
    pub fn get_protocol(&self) -> &str {
        if !self.protocol.is_empty() {
            &self.protocol
        } else {
            &self.tfa_mode
        }
    }

    /// Returns the protocol data, preferring I-D field over legacy.
    pub fn get_p_data(&self) -> &str {
        if !self.p_data.is_empty() {
            &self.p_data
        } else {
            &self.request
        }
    }
}

/// 2FA response data (draft-santesson-r2ps §4.3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFAResponseData {
    /// I-D field name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p_data: Option<String>,
    /// Legacy field name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TFAResponseData {
    /// Returns the protocol data, preferring I-D field over legacy.
    pub fn get_p_data(&self) -> Option<&str> {
        self.p_data.as_deref().or(self.response.as_deref())
    }
}

/// 2FA authentication response data — extends TFAResponseData with session info.
/// See draft-santesson-r2ps §4.3.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFAAuthResponseData {
    /// I-D field name for session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Legacy field name.
    #[serde(rename = "2fa_session_id", skip_serializing_if = "Option::is_none")]
    pub tfa_session_id: Option<String>,
    /// I-D field name for protocol data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p_data: Option<String>,
    /// Legacy field name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_expiration_time: Option<i64>,
    /// Echoed task binding (draft-santesson-r2ps §4.3.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

impl TFAAuthResponseData {
    /// Returns the session ID, preferring I-D field over legacy.
    pub fn get_session_id(&self) -> Option<&str> {
        self.session_id
            .as_deref()
            .or(self.tfa_session_id.as_deref())
    }

    /// Returns the protocol data, preferring I-D field over legacy.
    pub fn get_p_data(&self) -> Option<&str> {
        self.p_data.as_deref().or(self.response.as_deref())
    }
}

// Protocol version
pub const PROTOCOL_VERSION: &str = "1.0";

// 2FA mode identifiers (draft-santesson-r2ps §4.3.5)
pub const TFA_MODE_PASSWORD: &str = "password";
pub const TFA_MODE_OPAQUE: &str = "opaque";
pub const TFA_MODE_FIDO2: &str = "fido2";

// 2FA states (draft-santesson-r2ps §4.3.5)
pub const STATE_EVALUATE: &str = "evaluate";
pub const STATE_FINALIZE: &str = "finalize";
pub const STATE_CHALLENGE: &str = "challenge";
pub const STATE_REGISTER: &str = "register";

// Service types — base protocol (draft-santesson-r2ps §4.3.4)
pub const TYPE_2FA_REGISTRATION: &str = "2fa_registration";
pub const TYPE_CREATE_SESSION: &str = "create_session"; // I-D name for 2fa_authenticate
pub const TYPE_2FA_UPDATE: &str = "2fa_update"; // I-D name for 2fa_change
pub const TYPE_2FA_AUTHENTICATE: &str = "2fa_authenticate"; // legacy alias
pub const TYPE_2FA_CHANGE: &str = "2fa_change"; // legacy alias

// Service types — application (beyond I-D scope)
pub const TYPE_P256_GENERATE: &str = "p256_generate";
pub const TYPE_SIGN_ECDSA: &str = "sign_ecdsa";
pub const TYPE_AGREE_ECDH: &str = "agree_ecdh";
pub const TYPE_HSM_LIST_KEYS: &str = "hsm_list_keys";

// EUDIW service types
pub const TYPE_EUDIW_WKA_ETSI: &str = "eudiw_wka_etsi";
pub const TYPE_EUDIW_WIA_ETSI: &str = "eudiw_wia_etsi";
pub const TYPE_EUDIW_WI_REVOKE: &str = "eudiw_wi_revoke";
pub const TYPE_EUDIW_WI_SUSPEND: &str = "eudiw_wi_suspend";

// JWS typ header values
pub const TYP_REQUEST: &str = "r2ps-request+jwt";
pub const TYP_RESPONSE: &str = "r2ps-response+jwt";

// JWE typ header values (draft-santesson-r2ps §4.1)
pub const JWE_TYP_1FA: &str = "r2ps-1fa";
pub const JWE_TYP_2FA: &str = "r2ps-2fa";
