use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// JWS payload for an R2PS service request (r2ps.md §3).
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
}

/// JWS payload for an R2PS service response (r2ps.md §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub ver: String,
    pub nonce: String,
    pub iat: i64,
    pub data: Box<RawValue>,
}

/// Error response returned on failure (r2ps.md §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

/// 2FA request data (r2ps-service-types.md §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFARequestData {
    #[serde(rename = "2fa_mode")]
    pub tfa_mode: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
    pub request: String,
}

/// 2FA response data (r2ps-service-types.md §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFAResponseData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// 2FA authentication response data — extends TFAResponseData with session info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFAAuthResponseData {
    #[serde(rename = "2fa_session_id", skip_serializing_if = "Option::is_none")]
    pub tfa_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_expiration_time: Option<i64>,
}

// Protocol version
pub const PROTOCOL_VERSION: &str = "1.0";

// 2FA mode identifiers
pub const TFA_MODE_PASSWORD: &str = "password";
pub const TFA_MODE_OPAQUE: &str = "opaque";
pub const TFA_MODE_FIDO2: &str = "fido2";

// 2FA states
pub const STATE_EVALUATE: &str = "evaluate";
pub const STATE_FINALIZE: &str = "finalize";
pub const STATE_CHALLENGE: &str = "challenge";
pub const STATE_REGISTER: &str = "register";

// Service types (2FA)
pub const TYPE_2FA_REGISTRATION: &str = "2fa_registration";
pub const TYPE_2FA_AUTHENTICATE: &str = "2fa_authenticate";
pub const TYPE_2FA_CHANGE: &str = "2fa_change";

// Service types (HSM)
pub const TYPE_P256_GENERATE: &str = "p256_generate";
pub const TYPE_SIGN_ECDSA: &str = "sign_ecdsa";
pub const TYPE_AGREE_ECDH: &str = "agree_ecdh";
pub const TYPE_HSM_LIST_KEYS: &str = "hsm_list_keys";

// EUDIW service types
pub const TYPE_EUDIW_WKA_ETSI: &str = "eudiw_wka_etsi";
pub const TYPE_EUDIW_WIA_ETSI: &str = "eudiw_wia_etsi";

// JWS typ header values
pub const TYP_REQUEST: &str = "r2ps-request+jwt";
pub const TYP_RESPONSE: &str = "r2ps-response+jwt";
