use serde::{Deserialize, Serialize};

/// JWS payload for an R2PS service request (§3.1.1, §3.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRequest {
    pub ver: String,
    pub nonce: String,
    pub iat: i64,
    pub enc: String,
    pub data: String,
    pub client_id: String,
    pub kid: String,
    pub context: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pake_session_id: Option<String>,
}

/// JWS payload for an R2PS service response (§3.1.1, §3.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub ver: String,
    pub nonce: String,
    pub iat: i64,
    pub enc: String,
    pub data: String,
}

/// Error response returned on failure (§3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error_code: String,
    pub error_message: String,
}

/// Decrypted service data for PAKE requests (§3.3.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PakeRequest {
    pub protocol: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_duration: Option<i64>,
    pub req: String,
}

/// Decrypted service data for PAKE responses (§3.3.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PakeResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pake_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_expiration_time: Option<i64>,
}

// Protocol version
pub const PROTOCOL_VERSION: &str = "1.0";

// Encryption modes
pub const ENC_DEVICE: &str = "device";
pub const ENC_USER: &str = "user";

// PAKE protocol identifiers
pub const PAKE_PROTOCOL_OPAQUE: &str = "opaque";

// PAKE states
pub const PAKE_STATE_EVALUATE: &str = "evaluate";
pub const PAKE_STATE_FINALIZE: &str = "finalize";

// Service types (PAKE)
pub const TYPE_PIN_REGISTRATION: &str = "pin_registration";
pub const TYPE_PIN_CHANGE: &str = "pin_change";
pub const TYPE_AUTHENTICATE: &str = "authenticate";

// Service types (HSM)
pub const TYPE_HSM_EC_KEYGEN: &str = "hsm_ec_keygen";
pub const TYPE_HSM_ECDSA: &str = "hsm_ecdsa";
pub const TYPE_HSM_ECDH: &str = "hsm_ecdh";
pub const TYPE_HSM_LIST_KEYS: &str = "hsm_list_keys";

// JWS typ header values
pub const TYP_REQUEST: &str = "r2ps-request+json";
pub const TYP_RESPONSE: &str = "r2ps-response+json";
