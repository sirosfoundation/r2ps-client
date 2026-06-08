//! EUDIW attestation client operations (WKA/WIA).
//!
//! Provides typed request/response structs and convenience methods for the
//! `eudiw_wka_etsi` and `eudiw_wia_etsi` service types, aligned with
//! CS-04 (WUA Lifecycle) and ETSI TS 119 476-3.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    client::{R2psClient, Transport},
    error::Result,
    pake::PakeClient,
    types::*,
};

// ---------------------------------------------------------------------------
// Request / response structs
// ---------------------------------------------------------------------------

/// Request data for `eudiw_wka_etsi` and `eudiw_wia_etsi`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwAttestationRequest {
    /// Key identifiers to include in the attestation.
    pub keys_to_attest: Vec<String>,
    /// ETSI TS 119 476-3 version identifier (e.g. `"draft-008"`).
    pub ver: String,
}

/// Response data for `eudiw_wka_etsi`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwWkaResponse {
    /// The WKA JWT (`keyattestation+jwt`).
    pub wka: String,
}

/// Response data for `eudiw_wia_etsi`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwWiaResponse {
    /// The WIA JWT (`oauth-client-attestation+jwt`).
    pub wia: String,
}

/// Token Status List reference (RFC 9701).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListRef {
    pub idx: i64,
    pub uri: String,
}

/// Wrapper for a `status_list` reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListStatus {
    pub status_list: StatusListRef,
}

/// Status object for `client_status` (WIA) or `key_storage_status` (WKA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusObject {
    pub status: StatusListStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

/// Decoded WKA JWT payload (CS-04 §7.1 / TS-03 clause 2.3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WkaPayload {
    pub iat: i64,
    pub exp: i64,
    pub attested_keys: Vec<Value>,
    pub key_storage: Vec<String>,
    pub user_authentication: Vec<String>,
    #[serde(default)]
    pub certification: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_link: Option<String>,
    pub key_storage_status: StatusObject,
}

/// Decoded WIA JWT payload (CS-04 §7.1 / TS-03 clause 2.3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiaPayload {
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub wallet_name: String,
    #[serde(default)]
    pub wallet_version: String,
    #[serde(default)]
    pub wallet_solution_certification_information: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_link: Option<String>,
    pub client_status: StatusObject,
    pub cnf: CnfClaim,
}

/// Confirmation claim containing a JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    pub jwk: Value,
}

/// Request data for `eudiw_wi_revoke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwRevokeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response data for `eudiw_wi_revoke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwRevokeResponse {
    pub revoked_indices: i64,
    pub message: String,
}

/// Request data for `eudiw_wi_suspend`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwSuspendRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response data for `eudiw_wi_suspend`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EudiwSuspendResponse {
    pub suspended_indices: i64,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Client convenience methods
// ---------------------------------------------------------------------------

impl<T: Transport, P: PakeClient> R2psClient<T, P> {
    /// Request a Wallet Key Attestation (1FA, no session required).
    ///
    /// `kids` — key identifiers for the keys to be attested.
    /// `etsi_version` — ETSI TS 119 476-3 version (e.g. `"draft-008"`).
    pub fn wka_attest(&self, kids: &[&str], etsi_version: &str) -> Result<EudiwWkaResponse> {
        let req = EudiwAttestationRequest {
            keys_to_attest: kids.iter().map(|s| s.to_string()).collect(),
            ver: etsi_version.into(),
        };
        let data = serde_json::to_value(&req)?;
        let resp = self.call_service_1fa(TYPE_EUDIW_WKA_ETSI, &data)?;
        let wka_resp: EudiwWkaResponse = serde_json::from_value(resp)?;
        Ok(wka_resp)
    }

    /// Request a Wallet Instance Attestation (1FA, no session required).
    ///
    /// `kids` — key identifiers associated with the wallet instance.
    /// `etsi_version` — ETSI TS 119 476-3 version (e.g. `"draft-008"`).
    pub fn wia_attest(&self, kids: &[&str], etsi_version: &str) -> Result<EudiwWiaResponse> {
        let req = EudiwAttestationRequest {
            keys_to_attest: kids.iter().map(|s| s.to_string()).collect(),
            ver: etsi_version.into(),
        };
        let data = serde_json::to_value(&req)?;
        let resp = self.call_service_1fa(TYPE_EUDIW_WIA_ETSI, &data)?;
        let wia_resp: EudiwWiaResponse = serde_json::from_value(resp)?;
        Ok(wia_resp)
    }

    /// Revoke the wallet instance (1FA, no session required).
    /// Sets all status list entries for this client to revoked.
    pub fn wi_revoke(&self, reason: Option<&str>) -> Result<EudiwRevokeResponse> {
        let req = EudiwRevokeRequest {
            reason: reason.map(String::from),
        };
        let data = serde_json::to_value(&req)?;
        let resp = self.call_service_1fa(TYPE_EUDIW_WI_REVOKE, &data)?;
        let revoke_resp: EudiwRevokeResponse = serde_json::from_value(resp)?;
        Ok(revoke_resp)
    }

    /// Suspend the wallet instance (1FA, no session required).
    /// Sets all status list entries for this client to suspended.
    pub fn wi_suspend(&self, reason: Option<&str>) -> Result<EudiwSuspendResponse> {
        let req = EudiwSuspendRequest {
            reason: reason.map(String::from),
        };
        let data = serde_json::to_value(&req)?;
        let resp = self.call_service_1fa(TYPE_EUDIW_WI_SUSPEND, &data)?;
        let suspend_resp: EudiwSuspendResponse = serde_json::from_value(resp)?;
        Ok(suspend_resp)
    }
}
