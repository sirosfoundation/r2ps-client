//! Conformance tests: validate test vectors against the R2PS spec.
//!
//! Vectors are produced by both the Go and Rust implementations
//! and cross-validated to ensure interoperability.

use hex;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use p256::{PublicKey, SecretKey};
use r2ps_client::jwe::{decrypt_jwe, decrypt_jwe_symmetric, encrypt_jwe, encrypt_jwe_symmetric};
use r2ps_client::jws::{peek_jws_headers, sign_jws, verify_jws};
use r2ps_client::raw_sign::{
    HsmEcKeygenRequest, HsmEcKeygenResponse, HsmEcdhRequest, HsmEcdsaRequest, HsmListKeysRequest,
    HsmListKeysResponse,
};
use r2ps_client::{EudiwAttestationRequest, EudiwWiaResponse, EudiwWkaResponse};
use serde::Deserialize;
use std::path::Path;

// --- Test vector format (mirrors Go conformance package) ---

#[derive(Deserialize)]
struct TestVectors {
    #[allow(dead_code)]
    generator: String,
    #[allow(dead_code)]
    version: String,
    keys: Keys,
    jws: JWSVectors,
    jwe_ecdh: JWEVectors,
    jwe_symmetric: JWEVectors,
    protocol_types: ProtocolTypes,
    hsm_service_types: HSMVectors,
    #[serde(default)]
    eudiw_service_types: Option<EUDIWVectors>,
    #[serde(default)]
    #[allow(dead_code)]
    hkdf_vectors: Option<HKDFVectors>,
}

#[derive(Deserialize)]
struct Keys {
    ec_private_pkcs8_pem: String,
    ec_public_spki_pem: String,
    symmetric_key_hex: String,
}

#[derive(Deserialize)]
struct JWSVectors {
    compact: String,
    payload_hex: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
struct JWEVectors {
    compact: String,
    plaintext_hex: String,
}

#[derive(Deserialize)]
struct ProtocolTypes {
    service_request: String,
    service_response: String,
    #[allow(dead_code)]
    tfa_request: String,
    #[allow(dead_code)]
    tfa_response: String,
    error_response: String,
    #[serde(default)]
    request_response_pairs: Option<Vec<RequestResponsePair>>,
    #[serde(default)]
    all_error_responses: Option<Vec<NamedJSON>>,
    #[serde(default)]
    tfa_reg_evaluate_req: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tfa_reg_evaluate_resp: Option<String>,
    #[serde(default)]
    tfa_reg_finalize_req: Option<String>,
    #[serde(default)]
    tfa_reg_finalize_resp: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tfa_auth_evaluate_req: Option<String>,
    #[serde(default)]
    tfa_auth_evaluate_resp: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tfa_auth_finalize_req: Option<String>,
    #[serde(default)]
    tfa_auth_finalize_resp: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tfa_change_evaluate_req: Option<String>,
    #[serde(default)]
    tfa_change_finalize_req: Option<String>,
    #[serde(default)]
    mode_constraints: Option<Vec<ModeConstraint>>,
}

#[derive(Deserialize)]
struct RequestResponsePair {
    name: String,
    request: String,
    response: String,
}

#[derive(Deserialize)]
struct NamedJSON {
    name: String,
    json: String,
}

#[derive(Deserialize)]
struct ModeConstraint {
    #[serde(rename = "type")]
    service_type: String,
    required_mode: String,
}

#[derive(Deserialize)]
struct HSMVectors {
    ec_keygen_request: String,
    ec_keygen_response: String,
    ecdsa_request: String,
    ecdsa_response_hex: String,
    ecdh_request: String,
    ecdh_response_hex: String,
    list_keys_request: String,
    list_keys_response: String,
    #[serde(default)]
    keygen_p384_request: Option<String>,
    #[serde(default)]
    keygen_p384_response: Option<String>,
    #[serde(default)]
    keygen_p521_request: Option<String>,
    #[serde(default)]
    keygen_p521_response: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    list_all_keys_request: Option<String>,
    #[serde(default)]
    list_all_keys_response: Option<String>,
}

#[derive(Deserialize)]
struct EUDIWVectors {
    wka_request: String,
    wka_response: String,
    wia_request: String,
    wia_response: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct HKDFVectors {
    session_key_hex: String,
    session_id: String,
    kek_c2s_hex: String,
    kek_s2c_hex: String,
}

fn load_vectors(path: &str) -> Option<TestVectors> {
    let p = Path::new(path);
    if !p.exists() {
        return None;
    }
    let data = std::fs::read_to_string(p).expect("read vectors");
    Some(serde_json::from_str(&data).expect("parse vectors"))
}

fn vector_files() -> Vec<(&'static str, TestVectors)> {
    let mut files = Vec::new();
    let go_path = "testdata/vectors_go.json";
    match load_vectors(go_path) {
        Some(v) => files.push(("go", v)),
        None => panic!("vectors_go.json not found — copy from go-r2ps-service/testdata/"),
    }
    if let Some(v) = load_vectors("testdata/vectors_rust.json") {
        files.push(("rust", v));
    }
    files
}

fn parse_secret_key(pem: &str) -> SecretKey {
    SecretKey::from_pkcs8_pem(pem).expect("parse EC private key PEM")
}

fn parse_public_key(pem: &str) -> PublicKey {
    PublicKey::from_public_key_pem(pem).expect("parse EC public key PEM")
}

// ============================================================
// Layer 1: JWS / JWE crypto interop
// ============================================================

#[test]
fn jws_verify() {
    for (name, v) in vector_files() {
        let pub_key = parse_public_key(&v.keys.ec_public_spki_pem);
        let verifying_key = VerifyingKey::from(&pub_key);
        let payload = verify_jws(&v.jws.compact, &verifying_key)
            .unwrap_or_else(|e| panic!("[{name}] verify_jws: {e}"));
        let expected = hex::decode(&v.jws.payload_hex).unwrap();
        assert_eq!(payload, expected, "[{name}] JWS payload mismatch");
    }
}

#[test]
fn jws_headers() {
    for (name, v) in vector_files() {
        let hdrs = peek_jws_headers(&v.jws.compact)
            .unwrap_or_else(|e| panic!("[{name}] peek_jws_headers: {e}"));
        assert_eq!(
            hdrs.kid.as_deref(),
            Some(v.jws.kid.as_str()),
            "[{name}] kid mismatch"
        );
        assert_eq!(
            hdrs.typ.as_deref(),
            Some(v.jws.typ.as_str()),
            "[{name}] typ mismatch"
        );
    }
}

#[test]
fn jwe_decrypt_ecdh() {
    for (name, v) in vector_files() {
        let priv_key = parse_secret_key(&v.keys.ec_private_pkcs8_pem);
        let plaintext = decrypt_jwe(&v.jwe_ecdh.compact, &priv_key)
            .unwrap_or_else(|e| panic!("[{name}] decrypt_jwe: {e}"));
        let expected = hex::decode(&v.jwe_ecdh.plaintext_hex).unwrap();
        assert_eq!(plaintext, expected, "[{name}] JWE ECDH plaintext mismatch");
    }
}

#[test]
fn jwe_decrypt_symmetric() {
    for (name, v) in vector_files() {
        let key_bytes = hex::decode(&v.keys.symmetric_key_hex).unwrap();
        let key: [u8; 32] = key_bytes.try_into().expect("key must be 32 bytes");
        let plaintext = decrypt_jwe_symmetric(&v.jwe_symmetric.compact, &key)
            .unwrap_or_else(|e| panic!("[{name}] decrypt_jwe_symmetric: {e}"));
        let expected = hex::decode(&v.jwe_symmetric.plaintext_hex).unwrap();
        assert_eq!(
            plaintext, expected,
            "[{name}] JWE symmetric plaintext mismatch"
        );
    }
}

// ============================================================
// Layer 2: Protocol type field conformance (r2ps.md §3)
// ============================================================

#[test]
fn protocol_service_request_fields() {
    for (name, v) in vector_files() {
        let raw: serde_json::Value =
            serde_json::from_str(&v.protocol_types.service_request).unwrap();
        let obj = raw.as_object().unwrap();
        // Required fields per r2ps.md §3
        for field in &[
            "ver",
            "nonce",
            "iat",
            "data",
            "client_id",
            "context",
            "type",
        ] {
            assert!(
                obj.contains_key(*field),
                "[{name}] missing required field '{field}' in service_request"
            );
        }
        assert_eq!(obj["ver"], "1.0", "[{name}] ver must be 1.0");
        // enc and kid MUST NOT be present (removed in current spec)
        assert!(
            !obj.contains_key("enc"),
            "[{name}] service_request MUST NOT contain 'enc' (removed in current spec)"
        );
        assert!(
            !obj.contains_key("kid"),
            "[{name}] service_request MUST NOT contain 'kid' (removed from payload)"
        );
    }
}

#[test]
fn protocol_service_response_no_request_fields() {
    for (name, v) in vector_files() {
        let raw: serde_json::Value =
            serde_json::from_str(&v.protocol_types.service_response).unwrap();
        let obj = raw.as_object().unwrap();
        // Response MUST NOT contain request-only fields
        for field in &["client_id", "context", "type"] {
            assert!(
                !obj.contains_key(*field),
                "[{name}] service_response MUST NOT contain '{field}'"
            );
        }
    }
}

#[test]
fn protocol_error_response_valid_code() {
    for (name, v) in vector_files() {
        let raw: serde_json::Value =
            serde_json::from_str(&v.protocol_types.error_response).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(
            obj.contains_key("error_code"),
            "[{name}] missing error_code"
        );
        assert!(
            obj.contains_key("error_message"),
            "[{name}] missing error_message"
        );
        let code = obj["error_code"].as_str().unwrap();
        let valid = [
            "ILLEGAL_REQUEST_DATA",
            "UNAUTHORIZED",
            "ACCESS_DENIED",
            "ILLEGAL_STATE",
            "UNSUPPORTED_REQUEST_TYPE",
            "SERVER_ERROR",
            "TRY_LATER",
        ];
        assert!(
            valid.contains(&code),
            "[{name}] unknown error_code '{code}'"
        );
    }
}

// ============================================================
// Layer 3: HSM service type conformance (r2ps-service-types.md)
// ============================================================

#[test]
fn hsm_keygen_request_spec_fields() {
    for (name, v) in vector_files() {
        let _req: HsmEcKeygenRequest = serde_json::from_str(&v.hsm_service_types.ec_keygen_request)
            .unwrap_or_else(|e| panic!("[{name}] keygen request: {e}"));
        let raw: serde_json::Value =
            serde_json::from_str(&v.hsm_service_types.ec_keygen_request).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(obj.contains_key("curve"), "[{name}] missing 'curve'");
        assert_eq!(
            obj.len(),
            1,
            "[{name}] keygen request should only have 'curve'"
        );
    }
}

#[test]
fn hsm_keygen_response_spec_fields() {
    for (name, v) in vector_files() {
        let _resp: HsmEcKeygenResponse =
            serde_json::from_str(&v.hsm_service_types.ec_keygen_response)
                .unwrap_or_else(|e| panic!("[{name}] keygen response: {e}"));
        let raw: serde_json::Value =
            serde_json::from_str(&v.hsm_service_types.ec_keygen_response).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(
            obj.contains_key("created_key"),
            "[{name}] missing 'created_key'"
        );
        assert!(!obj.contains_key("kid"), "[{name}] non-spec field 'kid'");
        assert!(
            !obj.contains_key("pub_key"),
            "[{name}] non-spec field 'pub_key'"
        );
    }
}

#[test]
fn hsm_ecdsa_request_spec_fields() {
    for (name, v) in vector_files() {
        let _req: HsmEcdsaRequest = serde_json::from_str(&v.hsm_service_types.ecdsa_request)
            .unwrap_or_else(|e| panic!("[{name}] ecdsa request: {e}"));
        let raw: serde_json::Value =
            serde_json::from_str(&v.hsm_service_types.ecdsa_request).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(obj.contains_key("tbs_hash"), "[{name}] missing 'tbs_hash'");
        assert!(
            !obj.contains_key("hash"),
            "[{name}] non-spec field 'hash' — spec requires 'tbs_hash'"
        );
    }
}

#[test]
fn hsm_ecdsa_response_raw_der() {
    for (name, v) in vector_files() {
        let sig = hex::decode(&v.hsm_service_types.ecdsa_response_hex)
            .unwrap_or_else(|e| panic!("[{name}] decode hex: {e}"));
        assert!(!sig.is_empty(), "[{name}] empty ECDSA response");
        assert_eq!(
            sig[0], 0x30,
            "[{name}] ECDSA response must start with ASN.1 SEQUENCE tag 0x30"
        );
    }
}

#[test]
fn hsm_ecdh_request_spec_fields() {
    for (name, v) in vector_files() {
        let _req: HsmEcdhRequest = serde_json::from_str(&v.hsm_service_types.ecdh_request)
            .unwrap_or_else(|e| panic!("[{name}] ecdh request: {e}"));
        let raw: serde_json::Value =
            serde_json::from_str(&v.hsm_service_types.ecdh_request).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(
            obj.contains_key("public_key"),
            "[{name}] missing 'public_key'"
        );
        assert!(
            !obj.contains_key("peer_pub_key"),
            "[{name}] non-spec field 'peer_pub_key'"
        );
    }
}

#[test]
fn hsm_ecdh_response_raw_bytes() {
    for (name, v) in vector_files() {
        let secret = hex::decode(&v.hsm_service_types.ecdh_response_hex)
            .unwrap_or_else(|e| panic!("[{name}] decode hex: {e}"));
        assert!(!secret.is_empty(), "[{name}] empty ECDH response");
        assert_eq!(
            secret.len(),
            32,
            "[{name}] P-256 shared secret should be 32 bytes"
        );
    }
}

#[test]
fn hsm_list_keys_request_spec_fields() {
    for (name, v) in vector_files() {
        let _req: HsmListKeysRequest = serde_json::from_str(&v.hsm_service_types.list_keys_request)
            .unwrap_or_else(|e| panic!("[{name}] list_keys request: {e}"));
        let raw: serde_json::Value =
            serde_json::from_str(&v.hsm_service_types.list_keys_request).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(obj.contains_key("curve"), "[{name}] missing 'curve'");
        assert!(
            !obj.contains_key("curves"),
            "[{name}] non-spec field 'curves' — spec uses 'curve'"
        );
    }
}

#[test]
fn hsm_list_keys_response_spec_fields() {
    for (name, v) in vector_files() {
        let resp: HsmListKeysResponse =
            serde_json::from_str(&v.hsm_service_types.list_keys_response)
                .unwrap_or_else(|e| panic!("[{name}] list_keys response: {e}"));

        let raw: serde_json::Value =
            serde_json::from_str(&v.hsm_service_types.list_keys_response).unwrap();
        let obj = raw.as_object().unwrap();
        assert!(obj.contains_key("key_info"), "[{name}] missing 'key_info'");
        assert!(!obj.contains_key("keys"), "[{name}] non-spec field 'keys'");

        for (i, ki) in resp.key_info.iter().enumerate() {
            assert!(!ki.kid.is_empty(), "[{name}] key_info[{i}].kid empty");
            assert!(
                !ki.curve_name.is_empty(),
                "[{name}] key_info[{i}].curve_name empty"
            );
            assert!(
                ki.creation_time > 0,
                "[{name}] key_info[{i}].creation_time zero"
            );
            assert!(
                !ki.public_key.is_empty(),
                "[{name}] key_info[{i}].public_key empty"
            );
        }
    }
}

// ============================================================
// Extended Protocol Conformance
// ============================================================

#[test]
fn nonce_echo_validation() {
    for (name, v) in vector_files() {
        if let Some(ref pairs) = v.protocol_types.request_response_pairs {
            for pair in pairs {
                let req: serde_json::Value = serde_json::from_str(&pair.request).unwrap();
                let resp: serde_json::Value = serde_json::from_str(&pair.response).unwrap();
                assert_eq!(
                    req["nonce"], resp["nonce"],
                    "[{name}/{}] nonce must echo",
                    pair.name
                );
            }
        }
    }
}

#[test]
fn response_forbidden_fields() {
    for (name, v) in vector_files() {
        if let Some(ref pairs) = v.protocol_types.request_response_pairs {
            for pair in pairs {
                let resp: serde_json::Value = serde_json::from_str(&pair.response).unwrap();
                let obj = resp.as_object().unwrap();
                for field in &["client_id", "context", "type"] {
                    assert!(
                        !obj.contains_key(*field),
                        "[{name}/{}] response contains request-only field '{}'",
                        pair.name,
                        field
                    );
                }
            }
        }
    }
}

#[test]
fn all_error_codes() {
    let valid_codes = [
        "ILLEGAL_REQUEST_DATA",
        "UNAUTHORIZED",
        "ACCESS_DENIED",
        "ILLEGAL_STATE",
        "UNSUPPORTED_REQUEST_TYPE",
        "SERVER_ERROR",
        "TRY_LATER",
    ];
    for (name, v) in vector_files() {
        if let Some(ref errors) = v.protocol_types.all_error_responses {
            assert_eq!(errors.len(), 7, "[{name}] expected all 7 error codes");
            for ne in errors {
                let raw: serde_json::Value = serde_json::from_str(&ne.json).unwrap();
                let code = raw["error_code"].as_str().unwrap();
                assert!(
                    valid_codes.contains(&code),
                    "[{name}/{}] unknown error_code '{code}'",
                    ne.name
                );
                assert!(
                    raw["error_message"]
                        .as_str()
                        .map_or(false, |s| !s.is_empty()),
                    "[{name}/{}] error_message must not be empty",
                    ne.name
                );
            }
        }
    }
}

#[test]
fn tfa_registration_flow() {
    for (name, v) in vector_files() {
        if let Some(ref req_json) = v.protocol_types.tfa_reg_evaluate_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            let mode = req.get("protocol").or_else(|| req.get("2fa_mode")).unwrap();
            assert_eq!(mode, "opaque", "[{name}] reg evaluate protocol");
            assert_eq!(req["state"], "evaluate", "[{name}] reg evaluate state");
            assert!(
                req.get("p_data")
                    .or_else(|| req.get("request"))
                    .and_then(|v| v.as_str())
                    .map_or(false, |s| !s.is_empty()),
                "[{name}] request empty"
            );
        }
        if let Some(ref req_json) = v.protocol_types.tfa_reg_finalize_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            assert_eq!(req["state"], "finalize", "[{name}] reg finalize state");
            assert!(
                req["authorization"]
                    .as_str()
                    .map_or(false, |s| !s.is_empty()),
                "[{name}] authorization must be present for initial 2FA registration"
            );
        }
        if let Some(ref resp_json) = v.protocol_types.tfa_reg_finalize_resp {
            let resp: serde_json::Value = serde_json::from_str(resp_json).unwrap();
            assert!(
                resp["message"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] reg finalize message"
            );
        }
    }
}

#[test]
fn tfa_authentication_flow() {
    for (name, v) in vector_files() {
        if let Some(ref resp_json) = v.protocol_types.tfa_auth_evaluate_resp {
            let resp: serde_json::Value = serde_json::from_str(resp_json).unwrap();
            let sid = resp
                .get("session_id")
                .or_else(|| resp.get("2fa_session_id"));
            assert!(
                sid.and_then(|v| v.as_str())
                    .map_or(false, |s| !s.is_empty()),
                "[{name}] auth evaluate session_id must be present"
            );
        }
        if let Some(ref resp_json) = v.protocol_types.tfa_auth_finalize_resp {
            let resp: serde_json::Value = serde_json::from_str(resp_json).unwrap();
            let sid = resp
                .get("session_id")
                .or_else(|| resp.get("2fa_session_id"));
            assert!(sid
                .and_then(|v| v.as_str())
                .map_or(false, |s| !s.is_empty()));
            assert!(resp["session_expiration_time"]
                .as_i64()
                .map_or(false, |v| v > 0));
        }
    }
}

#[test]
fn tfa_change_no_authorization() {
    for (name, v) in vector_files() {
        if let Some(ref req_json) = v.protocol_types.tfa_change_finalize_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            assert!(
                req.get("authorization")
                    .map_or(true, |v| v.is_null() || v.as_str() == Some("")),
                "[{name}] authorization must NOT be present for 2FA change"
            );
        }
    }
}

#[test]
fn mode_constraints() {
    for (name, v) in vector_files() {
        if let Some(ref constraints) = v.protocol_types.mode_constraints {
            for c in constraints {
                assert!(
                    c.required_mode == "1FA" || c.required_mode == "2FA",
                    "[{name}] mode={} for type {}, expected 1FA or 2FA",
                    c.required_mode,
                    c.service_type
                );
            }
        }
    }
}

// ============================================================
// Extended HSM Conformance
// ============================================================

#[test]
fn hsm_keygen_multi_curve() {
    for (name, v) in vector_files() {
        for (curve, req_opt, resp_opt) in [
            (
                "P-384",
                &v.hsm_service_types.keygen_p384_request,
                &v.hsm_service_types.keygen_p384_response,
            ),
            (
                "P-521",
                &v.hsm_service_types.keygen_p521_request,
                &v.hsm_service_types.keygen_p521_response,
            ),
        ] {
            if let (Some(req_json), Some(resp_json)) = (req_opt, resp_opt) {
                let req: HsmEcKeygenRequest = serde_json::from_str(req_json).unwrap();
                assert_eq!(req.curve, curve, "[{name}] keygen {curve} curve mismatch");
                let resp: HsmEcKeygenResponse = serde_json::from_str(resp_json).unwrap();
                assert_eq!(
                    resp.created_key, curve,
                    "[{name}] keygen {curve} created_key mismatch"
                );
            }
        }
    }
}

#[test]
fn hsm_list_all_keys_multi_curve() {
    for (name, v) in vector_files() {
        if let Some(ref resp_json) = v.hsm_service_types.list_all_keys_response {
            let resp: HsmListKeysResponse = serde_json::from_str(resp_json).unwrap();
            assert!(
                resp.key_info.len() >= 2,
                "[{name}] list-all should return multiple keys"
            );
            let curves: std::collections::HashSet<&str> = resp
                .key_info
                .iter()
                .map(|k| k.curve_name.as_str())
                .collect();
            assert!(
                curves.len() >= 2,
                "[{name}] list-all should contain multiple curves, got {curves:?}"
            );
        }
    }
}

// ============================================================
// EUDIW Service Type Conformance
// (spec: r2ps-service-types-eudiw.md)
// ============================================================

#[test]
fn eudiw_wka_request_fields() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wka_request).unwrap();
            let obj = raw.as_object().unwrap();
            assert!(
                obj.contains_key("keys_to_attest"),
                "[{name}] missing keys_to_attest"
            );
            assert!(obj.contains_key("ver"), "[{name}] missing ver");
            let keys = raw["keys_to_attest"].as_array().unwrap();
            assert!(
                !keys.is_empty(),
                "[{name}] keys_to_attest must be non-empty"
            );
        }
    }
}

#[test]
fn eudiw_wka_response_fields() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wka_response).unwrap();
            assert!(
                raw["wka"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] wka must not be empty"
            );
        }
    }
}

#[test]
fn eudiw_wia_request_fields() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wia_request).unwrap();
            let obj = raw.as_object().unwrap();
            assert!(obj.contains_key("ver"), "[{name}] missing ver");
            assert!(
                obj.contains_key("keys_to_attest"),
                "[{name}] missing keys_to_attest"
            );
        }
    }
}

#[test]
fn eudiw_wia_response_fields() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wia_response).unwrap();
            assert!(
                raw["wia"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] wia must not be empty"
            );
        }
    }
}

#[test]
fn eudiw_version_identifier() {
    let valid_versions = ["draft-008"];
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let wka_req: serde_json::Value = serde_json::from_str(&eudiw.wka_request).unwrap();
            let ver = wka_req["ver"].as_str().unwrap();
            assert!(
                valid_versions.contains(&ver),
                "[{name}] WKA ver={ver} not in defined versions"
            );

            let wia_req: serde_json::Value = serde_json::from_str(&eudiw.wia_request).unwrap();
            let ver = wia_req["ver"].as_str().unwrap();
            assert!(
                valid_versions.contains(&ver),
                "[{name}] WIA ver={ver} not in defined versions"
            );
        }
    }
}

// ============================================================
// Rust vector generator: produce vectors_rust.json
// ============================================================

#[test]
fn generate_rust_vectors() {
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let signing_key = SigningKey::from(&secret_key);
    let _verifying_key = VerifyingKey::from(&signing_key);

    // PEM encode keys
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let priv_pem = secret_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("encode private PEM");
    let pub_pem = public_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .expect("encode public PEM");

    let sym_key: [u8; 32] = rand::random();

    // JWS — new typ value
    let payload = b"hello interop";
    let kid = "conformance-kid-1";
    let typ = "r2ps-request+jwt";
    let jws_compact = sign_jws(payload, &signing_key, Some(kid), Some(typ)).unwrap();

    // JWE ECDH
    let ecdh_plain = b"ecdh secret payload";
    let jwe_ecdh = encrypt_jwe(ecdh_plain, &public_key).unwrap();

    // JWE Symmetric
    let sym_plain = b"symmetric secret payload";
    let jwe_sym = encrypt_jwe_symmetric(sym_plain, &sym_key).unwrap();

    // Protocol types — new spec structure (no enc, no kid in payload)
    let svc_req = serde_json::json!({
        "ver": "1.0",
        "nonce": "dGVzdG5vbmNl",
        "iat": 1716400000,
        "data": {"kid": "key-0", "tbs_hash": "YUHJYg=="},
        "client_id": "test-client",
        "context": "hsm",
        "type": "sign_ecdsa",
        "session_id": "session-abc",
        "2fa_session_id": "session-abc"
    });
    let svc_resp = serde_json::json!({
        "ver": "1.0",
        "nonce": "cmVzcG5vbmNl",
        "iat": 1716400001,
        "data": {"signature": "MEQCIG..."}
    });
    let tfa_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "evaluate",
        "p_data": "b3BhcXVlLXJlcXVlc3Q",
        "request": "b3BhcXVlLXJlcXVlc3Q"
    });
    let tfa_resp = serde_json::json!({
        "p_data": "b3BhcXVlLXJlc3BvbnNl",
        "response": "b3BhcXVlLXJlc3BvbnNl"
    });
    let err_resp = serde_json::json!({
        "error_code": "UNAUTHORIZED",
        "error_message": "invalid credentials"
    });

    // 2FA registration flow
    let tfa_reg_eval_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "evaluate",
        "p_data": "cmVnaXN0cmF0aW9uLXJlcXVlc3Q",
        "request": "cmVnaXN0cmF0aW9uLXJlcXVlc3Q"
    });
    let tfa_reg_eval_resp = serde_json::json!({
        "p_data": "cmVnaXN0cmF0aW9uLXJlc3BvbnNl",
        "response": "cmVnaXN0cmF0aW9uLXJlc3BvbnNl"
    });
    let tfa_reg_fin_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "finalize",
        "p_data": "cmVnaXN0cmF0aW9uLXJlY29yZA",
        "request": "cmVnaXN0cmF0aW9uLXJlY29yZA",
        "authorization": "YXV0aG9yaXphdGlvbi1kYXRh"
    });
    let tfa_reg_fin_resp = serde_json::json!({
        "message": "success"
    });

    // 2FA auth flow
    let tfa_auth_eval_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "evaluate",
        "p_data": "S0UxLWJ5dGVz",
        "request": "S0UxLWJ5dGVz"
    });
    let tfa_auth_eval_resp = serde_json::json!({
        "session_id": "auth-session-001",
        "2fa_session_id": "auth-session-001",
        "p_data": "S0UyLWJ5dGVz",
        "response": "S0UyLWJ5dGVz"
    });
    let tfa_auth_fin_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "finalize",
        "p_data": "S0UzLWJ5dGVz",
        "request": "S0UzLWJ5dGVz"
    });
    let tfa_auth_fin_resp = serde_json::json!({
        "session_id": "auth-session-001",
        "2fa_session_id": "auth-session-001",
        "message": "authenticated",
        "session_expiration_time": 1716403600
    });

    // 2FA change flow
    let tfa_chg_eval_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "evaluate",
        "p_data": "bmV3LXJlZ2lzdHJhdGlvbi1yZXF1ZXN0",
        "request": "bmV3LXJlZ2lzdHJhdGlvbi1yZXF1ZXN0"
    });
    let tfa_chg_fin_req = serde_json::json!({
        "protocol": "opaque",
        "2fa_mode": "opaque",
        "state": "finalize",
        "p_data": "bmV3LXJlZ2lzdHJhdGlvbi1yZWNvcmQ",
        "request": "bmV3LXJlZ2lzdHJhdGlvbi1yZWNvcmQ"
    });

    // Mode constraints
    let mode_constraints = serde_json::json!([
        {"type": "2fa_registration", "required_mode": "1FA"},
        {"type": "2fa_authenticate", "required_mode": "1FA"},
        {"type": "2fa_change", "required_mode": "2FA"},
        {"type": "p256_generate", "required_mode": "1FA"},
        {"type": "sign_ecdsa", "required_mode": "2FA"},
        {"type": "agree_ecdh", "required_mode": "2FA"},
        {"type": "eudiw_wka_etsi", "required_mode": "1FA"},
        {"type": "eudiw_wia_etsi", "required_mode": "1FA"}
    ]);

    // Request/response pair
    let pair_req = serde_json::json!({
        "ver": "1.0",
        "nonce": "Y29uZm9ybWFuY2Vub25jZQ",
        "iat": 1716400000,
        "data": {"kid": "key-0", "tbs_hash": "YUHJYg=="},
        "client_id": "test-client",
        "context": "hsm",
        "type": "sign_ecdsa",
        "session_id": "session-abc",
        "2fa_session_id": "session-abc"
    });
    let pair_resp = serde_json::json!({
        "ver": "1.0",
        "nonce": "Y29uZm9ybWFuY2Vub25jZQ",
        "iat": 1716400001,
        "data": {"signature": "MEQCIG..."}
    });

    // All error codes
    let all_errors = serde_json::json!([
        {"name": "ILLEGAL_REQUEST_DATA", "json": "{\"error_code\":\"ILLEGAL_REQUEST_DATA\",\"error_message\":\"malformed request\"}"},
        {"name": "UNAUTHORIZED", "json": "{\"error_code\":\"UNAUTHORIZED\",\"error_message\":\"invalid credentials\"}"},
        {"name": "ACCESS_DENIED", "json": "{\"error_code\":\"ACCESS_DENIED\",\"error_message\":\"service not allowed\"}"},
        {"name": "ILLEGAL_STATE", "json": "{\"error_code\":\"ILLEGAL_STATE\",\"error_message\":\"unexpected state\"}"},
        {"name": "UNSUPPORTED_REQUEST_TYPE", "json": "{\"error_code\":\"UNSUPPORTED_REQUEST_TYPE\",\"error_message\":\"unknown type\"}"},
        {"name": "SERVER_ERROR", "json": "{\"error_code\":\"SERVER_ERROR\",\"error_message\":\"internal error\"}"},
        {"name": "TRY_LATER", "json": "{\"error_code\":\"TRY_LATER\",\"error_message\":\"service busy\"}"}
    ]);

    // HSM service types
    let keygen_req = serde_json::to_string(&HsmEcKeygenRequest {
        curve: "P-256".into(),
    })
    .unwrap();
    let keygen_resp = serde_json::json!({"created_key": "P-256"});
    let ecdsa_req = serde_json::to_string(&HsmEcdsaRequest {
        kid: "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216".into(),
        tbs_hash: "YUHJYghlxa4CTkBEKvtPmiA+jCMUURknHs19sd7bNjs=".into(),
    })
    .unwrap();
    let ecdsa_resp_hex = "30440220260a6228484119be74f7f8f46f964af0433b1f1218e667a92e82e45e48ef488d02207cfe73d85a7b81d7853aa680ba4a0ee17120f7fd87b7542b34f79863052abcbf";
    let ecdh_req = serde_json::to_string(&HsmEcdhRequest {
        kid: "0294ddc3fd5554688bf619987b63bbb09b13e0d04b8a9da493309eef3f41767228".into(),
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpEgaHsA2UTbSkn7hJb3KfvrlAMb+p715Gw/q5x01ZgQZWL7xURVYB9Fw+B7TK+GYMShDJYjLlKva5f+KkTx3w==".into(),
    }).unwrap();
    let ecdh_resp_hex = "ad91d860a109cce0e7d334813f434be8d44a21f8b3677cfe00c25fb572950687";
    let list_req = serde_json::to_string(&HsmListKeysRequest {
        curve: vec!["P-256".into()],
    })
    .unwrap();
    let list_resp = serde_json::json!({
        "key_info": [{
            "kid": "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
            "curve_name": "P-256",
            "creation_time": 1750751069,
            "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE++Y2BZAzoH7jCZyvhKh0dNlK+ix9Qx8zkevYzyGiQhYdmIZjwS5S9fMegmKL685ctyQMNS8Jh1QayMYzwpL4AQ=="
        }]
    });

    // EUDIW service types — per r2ps-service-types-eudiw.md
    let wka_req_typed = EudiwAttestationRequest {
        keys_to_attest: vec!["key-0".into()],
        ver: "draft-008".into(),
    };
    let wka_req = serde_json::to_value(&wka_req_typed).unwrap();
    let wka_resp_typed = EudiwWkaResponse {
        wka: "eyJ0eXAiOiJrZXktYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE3MTY0MDAwMDB9.fake-signature".into(),
    };
    let wka_resp = serde_json::to_value(&wka_resp_typed).unwrap();
    let wia_req_typed = EudiwAttestationRequest {
        keys_to_attest: vec!["key-0".into()],
        ver: "draft-008".into(),
    };
    let wia_req = serde_json::to_value(&wia_req_typed).unwrap();
    let wia_resp_typed = EudiwWiaResponse {
        wia: "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE3MTY0MDAwMDB9.fake-signature".into(),
    };
    let wia_resp = serde_json::to_value(&wia_resp_typed).unwrap();

    let vectors = serde_json::json!({
        "generator": "r2ps-client",
        "version": "1.0",
        "keys": {
            "ec_private_pkcs8_pem": priv_pem.as_str(),
            "ec_public_spki_pem": pub_pem,
            "symmetric_key_hex": hex::encode(sym_key),
        },
        "jws": {
            "compact": jws_compact,
            "payload_hex": hex::encode(payload),
            "kid": kid,
            "typ": typ,
        },
        "jwe_ecdh": {
            "compact": jwe_ecdh,
            "plaintext_hex": hex::encode(ecdh_plain),
        },
        "jwe_symmetric": {
            "compact": jwe_sym,
            "plaintext_hex": hex::encode(sym_plain),
        },
        "protocol_types": {
            "service_request": svc_req.to_string(),
            "service_response": svc_resp.to_string(),
            "tfa_request": tfa_req.to_string(),
            "tfa_response": tfa_resp.to_string(),
            "error_response": err_resp.to_string(),
            "request_response_pairs": [
                {"name": "sign_ecdsa", "request": pair_req.to_string(), "response": pair_resp.to_string()}
            ],
            "all_error_responses": all_errors,
            "tfa_reg_evaluate_req": tfa_reg_eval_req.to_string(),
            "tfa_reg_evaluate_resp": tfa_reg_eval_resp.to_string(),
            "tfa_reg_finalize_req": tfa_reg_fin_req.to_string(),
            "tfa_reg_finalize_resp": tfa_reg_fin_resp.to_string(),
            "tfa_auth_evaluate_req": tfa_auth_eval_req.to_string(),
            "tfa_auth_evaluate_resp": tfa_auth_eval_resp.to_string(),
            "tfa_auth_finalize_req": tfa_auth_fin_req.to_string(),
            "tfa_auth_finalize_resp": tfa_auth_fin_resp.to_string(),
            "tfa_change_evaluate_req": tfa_chg_eval_req.to_string(),
            "tfa_change_finalize_req": tfa_chg_fin_req.to_string(),
            "mode_constraints": mode_constraints,
        },
        "hsm_service_types": {
            "ec_keygen_request": keygen_req,
            "ec_keygen_response": keygen_resp.to_string(),
            "ecdsa_request": ecdsa_req,
            "ecdsa_response_hex": ecdsa_resp_hex,
            "ecdh_request": ecdh_req,
            "ecdh_response_hex": ecdh_resp_hex,
            "list_keys_request": list_req,
            "list_keys_response": list_resp.to_string(),
        },
        "eudiw_service_types": {
            "wka_request": wka_req.to_string(),
            "wka_response": wka_resp.to_string(),
            "wia_request": wia_req.to_string(),
            "wia_response": wia_resp.to_string(),
        }
    });

    let out = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::create_dir_all("testdata").unwrap();
    std::fs::write("testdata/vectors_rust.json", &out).unwrap();
    eprintln!("wrote {} bytes to testdata/vectors_rust.json", out.len());
}
