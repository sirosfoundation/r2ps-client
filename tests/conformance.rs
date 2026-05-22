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
    pake_request: String,
    #[allow(dead_code)]
    pake_response: String,
    error_response: String,
    #[serde(default)]
    request_response_pairs: Option<Vec<RequestResponsePair>>,
    #[serde(default)]
    all_error_responses: Option<Vec<NamedJSON>>,
    #[serde(default)]
    pake_reg_evaluate_req: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pake_reg_evaluate_resp: Option<String>,
    #[serde(default)]
    pake_reg_finalize_req: Option<String>,
    #[serde(default)]
    pake_reg_finalize_resp: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pake_auth_evaluate_req: Option<String>,
    #[serde(default)]
    pake_auth_evaluate_resp: Option<String>,
    #[serde(default)]
    pake_auth_finalize_req: Option<String>,
    #[serde(default)]
    pake_auth_finalize_resp: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pake_pinchange_evaluate_req: Option<String>,
    #[serde(default)]
    pake_pinchange_finalize_req: Option<String>,
    #[serde(default)]
    enc_mode_constraints: Option<Vec<EncModeConstraint>>,
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
struct EncModeConstraint {
    #[serde(rename = "type")]
    service_type: String,
    required_enc: String,
    request_json: String,
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
// Layer 2: Protocol type field conformance (R2PS spec §3)
// ============================================================

#[test]
fn protocol_service_request_fields() {
    for (name, v) in vector_files() {
        let raw: serde_json::Value =
            serde_json::from_str(&v.protocol_types.service_request).unwrap();
        let obj = raw.as_object().unwrap();
        // Required fields per spec §3.1.1 + §3.1.2
        for field in &[
            "ver",
            "nonce",
            "iat",
            "enc",
            "data",
            "client_id",
            "kid",
            "context",
            "type",
        ] {
            assert!(
                obj.contains_key(*field),
                "[{name}] missing required field '{field}' in service_request"
            );
        }
        assert_eq!(obj["ver"], "1.0", "[{name}] ver must be 1.0");
        let enc = obj["enc"].as_str().unwrap();
        assert!(
            enc == "device" || enc == "user",
            "[{name}] enc must be 'device' or 'user', got '{enc}'"
        );
    }
}

#[test]
fn protocol_service_response_no_request_fields() {
    for (name, v) in vector_files() {
        let raw: serde_json::Value =
            serde_json::from_str(&v.protocol_types.service_response).unwrap();
        let obj = raw.as_object().unwrap();
        // Response MUST NOT contain request-only fields (spec §3.1.3)
        for field in &["client_id", "kid", "context", "type", "pake_session_id"] {
            assert!(
                !obj.contains_key(*field),
                "[{name}] service_response MUST NOT contain '{field}' (spec §3.1.3)"
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
// Layer 3: HSM service type conformance
// (spec: security/remote-hsm-apake-service-types.md)
// ============================================================

#[test]
fn hsm_keygen_request_spec_fields() {
    for (name, v) in vector_files() {
        // Must deserialize into spec type
        let _req: HsmEcKeygenRequest = serde_json::from_str(&v.hsm_service_types.ec_keygen_request)
            .unwrap_or_else(|e| panic!("[{name}] keygen request: {e}"));
        // Verify only 'curve' field present (spec §1.2)
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
            "[{name}] missing 'created_key' (spec §1.2)"
        );
        // Must NOT contain non-spec Go fields
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
        assert!(
            obj.contains_key("tbs_hash"),
            "[{name}] missing 'tbs_hash' (spec §3.2)"
        );
        assert!(
            !obj.contains_key("hash"),
            "[{name}] non-spec field 'hash' — spec §3.2 requires 'tbs_hash'"
        );
    }
}

#[test]
fn hsm_ecdsa_response_raw_der() {
    for (name, v) in vector_files() {
        // Spec §3.2: response is raw DER bytes
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
            "[{name}] missing 'public_key' (spec §4.2)"
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
        assert!(
            obj.contains_key("curve"),
            "[{name}] missing 'curve' (spec §2.2)"
        );
        assert!(
            !obj.contains_key("curves"),
            "[{name}] non-spec field 'curves' — spec §2.2 uses 'curve'"
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
        assert!(
            obj.contains_key("key_info"),
            "[{name}] missing 'key_info' (spec §2.2)"
        );
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
// Extended Protocol Conformance (rp2s-peter.md)
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
                    "[{name}/{}] nonce must echo (spec §3.1.3)",
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
                for field in &["client_id", "kid", "context", "type", "pake_session_id"] {
                    assert!(
                        !obj.contains_key(*field),
                        "[{name}/{}] response contains request-only field '{}' (spec §3.1.3)",
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
fn pake_registration_flow() {
    for (name, v) in vector_files() {
        if let Some(ref req_json) = v.protocol_types.pake_reg_evaluate_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            assert_eq!(req["protocol"], "opaque", "[{name}] reg evaluate protocol");
            assert_eq!(req["state"], "evaluate", "[{name}] reg evaluate state");
            assert!(
                req["req"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] req empty"
            );
        }
        if let Some(ref req_json) = v.protocol_types.pake_reg_finalize_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            assert_eq!(req["state"], "finalize", "[{name}] reg finalize state");
            // Authorization MUST be present for initial registration (§3.3.3.1)
            assert!(
                req["authorization"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] authorization must be present for initial PIN registration (spec §3.3.3.1)"
            );
        }
        if let Some(ref resp_json) = v.protocol_types.pake_reg_finalize_resp {
            let resp: serde_json::Value = serde_json::from_str(resp_json).unwrap();
            assert_eq!(resp["msg"], "OK", "[{name}] reg finalize msg");
        }
    }
}

#[test]
fn pake_authentication_flow() {
    for (name, v) in vector_files() {
        if let Some(ref resp_json) = v.protocol_types.pake_auth_evaluate_resp {
            let resp: serde_json::Value = serde_json::from_str(resp_json).unwrap();
            assert!(
                resp["pake_session_id"]
                    .as_str()
                    .map_or(false, |s| !s.is_empty()),
                "[{name}] auth evaluate pake_session_id must be present (§3.3.3.2)"
            );
        }
        if let Some(ref req_json) = v.protocol_types.pake_auth_finalize_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            assert!(
                req["task"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] auth finalize task must be present (§3.3.3.2)"
            );
            assert!(
                req["session_duration"].as_i64().map_or(false, |v| v > 0),
                "[{name}] auth finalize session_duration must be present (§3.3.3.2)"
            );
        }
        if let Some(ref resp_json) = v.protocol_types.pake_auth_finalize_resp {
            let resp: serde_json::Value = serde_json::from_str(resp_json).unwrap();
            assert!(resp["pake_session_id"]
                .as_str()
                .map_or(false, |s| !s.is_empty()));
            assert!(resp["task"].as_str().map_or(false, |s| !s.is_empty()));
            assert!(resp["session_expiration_time"]
                .as_i64()
                .map_or(false, |v| v > 0));
            assert_eq!(resp["msg"], "OK");
        }
    }
}

#[test]
fn pake_pin_change_no_authorization() {
    for (name, v) in vector_files() {
        if let Some(ref req_json) = v.protocol_types.pake_pinchange_finalize_req {
            let req: serde_json::Value = serde_json::from_str(req_json).unwrap();
            // Authorization MUST NOT be present for PIN change (§3.3.3.3)
            assert!(
                req.get("authorization")
                    .map_or(true, |v| v.is_null() || v.as_str() == Some("")),
                "[{name}] authorization must NOT be present for PIN change (spec §3.3.3.3)"
            );
        }
    }
}

#[test]
fn enc_mode_constraints() {
    for (name, v) in vector_files() {
        if let Some(ref constraints) = v.protocol_types.enc_mode_constraints {
            for c in constraints {
                let req: serde_json::Value = serde_json::from_str(&c.request_json).unwrap();
                let enc = req["enc"].as_str().unwrap();
                assert_eq!(
                    enc, c.required_enc,
                    "[{name}] enc={enc} for type {}, spec requires {}",
                    c.service_type, c.required_enc
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
// (spec: security/r2ps-service-types-eudiw.md)
// ============================================================

#[test]
fn eudiw_wka_request_fields() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wka_request).unwrap();
            let obj = raw.as_object().unwrap();
            assert!(
                obj.contains_key("keys_to_attest"),
                "[{name}] missing keys_to_attest (EUDIW §1.1)"
            );
            assert!(obj.contains_key("ver"), "[{name}] missing ver (EUDIW §1.1)");
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
                raw["attestation"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] attestation must not be empty (EUDIW §1.1)"
            );
        }
    }
}

#[test]
fn eudiw_wia_request_only_ver() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wia_request).unwrap();
            let obj = raw.as_object().unwrap();
            assert!(obj.contains_key("ver"), "[{name}] missing ver (EUDIW §2.1)");
            // WIA request has only 'ver'
            for key in obj.keys() {
                assert_eq!(
                    key, "ver",
                    "[{name}] unexpected field '{key}' — EUDIW §2.1 defines only 'ver'"
                );
            }
        }
    }
}

#[test]
fn eudiw_wia_response_fields() {
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let raw: serde_json::Value = serde_json::from_str(&eudiw.wia_response).unwrap();
            assert!(
                raw["attestation"].as_str().map_or(false, |s| !s.is_empty()),
                "[{name}] attestation must not be empty (EUDIW §2.1)"
            );
        }
    }
}

#[test]
fn eudiw_version_identifier() {
    let valid_versions = ["d008"]; // ETSI TS 119 476-3 V0.0.8
    for (name, v) in vector_files() {
        if let Some(ref eudiw) = v.eudiw_service_types {
            let wka_req: serde_json::Value = serde_json::from_str(&eudiw.wka_request).unwrap();
            let ver = wka_req["ver"].as_str().unwrap();
            assert!(
                valid_versions.contains(&ver),
                "[{name}] WKA ver={ver} not in defined versions (EUDIW §3)"
            );

            let wia_req: serde_json::Value = serde_json::from_str(&eudiw.wia_request).unwrap();
            let ver = wia_req["ver"].as_str().unwrap();
            assert!(
                valid_versions.contains(&ver),
                "[{name}] WIA ver={ver} not in defined versions (EUDIW §3)"
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

    // JWS
    let payload = b"hello interop";
    let kid = "conformance-kid-1";
    let typ = "r2ps-request+json";
    let jws_compact = sign_jws(payload, &signing_key, Some(kid), Some(typ)).unwrap();

    // JWE ECDH
    let ecdh_plain = b"ecdh secret payload";
    let jwe_ecdh = encrypt_jwe(ecdh_plain, &public_key).unwrap();

    // JWE Symmetric
    let sym_plain = b"symmetric secret payload";
    let jwe_sym = encrypt_jwe_symmetric(sym_plain, &sym_key).unwrap();

    // Protocol types (minimal but spec-compliant)
    let svc_req = serde_json::json!({
        "ver": "1.0",
        "nonce": "dGVzdG5vbmNl",
        "iat": 1716400000,
        "enc": "device",
        "data": "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9...",
        "client_id": "test-client",
        "kid": "key-1",
        "context": "signing",
        "type": "hsm_ecdsa",
        "pake_session_id": "session-abc"
    });
    let svc_resp = serde_json::json!({
        "ver": "1.0",
        "nonce": "cmVzcG5vbmNl",
        "iat": 1716400001,
        "enc": "user",
        "data": "eyJhbGciOiJkaXIifQ..."
    });
    let pake_req = serde_json::json!({
        "protocol": "opaque",
        "state": "evaluate",
        "task": "sign",
        "req": "b3BhcXVlLXJlcXVlc3Q"
    });
    let pake_resp = serde_json::json!({
        "pake_session_id": "sess-123",
        "resp": "b3BhcXVlLXJlc3BvbnNl",
        "task": "sign",
        "session_expiration_time": 1716403600
    });
    let err_resp = serde_json::json!({
        "error_code": "UNAUTHORIZED",
        "error_message": "invalid credentials"
    });

    // HSM service types (spec-compliant)
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
            "pake_request": pake_req.to_string(),
            "pake_response": pake_resp.to_string(),
            "error_response": err_resp.to_string(),
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
        }
    });

    let out = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::create_dir_all("testdata").unwrap();
    std::fs::write("testdata/vectors_rust.json", &out).unwrap();
    eprintln!("wrote {} bytes to testdata/vectors_rust.json", out.len());
}
