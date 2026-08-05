//! Cross-language interop check for [`OpaqueClient`] against a real
//! `go-r2ps-service` OPAQUE server (`bytemare/opaque`). `#[ignore]`d by
//! default (no CI job here can run a second-language server), but kept as
//! a real, repeatable manual check - a future change to the ciphersuite or
//! `opaque-ke` version bump should be re-verified against it.
//!
//! Exchanges hex-encoded OPAQUE protocol messages via files in
//! `/tmp/opaque-interop` with a concurrently-running Go test against a
//! real `go-r2ps-service` OPAQUE server, polling for each file since the
//! two processes run in parallel with no other synchronization. The
//! Go-side counterpart lives outside this repo (`go-r2ps-service` is a
//! separate service repo) and isn't checked in anywhere as of writing -
//! it's a small `internal/pake` test that reads/writes the same six
//! `NN_*.hex` files this test does, driving `OPAQUEServer.RegistrationResponse`/
//! `AuthEvaluate`/`AuthFinalize`. To run both sides:
//! ```sh
//! mkdir -p /tmp/opaque-interop
//! (cd ../go-r2ps-service && go test ./internal/pake/ -run TestOpaqueInteropSmoke -v) &
//! cargo test --test opaque_interop_smoke -- --ignored --nocapture
//! ```

use r2ps_client::{OpaqueClient, PakeClient};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const INTEROP_DIR: &str = "/tmp/opaque-interop";
const PASSWORD: &[u8] = b"interop-test-password-12345";

fn wait_for_hex(name: &str) -> Vec<u8> {
    let path = format!("{INTEROP_DIR}/{name}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = fs::read_to_string(&path) {
            return hex::decode(s.trim()).unwrap_or_else(|e| panic!("decode hex {path}: {e}"));
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {path}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn write_hex(name: &str, data: &[u8]) {
    let path = format!("{INTEROP_DIR}/{name}");
    fs::write(&path, hex::encode(data)).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

#[test]
#[ignore = "manual cross-language interop smoke test against a live go-r2ps-service OPAQUE server"]
fn opaque_registration_and_auth_round_trip() {
    assert!(
        Path::new(INTEROP_DIR).exists(),
        "interop dir not set up: {INTEROP_DIR}"
    );
    let mut client = OpaqueClient::new();

    // --- Registration ---
    let reg_req = client
        .registration_init(PASSWORD)
        .expect("registration_init");
    write_hex("01_reg_req.hex", &reg_req);

    let reg_resp = wait_for_hex("02_reg_resp.hex");
    let reg_record = client
        .registration_finalize(&reg_resp)
        .expect("registration_finalize");
    write_hex("03_reg_record.hex", &reg_record);

    // --- Authentication ---
    let ke1 = client.auth_init(PASSWORD).expect("auth_init");
    write_hex("04_ke1.hex", &ke1);

    let ke2 = wait_for_hex("05_ke2.hex");
    let (ke3, session_key) = client.auth_finalize(&ke2).expect("auth_finalize");
    write_hex("06_ke3.hex", &ke3);
    write_hex("07_rust_session_key.hex", &session_key);

    println!(
        "Rust side complete. session_key = {} ({} bytes)",
        hex::encode(&session_key),
        session_key.len()
    );
}
