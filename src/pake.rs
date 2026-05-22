use crate::error::Result;

/// PAKE client trait for pluggable OPAQUE implementations.
///
/// The wire format of `req`/`resp` bytes must be compatible with the R2PS
/// server's OPAQUE implementation (bytemare/opaque, RFC 9807).
///
/// # Registration flow
/// 1. `registration_init(password)` → `req` bytes (RegistrationRequest)
/// 2. Server returns `resp` bytes (RegistrationResponse)
/// 3. `registration_finalize(resp)` → `req` bytes (RegistrationRecord)
///
/// # Authentication flow
/// 1. `auth_init(password)` → `req` bytes (KE1)
/// 2. Server returns `resp` bytes (KE2)
/// 3. `auth_finalize(resp)` → `(req, session_key)` — KE3 + negotiated key
pub trait PakeClient {
    /// Start registration: returns serialized RegistrationRequest.
    fn registration_init(&mut self, password: &[u8]) -> Result<Vec<u8>>;

    /// Finalize registration: consumes RegistrationResponse, returns RegistrationRecord.
    fn registration_finalize(&mut self, server_resp: &[u8]) -> Result<Vec<u8>>;

    /// Start authentication: returns serialized KE1.
    fn auth_init(&mut self, password: &[u8]) -> Result<Vec<u8>>;

    /// Finalize authentication: consumes KE2, returns (KE3, session_key).
    fn auth_finalize(&mut self, server_resp: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
}
