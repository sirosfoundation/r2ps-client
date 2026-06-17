pub mod client;
pub mod error;
pub mod eudiw;
pub mod fido2;
pub mod jwe;
pub mod jws;
pub mod pake;
pub mod raw_sign;
pub mod types;

pub use client::{R2psClient, Transport};
pub use error::{R2psError, Result};
pub use eudiw::{
    CnfClaim, EudiwAttestationRequest, EudiwRevokeRequest, EudiwRevokeResponse,
    EudiwSuspendRequest, EudiwSuspendResponse, EudiwWiaResponse, EudiwWkaResponse, StatusListRef,
    StatusListStatus, StatusObject, WiaPayload, WkaPayload,
};
pub use fido2::{
    AssertionResult, Fido2Ceremony, Fido2ChallengeResponse, Fido2FinalizeResponse,
    RegistrationResult,
};
pub use pake::PakeClient;
pub use raw_sign::{
    HsmEcKeygenRequest, HsmEcKeygenResponse, HsmEcdhRequest, HsmEcdsaRequest, HsmKeyInfo,
    HsmListKeysRequest, HsmListKeysResponse, R2psRawSign, RawSign,
};
