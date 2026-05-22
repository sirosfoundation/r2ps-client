use thiserror::Error;

#[derive(Debug, Error)]
pub enum R2psError {
    #[error("JWS error: {0}")]
    Jws(String),

    #[error("JWE error: {0}")]
    Jwe(String),

    #[error("PAKE error: {0}")]
    Pake(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("server error ({code}): {message}")]
    Server { code: String, message: String },

    #[error("not authenticated")]
    NotAuthenticated,

    #[error("base64 decode: {0}")]
    Base64(String),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, R2psError>;
