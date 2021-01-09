use crate::client::StatusResponse;

use std::result;

use awc::http::StatusCode;
use thiserror::Error;

pub mod client;
pub mod model;

const DEFAULT_HOST: &str = "https://api.tarkov-database.com";
const ENDPOINT_VERSION: &str = "/v2";

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Resource(s) not found")]
    ResourceNotFound,
    #[error("Authorization error: {0}")]
    Authorization(String),
    #[error("API error: {0}")]
    APIError(StatusResponse),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Client request error: {0}")]
    RequestError(#[from] awc::error::SendRequestError),
    #[error("JSON parsing error: {0}")]
    JSONError(#[from] awc::error::JsonPayloadError),
    #[cfg(feature = "openssl")]
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] open_ssl::error::ErrorStack),
    #[cfg(feature = "rustls")]
    #[error("Rustls error: {0}")]
    RustlsError(#[from] rust_tls::TLSError),
}

impl From<StatusResponse> for Error {
    fn from(s: StatusResponse) -> Self {
        match StatusCode::from_u16(s.code).unwrap() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Self::Authorization(s.message),
            StatusCode::NOT_FOUND => Self::ResourceNotFound,
            _ => Self::APIError(s),
        }
    }
}
