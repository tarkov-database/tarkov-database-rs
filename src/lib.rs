use crate::client::StatusResponse;

use std::result;

use thiserror::Error;

pub mod client;
pub mod model;

const DEFAULT_HOST: &str = "https://api.tarkov-database.com";
const ENDPOINT_VERSION: &str = "/v2";

#[derive(Debug, Error)]
pub enum Error {
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

pub type Result<T> = result::Result<T, Error>;
