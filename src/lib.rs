use crate::client::StatusResponse;

use std::result;

use thiserror::Error;

pub mod client;
pub mod model;

const DEFAULT_HOST: &'static str = "https://api.tarkov-database.com";
const ENDPOINT_VERSION: &'static str = "/v2";

#[derive(Debug, Error)]
pub enum Error {
    #[error("API error: {0}")]
    APIError(StatusResponse),
    #[error("Client request error: {0}")]
    RequestError(#[from] awc::error::SendRequestError),
    #[error("JSON parsing error: {0}")]
    JSONError(#[from] awc::error::JsonPayloadError),
    #[cfg(feature = "openssl")]
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] open_ssl::error::ErrorStack),
}

pub type Result<T> = result::Result<T, Error>;
