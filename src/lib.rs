use crate::client::StatusResponse;

use std::result;

use err_derive::Error;

pub mod client;
pub mod model;

const DEFAULT_HOST: &'static str = "https://api.tarkov-database.com";
const ENDPOINT_VERSION: &'static str = "/v2";

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "API error: {}", _0)]
    APIError(StatusResponse),
    #[error(display = "Client request error: {}", _0)]
    RequestError(#[error(source)] awc::error::SendRequestError),
    #[error(display = "JSON parsing error: {}", _0)]
    JSONError(#[error(source)] awc::error::JsonPayloadError),
    #[cfg(feature = "openssl")]
    #[error(display = "OpenSSL error: {}", _0)]
    OpenSSLError(#[error(source)] open_ssl::error::ErrorStack),
}

pub type Result<T> = result::Result<T, Error>;
