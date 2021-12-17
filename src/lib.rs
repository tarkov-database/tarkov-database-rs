pub mod client;
pub mod model;

use crate::client::StatusResponse;

use std::result;

use reqwest::StatusCode;
use thiserror::Error;

const DEFAULT_ORIGIN: &str = "https://api.tarkov-database.com";
const ENDPOINT_VERSION: &str = "v2";

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Resource(s) not found")]
    ResourceNotFound,
    #[error("Authorization error: {0}")]
    Authorization(String),
    #[error("API error: {0}")]
    ApiError(StatusResponse),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("reqwest error: {0}")]
    Client(#[from] reqwest::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("client tls error: {0}")]
    ClientTls(#[from] client::ClientTlsError),
}

impl From<StatusResponse> for Error {
    fn from(s: StatusResponse) -> Self {
        match StatusCode::from_u16(s.code).unwrap() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Self::Authorization(s.message),
            StatusCode::NOT_FOUND => Self::ResourceNotFound,
            _ => Self::ApiError(s),
        }
    }
}
