use crate::{Error, Result, DEFAULT_HOST, ENDPOINT_VERSION};

use std::fmt;

use awc::{
    http::{
        header::{ContentType, USER_AGENT},
        Method, PathAndQuery,
    },
    Client as ActixClient, ClientBuilder,
};
use chrono::{serde::ts_seconds, DateTime, Utc};
use jsonwebtoken::dangerous_insecure_decode;
use serde::{de::DeserializeOwned, Deserialize};

const USER_AGENT_VALUE: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

const RESPONSE_BODY_LIMIT: usize = 1024_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    status: String,
    message: String,
    code: u16,
}

impl fmt::Display for StatusResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.code, self.status, self.message)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct TokenClaims {
    aud: String,
    #[serde(with = "ts_seconds")]
    exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    iat: DateTime<Utc>,
    iss: String,
    sub: String,
    scope: Vec<String>,
}

pub struct Client {
    host: String,
    token: String,
    client: ActixClient,
}

impl Client {
    pub(crate) const MAX_PAGE_LIMIT: i64 = 100;

    /// Create a new HTTP client
    pub fn new(token: &str) -> Self {
        let client = ClientBuilder::default()
            .header(USER_AGENT, USER_AGENT_VALUE)
            .bearer_auth(token)
            .finish();

        let host = format!("{}{}", DEFAULT_HOST, ENDPOINT_VERSION);

        Self {
            host,
            token: token.to_string(),
            client,
        }
    }

    /// Create a new HTTP client
    pub fn with_host(token: &str, host: &str) -> Self {
        let client = ClientBuilder::default()
            .header(USER_AGENT, USER_AGENT_VALUE)
            .bearer_auth(token)
            .finish();

        let host = format!("{}{}", host, ENDPOINT_VERSION);

        Self {
            host,
            token: token.to_string(),
            client,
        }
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(&self, path: PathAndQuery) -> Result<T> {
        let req = self
            .client
            .request(Method::GET, format!("{}{}", self.host, path))
            .bearer_auth(&self.token)
            .set(ContentType::json());

        let mut res = req.send().await?;

        if !res.status().is_success() {
            let sr: StatusResponse = res.json().await?;
            return Err(Error::APIError(sr));
        }

        let data = res.json().limit(RESPONSE_BODY_LIMIT).await?;

        Ok(data)
    }

    /// Validate set token
    pub fn token_is_valid(&self) -> bool {
        let claims = match dangerous_insecure_decode::<TokenClaims>(&self.token) {
            Ok(d) => d.claims,
            Err(_) => return false,
        };

        let now = Utc::now();

        if now.ge(&claims.exp) {
            return false;
        }

        true
    }

    /// Refresh authentication token
    pub async fn refresh_token(&mut self) -> Result<()> {
        let resp: TokenResponse = self.get_json("token".parse().unwrap()).await?;

        self.token = resp.token;

        Ok(())
    }
}
