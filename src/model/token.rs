use crate::{
    client::{Client, PathAndQuery},
    Error, Result,
};

use base64::URL_SAFE_NO_PAD;
use chrono::{serde::ts_seconds, DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize};

const ENDPOINT_TOKEN: &str = "token";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires: DateTime<Utc>,
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
    scope: Vec<Scope>,
}

#[derive(Debug, Deserialize)]
enum Scope {
    #[serde(rename = "read:all")]
    ReadAll,
    #[serde(rename = "write:all")]
    WriteAll,
    #[serde(rename = "read:user")]
    ReadUser,
    #[serde(rename = "write:user")]
    WriteUser,
    #[serde(rename = "read:item")]
    ReadItem,
    #[serde(rename = "write:item")]
    WriteItem,
    #[serde(rename = "read:location")]
    ReadLocation,
    #[serde(rename = "write:location")]
    WriteLocation,
    #[serde(rename = "write:token")]
    WriteToken,
}

impl Client {
    /// Refresh authentication token
    pub async fn refresh_token(&mut self) -> Result<()> {
        let path = PathAndQuery::new(ENDPOINT_TOKEN.to_string());

        let resp: TokenResponse = self.get_json(path).await?;

        let mut token = self.token.write().await;
        *token = resp.token;

        Ok(())
    }

    /// Validate set token
    pub async fn token_is_valid(&self) -> bool {
        let token = &self.token.read().await;
        let claims = match decode_token_claims::<TokenClaims>(token) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let now = Utc::now();

        if now.ge(&claims.exp) {
            return false;
        }

        true
    }
}

#[inline]
fn decode_token_claims<T: DeserializeOwned>(token: &str) -> Result<T> {
    let claims = token
        .split('.')
        .nth(1)
        .ok_or(Error::InvalidToken)
        .map(|v| base64::decode_config(v, URL_SAFE_NO_PAD))?
        .map(|v| serde_json::from_slice(&v))??;

    Ok(claims)
}
