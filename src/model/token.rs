use crate::{
    client::{Client, PathAndQuery},
    Result,
};

use chrono::{serde::ts_seconds, DateTime, Utc};
use jsonwebtoken::dangerous_insecure_decode;
use serde::Deserialize;

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
        let claims = match dangerous_insecure_decode::<TokenClaims>(token) {
            Ok(d) => d.claims,
            Err(_) => return false,
        };

        let now = Utc::now();

        if now.ge(&claims.exp) {
            return false;
        }

        true
    }
}
