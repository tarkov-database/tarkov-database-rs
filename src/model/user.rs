use crate::{client::Client, Result};

use awc::http::PathAndQuery;
use chrono::{serde::ts_seconds, DateTime, Utc};
use serde::Deserialize;

const ENDPOINT_USER: &str = "/user";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResult {
    pub total: i64,
    pub items: Vec<User>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(rename = "_id")]
    pub id: String,
    pub email: String,
    pub locked: bool,
    #[serde(with = "ts_seconds", rename = "_modified")]
    pub modified: DateTime<Utc>,
}

impl Client {
    pub async fn get_users_all(&self, limit: i64, offset: i64) -> Result<UserResult> {
        let path: PathAndQuery = format!("{}?limit={}&offset={}", ENDPOINT_USER, limit, offset)
            .parse()
            .unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_users_by_email(&self, email: &str) -> Result<UserResult> {
        let path: PathAndQuery = format!("{}?email={}", ENDPOINT_USER, email)
            .parse()
            .unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_users_by_locked(&self, locked: bool) -> Result<UserResult> {
        let path: PathAndQuery = format!("{}?locked={}", ENDPOINT_USER, locked)
            .parse()
            .unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<User> {
        let path: PathAndQuery = format!("{}/{}", ENDPOINT_USER, id).parse().unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }
}
