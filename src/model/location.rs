use crate::{client::Client, Result};

use awc::http::uri::PathAndQuery;
use chrono::{serde::ts_seconds, DateTime, Utc};
use serde::Deserialize;

const ENDPOINT_LOCATION: &str = "/location";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationResult {
    pub total: i64,
    pub items: Vec<Location>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub description: String,
    pub min_players: i64,
    pub max_players: i64,
    pub escape_time: i64,
    pub insurance: bool,
    pub available: bool,
    pub exits: Vec<Exit>,
    pub bosses: Vec<Boss>,
    #[serde(with = "ts_seconds", rename = "_modified")]
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exit {
    pub name: String,
    pub description: String,
    pub chance: f64,
    pub min_time: i64,
    pub max_time: i64,
    pub exfil_time: i64,
    pub requirement: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Boss {
    pub name: String,
    pub description: String,
    pub chance: f64,
    pub followers: i64,
}

impl Client {
    pub async fn get_locations_all(&self, limit: i64, offset: i64) -> Result<LocationResult> {
        let path: PathAndQuery = format!("{}?limit={}&offset={}", ENDPOINT_LOCATION, limit, offset)
            .parse()
            .unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_locations_by_availability(&self, email: &str) -> Result<LocationResult> {
        let path: PathAndQuery = format!("{}?available={}", ENDPOINT_LOCATION, email)
            .parse()
            .unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_location_by_id(&self, id: &str) -> Result<Location> {
        let path: PathAndQuery = format!("{}/{}", ENDPOINT_LOCATION, id).parse().unwrap();

        let resp = self.get_json(path).await?;

        Ok(resp)
    }
}
