use chrono::{serde::ts_seconds, DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub short_name: String,
    pub description: String,
    pub price: i64,
    pub weight: f64,
    pub max_stack: i64,
    pub rarity: String,
    pub grid: Grid,
    #[serde(with = "ts_seconds", rename = "_modified")]
    pub modified: DateTime<Utc>,
    #[serde(rename = "_kind")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grid {
    pub color: RGBA,
    pub height: i64,
    pub width: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RGBA {
    pub r: u64,
    pub g: u64,
    pub b: u64,
    pub a: u64,
}
