pub mod ammunition;
pub mod armor;
pub mod common;

use crate::{
    client::{Client, PathAndQuery},
    Result,
};

use self::common::Item;

use std::collections::HashMap;

use chrono::{serde::ts_seconds, DateTime, Utc};
use serde::Deserialize;

const ENDPOINT_ITEM: &str = "item";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemIndex {
    pub total: i64,
    #[serde(with = "ts_seconds")]
    pub modified: DateTime<Utc>,
    pub kinds: HashMap<String, KindProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindProperties {
    pub count: i64,
    #[serde(with = "ts_seconds")]
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemResult {
    pub total: i64,
    pub items: Vec<Item>,
}

impl Client {
    pub async fn get_item_index(&self) -> Result<ItemIndex> {
        let path = PathAndQuery::new(ENDPOINT_ITEM.to_string());

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_items_by_kind(
        &self,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> Result<ItemResult> {
        let mut path = PathAndQuery::new(format!("{}/{}", ENDPOINT_ITEM, kind));
        path.add_query_pair("limit", limit);
        path.add_query_pair("offset", offset);

        let resp = self.get_json(path).await?;

        Ok(resp)
    }

    pub async fn get_items_all(&self) -> Result<Vec<Item>> {
        let index = self.get_item_index().await?;

        let limit = Self::MAX_PAGE_LIMIT;

        let mut items: Vec<Item> = Vec::with_capacity(index.total as usize);
        for (k, p) in index.kinds.into_iter() {
            let pages = if (p.count % limit) != 0 {
                (p.count / limit) + 1
            } else {
                p.count / limit
            };
            for i in 0..=(pages - 1) {
                let offset = i * limit;
                items.append(&mut self.get_items_by_kind(&k, limit, offset).await?.items);
            }
        }

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_TOKEN: Option<&str> = option_env!("TEST_API_TOKEN");

    #[tokio::test]
    async fn get_index() {
        let mut client = Client::new(API_TOKEN.unwrap()).unwrap();

        if !client.token_is_valid().await {
            client.refresh_token().await.unwrap();
        }

        client.get_item_index().await.unwrap();
    }
}
