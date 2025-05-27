use chrono::{TimeZone, Utc};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct TimelineEvent {
    pub ts: String,
    pub tx_seq: u32,
    pub action: String,
    pub target: String,
    pub details: HashMap<&'static str, String>,
}

impl TimelineEvent {
    pub fn new(tx: u32, sec: u64, nsec: u32, action: &str, target: String) -> Self {
        Self {
            ts: Utc
                .timestamp_opt(sec as i64, nsec)
                .single()
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            tx_seq: tx,
            action: action.to_owned(),
            target,
            details: HashMap::new(),
        }
    }
}
