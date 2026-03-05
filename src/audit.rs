use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::VecDeque;

const MAX_LOG_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub details: String,
    pub user_id: String,
}

pub struct AuditLogger {
    entries: VecDeque<AuditEntry>,
    total_requests: u64,
    blocked_requests: u64,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            total_requests: 0,
            blocked_requests: 0,
        }
    }

    pub fn log(&mut self, event_type: &str, details: &str, user_id: &str) {
        self.total_requests += 1;
        if event_type.contains("BLOCKED") || event_type.contains("VIOLATION") || event_type.contains("RATE_LIMIT") {
            self.blocked_requests += 1;
        }

        let entry = AuditEntry {
            id: format!("gr_{}", uuid::Uuid::new_v4()),
            event_type: event_type.into(),
            timestamp: Utc::now(),
            details: details.into(),
            user_id: user_id.into(),
        };

        self.entries.push_back(entry);
        if self.entries.len() > MAX_LOG_ENTRIES {
            self.entries.pop_front();
        }
    }

    pub fn get_logs(&self, event_type: Option<&str>, limit: usize) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|e| event_type.map_or(true, |t| e.event_type == t))
            .take(limit)
            .collect()
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn blocked_requests(&self) -> u64 {
        self.blocked_requests
    }
}
