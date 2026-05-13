// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use std::{path::Path, sync::Mutex};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

pub struct MessageStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundState {
    Sending,
    Sent,
    Delivered,
    Failed,
}

impl OutboundState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }
}

impl MessageStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create store dir at {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open SQLite store at {}", path.display()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER NOT NULL
             );
             INSERT INTO schema_version (version)
                 SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
             CREATE TABLE IF NOT EXISTS received_messages (
                 group_id TEXT NOT NULL,
                 msg_id   TEXT NOT NULL,
                 seq      INTEGER,
                 ts_ms    INTEGER NOT NULL,
                 sender_role TEXT,
                 PRIMARY KEY (group_id, msg_id)
             );
             CREATE INDEX IF NOT EXISTS idx_received_seq
                 ON received_messages(group_id, seq);
             CREATE TABLE IF NOT EXISTS seq_watermark (
                 group_id  TEXT NOT NULL,
                 device_id TEXT NOT NULL,
                 last_acked_seq INTEGER NOT NULL,
                 PRIMARY KEY (group_id, device_id)
             );
             CREATE TABLE IF NOT EXISTS outbound_messages (
                 group_id TEXT NOT NULL,
                 msg_id   TEXT NOT NULL,
                 state    TEXT NOT NULL,
                 ts_ms    INTEGER NOT NULL,
                 PRIMARY KEY (group_id, msg_id)
             );",
        )
        .context("failed to run store migration")?;
        Ok(())
    }

    pub fn last_acked_seq(&self, group_id: &str, device_id: &str) -> Result<u64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let value: Option<i64> = conn
            .query_row(
                "SELECT last_acked_seq FROM seq_watermark
                  WHERE group_id = ?1 AND device_id = ?2",
                params![group_id, device_id],
                |row| row.get(0),
            )
            .optional()
            .context("failed to query last_acked_seq")?;
        Ok(value.unwrap_or(0).max(0) as u64)
    }

    pub fn set_last_acked_seq(
        &self,
        group_id: &str,
        device_id: &str,
        last_acked_seq: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO seq_watermark (group_id, device_id, last_acked_seq)
              VALUES (?1, ?2, ?3)
              ON CONFLICT(group_id, device_id) DO UPDATE SET
                last_acked_seq = MAX(last_acked_seq, excluded.last_acked_seq)",
            params![group_id, device_id, last_acked_seq as i64],
        )
        .context("failed to update last_acked_seq")?;
        Ok(())
    }

    /// Returns true if the message was newly inserted, false if it was a duplicate `msg_id`.
    pub fn try_persist_received(
        &self,
        group_id: &str,
        msg_id: &str,
        seq: Option<u64>,
        ts_ms: i64,
        sender_role: Option<&str>,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let rows = conn
            .execute(
                "INSERT OR IGNORE INTO received_messages
                    (group_id, msg_id, seq, ts_ms, sender_role)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![group_id, msg_id, seq.map(|v| v as i64), ts_ms, sender_role],
            )
            .context("failed to persist received message")?;
        Ok(rows > 0)
    }

    pub fn record_outbound(&self, group_id: &str, msg_id: &str, ts_ms: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO outbound_messages
                (group_id, msg_id, state, ts_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, msg_id, OutboundState::Sending.as_str(), ts_ms],
        )
        .context("failed to record outbound message")?;
        Ok(())
    }

    pub fn set_outbound_state(
        &self,
        group_id: &str,
        msg_id: &str,
        state: OutboundState,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE outbound_messages SET state = ?3
              WHERE group_id = ?1 AND msg_id = ?2",
            params![group_id, msg_id, state.as_str()],
        )
        .context("failed to update outbound state")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_in_memory() -> MessageStore {
        let conn = Connection::open_in_memory().unwrap();
        let store = MessageStore {
            conn: Mutex::new(conn),
        };
        store.migrate().unwrap();
        store
    }

    #[test]
    fn watermark_round_trip() {
        let store = open_in_memory();
        assert_eq!(store.last_acked_seq("g", "d").unwrap(), 0);
        store.set_last_acked_seq("g", "d", 42).unwrap();
        assert_eq!(store.last_acked_seq("g", "d").unwrap(), 42);
        // monotonic: a lower value should not regress
        store.set_last_acked_seq("g", "d", 10).unwrap();
        assert_eq!(store.last_acked_seq("g", "d").unwrap(), 42);
    }

    #[test]
    fn dedupes_received_messages() {
        let store = open_in_memory();
        assert!(
            store
                .try_persist_received("g", "m-1", Some(1), 100, Some("plugin"))
                .unwrap()
        );
        assert!(
            !store
                .try_persist_received("g", "m-1", Some(1), 200, Some("plugin"))
                .unwrap()
        );
    }

    #[test]
    fn outbound_state_transitions() {
        let store = open_in_memory();
        store.record_outbound("g", "m-out", 100).unwrap();
        store
            .set_outbound_state("g", "m-out", OutboundState::Sent)
            .unwrap();
        store
            .set_outbound_state("g", "m-out", OutboundState::Delivered)
            .unwrap();
    }
}
