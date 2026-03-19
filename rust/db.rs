use std::sync::{Arc, Mutex};

use anyhow::Context;
use rusqlite::Connection;

pub type Database = Arc<Mutex<Connection>>;

pub async fn connect(database_url: &str) -> anyhow::Result<Database> {
    let path = database_url.strip_prefix("sqlite:").unwrap_or(database_url);
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database at {path}"))?;
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            "#,
        )
        .with_context(|| "failed to initialize sqlite pragmas")?;
    connection
        .execute_batch(include_str!("../migrations/20260319000000_init.sql"))
        .with_context(|| "failed to run sqlite schema migration")?;
    Ok(Arc::new(Mutex::new(connection)))
}
