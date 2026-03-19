use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, params};

use crate::{config::AppConfig, db::Database};

#[derive(Debug, Clone)]
pub struct EntitlementRow {
    pub id: String,
    pub npub: String,
    pub platform: String,
    pub product_id: String,
    pub original_tx_id: Option<String>,
    pub purchase_token: Option<String>,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub quota_bytes: i64,
}

#[derive(Debug, Clone)]
pub struct UsageRow {
    pub npub: String,
    pub stored_bytes: i64,
    pub egress_bytes_mon: i64,
}

pub async fn ensure_user_exists(db: &Database, npub: &str) -> anyhow::Result<()> {
    ensure_user_exists_sync(db, npub)
}

fn ensure_user_exists_sync(db: &Database, npub: &str) -> anyhow::Result<()> {
    let conn = db.lock().expect("db lock poisoned");
    conn.execute(
        r#"INSERT INTO "User" ("npub") VALUES (?) ON CONFLICT("npub") DO NOTHING"#,
        params![npub],
    )
    .with_context(|| "failed to upsert user")?;
    Ok(())
}

pub async fn get_entitlement_for_npub(
    db: &Database,
    config: &AppConfig,
    npub: &str,
) -> anyhow::Result<Option<EntitlementRow>> {
    let now = Utc::now();
    let active = {
        let conn = db.lock().expect("db lock poisoned");
        conn.query_row(
            r#"
            SELECT "id", "npub", "platform", "productId", "originalTxId", "purchaseToken", "status", "expiresAt", "quotaBytes"
            FROM "Entitlement"
            WHERE "npub" = ?
              AND "status" IN ('active', 'grace')
              AND "expiresAt" > ?
            ORDER BY "expiresAt" DESC
            LIMIT 1
            "#,
            params![npub, now],
            map_entitlement,
        )
        .optional()
        .with_context(|| "failed to fetch active entitlement")?
    };

    if active.is_some() {
        return Ok(active);
    }

    if config.free_trial_enabled {
        let trial = ensure_free_trial_entitlement_sync(db, config, npub, now)?;
        if let Some(ref row) = trial
            && row.expires_at > now
            && matches!(row.status.as_str(), "active" | "grace")
        {
            return Ok(trial);
        }
    }

    {
        let conn = db.lock().expect("db lock poisoned");
        conn.query_row(
            r#"
            SELECT "id", "npub", "platform", "productId", "originalTxId", "purchaseToken", "status", "expiresAt", "quotaBytes"
            FROM "Entitlement"
            WHERE "npub" = ?
            ORDER BY "expiresAt" DESC
            LIMIT 1
            "#,
            params![npub],
            map_entitlement,
        )
        .optional()
        .with_context(|| "failed to fetch fallback entitlement")
    }
}

pub async fn get_usage(db: &Database, npub: &str) -> anyhow::Result<Option<UsageRow>> {
    let conn = db.lock().expect("db lock poisoned");
    conn.query_row(
        r#"SELECT "npub", "storedBytes", "egressBytesMon" FROM "Usage" WHERE "npub" = ?"#,
        params![npub],
        |row| {
            Ok(UsageRow {
                npub: row.get(0)?,
                stored_bytes: row.get(1)?,
                egress_bytes_mon: row.get(2)?,
            })
        },
    )
    .optional()
    .with_context(|| "failed to fetch usage")
}

pub async fn increment_usage(db: &Database, npub: &str, bytes: i64) -> anyhow::Result<()> {
    let conn = db.lock().expect("db lock poisoned");
    conn.execute(
        r#"
        INSERT INTO "Usage" ("npub", "storedBytes", "egressBytesMon", "updatedAt")
        VALUES (?, ?, 0, CURRENT_TIMESTAMP)
        ON CONFLICT("npub") DO UPDATE SET
            "storedBytes" = "Usage"."storedBytes" + excluded."storedBytes",
            "updatedAt" = CURRENT_TIMESTAMP
        "#,
        params![npub, bytes],
    )
    .with_context(|| "failed to increment usage")?;
    Ok(())
}

fn map_entitlement(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntitlementRow> {
    Ok(EntitlementRow {
        id: row.get(0)?,
        npub: row.get(1)?,
        platform: row.get(2)?,
        product_id: row.get(3)?,
        original_tx_id: row.get(4)?,
        purchase_token: row.get(5)?,
        status: row.get(6)?,
        expires_at: row.get(7)?,
        quota_bytes: row.get(8)?,
    })
}

fn plan_to_quota(product_id: &str) -> i64 {
    let value = product_id.to_lowercase();
    if value.contains("ultra") {
        500 * 1024 * 1024 * 1024
    } else if value.contains("pro") {
        200 * 1024 * 1024 * 1024
    } else {
        50 * 1024 * 1024 * 1024
    }
}

fn ensure_free_trial_entitlement_sync(
    db: &Database,
    config: &AppConfig,
    npub: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<EntitlementRow>> {
    let trial_id = format!("{npub}-trial");
    let existing = {
        let conn = db.lock().expect("db lock poisoned");
        conn.query_row(
            r#"
            SELECT "id", "npub", "platform", "productId", "originalTxId", "purchaseToken", "status", "expiresAt", "quotaBytes"
            FROM "Entitlement"
            WHERE "id" = ?
            "#,
            params![trial_id],
            map_entitlement,
        )
        .optional()
        .with_context(|| "failed to fetch trial entitlement")?
    };

    let expires_at = now + Duration::days(config.free_trial_days);

    if existing.is_none() {
        ensure_user_exists_sync(db, npub)?;
        let conn = db.lock().expect("db lock poisoned");
        conn.execute(
            r#"
            INSERT INTO "Entitlement"
                ("id", "npub", "platform", "productId", "originalTxId", "purchaseToken", "status", "expiresAt", "quotaBytes", "egressBytesMon", "updatedAt")
            VALUES (?, ?, 'trial', 'trial', NULL, NULL, 'active', ?, ?, 0, CURRENT_TIMESTAMP)
            "#,
            params![trial_id, npub, expires_at, plan_to_quota("trial")],
        )
        .with_context(|| "failed to create free trial entitlement")?;

        let created = conn
            .query_row(
                r#"
                SELECT "id", "npub", "platform", "productId", "originalTxId", "purchaseToken", "status", "expiresAt", "quotaBytes"
                FROM "Entitlement"
                WHERE "id" = ?
                "#,
                params![format!("{npub}-trial")],
                map_entitlement,
            )
            .optional()?;
        return Ok(created);
    }

    let existing = existing.expect("checked above");
    let conn = db.lock().expect("db lock poisoned");
    if existing.expires_at <= now && existing.status != "expired" {
        conn.execute(
            r#"UPDATE "Entitlement" SET "status" = 'expired', "updatedAt" = CURRENT_TIMESTAMP WHERE "id" = ?"#,
            params![trial_id],
        )
        .with_context(|| "failed to expire trial entitlement")?;
    } else if existing.expires_at > now && existing.status != "active" {
        conn.execute(
            r#"UPDATE "Entitlement" SET "status" = 'active', "updatedAt" = CURRENT_TIMESTAMP WHERE "id" = ?"#,
            params![trial_id],
        )
        .with_context(|| "failed to reactivate trial entitlement")?;
    }

    conn.query_row(
        r#"
        SELECT "id", "npub", "platform", "productId", "originalTxId", "purchaseToken", "status", "expiresAt", "quotaBytes"
        FROM "Entitlement"
        WHERE "id" = ?
        "#,
        params![format!("{npub}-trial")],
        map_entitlement,
    )
    .optional()
    .with_context(|| "failed to load trial entitlement")
}
