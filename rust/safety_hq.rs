use std::{
    collections::HashSet,
    fs,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use mdk_core::{MDK, messages::MessageProcessingResult};
use mdk_sqlite_storage::{EncryptionConfig, MdkSqliteStorage};
use mdk_storage_traits::messages::types::Message as MdkMessage;
use nostr_sdk::prelude::{
    Alphabet, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, PublicKey, RelayPoolNotification,
    SingleLetterTag, SubscriptionId, Timestamp, UnwrappedGift,
};
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::{config::AppConfig, db::Database};

const REPORT_KIND: u16 = 4547;
const KEY_PACKAGE_KIND: u16 = 30443;
const WELCOME_KIND: u16 = 444;
const GIFT_WRAP_KIND: u16 = 1059;
const GROUP_COMMIT_KIND: u16 = 445;
const CHECKPOINT_WELCOMES: &str = "welcomes";
const CHECKPOINT_GROUPS: &str = "groups";

fn format_error_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

fn parse_unsigned_rumor_json(rumor_json: &str) -> anyhow::Result<nostr_sdk::prelude::UnsignedEvent> {
    match nostr_sdk::prelude::UnsignedEvent::from_json(rumor_json) {
        Ok(rumor) => Ok(rumor),
        Err(initial_error) => {
            let mut value: serde_json::Value =
                serde_json::from_str(rumor_json).with_context(|| "failed to parse rumor JSON")?;

            let removed_null_sig = value
                .as_object_mut()
                .and_then(|object| match object.get("sig") {
                    Some(serde_json::Value::Null) => object.remove("sig"),
                    _ => None,
                })
                .is_some();

            if !removed_null_sig {
                return Err(initial_error).with_context(|| "failed to decode rumor as unsigned event");
            }

            let normalized_json =
                serde_json::to_string(&value).with_context(|| "failed to normalize rumor JSON")?;

            nostr_sdk::prelude::UnsignedEvent::from_json(normalized_json)
                .with_context(|| "failed to decode normalized rumor as unsigned event")
        }
    }
}

struct ParsedSeal {
    pubkey: PublicKey,
    content: String,
    used_unsigned_compat: bool,
}

fn parse_seal_json(seal_json: &str) -> anyhow::Result<ParsedSeal> {
    match Event::from_json(seal_json) {
        Ok(seal) => {
            seal.verify()
                .with_context(|| "failed to verify decrypted seal event")?;
            Ok(ParsedSeal {
                pubkey: seal.pubkey,
                content: seal.content,
                used_unsigned_compat: false,
            })
        }
        Err(initial_error) => {
            let mut value: serde_json::Value =
                serde_json::from_str(seal_json).with_context(|| "failed to parse decrypted seal JSON")?;

            let removed_null_sig = value
                .as_object_mut()
                .and_then(|object| match object.get("sig") {
                    Some(serde_json::Value::Null) => object.remove("sig"),
                    _ => None,
                })
                .is_some();

            if !removed_null_sig {
                return Err(initial_error).with_context(|| "failed to decode decrypted seal event");
            }

            let normalized_json =
                serde_json::to_string(&value).with_context(|| "failed to normalize decrypted seal JSON")?;
            let seal = nostr_sdk::prelude::UnsignedEvent::from_json(normalized_json)
                .with_context(|| "failed to decode normalized decrypted seal as unsigned event")?;
            seal.verify_id()
                .with_context(|| "normalized decrypted seal has invalid event id")?;

            Ok(ParsedSeal {
                pubkey: seal.pubkey,
                content: seal.content,
                used_unsigned_compat: true,
            })
        }
    }
}

async fn unwrap_gift_wrap_compat(client: &nostr_sdk::Client, gift_wrap: &Event) -> anyhow::Result<UnwrappedGift> {
    let signer = client
        .signer()
        .await
        .with_context(|| "missing signer for gift wrap unwrap")?;

    let seal_json = signer
        .nip44_decrypt(&gift_wrap.pubkey, &gift_wrap.content)
        .await
        .with_context(|| "failed to decrypt gift wrap seal")?;
    let seal = parse_seal_json(&seal_json)?;
    if seal.used_unsigned_compat {
        warn!("using unsigned compatibility path for decrypted Safety HQ seal event");
    }

    let rumor_json = signer
        .nip44_decrypt(&seal.pubkey, &seal.content)
        .await
        .with_context(|| "failed to decrypt gift wrap rumor")?;
    let rumor = parse_unsigned_rumor_json(&rumor_json)?;

    if rumor.pubkey != seal.pubkey {
        return Err(anyhow!("gift wrap rumor pubkey does not match seal pubkey"));
    }

    Ok(UnwrappedGift {
        sender: seal.pubkey,
        rumor,
    })
}

#[derive(Default)]
pub struct SafetyHqMetrics {
    pub welcomes_received: AtomicU64,
    pub groups_joined: AtomicU64,
    pub reports_received: AtomicU64,
    pub decrypt_failures: AtomicU64,
    pub parse_failures: AtomicU64,
    pub duplicate_report_ids: AtomicU64,
}

impl SafetyHqMetrics {
    pub fn snapshot(&self) -> SafetyHqMetricsSnapshot {
        SafetyHqMetricsSnapshot {
            welcomes_received: self.welcomes_received.load(Ordering::Relaxed),
            groups_joined: self.groups_joined.load(Ordering::Relaxed),
            reports_received: self.reports_received.load(Ordering::Relaxed),
            decrypt_failures: self.decrypt_failures.load(Ordering::Relaxed),
            parse_failures: self.parse_failures.load(Ordering::Relaxed),
            duplicate_report_ids: self.duplicate_report_ids.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SafetyHqMetricsSnapshot {
    pub welcomes_received: u64,
    pub groups_joined: u64,
    pub reports_received: u64,
    pub decrypt_failures: u64,
    pub parse_failures: u64,
    pub duplicate_report_ids: u64,
}

#[derive(Debug, Serialize)]
pub struct SafetyHqRuntimeSnapshot {
    pub started: bool,
    pub ready: bool,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct SafetyHqService {
    pub metrics: Arc<SafetyHqMetrics>,
    runtime: Arc<SafetyHqRuntime>,
    config: AppConfig,
    pool: Database,
    inner: Arc<Mutex<SafetyHqInner>>,
}

#[derive(Default)]
struct SafetyHqRuntime {
    ready: AtomicBool,
    started: AtomicBool,
    last_error: Mutex<Option<String>>,
}

struct SafetyHqInner {
    client: nostr_sdk::Client,
    keys: Keys,
    mdk: MDK<MdkSqliteStorage>,
}

#[derive(Debug, Serialize)]
pub struct BootstrapResponse {
    pub service_public_key_hex: String,
    pub signed_key_package_event_json: String,
    pub key_package_event_id: String,
    pub relays: Vec<String>,
    pub version: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportPayload {
    pub t: String,
    pub report_id: String,
    pub video_id: String,
    pub subject_child_id: String,
    pub blob_hash: String,
    pub reason: String,
    pub note: Option<String>,
    pub level: i64,
    pub recipient_type: String,
    pub reporter_child_id: Option<String>,
    pub by: String,
    pub ts: i64,
}

#[derive(Debug, Serialize, Clone)]
pub struct ModerationCase {
    pub report_id: String,
    pub mls_group_id_hex: String,
    pub sender_parent_pubkey: String,
    pub video_id: String,
    pub subject_child_id: String,
    pub reporter_child_id: Option<String>,
    pub blob_hash: String,
    pub reason: String,
    pub note: Option<String>,
    pub level: i64,
    pub recipient_type: String,
    pub ts: i64,
    pub raw_event_id: Option<String>,
    pub raw_wrapper_event_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct CaseStatusUpdate {
    pub status: String,
    pub note: Option<String>,
    pub changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CaseQuery {
    pub status: Option<String>,
    pub group: Option<String>,
    pub received_after: Option<String>,
    pub received_before: Option<String>,
}

impl SafetyHqService {
    pub async fn new(config: AppConfig, pool: Database) -> anyhow::Result<Self> {
        let service_identity =
            ensure_service_identity(&pool, config.safety_hq_secret_key_hex.as_deref()).await?;

        let keys = Keys::parse(&service_identity.service_secret_key_hex)
            .with_context(|| "failed to parse Safety HQ secret key")?;

        if let Some(parent) = Path::new(&config.safety_hq_mdk_db_path).parent() {
            fs::create_dir_all(parent)
                .with_context(|| "failed to create Safety HQ data directory")?;
        }

        let mdk_storage = match config.safety_hq_mdk_db_key_hex.as_deref() {
            Some(key_hex) => {
                let key_bytes = hex::decode(key_hex)
                    .with_context(|| "SAFETY_HQ_MDK_DB_KEY_HEX must be hex-encoded")?;
                let key: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| anyhow!("SAFETY_HQ_MDK_DB_KEY_HEX must decode to 32 bytes"))?;
                MdkSqliteStorage::new_with_key(
                    &config.safety_hq_mdk_db_path,
                    EncryptionConfig::new(key),
                )
                .with_context(|| "failed to initialize encrypted MDK sqlite storage")?
            }
            None => {
                warn!(
                    "SAFETY_HQ_MDK_DB_KEY_HEX not set; Safety HQ MLS state stored unencrypted"
                );
                MdkSqliteStorage::new_unencrypted(&config.safety_hq_mdk_db_path)
                    .with_context(|| "failed to initialize MDK sqlite storage")?
            }
        };
        let mdk = MDK::new(mdk_storage);

        let client = nostr_sdk::Client::builder().signer(keys.clone()).build();

        Ok(Self {
            metrics: Arc::new(SafetyHqMetrics::default()),
            runtime: Arc::new(SafetyHqRuntime::default()),
            config,
            pool,
            inner: Arc::new(Mutex::new(SafetyHqInner { client, keys, mdk })),
        })
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        {
            let mut last_error = self.runtime.last_error.lock().await;
            *last_error = None;
        }
        let client = {
            let inner = self.inner.lock().await;
            inner.client.clone()
        };

        for relay in &self.config.safety_hq_relays {
            if let Err(error) = client.add_relay(relay).await {
                self.mark_runtime_failure(format!("failed to add relay {relay}: {error}"))
                    .await;
                return Err(error).with_context(|| format!("failed to add relay {relay}"));
            }
        }
        client.connect().await;

        if let Err(error) = self.refresh_subscriptions().await {
            self.mark_runtime_failure(format!("failed to refresh subscriptions: {error}"))
                .await;
            return Err(error);
        }

        self.runtime.started.store(true, Ordering::Relaxed);
        self.runtime.ready.store(true, Ordering::Relaxed);

        let service = self.clone();
        tokio::spawn(async move {
            let client = {
                let inner = service.inner.lock().await;
                inner.client.clone()
            };

            let result = client
                .handle_notifications(|notification| {
                    let service = service.clone();
                    async move {
                        service.handle_notification(notification).await;
                        Ok(false)
                    }
                })
                .await;

            if let Err(error) = result {
                service
                    .mark_runtime_failure(format!("relay listener exited: {error}"))
                    .await;
                error!(error = %error, "Safety HQ relay listener exited");
            }
        });

        Ok(())
    }

    pub async fn bootstrap(&self) -> anyhow::Result<BootstrapResponse> {
        let identity =
            ensure_service_identity(&self.pool, self.config.safety_hq_secret_key_hex.as_deref())
                .await?;
        let public_key = PublicKey::parse(&identity.service_public_key_hex)
            .with_context(|| "invalid persisted service public key")?;

        let (event_json, event_id) = {
            let inner = self.inner.lock().await;
            let relay_urls = self.config.safety_hq_relays.clone();
            let key_package = inner
                .mdk
                .create_key_package_for_event(&public_key, parse_relay_urls(&relay_urls)?)
                .with_context(|| "failed to create Safety HQ key package")?;

            let event = EventBuilder::new(Kind::Custom(KEY_PACKAGE_KIND), key_package.content)
                .tags(key_package.tags_30443)
                .sign_with_keys(&inner.keys)
                .with_context(|| "failed to sign key package event")?;

            (event.as_json(), event.id.to_hex())
        };

        Ok(BootstrapResponse {
            service_public_key_hex: identity.service_public_key_hex,
            signed_key_package_event_json: event_json,
            key_package_event_id: event_id,
            relays: self.config.safety_hq_relays.clone(),
            version: self.config.safety_hq_version.clone(),
            generated_at: identity.generated_at,
        })
    }

    pub async fn list_cases(&self, query: &CaseQuery) -> anyhow::Result<Vec<ModerationCase>> {
        let mut sql = String::from(
            r#"
            SELECT
                "report_id", "mls_group_id_hex", "sender_parent_pubkey", "video_id",
                "subject_child_id", "reporter_child_id", "blob_hash", "reason", "note",
                "level", "recipient_type", "ts", "raw_event_id", "raw_wrapper_event_id",
                "received_at", "status"
            FROM "moderation_cases"
            WHERE 1 = 1
            "#,
        );

        let mut binds: Vec<String> = Vec::new();

        if let Some(status) = &query.status {
            sql.push_str(r#" AND "status" = ?"#);
            binds.push(status.clone());
        }
        if let Some(group) = &query.group {
            sql.push_str(r#" AND "mls_group_id_hex" = ?"#);
            binds.push(group.clone());
        }
        if let Some(after) = &query.received_after {
            sql.push_str(r#" AND "received_at" >= ?"#);
            binds.push(after.clone());
        }
        if let Some(before) = &query.received_before {
            sql.push_str(r#" AND "received_at" <= ?"#);
            binds.push(before.clone());
        }

        sql.push_str(r#" ORDER BY "received_at" DESC"#);

        let conn = self.pool.lock().expect("db lock poisoned");
        let mut statement = conn
            .prepare(&sql)
            .with_context(|| "failed to prepare moderation case query")?;
        let rows = statement
            .query_map(params_from_iter(binds.iter()), map_case)?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| "failed to fetch moderation cases")?;
        Ok(rows)
    }

    pub async fn get_case(&self, report_id: &str) -> anyhow::Result<Option<ModerationCase>> {
        let conn = self.pool.lock().expect("db lock poisoned");
        conn.query_row(
            r#"
            SELECT
                "report_id", "mls_group_id_hex", "sender_parent_pubkey", "video_id",
                "subject_child_id", "reporter_child_id", "blob_hash", "reason", "note",
                "level", "recipient_type", "ts", "raw_event_id", "raw_wrapper_event_id",
                "received_at", "status"
            FROM "moderation_cases"
            WHERE "report_id" = ?
            "#,
            params![report_id],
            map_case,
        )
        .optional()
        .with_context(|| "failed to fetch moderation case")
    }

    pub async fn update_case_status(
        &self,
        report_id: &str,
        update: &CaseStatusUpdate,
    ) -> anyhow::Result<Option<ModerationCase>> {
        if !matches!(update.status.as_str(), "new" | "triaged" | "closed") {
            return Err(anyhow!("invalid status"));
        }

        let existing = self.get_case(report_id).await?;
        let Some(existing) = existing else {
            return Ok(None);
        };

        let conn = self.pool.lock().expect("db lock poisoned");
        conn.execute(
            r#"UPDATE "moderation_cases" SET "status" = ? WHERE "report_id" = ?"#,
            params![&update.status, report_id],
        )
        .with_context(|| "failed to update moderation case status")?;

        conn.execute(
            r#"
            INSERT INTO "case_status_history"
                ("report_id", "from_status", "to_status", "changed_by", "note")
            VALUES (?, ?, ?, ?, ?)
            "#,
            params![
                report_id,
                existing.status,
                &update.status,
                update.changed_by.clone(),
                update.note.clone()
            ],
        )
        .with_context(|| "failed to insert case status history")?;

        let updated = conn
            .query_row(
                r#"
                SELECT
                    "report_id", "mls_group_id_hex", "sender_parent_pubkey", "video_id",
                    "subject_child_id", "reporter_child_id", "blob_hash", "reason", "note",
                    "level", "recipient_type", "ts", "raw_event_id", "raw_wrapper_event_id",
                    "received_at", "status"
                FROM "moderation_cases"
                WHERE "report_id" = ?
                "#,
                params![report_id],
                map_case,
            )
            .with_context(|| "failed to reload moderation case status")?;

        Ok(Some(updated))
    }

    async fn handle_notification(&self, notification: RelayPoolNotification) {
        match notification {
            RelayPoolNotification::Event {
                relay_url, event, ..
            } => {
                let relay = relay_url.to_string();
                if event.kind == Kind::GiftWrap {
                    if let Err(error) = self.handle_gift_wrap(*event, &relay).await {
                        self.metrics
                            .decrypt_failures
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            error = %format_error_chain(&error),
                            relay = relay,
                            "failed to process Safety HQ gift wrap"
                        );
                    }
                } else if event.kind == Kind::Custom(GROUP_COMMIT_KIND)
                    || event.kind == Kind::Custom(REPORT_KIND)
                {
                    if let Err(error) = self.handle_group_event(*event, &relay).await {
                        warn!(
                            error = %format_error_chain(&error),
                            relay = relay,
                            "failed to process Safety HQ group event"
                        );
                    }
                }
            }
            RelayPoolNotification::Message { relay_url, message } => {
                info!(relay = relay_url.to_string(), message = ?message, "relay message");
            }
            _ => {}
        }
    }

    async fn handle_gift_wrap(&self, event: Event, relay_url: &str) -> anyhow::Result<()> {
        let client = {
            let inner = self.inner.lock().await;
            inner.client.clone()
        };
        let unwrapped = unwrap_gift_wrap_compat(&client, &event)
            .await
            .with_context(|| "unable to unwrap gift wrap")?;

        info!(
            relay = relay_url,
            wrapper_event_id = event.id.to_hex(),
            sender = unwrapped.sender.to_hex(),
            rumor_kind = unwrapped.rumor.kind.as_u16(),
            rumor_created_at = unwrapped.rumor.created_at.as_secs(),
            "unwrapped Safety HQ gift wrap"
        );

        if unwrapped.rumor.kind != Kind::Custom(WELCOME_KIND) {
            info!(
                relay = relay_url,
                wrapper_event_id = event.id.to_hex(),
                rumor_kind = unwrapped.rumor.kind.as_u16(),
                "ignoring non-welcome Safety HQ gift wrap"
            );
            return Ok(());
        }

        self.metrics
            .welcomes_received
            .fetch_add(1, Ordering::Relaxed);

        let welcome = {
            let inner = self.inner.lock().await;
            inner
                .mdk
                .process_welcome(&event.id, &unwrapped.rumor)
                .with_context(|| "failed to process welcome rumor")?
        };

        info!(
            relay = relay_url,
            wrapper_event_id = event.id.to_hex(),
            mls_group_id = hex::encode(welcome.mls_group_id.as_slice()),
            welcomer_pubkey = welcome.welcomer.to_hex(),
            "processed Safety HQ welcome rumor"
        );

        {
            let inner = self.inner.lock().await;
            inner
                .mdk
                .accept_welcome(&welcome)
                .with_context(|| "failed to accept welcome")?;
        }

        info!(
            relay = relay_url,
            wrapper_event_id = event.id.to_hex(),
            mls_group_id = hex::encode(welcome.mls_group_id.as_slice()),
            "accepted Safety HQ welcome"
        );

        let group = {
            let inner = self.inner.lock().await;
            inner
                .mdk
                .get_group(&welcome.mls_group_id)?
                .ok_or_else(|| anyhow!("joined group missing after welcome acceptance"))?
        };

        let (relays, member_count) = {
            let inner = self.inner.lock().await;
            let relays = inner
                .mdk
                .get_relays(&group.mls_group_id)
                .with_context(|| "failed to fetch group relays after enrollment")?
                .iter()
                .map(|relay| relay.to_string())
                .collect::<Vec<_>>();
            let member_count = inner
                .mdk
                .get_members(&group.mls_group_id)
                .with_context(|| "failed to fetch group members after enrollment")?
                .len() as i64;
            (relays, member_count)
        };

        {
            let conn = self.pool.lock().expect("db lock poisoned");
            conn.execute(
            r#"
            INSERT INTO "enrolled_groups"
                ("mls_group_id_hex", "nostr_group_id_hex", "group_name", "group_description", "group_relays_json", "welcomer_pubkey_hex", "wrapper_event_id", "member_count")
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT("mls_group_id_hex") DO UPDATE SET
                "nostr_group_id_hex" = excluded."nostr_group_id_hex",
                "group_name" = excluded."group_name",
                "group_description" = excluded."group_description",
                "group_relays_json" = excluded."group_relays_json",
                "welcomer_pubkey_hex" = excluded."welcomer_pubkey_hex",
                "wrapper_event_id" = excluded."wrapper_event_id",
                "member_count" = excluded."member_count",
                "updated_at" = CURRENT_TIMESTAMP
            "#,
                params![
                    hex::encode(group.mls_group_id.as_slice()),
                    hex::encode(group.nostr_group_id),
                    group.name,
                    group.description,
                    serde_json::to_string(&relays)?,
                    welcome.welcomer.to_hex(),
                    event.id.to_hex(),
                    member_count
                ],
            )
            .with_context(|| "failed to persist enrolled group")?;
        }

        let client = {
            let inner = self.inner.lock().await;
            inner.client.clone()
        };
        for relay in &relays {
            let _ = client.add_relay(relay).await;
        }

        self.metrics.groups_joined.fetch_add(1, Ordering::Relaxed);
        update_checkpoint(&self.pool, CHECKPOINT_WELCOMES, &event).await?;
        self.refresh_subscriptions().await?;

        info!(
            relay = relay_url,
            mls_group_id = hex::encode(group.mls_group_id.as_slice()),
            "Safety HQ enrolled in group"
        );

        Ok(())
    }

    async fn handle_group_event(&self, event: Event, relay_url: &str) -> anyhow::Result<()> {
        self.persist_raw_intake_event(&event, relay_url, None, None)
            .await?;

        let result = {
            let inner = self.inner.lock().await;
            inner
                .mdk
                .process_message(&event)
                .with_context(|| "failed to process group message")?
        };

        match result {
            MessageProcessingResult::ApplicationMessage(message) => {
                if message.kind.as_u16() == REPORT_KIND {
                    self.ingest_report(message, &event, relay_url).await?;
                } else {
                    info!(
                        relay = relay_url,
                        wrapper_event_id = event.id.to_hex(),
                        inner_kind = message.kind.as_u16(),
                        mls_group_id = hex::encode(message.mls_group_id.as_slice()),
                        "ignoring non-report application message in Safety HQ group"
                    );
                }
            }
            MessageProcessingResult::Commit { mls_group_id } => {
                info!(
                    relay = relay_url,
                    mls_group_id = hex::encode(mls_group_id.as_slice()),
                    "processed Safety HQ commit"
                );
            }
            MessageProcessingResult::Proposal(result) => {
                warn!(
                    mls_group_id = hex::encode(result.mls_group_id.as_slice()),
                    "received proposal in Safety HQ group; auto-commit flow not yet published by backend"
                );
            }
            MessageProcessingResult::PendingProposal { .. }
            | MessageProcessingResult::ExternalJoinProposal { .. }
            | MessageProcessingResult::Unprocessable { .. }
            | MessageProcessingResult::IgnoredProposal { .. }
            | MessageProcessingResult::PreviouslyFailed => {}
        }

        update_checkpoint(&self.pool, CHECKPOINT_GROUPS, &event).await?;
        Ok(())
    }

    async fn ingest_report(
        &self,
        message: MdkMessage,
        wrapper_event: &Event,
        relay_url: &str,
    ) -> anyhow::Result<()> {
        let payload: ReportPayload = serde_json::from_str(&message.content).map_err(|error| {
            self.metrics.parse_failures.fetch_add(1, Ordering::Relaxed);
            anyhow!("failed to parse report payload: {error}")
        })?;

        if let Err(error) = validate_report_payload(&payload) {
            self.metrics.parse_failures.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }

        let mls_group_id_hex = hex::encode(message.mls_group_id.as_slice());
        self.persist_raw_intake_event(
            wrapper_event,
            relay_url,
            Some(&mls_group_id_hex),
            Some(&message.wrapper_event_id.to_hex()),
        )
        .await?;

        self.persist_report_payload(
            &payload,
            &mls_group_id_hex,
            wrapper_event.id.to_hex(),
            message.wrapper_event_id.to_hex(),
            relay_url,
        )
        .await
    }

    async fn persist_raw_intake_event(
        &self,
        event: &Event,
        relay_url: &str,
        mls_group_id_hex: Option<&str>,
        wrapper_event_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.pool.lock().expect("db lock poisoned");
        conn.execute(
            r#"
            INSERT INTO "raw_intake_events"
                ("event_id", "kind", "wrapper_event_id", "mls_group_id_hex", "source_relay_url", "event_json")
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT("event_id") DO NOTHING
            "#,
            params![
                event.id.to_hex(),
                event.kind.as_u16() as i64,
                wrapper_event_id,
                mls_group_id_hex,
                relay_url,
                event.as_json()
            ],
        )
        .with_context(|| "failed to persist raw intake event")?;
        Ok(())
    }

    async fn refresh_subscriptions(&self) -> anyhow::Result<()> {
        let welcome_since = checkpoint_since(&self.pool, CHECKPOINT_WELCOMES).await?;
        let group_since = checkpoint_since(&self.pool, CHECKPOINT_GROUPS).await?;
        let enrolled_groups = load_enrolled_groups(&self.pool).await?;

        let welcome_filter = Filter::new()
            .kind(Kind::Custom(GIFT_WRAP_KIND))
            .custom_tags(
                SingleLetterTag::lowercase(Alphabet::P),
                [self.public_key().await?.to_hex()].into_iter().collect::<HashSet<_>>(),
            )
            .since(welcome_since);

        {
            let client = {
                let inner = self.inner.lock().await;
                inner.client.clone()
            };
            client
                .subscribe_with_id(
                    SubscriptionId::new("safetyhq-welcomes"),
                    welcome_filter,
                    None,
                )
                .await
                .with_context(|| "failed to subscribe to Safety HQ welcomes")?;
        }

        if !enrolled_groups.is_empty() {
            let group_filter = Filter::new()
                .kinds([Kind::Custom(GROUP_COMMIT_KIND), Kind::Custom(REPORT_KIND)])
                .custom_tags(
                    SingleLetterTag::lowercase(Alphabet::H),
                    enrolled_groups.into_iter().collect::<HashSet<_>>(),
                )
                .since(group_since);

            let client = {
                let inner = self.inner.lock().await;
                inner.client.clone()
            };
            client
                .subscribe_with_id(SubscriptionId::new("safetyhq-groups"), group_filter, None)
                .await
                .with_context(|| "failed to subscribe to Safety HQ group traffic")?;
        }

        Ok(())
    }

    pub async fn public_key(&self) -> anyhow::Result<PublicKey> {
        let inner = self.inner.lock().await;
        Ok(inner.keys.public_key())
    }

    pub async fn runtime_snapshot(&self) -> SafetyHqRuntimeSnapshot {
        let last_error = self.runtime.last_error.lock().await.clone();
        SafetyHqRuntimeSnapshot {
            started: self.runtime.started.load(Ordering::Relaxed),
            ready: self.runtime.ready.load(Ordering::Relaxed),
            last_error,
        }
    }

    #[cfg(test)]
    pub async fn ingest_report_payload_for_test(
        &self,
        payload: ReportPayload,
        mls_group_id_hex: &str,
        raw_event_id: &str,
        raw_wrapper_event_id: &str,
        relay_url: &str,
    ) -> anyhow::Result<()> {
        self.persist_report_payload(
            &payload,
            mls_group_id_hex,
            raw_event_id.to_string(),
            raw_wrapper_event_id.to_string(),
            relay_url,
        )
        .await
    }

    async fn mark_runtime_failure(&self, error: String) {
        self.runtime.ready.store(false, Ordering::Relaxed);
        self.runtime.started.store(true, Ordering::Relaxed);
        let mut last_error = self.runtime.last_error.lock().await;
        *last_error = Some(error);
    }

    async fn persist_report_payload(
        &self,
        payload: &ReportPayload,
        mls_group_id_hex: &str,
        raw_event_id: String,
        raw_wrapper_event_id: String,
        relay_url: &str,
    ) -> anyhow::Result<()> {
        if let Err(error) = validate_report_payload(payload) {
            self.metrics.parse_failures.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }

        let insert = {
            let conn = self.pool.lock().expect("db lock poisoned");
            conn.execute(
                r#"
                INSERT INTO "moderation_cases"
                    ("report_id", "mls_group_id_hex", "sender_parent_pubkey", "video_id", "subject_child_id", "reporter_child_id", "blob_hash", "reason", "note", "level", "recipient_type", "ts", "raw_event_id", "raw_wrapper_event_id", "status")
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
                "#,
                params![
                    &payload.report_id,
                    mls_group_id_hex,
                    &payload.by,
                    &payload.video_id,
                    &payload.subject_child_id,
                    payload.reporter_child_id.clone(),
                    &payload.blob_hash,
                    &payload.reason,
                    payload.note.clone(),
                    payload.level,
                    &payload.recipient_type,
                    payload.ts,
                    raw_event_id,
                    raw_wrapper_event_id
                ],
            )
        };

        match insert {
            Ok(_) => {
                self.metrics
                    .reports_received
                    .fetch_add(1, Ordering::Relaxed);
                let conn = self.pool.lock().expect("db lock poisoned");
                conn.execute(
                    r#"
                    INSERT INTO "case_status_history"
                        ("report_id", "from_status", "to_status", "changed_by", "note")
                    VALUES (?, NULL, 'new', ?, ?)
                    "#,
                    params![&payload.report_id, &payload.by, "initial intake"],
                )
                .with_context(|| "failed to insert initial case audit row")?;

                info!(
                    relay = relay_url,
                    report_id = payload.report_id,
                    mls_group_id = mls_group_id_hex,
                    "Safety HQ stored moderation case"
                );
                Ok(())
            }
            Err(error)
                if error
                    .to_string()
                    .contains("UNIQUE constraint failed: moderation_cases.report_id") =>
            {
                self.metrics
                    .duplicate_report_ids
                    .fetch_add(1, Ordering::Relaxed);
                info!(
                    report_id = payload.report_id,
                    "duplicate report delivery ignored"
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

struct ServiceIdentityRow {
    pub service_secret_key_hex: String,
    pub service_public_key_hex: String,
    pub generated_at: DateTime<Utc>,
}

async fn ensure_service_identity(
    pool: &Database,
    configured_secret_key_hex: Option<&str>,
) -> anyhow::Result<ServiceIdentityRow> {
    let conn = pool.lock().expect("db lock poisoned");
    let existing = conn
        .query_row(
            r#"
            SELECT "service_secret_key_hex", "service_public_key_hex", "generated_at"
            FROM "service_config"
            WHERE "id" = 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<DateTime<Utc>>>(2)?,
                ))
            },
        )
        .optional()
        .with_context(|| "failed to fetch service identity")?;

    if let Some(secret_hex) = configured_secret_key_hex {
        let keys = Keys::parse(secret_hex)
            .with_context(|| "failed to parse configured Safety HQ secret key")?;
        let public_hex = keys.public_key().to_hex();
        let generated_at = existing
            .as_ref()
            .and_then(|(_, _, generated_at)| generated_at.clone())
            .unwrap_or_else(Utc::now);

        conn.execute(
            r#"
            INSERT INTO "service_config"
                ("id", "service_secret_key_hex", "service_public_key_hex", "version", "generated_at")
            VALUES (1, NULL, ?, 'v1', ?)
            ON CONFLICT("id") DO UPDATE SET
                "service_secret_key_hex" = NULL,
                "service_public_key_hex" = excluded."service_public_key_hex",
                "version" = excluded."version",
                "generated_at" = COALESCE("service_config"."generated_at", excluded."generated_at"),
                "updated_at" = CURRENT_TIMESTAMP
            "#,
            params![&public_hex, generated_at],
        )
        .with_context(|| "failed to persist configured service identity metadata")?;

        return Ok(ServiceIdentityRow {
            service_secret_key_hex: secret_hex.to_string(),
            service_public_key_hex: public_hex,
            generated_at,
        });
    }

    if let Some((Some(secret_hex), Some(public_hex), Some(generated_at))) = existing {
        return Ok(ServiceIdentityRow {
            service_secret_key_hex: secret_hex,
            service_public_key_hex: public_hex,
            generated_at,
        });
    }

    let keys = Keys::generate();
    let secret_hex = keys.secret_key().to_secret_hex();
    let public_hex = keys.public_key().to_hex();
    let generated_at = Utc::now();

    conn.execute(
        r#"
        INSERT INTO "service_config"
            ("id", "service_secret_key_hex", "service_public_key_hex", "version", "generated_at")
        VALUES (1, ?, ?, 'v1', ?)
        "#,
        params![&secret_hex, &public_hex, generated_at],
    )
    .with_context(|| "failed to persist generated service identity")?;

    Ok(ServiceIdentityRow {
        service_secret_key_hex: secret_hex,
        service_public_key_hex: public_hex,
        generated_at,
    })
}

async fn load_enrolled_groups(pool: &Database) -> anyhow::Result<Vec<String>> {
    let conn = pool.lock().expect("db lock poisoned");
    let mut statement = conn
        .prepare(
            r#"SELECT "nostr_group_id_hex" FROM "enrolled_groups" ORDER BY "enrolled_at" DESC"#,
        )
        .with_context(|| "failed to prepare enrolled groups query")?;
    let rows = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()
        .with_context(|| "failed to load enrolled groups")?;
    Ok(rows)
}

async fn checkpoint_since(pool: &Database, stream_key: &str) -> anyhow::Result<Timestamp> {
    let conn = pool.lock().expect("db lock poisoned");
    let value = conn
        .query_row(
            r#"SELECT "last_created_at" FROM "relay_checkpoints" WHERE "stream_key" = ?"#,
            params![stream_key],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .with_context(|| "failed to fetch relay checkpoint")?
        .unwrap_or(0);
    Ok(Timestamp::from(value as u64))
}

async fn update_checkpoint(pool: &Database, stream_key: &str, event: &Event) -> anyhow::Result<()> {
    let conn = pool.lock().expect("db lock poisoned");
    conn.execute(
        r#"
        INSERT INTO "relay_checkpoints" ("stream_key", "last_created_at", "last_event_id")
        VALUES (?, ?, ?)
        ON CONFLICT("stream_key") DO UPDATE SET
            "last_created_at" = CASE
                WHEN excluded."last_created_at" > "relay_checkpoints"."last_created_at" THEN excluded."last_created_at"
                ELSE "relay_checkpoints"."last_created_at"
            END,
            "last_event_id" = CASE
                WHEN excluded."last_created_at" > "relay_checkpoints"."last_created_at" THEN excluded."last_event_id"
                WHEN excluded."last_created_at" = "relay_checkpoints"."last_created_at"
                  AND COALESCE(excluded."last_event_id", '') > COALESCE("relay_checkpoints"."last_event_id", '') THEN excluded."last_event_id"
                ELSE "relay_checkpoints"."last_event_id"
            END,
            "updated_at" = CURRENT_TIMESTAMP
        "#,
        params![stream_key, event.created_at.as_secs() as i64, event.id.to_hex()],
    )
    .with_context(|| "failed to update relay checkpoint")?;
    Ok(())
}

fn parse_relay_urls(relays: &[String]) -> anyhow::Result<Vec<nostr_sdk::RelayUrl>> {
    relays
        .iter()
        .map(|relay| nostr_sdk::RelayUrl::parse(relay).map_err(anyhow::Error::from))
        .collect()
}

#[allow(dead_code)]
fn _debug_unwrapped_gift(unwrapped: &UnwrappedGift) -> String {
    format!(
        "sender={}, kind={}",
        unwrapped.sender,
        unwrapped.rumor.kind.as_u16()
    )
}

fn map_case(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModerationCase> {
    Ok(ModerationCase {
        report_id: row.get(0)?,
        mls_group_id_hex: row.get(1)?,
        sender_parent_pubkey: row.get(2)?,
        video_id: row.get(3)?,
        subject_child_id: row.get(4)?,
        reporter_child_id: row.get(5)?,
        blob_hash: row.get(6)?,
        reason: row.get(7)?,
        note: row.get(8)?,
        level: row.get(9)?,
        recipient_type: row.get(10)?,
        ts: row.get(11)?,
        raw_event_id: row.get(12)?,
        raw_wrapper_event_id: row.get(13)?,
        received_at: row.get(14)?,
        status: row.get(15)?,
    })
}

fn validate_report_payload(payload: &ReportPayload) -> anyhow::Result<()> {
    if payload.t != "mytube/report" {
        return Err(anyhow!("unexpected report payload type"));
    }
    if payload.level != 3 {
        return Err(anyhow!("Safety HQ only accepts level-3 reports"));
    }
    if is_blank(&payload.report_id)
        || is_blank(&payload.video_id)
        || is_blank(&payload.subject_child_id)
        || is_blank(&payload.blob_hash)
        || is_blank(&payload.reason)
        || is_blank(&payload.recipient_type)
        || is_blank(&payload.by)
    {
        return Err(anyhow!("report payload missing required fields"));
    }
    if payload.ts <= 0 {
        return Err(anyhow!(
            "report payload ts must be a positive unix timestamp"
        ));
    }
    if let Some(note) = &payload.note
        && note.trim().is_empty()
    {
        return Err(anyhow!("report payload note cannot be blank when provided"));
    }
    if let Some(reporter_child_id) = &payload.reporter_child_id
        && reporter_child_id.trim().is_empty()
    {
        return Err(anyhow!(
            "report payload reporter_child_id cannot be blank when provided"
        ));
    }
    Ok(())
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::db;

    fn test_config(database_url: String, mdk_db_path: String) -> AppConfig {
        AppConfig {
            port: 0,
            host: "127.0.0.1".to_string(),
            node_env: "test".to_string(),
            database_url,
            blossom_server_url: "http://localhost:3000".to_string(),
            blossom_public_url: "http://localhost:3000".to_string(),
            nip98_challenge_ttl_seconds: 300,
            free_trial_enabled: false,
            free_trial_days: 30,
            moderator_npub: None,
            moderator_public_key: None,
            safety_hq_secret_key_hex: None,
            safety_hq_relays: vec!["wss://relay.test".to_string()],
            safety_hq_version: "v1".to_string(),
            safety_hq_mdk_db_path: mdk_db_path,
            safety_hq_mdk_db_key_hex: None,
        }
    }

    async fn test_service(database_url: String, mdk_db_path: String) -> SafetyHqService {
        let config = test_config(database_url, mdk_db_path);
        let pool = db::connect(&config.database_url).await.expect("db");
        SafetyHqService::new(config, pool).await.expect("service")
    }

    fn sample_payload(report_id: &str, level: i64) -> ReportPayload {
        ReportPayload {
            t: "mytube/report".to_string(),
            report_id: report_id.to_string(),
            video_id: "video-123".to_string(),
            subject_child_id: "child-456".to_string(),
            blob_hash: "abcdef0123456789".to_string(),
            reason: "safety".to_string(),
            note: Some("needs review".to_string()),
            level,
            recipient_type: "safety_hq".to_string(),
            reporter_child_id: Some("reporter-789".to_string()),
            by: "f".repeat(64),
            ts: 1_763_000_000,
        }
    }

    #[tokio::test]
    async fn service_identity_persists_across_restart() {
        let database_url = format!("sqlite:./prisma/safety-hq-{}.db", Uuid::new_v4());
        let mdk_db_path = format!("./prisma/safety-hq-mdk-{}.db", Uuid::new_v4());

        let first = test_service(database_url.clone(), mdk_db_path.clone()).await;
        let first_bootstrap = first.bootstrap().await.expect("first bootstrap");

        let second = test_service(database_url, mdk_db_path).await;
        let second_bootstrap = second.bootstrap().await.expect("second bootstrap");

        assert_eq!(
            first_bootstrap.service_public_key_hex,
            second_bootstrap.service_public_key_hex
        );
    }

    #[tokio::test]
    async fn report_intake_dedupes_and_survives_restart() {
        let database_url = format!("sqlite:./prisma/safety-hq-{}.db", Uuid::new_v4());
        let mdk_db_path = format!("./prisma/safety-hq-mdk-{}.db", Uuid::new_v4());
        let mls_group_id_hex = "ab".repeat(16);

        let first = test_service(database_url.clone(), mdk_db_path.clone()).await;
        let payload = sample_payload("report-1", 3);

        first
            .ingest_report_payload_for_test(
                payload.clone(),
                &mls_group_id_hex,
                &"01".repeat(32),
                &"02".repeat(32),
                "wss://relay.test",
            )
            .await
            .expect("first intake");
        first
            .ingest_report_payload_for_test(
                payload.clone(),
                &mls_group_id_hex,
                &"03".repeat(32),
                &"04".repeat(32),
                "wss://relay.test",
            )
            .await
            .expect("duplicate intake");

        let first_case = first
            .get_case("report-1")
            .await
            .expect("case lookup")
            .expect("case exists");
        assert_eq!(first_case.status, "new");
        assert_eq!(first_case.mls_group_id_hex, mls_group_id_hex);
        assert_eq!(first.metrics.snapshot().reports_received, 1);
        assert_eq!(first.metrics.snapshot().duplicate_report_ids, 1);

        let second = test_service(database_url, mdk_db_path).await;
        let second_case = second
            .get_case("report-1")
            .await
            .expect("persisted case lookup")
            .expect("persisted case exists");
        assert_eq!(second_case.report_id, "report-1");
        assert_eq!(second_case.level, 3);
    }

    #[tokio::test]
    async fn report_intake_rejects_non_level_three_payloads() {
        let database_url = format!("sqlite:./prisma/safety-hq-{}.db", Uuid::new_v4());
        let mdk_db_path = format!("./prisma/safety-hq-mdk-{}.db", Uuid::new_v4());
        let service = test_service(database_url, mdk_db_path).await;

        let error = service
            .ingest_report_payload_for_test(
                sample_payload("report-2", 2),
                &"cd".repeat(16),
                &"05".repeat(32),
                &"06".repeat(32),
                "wss://relay.test",
            )
            .await
            .expect_err("level-2 report should fail");

        assert!(error.to_string().contains("level-3"));
        assert!(
            service
                .get_case("report-2")
                .await
                .expect("lookup")
                .is_none()
        );
        assert_eq!(service.metrics.snapshot().parse_failures, 1);
    }

    #[tokio::test]
    async fn configured_secret_key_overrides_database_secret() {
        let database_url = format!("sqlite:./prisma/safety-hq-{}.db", Uuid::new_v4());
        let mdk_db_path = format!("./prisma/safety-hq-mdk-{}.db", Uuid::new_v4());
        let configured_keys = Keys::generate();
        let expected_public_key = configured_keys.public_key().to_hex();

        let config = AppConfig {
            safety_hq_secret_key_hex: Some(configured_keys.secret_key().to_secret_hex()),
            ..test_config(database_url.clone(), mdk_db_path.clone())
        };
        let pool = db::connect(&config.database_url).await.expect("db");
        let service = SafetyHqService::new(config, pool).await.expect("service");
        let bootstrap = service.bootstrap().await.expect("bootstrap");
        assert_eq!(bootstrap.service_public_key_hex, expected_public_key);

        let replacement_keys = Keys::generate();
        let replacement_public_key = replacement_keys.public_key().to_hex();
        let replacement_config = AppConfig {
            safety_hq_secret_key_hex: Some(replacement_keys.secret_key().to_secret_hex()),
            ..test_config(database_url, mdk_db_path)
        };
        let replacement_pool = db::connect(&replacement_config.database_url)
            .await
            .expect("db");
        let replacement_service = SafetyHqService::new(replacement_config, replacement_pool)
            .await
            .expect("replacement service");
        let replacement_bootstrap = replacement_service.bootstrap().await.expect("bootstrap");
        assert_eq!(
            replacement_bootstrap.service_public_key_hex,
            replacement_public_key
        );
    }
}
