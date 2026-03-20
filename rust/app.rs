use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

use sha2::{Digest, Sha256};

use crate::{
    auth::{AuthenticatedUser, ChallengeStore, parse_public_key_hex, require_nip98_auth},
    blossom::blob_url,
    config::AppConfig,
    db::{self, Database},
    entitlements::{ensure_user_exists, get_entitlement_for_npub, get_usage, increment_usage},
    safety_hq::{
        BootstrapResponse, CaseQuery, CaseStatusUpdate, ModerationCase, SafetyHqRuntimeSnapshot,
        SafetyHqService,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub pool: Database,
    pub challenges: ChallengeStore,
    pub safety_hq: SafetyHqService,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    safety_hq: SafetyHqRuntimeSnapshot,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct EntitlementResponse {
    plan: Option<String>,
    status: String,
    expires_at: Option<String>,
    quota_bytes: String,
    used_bytes: String,
}

#[derive(Debug, Deserialize)]
struct UploadAuthorizeBody {
    filename: Option<String>,
    content_type: Option<String>,
    size_bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
struct UploadAuthorizeResponse {
    upload_id: String,
    blossom_url: String,
}

#[derive(Debug, Deserialize)]
struct UploadCompleteBody {
    upload_id: Option<String>,
    sha256: Option<String>,
    size_bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
struct UploadCompleteResponse {
    url: String,
}

#[derive(Debug, Deserialize)]
struct DownloadUrlBody {
    sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct DownloadUrlResponse {
    url: String,
}

#[derive(Debug, Serialize)]
struct ModeratorKeyResponse {
    npub: String,
}

#[derive(Debug, Serialize)]
struct MetricsResponse {
    safety_hq: crate::safety_hq::SafetyHqMetricsSnapshot,
}

#[derive(Debug)]
struct UploadRow {
    id: String,
    npub: String,
    sha256: Option<String>,
    status: String,
}

#[derive(Debug, Serialize)]
struct AccountDeleteResponse {
    ok: bool,
    npub: String,
    deleted: AccountDeletedCounts,
}

#[derive(Debug, Serialize)]
struct AccountDeletedCounts {
    apple_purchases: usize,
    google_purchases: usize,
    uploads: usize,
    entitlements: usize,
    usage: usize,
    users: usize,
}

#[derive(Debug, Deserialize)]
struct BetaFunnelEventBody {
    source: Option<String>,
    event_name: Option<String>,
    platform: Option<String>,
    session_id: Option<String>,
    context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct BetaFunnelEventResponse {
    ok: bool,
    id: String,
}

#[derive(Debug, Deserialize)]
struct BetaFunnelSummaryQuery {
    days: Option<String>,
}

#[derive(Debug, Serialize)]
struct BetaFunnelSummaryResponse {
    window_days: i64,
    since: String,
    totals: usize,
    events: Vec<BetaFunnelEventSummary>,
}

#[derive(Debug, Serialize)]
struct BetaFunnelEventSummary {
    event_name: String,
    source: String,
    total: usize,
    unique_families: usize,
}

const BETA_FUNNEL_SOURCES: &[&str] = &["app", "marketing"];

pub async fn build_state(config: AppConfig) -> anyhow::Result<AppState> {
    let pool = db::connect(&config.database_url).await?;
    let safety_hq = SafetyHqService::new(config.clone(), pool.clone())
        .await
        .with_context(|| "failed to initialize Safety HQ service")?;

    Ok(AppState {
        config,
        pool,
        challenges: Arc::new(RwLock::new(HashMap::new())),
        safety_hq,
    })
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/auth/challenge", post(auth_challenge))
        .route("/entitlement", get(get_entitlement))
        .route("/safety/moderator-key", get(get_moderator_key))
        .route("/upload/authorize", post(upload_authorize))
        .route("/upload/complete", post(upload_complete))
        .route("/download/url", post(download_url))
        .route("/account", delete(delete_account))
        .route("/beta/funnel-events", post(beta_funnel_event))
        .route("/beta/funnel-summary", get(beta_funnel_summary))
        .route("/webhooks/appstore", post(webhook_appstore))
        .route("/webhooks/play", post(webhook_play))
        .route("/v1/safety-hq/bootstrap", get(safety_hq_bootstrap))
        .route("/v1/safety-hq/cases", get(safety_hq_cases))
        .route("/v1/safety-hq/cases/{report_id}", get(safety_hq_case))
        .route(
            "/v1/safety-hq/cases/{report_id}/status",
            post(safety_hq_case_status),
        )
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let runtime = state.safety_hq.runtime_snapshot().await;
    let ok = runtime.ready;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            ok,
            safety_hq: runtime,
        }),
    )
}

async fn metrics(State(state): State<AppState>) -> Json<MetricsResponse> {
    Json(MetricsResponse {
        safety_hq: state.safety_hq.metrics.snapshot(),
    })
}

async fn auth_challenge(State(state): State<AppState>) -> Json<ChallengeResponse> {
    let challenge = Uuid::new_v4().simple().to_string();
    let exp = Utc::now().timestamp() + state.config.nip98_challenge_ttl_seconds as i64;
    state
        .challenges
        .write()
        .await
        .insert(challenge.clone(), exp);

    Json(ChallengeResponse {
        challenge,
        expires_at: chrono::DateTime::<chrono::Utc>::from_timestamp(exp, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339(),
    })
}

async fn get_entitlement(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<EntitlementResponse>, (StatusCode, String)> {
    let auth = authenticated(&state, &headers, Method::GET, "/entitlement", None).await?;

    ensure_user_exists(&state.pool, &auth.npub)
        .await
        .map_err(internal_error)?;

    let entitlement = get_entitlement_for_npub(&state.pool, &state.config, &auth.npub)
        .await
        .map_err(internal_error)?;
    let usage = get_usage(&state.pool, &auth.npub)
        .await
        .map_err(internal_error)?;

    Ok(Json(EntitlementResponse {
        plan: entitlement.as_ref().map(|row| row.product_id.clone()),
        status: entitlement
            .as_ref()
            .map(|row| row.status.clone())
            .unwrap_or_else(|| "none".to_string()),
        expires_at: entitlement.as_ref().map(|row| row.expires_at.to_rfc3339()),
        quota_bytes: entitlement
            .as_ref()
            .map(|row| row.quota_bytes.to_string())
            .unwrap_or_else(|| "0".to_string()),
        used_bytes: usage
            .as_ref()
            .map(|row| row.stored_bytes.to_string())
            .unwrap_or_else(|| "0".to_string()),
    }))
}

async fn get_moderator_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ModeratorKeyResponse>, (StatusCode, String)> {
    let _ = authenticated(&state, &headers, Method::GET, "/safety/moderator-key", None).await?;

    let configured = state
        .config
        .moderator_npub
        .clone()
        .or_else(|| {
            state
                .config
                .moderator_public_key
                .as_deref()
                .and_then(parse_public_key_hex)
        })
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Moderator key not configured".to_string(),
            )
        })?;

    Ok(Json(ModeratorKeyResponse { npub: configured }))
}

async fn upload_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UploadAuthorizeBody>,
) -> Result<Json<UploadAuthorizeResponse>, (StatusCode, String)> {
    let auth = authenticated(&state, &headers, Method::POST, "/upload/authorize", None).await?;

    let filename = body
        .filename
        .ok_or_else(|| bad_request("filename, content_type, and size_bytes are required"))?;
    let content_type = body
        .content_type
        .ok_or_else(|| bad_request("filename, content_type, and size_bytes are required"))?;
    let size_bytes = body
        .size_bytes
        .ok_or_else(|| bad_request("filename, content_type, and size_bytes are required"))?;

    let entitlement = get_entitlement_for_npub(&state.pool, &state.config, &auth.npub)
        .await
        .map_err(internal_error)?;

    let Some(entitlement) = entitlement else {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            "No active subscription".to_string(),
        ));
    };

    if matches!(
        entitlement.status.as_str(),
        "expired" | "canceled" | "paused"
    ) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            "No active subscription".to_string(),
        ));
    }

    ensure_user_exists(&state.pool, &auth.npub)
        .await
        .map_err(internal_error)?;

    let upload_id = Uuid::new_v4().to_string();
    {
        let conn = state.pool.lock().expect("db lock poisoned");
        conn.execute(
            r#"
            INSERT INTO "Upload" ("id", "npub", "sha256", "status", "sizeBytes", "contentType")
            VALUES (?, ?, NULL, 'pending', ?, ?)
            "#,
            params![&upload_id, &auth.npub, size_bytes, content_type],
        )
        .map_err(internal_error)?;
    }

    increment_usage(&state.pool, &auth.npub, size_bytes)
        .await
        .map_err(internal_error)?;

    let _ = filename;
    Ok(Json(UploadAuthorizeResponse {
        upload_id,
        blossom_url: state.config.blossom_public_url.clone(),
    }))
}

async fn upload_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UploadCompleteBody>,
) -> Result<Json<UploadCompleteResponse>, (StatusCode, String)> {
    let auth = authenticated(&state, &headers, Method::POST, "/upload/complete", None).await?;

    let upload_id = body
        .upload_id
        .ok_or_else(|| bad_request("upload_id and sha256 are required"))?;
    let sha256 = body
        .sha256
        .ok_or_else(|| bad_request("upload_id and sha256 are required"))?;

    if !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) || sha256.len() != 64 {
        return Err(bad_request("sha256 must be a 64-character hex string"));
    }

    let upload = {
        let conn = state.pool.lock().expect("db lock poisoned");
        conn.query_row(
            r#"SELECT "id", "npub", "sha256", "status" FROM "Upload" WHERE "id" = ?"#,
            params![&upload_id],
            |row| {
                Ok(UploadRow {
                    id: row.get(0)?,
                    npub: row.get(1)?,
                    sha256: row.get(2)?,
                    status: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(internal_error)?
    };

    let Some(upload) = upload else {
        return Err((StatusCode::NOT_FOUND, "Upload not found".to_string()));
    };

    if upload.npub != auth.npub {
        return Err((StatusCode::NOT_FOUND, "Upload not found".to_string()));
    }
    if upload.status != "pending" {
        return Err((StatusCode::CONFLICT, "Upload already completed".to_string()));
    }

    {
        let conn = state.pool.lock().expect("db lock poisoned");
        conn.execute(
            r#"
            UPDATE "Upload"
            SET "sha256" = ?, "status" = 'uploaded', "sizeBytes" = COALESCE(?, "sizeBytes")
            WHERE "id" = ?
            "#,
            params![&sha256, body.size_bytes, &upload_id],
        )
        .map_err(internal_error)?;
    }

    let _ = upload.sha256;
    Ok(Json(UploadCompleteResponse {
        url: blob_url(&state.config.blossom_public_url, &sha256),
    }))
}

async fn download_url(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DownloadUrlBody>,
) -> Result<Json<DownloadUrlResponse>, (StatusCode, String)> {
    let _ = authenticated(&state, &headers, Method::POST, "/download/url", None).await?;
    let sha256 = body
        .sha256
        .ok_or_else(|| bad_request("sha256 is required"))?;

    Ok(Json(DownloadUrlResponse {
        url: blob_url(&state.config.blossom_public_url, &sha256),
    }))
}

async fn webhook_appstore() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn webhook_play() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccountDeleteResponse>, (StatusCode, String)> {
    let auth = authenticated(&state, &headers, Method::DELETE, "/account", None).await?;
    let npub = auth.npub.clone();

    let deleted = {
        let conn = state.pool.lock().expect("db lock poisoned");
        let apple = conn
            .execute(
                r#"DELETE FROM "ApplePurchase" WHERE "npub" = ?"#,
                params![&npub],
            )
            .map_err(internal_error)?;
        let google = conn
            .execute(
                r#"DELETE FROM "GooglePurchase" WHERE "npub" = ?"#,
                params![&npub],
            )
            .map_err(internal_error)?;
        let uploads = conn
            .execute(r#"DELETE FROM "Upload" WHERE "npub" = ?"#, params![&npub])
            .map_err(internal_error)?;
        let entitlements = conn
            .execute(
                r#"DELETE FROM "Entitlement" WHERE "npub" = ?"#,
                params![&npub],
            )
            .map_err(internal_error)?;
        let usage = conn
            .execute(r#"DELETE FROM "Usage" WHERE "npub" = ?"#, params![&npub])
            .map_err(internal_error)?;
        let users = conn
            .execute(r#"DELETE FROM "User" WHERE "npub" = ?"#, params![&npub])
            .map_err(internal_error)?;

        AccountDeletedCounts {
            apple_purchases: apple,
            google_purchases: google,
            uploads,
            entitlements,
            usage,
            users,
        }
    };

    Ok(Json(AccountDeleteResponse {
        ok: true,
        npub,
        deleted,
    }))
}

fn hash_family_npub(npub: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("beta-funnel:{npub}"));
    format!("{:x}", hasher.finalize())
}

async fn beta_funnel_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BetaFunnelEventBody>,
) -> Result<Json<BetaFunnelEventResponse>, (StatusCode, String)> {
    // Auth is optional for this endpoint — used only for familyHash
    let auth = authenticated(&state, &headers, Method::POST, "/beta/funnel-events", None)
        .await
        .ok();

    let source = body
        .source
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if source.is_empty() || !BETA_FUNNEL_SOURCES.contains(&source.as_str()) {
        return Err(bad_request("source must be one of: app, marketing"));
    }

    let event_name = body
        .event_name
        .as_deref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if event_name.is_empty() {
        return Err(bad_request("event_name is required"));
    }

    let platform = body
        .platform
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let session_id = body
        .session_id
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let context_json = body.context.as_ref().map(|v| v.to_string());
    let family_hash = auth.as_ref().map(|a| hash_family_npub(&a.npub));

    let id = Uuid::new_v4().to_string();
    {
        let conn = state.pool.lock().expect("db lock poisoned");
        conn.execute(
            r#"
            INSERT INTO "BetaFunnelEvent" ("id", "source", "eventName", "platform", "familyHash", "sessionId", "contextJson")
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            params![&id, &source, &event_name, &platform, &family_hash, &session_id, &context_json],
        )
        .map_err(internal_error)?;
    }

    Ok(Json(BetaFunnelEventResponse { ok: true, id }))
}

async fn beta_funnel_summary(
    State(state): State<AppState>,
    Query(query): Query<BetaFunnelSummaryQuery>,
) -> Result<Json<BetaFunnelSummaryResponse>, (StatusCode, String)> {
    let days: i64 = query
        .days
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7)
        .max(1)
        .min(90);

    let since = Utc::now() - chrono::Duration::days(days);
    let since_str = since.to_rfc3339();

    let rows: Vec<(String, String, Option<String>)> = {
        let conn = state.pool.lock().expect("db lock poisoned");
        let mut stmt = conn
            .prepare(
                r#"
                SELECT "eventName", "source", "familyHash"
                FROM "BetaFunnelEvent"
                WHERE "createdAt" >= ?
                ORDER BY "createdAt" ASC
                "#,
            )
            .map_err(internal_error)?;
        let rows = stmt
            .query_map(params![&since_str], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(internal_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(internal_error)?
    };

    let total = rows.len();
    let mut by_event: HashMap<String, (String, usize, std::collections::HashSet<String>)> =
        HashMap::new();

    for (event_name, source, family_hash) in &rows {
        let entry = by_event
            .entry(event_name.clone())
            .or_insert_with(|| (source.clone(), 0, std::collections::HashSet::new()));
        entry.1 += 1;
        if let Some(fh) = family_hash {
            entry.2.insert(fh.clone());
        }
    }

    let mut events: Vec<BetaFunnelEventSummary> = by_event
        .into_iter()
        .map(|(event_name, (source, total, families))| BetaFunnelEventSummary {
            event_name,
            source,
            total,
            unique_families: families.len(),
        })
        .collect();
    events.sort_by(|a, b| a.event_name.cmp(&b.event_name));

    Ok(Json(BetaFunnelSummaryResponse {
        window_days: days,
        since: since_str,
        totals: total,
        events,
    }))
}

async fn safety_hq_bootstrap(
    State(state): State<AppState>,
) -> Result<Json<BootstrapResponse>, (StatusCode, String)> {
    state
        .safety_hq
        .bootstrap()
        .await
        .map(Json)
        .map_err(internal_error)
}

async fn safety_hq_cases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CaseQuery>,
) -> Result<Json<Vec<ModerationCase>>, (StatusCode, String)> {
    let _ = authenticated(&state, &headers, Method::GET, "/v1/safety-hq/cases", None).await?;
    state
        .safety_hq
        .list_cases(&query)
        .await
        .map(Json)
        .map_err(internal_error)
}

async fn safety_hq_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(report_id): Path<String>,
) -> Result<Json<ModerationCase>, (StatusCode, String)> {
    let path = format!("/v1/safety-hq/cases/{report_id}");
    let _ = authenticated(&state, &headers, Method::GET, &path, None).await?;
    match state
        .safety_hq
        .get_case(&report_id)
        .await
        .map_err(internal_error)?
    {
        Some(case) => Ok(Json(case)),
        None => Err((StatusCode::NOT_FOUND, "Case not found".to_string())),
    }
}

async fn safety_hq_case_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(report_id): Path<String>,
    body: Bytes,
) -> Result<Json<ModerationCase>, (StatusCode, String)> {
    let path = format!("/v1/safety-hq/cases/{report_id}/status");
    let _auth = authenticated(&state, &headers, Method::POST, &path, Some(&body)).await?;
    let update: CaseStatusUpdate =
        serde_json::from_slice(&body).map_err(|_| bad_request("invalid status payload"))?;

    match state
        .safety_hq
        .update_case_status(&report_id, &update)
        .await
        .map_err(internal_error)?
    {
        Some(case) => Ok(Json(case)),
        None => Err((StatusCode::NOT_FOUND, "Case not found".to_string())),
    }
}

async fn authenticated(
    state: &AppState,
    headers: &HeaderMap,
    method: Method,
    path: &str,
    body: Option<&[u8]>,
) -> Result<AuthenticatedUser, (StatusCode, String)> {
    require_nip98_auth(state, headers, &method, path, body).await
}

fn bad_request(message: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.to_string())
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!(error = %error, "request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error".to_string(),
    )
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use http::{Request, StatusCode};
    use nostr_sdk::{
        Url,
        nips::nip98::{HttpData, HttpMethod},
        prelude::{EventBuilder, JsonUtil, Keys},
    };
    use tower::ServiceExt;

    use super::*;

    async fn test_state() -> AppState {
        let config = AppConfig {
            port: 0,
            host: "127.0.0.1".to_string(),
            node_env: "test".to_string(),
            database_url: format!("sqlite:./prisma/test-rust-{}.db", Uuid::new_v4()),
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
            safety_hq_mdk_db_path: format!("./prisma/mdk-test-{}.db", Uuid::new_v4()),
        };
        build_state(config).await.expect("state")
    }

    #[tokio::test]
    async fn health_route_works() {
        let state = test_state().await;
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["safety_hq"]["ready"], false);
    }

    #[tokio::test]
    async fn entitlement_requires_auth() {
        let state = test_state().await;
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/entitlement")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    fn build_nip98_header(url: &str, method: HttpMethod, use_url_safe: bool) -> String {
        let keys = Keys::generate();
        let event = EventBuilder::http_auth(HttpData::new(Url::parse(url).expect("url"), method))
            .sign_with_keys(&keys)
            .expect("signed auth event");
        let payload = if use_url_safe {
            URL_SAFE_NO_PAD.encode(event.as_json())
        } else {
            STANDARD.encode(event.as_json())
        };
        format!("Nostr {payload}")
    }

    #[tokio::test]
    async fn entitlement_accepts_standard_nip98_tags() {
        let state = test_state().await;
        let app = build_router(state);
        let auth = build_nip98_header("http://localhost/entitlement", HttpMethod::GET, false);

        let res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/entitlement")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn entitlement_accepts_urlsafe_nip98_header() {
        let state = test_state().await;
        let app = build_router(state);
        let auth = build_nip98_header("http://localhost/entitlement", HttpMethod::GET, true);

        let res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/entitlement")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn safety_hq_bootstrap_works() {
        let state = test_state().await;
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/safety-hq/bootstrap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["service_public_key_hex"].as_str().unwrap().len() == 64);
    }
}
