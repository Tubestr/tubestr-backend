use std::env;

use anyhow::{Result, anyhow};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
    pub node_env: String,
    pub database_url: String,
    pub blossom_server_url: String,
    pub blossom_public_url: String,
    pub nip98_challenge_ttl_seconds: u64,
    pub free_trial_enabled: bool,
    pub free_trial_days: i64,
    pub moderator_npub: Option<String>,
    pub moderator_public_key: Option<String>,
    pub safety_hq_secret_key_hex: Option<String>,
    pub safety_hq_relays: Vec<String>,
    pub safety_hq_version: String,
    pub safety_hq_mdk_db_path: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let database_url = required("DATABASE_URL")?;
        Ok(Self {
            port: number("PORT", 8080_u16),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            node_env: env::var("NODE_ENV").unwrap_or_else(|_| "production".to_string()),
            blossom_server_url: required("BLOSSOM_SERVER_URL")?,
            blossom_public_url: required("BLOSSOM_PUBLIC_URL")?,
            nip98_challenge_ttl_seconds: number("NIP98_CHALLENGE_TTL_SECONDS", 300_u64),
            free_trial_enabled: boolean("FREE_TRIAL_MODE", false),
            free_trial_days: number("FREE_TRIAL_DAYS", 30_i64),
            moderator_npub: env::var("MODERATOR_NPUB").ok(),
            moderator_public_key: env::var("MODERATOR_PUBLIC_KEY").ok(),
            safety_hq_secret_key_hex: env::var("SAFETY_HQ_SECRET_KEY_HEX").ok(),
            safety_hq_relays: relay_list(
                "SAFETY_HQ_RELAYS",
                &["wss://no.str.cr", "wss://relay.primal.net", "wss://nos.lol"],
            ),
            safety_hq_version: env::var("SAFETY_HQ_VERSION").unwrap_or_else(|_| "v1".to_string()),
            safety_hq_mdk_db_path: env::var("SAFETY_HQ_MDK_DB_PATH")
                .unwrap_or_else(|_| "./data/safety-hq-mdk.sqlite".to_string()),
            database_url: normalize_database_url(&database_url),
        })
    }
}

fn required(key: &str) -> Result<String> {
    env::var(key).map_err(|_| anyhow!("missing required environment variable: {key}"))
}

fn number<T>(key: &str, fallback: T) -> T
where
    T: std::str::FromStr + Copy,
{
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(fallback)
}

fn boolean(key: &str, fallback: bool) -> bool {
    env::var(key)
        .ok()
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(fallback)
}

fn relay_list(key: &str, default: &[&str]) -> Vec<String> {
    env::var(key)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| default.iter().map(|item| (*item).to_string()).collect())
}

fn normalize_database_url(input: &str) -> String {
    if let Some(path) = input.strip_prefix("file:") {
        return format!("sqlite:{path}");
    }
    if input.starts_with("sqlite:") {
        return input.to_string();
    }
    format!("sqlite:{input}")
}
