use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use axum::http::{HeaderMap, Method, StatusCode};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nostr_sdk::prelude::{Event, JsonUtil, Kind, PublicKey, TagStandard, ToBech32};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::app::AppState;

pub type ChallengeStore = Arc<RwLock<HashMap<String, i64>>>;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub npub: String,
    pub public_key_hex: String,
}

#[derive(Debug, Default)]
struct Nip98Claims {
    challenge: Option<String>,
    method: Option<String>,
    url: Option<String>,
    body_hash: Option<String>,
}

pub async fn require_nip98_auth(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    body: Option<&[u8]>,
) -> Result<AuthenticatedUser, (StatusCode, String)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| unauthorized("NIP-98 authentication required"))?;

    let payload = auth_header
        .strip_prefix("Nostr ")
        .ok_or_else(|| unauthorized("NIP-98 authentication required"))?;

    let json = decode_nip98_payload(payload.trim())
        .map_err(|_| unauthorized("Invalid NIP-98 payload"))?;
    let event = Event::from_json(String::from_utf8_lossy(&json).as_ref())
        .map_err(|_| unauthorized("Invalid NIP-98 event"))?;

    if event.kind != Kind::HttpAuth {
        return Err(unauthorized("Invalid NIP-98 event"));
    }

    if event.verify().is_err() {
        return Err(unauthorized("Invalid NIP-98 signature"));
    }

    let claims = extract_nip98_claims(&event);
    validate_nip98_challenge(state, claims.challenge.as_deref()).await?;

    if claims
        .method
        .map(|value| value.to_uppercase())
        .unwrap_or_default()
        != method.as_str()
    {
        return Err(unauthorized("NIP-98 method mismatch"));
    }

    if let Some(url) = claims.url.as_deref()
        && normalize_request_target(url).as_deref() != Some(path)
    {
        return Err(unauthorized("NIP-98 URL mismatch"));
    }

    if let Some(expected_body_hash) = claims.body_hash.as_deref() {
        let body = body.ok_or_else(|| unauthorized("NIP-98 body hash mismatch"))?;
        let actual = hex::encode(Sha256::digest(body));
        if actual != expected_body_hash {
            return Err(unauthorized("NIP-98 body hash mismatch"));
        }
    }

    let public_key_hex = event.pubkey.to_hex();
    let npub = event
        .pubkey
        .to_bech32()
        .map_err(|_| unauthorized("Failed to encode npub"))?;

    Ok(AuthenticatedUser {
        npub,
        public_key_hex,
    })
}

fn decode_nip98_payload(payload: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(payload)
        .or_else(|_| URL_SAFE_NO_PAD.decode(payload))
}

fn extract_nip98_claims(event: &Event) -> Nip98Claims {
    let params: HashMap<String, String> = url::form_urlencoded::parse(event.content.as_bytes())
        .into_owned()
        .collect();

    let mut claims = Nip98Claims {
        challenge: params.get("challenge").cloned(),
        method: params.get("method").cloned(),
        url: params.get("url").cloned(),
        body_hash: params.get("body").cloned(),
    };

    for tag in event.tags.as_ref() {
        match tag.as_standardized() {
            Some(TagStandard::AbsoluteURL(url)) => claims.url = Some(url.to_string()),
            Some(TagStandard::Method(method)) => claims.method = Some(method.to_string()),
            Some(TagStandard::Payload(hash)) => claims.body_hash = Some(hash.to_string()),
            _ => {}
        }
    }

    claims
}

async fn validate_nip98_challenge(
    state: &AppState,
    challenge: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(challenge) = challenge else {
        return Ok(());
    };

    let mut challenges = state.challenges.write().await;
    let exp = challenges
        .get(challenge)
        .copied()
        .ok_or_else(|| unauthorized("Unknown NIP-98 challenge"))?;

    let now = chrono::Utc::now().timestamp();
    if exp < now {
        challenges.remove(challenge);
        return Err(unauthorized("Expired NIP-98 challenge"));
    }

    challenges.remove(challenge);
    Ok(())
}

fn normalize_request_target(url: &str) -> Option<String> {
    if url.starts_with('/') {
        return Some(url.to_string());
    }

    let parsed = url::Url::parse(url).ok()?;
    let mut target = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Some(target)
}

fn unauthorized(message: &str) -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, message.to_string())
}

pub fn parse_public_key_hex(hex_value: &str) -> Option<String> {
    PublicKey::parse(hex_value)
        .ok()
        .and_then(|pk| pk.to_bech32().ok())
}
