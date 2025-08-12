use axum::{extract::{State, FromRef, OriginalUri}, http::{HeaderMap, StatusCode, header, Method}, response::IntoResponse, routing::{post, get}, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use base64::Engine; // for .encode on URL_SAFE_NO_PAD
use rand::RngCore;
use argon2::{Argon2, password_hash::{PasswordHasher, PasswordVerifier, SaltString}};
use std::sync::Arc;
use webauthn_rs::prelude::*;

use crate::{config::Config, db::Db, auth::tokens};
use crate::auth::dpop::{validate_dpop, ReplayCache};

#[derive(Clone, Debug)]
pub struct Security { pub replay: ReplayCache }

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Config,
    pub sec: Security,
    pub webauthn: Arc<Webauthn>,
}

impl FromRef<AppState> for Db { fn from_ref(s: &AppState) -> Db { s.db.clone() } }
impl FromRef<AppState> for Config { fn from_ref(s: &AppState) -> Config { s.cfg.clone() } }
impl FromRef<AppState> for Security { fn from_ref(s: &AppState) -> Security { s.sec.clone() } }

#[derive(Debug, Deserialize)]
struct BeginRegisterReq { username: String, display_name: Option<String> }
#[derive(Debug, Serialize)]
struct BeginRegisterResp { challenge: CreationChallengeResponse, reg_id: String }

async fn begin_register(State(state): State<AppState>, Json(req): Json<BeginRegisterReq>) -> impl IntoResponse {
    let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if exists > 0 { return (StatusCode::CONFLICT, "username_taken").into_response(); }

    // Generate a stable user id for this registration flow
    let user_id = Uuid::new_v4();
    let display = req.display_name.clone().unwrap_or_else(|| req.username.clone());

    let (challenge, reg_state) = match state.webauthn.start_passkey_registration(
        user_id,
        &req.username,
        &display,
        None,
    ) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "webauthn_error").into_response(),
    };

    let reg_id = Uuid::new_v4().to_string();
    let state_json = match serde_json::to_string(&reg_state) { Ok(s) => s, Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "state_error").into_response() };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let _ = sqlx::query("INSERT INTO webauthn_reg (id, username, user_id, state_json, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&reg_id).bind(&req.username).bind(user_id.to_string()).bind(state_json).bind(now)
        .execute(&state.db).await;

    (StatusCode::OK, Json(BeginRegisterResp{ challenge, reg_id })).into_response()
}

#[derive(Debug, Deserialize)]
struct FinishRegisterReq { reg_id: String, credential: RegisterPublicKeyCredential }

async fn finish_register(State(state): State<AppState>, Json(req): Json<FinishRegisterReq>) -> impl IntoResponse {
    // Load pending state
    let row = sqlx::query_as::<_, (String, String, String)>("SELECT username, user_id, state_json FROM webauthn_reg WHERE id = ?")
        .bind(&req.reg_id)
        .fetch_optional(&state.db).await;

    let Some((username, user_id, state_json)) = (match row { Ok(v) => v, Err(_) => None }) else {
        return (StatusCode::BAD_REQUEST, "invalid_reg").into_response();
    };

    let reg_state: PasskeyRegistration = match serde_json::from_str(&state_json) { Ok(s) => s, Err(_) => return (StatusCode::BAD_REQUEST, "bad_state").into_response() };

    // Complete registration
    let passkey: Passkey = match state.webauthn.finish_passkey_registration(&req.credential, &reg_state) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, "webauthn_verify_failed").into_response(),
    };

    // Create user record (id from begin step)
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let _ = sqlx::query("INSERT OR IGNORE INTO users (id, username, created_at) VALUES (?, ?, ?)")
        .bind(&user_id).bind(&username).bind(now)
        .execute(&state.db).await;

    // Store credential
    let passkey_json = match serde_json::to_string(&passkey) { Ok(s) => s, Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "persist_error").into_response() };
    let cred_row_id = Uuid::new_v4().to_string();
    let _ = sqlx::query("INSERT INTO credentials (id, user_id, passkey_json, created_at) VALUES (?, ?, ?, ?)")
        .bind(&cred_row_id).bind(&user_id).bind(passkey_json).bind(now)
        .execute(&state.db).await;

    // Cleanup
    let _ = sqlx::query("DELETE FROM webauthn_reg WHERE id = ?").bind(&req.reg_id).execute(&state.db).await;

    (StatusCode::CREATED, "registered").into_response()
}

#[derive(Debug, Deserialize)]
struct LoginReq { username: String, jkt: Option<String>, device_name: Option<String> }
#[derive(Debug, Serialize)]
struct LoginResp { access_token: String, expires_at: i64, refresh_token: String }

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> impl IntoResponse {
    let rec = sqlx::query_as::<_, (String,)>("SELECT id FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&state.db).await;

    let user_id = match rec { Ok(Some((id,))) => id, _ => return (StatusCode::UNAUTHORIZED, "invalid_user").into_response() };

    // upsert device
    let device_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let name = req.device_name.unwrap_or_else(|| "device".into());
    let _ = sqlx::query("INSERT INTO devices (id, user_id, name, jkt, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&device_id).bind(&user_id).bind(&name).bind(&req.jkt).bind(now)
        .execute(&state.db).await;

    // access token
    let (access_token, exp) = match tokens::issue_access(&user_id, req.jkt.clone(), &state.cfg.jwt_secret, (state.cfg.jwt_ttl_secs/60).max(1) as i64) {
        Ok(x) => x,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "token_error").into_response(),
    };

    // refresh token (opaque), store argon2 hash
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let refresh = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default().hash_password(refresh.as_bytes(), &salt).map(|p| p.to_string()).unwrap_or_default();

    let _ = sqlx::query("INSERT INTO refresh_tokens (token_hash, user_id, device_id, expires_at, created_at, revoked) VALUES (?, ?, ?, ?, ?, 0)")
        .bind(&hash).bind(&user_id).bind(&device_id).bind(now + state.cfg.refresh_ttl_secs).bind(now)
        .execute(&state.db).await;

    (StatusCode::OK, Json(LoginResp { access_token, expires_at: exp, refresh_token: refresh })).into_response()
}

#[derive(Debug, Deserialize)]
struct RefreshReq { refresh_token: String, jkt: Option<String> }
#[derive(Debug, Serialize)]
struct RefreshResp { access_token: String, expires_at: i64, refresh_token: String }

async fn refresh(State(state): State<AppState>, headers: HeaderMap, method: Method, original_uri: OriginalUri, Json(req_body): Json<RefreshReq>) -> impl IntoResponse {
    // Find matching hash (runtime query to avoid sqlx compile-time DB access)
    let rows = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT token_hash, user_id, device_id, expires_at, revoked FROM refresh_tokens"
    )
    .fetch_all(&state.db).await;

    let Ok(rows) = rows else { return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response() };

    let mut matched: Option<(String, String)> = None; // (user_id, device_id)
    for (token_hash, user_id, device_id, expires_at, revoked) in rows {
        if revoked != 0 { continue; }
        if expires_at < OffsetDateTime::now_utc().unix_timestamp() { continue; }
        let parsed = match argon2::PasswordHash::new(&token_hash) { Ok(p) => p, Err(_) => continue };
        if Argon2::default().verify_password(req_body.refresh_token.as_bytes(), &parsed).is_ok() {
            matched = Some((user_id, device_id));
            break;
        }
    }

    let Some((user_id, device_id)) = matched else { return (StatusCode::UNAUTHORIZED, "invalid_refresh").into_response() };

    // Update device metadata
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()));
    let now_ts = OffsetDateTime::now_utc().unix_timestamp();
    let _ = sqlx::query("UPDATE devices SET last_seen = ?, ua = COALESCE(?, ua), ip = COALESCE(?, ip) WHERE id = ?")
        .bind(now_ts).bind(ua).bind(ip).bind(&device_id)
        .execute(&state.db).await;

    // If device has jkt, enforce DPoP; if absent, bind on first valid DPoP
    let device_jkt = sqlx::query_scalar::<_, Option<String>>("SELECT jkt FROM devices WHERE id = ?")
        .bind(&device_id)
        .fetch_one(&state.db).await.ok().flatten();

    let dpop = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let method_str = method.as_str();
    let path_q = original_uri.0.path_and_query().map(|pq| pq.as_str()).unwrap_or(original_uri.0.path());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = state.cfg.public_origin.as_deref();

    match device_jkt {
        Some(required_jkt) => {
            if dpop.is_none() { return (StatusCode::UNAUTHORIZED, "missing_dpop").into_response(); }
            if validate_dpop(method_str, host, path_q, dpop.unwrap(), &required_jkt, origin, &state.sec.replay, now_ts).is_err() {
                return (StatusCode::UNAUTHORIZED, "invalid_dpop").into_response();
            }
        }
        None => {
            if let Some(dpop_val) = dpop {
                // Try to validate and bind
                match crate::auth::dpop::validate_dpop_and_get_jkt(method_str, host, path_q, dpop_val, origin, &state.sec.replay, now_ts) {
                    Ok(jkt) => {
                        let _ = sqlx::query("UPDATE devices SET jkt = ? WHERE id = ?").bind(&jkt).bind(&device_id).execute(&state.db).await;
                    }
                    Err(_) => return (StatusCode::UNAUTHORIZED, "invalid_dpop").into_response(),
                }
            }
        }
    }

    // rotate: revoke all matching hashes for this device (reuse detection simplified)
    let _ = sqlx::query("UPDATE refresh_tokens SET revoked = 1, last_used_at = ? WHERE device_id = ? AND revoked = 0")
        .bind(OffsetDateTime::now_utc().unix_timestamp()).bind(&device_id).execute(&state.db).await;

    // issue new access
    let (access_token, exp) = match tokens::issue_access(&user_id, req_body.jkt.clone(), &state.cfg.jwt_secret, (state.cfg.jwt_ttl_secs/60).max(1) as i64) {
        Ok(x) => x,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "token_error").into_response(),
    };

    // new refresh
    let mut raw = [0u8; 32]; rand::thread_rng().fill_bytes(&mut raw);
    let refresh = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default().hash_password(refresh.as_bytes(), &salt).map(|p| p.to_string()).unwrap_or_default();

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let _ = sqlx::query("INSERT INTO refresh_tokens (token_hash, user_id, device_id, expires_at, created_at, revoked) VALUES (?, ?, ?, ?, ?, 0)")
        .bind(&hash).bind(&user_id).bind(&device_id).bind(now + state.cfg.refresh_ttl_secs).bind(now)
        .execute(&state.db).await;

    (StatusCode::OK, Json(RefreshResp { access_token, expires_at: exp, refresh_token: refresh })).into_response()
}

// Extractor that validates Bearer and DPoP
struct AuthCtx { pub sub: String }

async fn require_dpop(State(state): State<AppState>, headers: HeaderMap, method: Method, original_uri: OriginalUri) -> Result<AuthCtx, (StatusCode, &'static str)> {
    // Authorization
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "missing_auth"))?;
    if !auth.starts_with("Bearer ") { return Err((StatusCode::UNAUTHORIZED, "invalid_auth")); }
    let token = &auth[7..];

    // Decode token and get cnf.jkt
    let data = tokens::decode(token, &state.cfg.jwt_secret).map_err(|_| (StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let sub = data.claims.sub.clone();
    let jkt = data.claims.cnf.as_ref().map(|c| c.jkt.clone()).ok_or((StatusCode::UNAUTHORIZED, "missing_cnf"))?;

    // DPoP header
    let dpop = headers.get("DPoP").and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "missing_dpop"))?;

    // Build request context
    let method = method.as_str();
    let path_q = original_uri.0.path_and_query().map(|pq| pq.as_str()).unwrap_or(original_uri.0.path());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let origin = state.cfg.public_origin.as_deref();
    validate_dpop(method, host, path_q, dpop, &jkt, origin, &state.sec.replay, now)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid_dpop"))?;
    Ok(AuthCtx { sub })
}

async fn me(State(state): State<AppState>, headers: HeaderMap, method: Method, original_uri: OriginalUri) -> impl IntoResponse {
    // Update device metadata could be added here when we have device_id in the JWT
    match require_dpop(State(state.clone()), headers, method, original_uri).await {
        Ok(ctx) => (StatusCode::OK, Json(serde_json::json!({"sub": ctx.sub }))).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct BeginLoginReq { username: String }
#[derive(Debug, Serialize)]
struct BeginLoginResp { challenge: RequestChallengeResponse, auth_id: String }

async fn begin_login(State(state): State<AppState>, Json(req): Json<BeginLoginReq>) -> impl IntoResponse {
    // Find user and their credentials
    let user_row = sqlx::query_as::<_, (String,)>("SELECT id FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&state.db).await;
    let Some((user_id,)) = (match user_row { Ok(v) => v, Err(_) => None }) else {
        return (StatusCode::UNAUTHORIZED, "invalid_user").into_response();
    };

    let creds_json: Vec<(String,)> = sqlx::query_as("SELECT passkey_json FROM credentials WHERE user_id = ?")
        .bind(&user_id)
        .fetch_all(&state.db).await.unwrap_or_default();
    let mut passkeys: Vec<Passkey> = Vec::new();
    for (pjson,) in creds_json {
        if let Ok(pk) = serde_json::from_str::<Passkey>(&pjson) { passkeys.push(pk); }
    }

    let (challenge, auth_state) = match state.webauthn.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "webauthn_error").into_response(),
    };

    let auth_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let state_json = serde_json::to_string(&auth_state).unwrap_or_default();
    let _ = sqlx::query("INSERT INTO webauthn_reg (id, username, user_id, state_json, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&auth_id).bind(&req.username).bind(&user_id).bind(state_json).bind(now)
        .execute(&state.db).await;

    (StatusCode::OK, Json(BeginLoginResp { challenge, auth_id })).into_response()
}

#[derive(Debug, Deserialize)]
struct FinishLoginReq { auth_id: String, credential: PublicKeyCredential, jkt: Option<String>, device_name: Option<String> }

async fn finish_login(State(state): State<AppState>, headers: HeaderMap, method: Method, original_uri: OriginalUri, Json(req): Json<FinishLoginReq>) -> impl IntoResponse {
    // Load pending auth state
    let row = sqlx::query_as::<_, (String, String, String)>("SELECT username, user_id, state_json FROM webauthn_reg WHERE id = ?")
        .bind(&req.auth_id)
        .fetch_optional(&state.db).await;
    let Some((username, user_id, state_json)) = (match row { Ok(v) => v, Err(_) => None }) else {
        return (StatusCode::BAD_REQUEST, "invalid_auth").into_response();
    };

    let auth_state: PasskeyAuthentication = match serde_json::from_str(&state_json) { Ok(s) => s, Err(_) => return (StatusCode::BAD_REQUEST, "bad_state").into_response() };

    // Load passkeys
    let creds_json: Vec<(String,)> = sqlx::query_as("SELECT passkey_json FROM credentials WHERE user_id = ?")
        .bind(&user_id)
        .fetch_all(&state.db).await.unwrap_or_default();
    let mut passkeys: Vec<Passkey> = Vec::new();
    for (pjson,) in creds_json { if let Ok(pk) = serde_json::from_str::<Passkey>(&pjson) { passkeys.push(pk); } }

    // Complete authentication
    let result = match state.webauthn.finish_passkey_authentication(&req.credential, &auth_state) {
        Ok(r) => r,
        Err(_) => return (StatusCode::UNAUTHORIZED, "webauthn_verify_failed").into_response(),
    };
    let _ = result;

    // If client provided jkt, require DPoP and ensure match; use computed jkt for device/token
    let token_jkt: Option<String> = if let Some(provided) = &req.jkt {
        let dpop = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => return (StatusCode::UNAUTHORIZED, "missing_dpop").into_response(),
        };
        let method_str = method.as_str();
        let path_q = original_uri.0.path_and_query().map(|pq| pq.as_str()).unwrap_or(original_uri.0.path());
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
        let now_ts = OffsetDateTime::now_utc().unix_timestamp();
        let origin = state.cfg.public_origin.as_deref();
        match crate::auth::dpop::validate_dpop_and_get_jkt(method_str, host, path_q, dpop, origin, &state.sec.replay, now_ts) {
            Ok(calc) => {
                if &calc != provided { return (StatusCode::UNAUTHORIZED, "jkt_mismatch").into_response(); }
                Some(calc)
            }
            Err(_) => return (StatusCode::UNAUTHORIZED, "invalid_dpop").into_response(),
        }
    } else { None };

    // Create a new device entry (per login)
    let device_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let name = req.device_name.clone().unwrap_or_else(|| "device".into());
    let _ = sqlx::query("INSERT INTO devices (id, user_id, name, jkt, ua, ip, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)" )
        .bind(&device_id).bind(&user_id).bind(&name).bind(&token_jkt)
        .bind(headers.get("user-agent").and_then(|v| v.to_str().ok()))
        .bind(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok())))
        .bind(now).bind(now)
        .execute(&state.db).await;

    // Issue tokens
    let (access_token, exp) = match tokens::issue_access(&user_id, token_jkt.clone(), &state.cfg.jwt_secret, (state.cfg.jwt_ttl_secs/60).max(1) as i64) { Ok(x) => x, Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "token_error").into_response() };

    let mut raw = [0u8; 32]; rand::thread_rng().fill_bytes(&mut raw);
    let refresh = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default().hash_password(refresh.as_bytes(), &salt).map(|p| p.to_string()).unwrap_or_default();
    let _ = sqlx::query("INSERT INTO refresh_tokens (token_hash, user_id, device_id, expires_at, created_at, revoked) VALUES (?, ?, ?, ?, ?, 0)")
        .bind(&hash).bind(&user_id).bind(&device_id).bind(now + state.cfg.refresh_ttl_secs).bind(now)
        .execute(&state.db).await;

    // Cleanup auth state
    let _ = sqlx::query("DELETE FROM webauthn_reg WHERE id = ?").bind(&req.auth_id).execute(&state.db).await;

    #[derive(Serialize)]
    struct LoginResp { access_token: String, expires_at: i64, refresh_token: String }
    (StatusCode::OK, Json(LoginResp { access_token, expires_at: exp, refresh_token: refresh })).into_response()
}

pub fn router(db: Db, cfg: Config) -> Router {
    let origin = cfg.public_origin.clone().expect("EV_PUBLIC_ORIGIN must be set for WebAuthn");
    let url = Url::parse(&origin).expect("valid EV_PUBLIC_ORIGIN");
    let rp_id = cfg.rp_id.clone().unwrap_or_else(|| url.domain().map(|s| s.to_string()).or_else(|| url.host_str().map(|s| s.to_string())).unwrap_or_else(|| "localhost".to_string()));

    let builder = WebauthnBuilder::new(&rp_id, &url).expect("valid WebAuthn config");
    let webauthn = builder.build().expect("valid WebAuthn build");

    let state = AppState { db, cfg, sec: Security { replay: ReplayCache::new(300) }, webauthn: Arc::new(webauthn) };
    Router::new()
        .route("/auth/register", post(begin_register))
        .route("/auth/register/finish", post(finish_register))
        .route("/auth/login/begin", post(begin_login))
        .route("/auth/login/finish", post(finish_login))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/me", get(me))
        .with_state(state)
}
