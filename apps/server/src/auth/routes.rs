use axum::{extract::{State, FromRef, Request}, http::{HeaderMap, StatusCode, header}, response::IntoResponse, routing::{post, get}, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use base64::Engine; // for .encode on URL_SAFE_NO_PAD
use rand::RngCore;
use argon2::{Argon2, password_hash::{PasswordHasher, PasswordVerifier, SaltString}};

use crate::{config::Config, db::Db, auth::tokens};
use crate::auth::dpop::{validate_dpop, ReplayCache};
use http::Request as HttpRequest;

#[derive(Clone)]
struct Security { replay: ReplayCache }

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Config,
    pub sec: Security,
}

impl FromRef<AppState> for Db { fn from_ref(s: &AppState) -> Db { s.db.clone() } }
impl FromRef<AppState> for Config { fn from_ref(s: &AppState) -> Config { s.cfg.clone() } }
impl FromRef<AppState> for Security { fn from_ref(s: &AppState) -> Security { s.sec.clone() } }

#[derive(Debug, Deserialize)]
struct BeginRegisterReq { username: String }
#[derive(Debug, Serialize)]
struct BeginRegisterResp { challenge: String }

async fn begin_register(State(state): State<AppState>, Json(req): Json<BeginRegisterReq>) -> impl IntoResponse {
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());

    let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if exists > 0 { return (StatusCode::CONFLICT, "username_taken").into_response(); }

    (StatusCode::OK, Json(BeginRegisterResp{ challenge })).into_response()
}

#[derive(Debug, Deserialize)]
struct FinishRegisterReq { username: String }

async fn finish_register(State(state): State<AppState>, Json(req): Json<FinishRegisterReq>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let res = sqlx::query("INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)")
        .bind(&id).bind(&req.username).bind(now)
        .execute(&state.db).await;

    match res {
        Ok(_) => (StatusCode::CREATED, "registered").into_response(),
        Err(e) if e.as_database_error().map(|d| d.message().contains("UNIQUE")).unwrap_or(false) => (StatusCode::CONFLICT, "username_taken").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response(),
    }
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
    let (access_token, exp) = match tokens::issue_access(&user_id, req.jkt.clone(), &state.cfg.jwt_secret, 15) {
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
        .bind(&hash).bind(&user_id).bind(&device_id).bind(now + 60*60*24*30).bind(now)
        .execute(&state.db).await;

    (StatusCode::OK, Json(LoginResp { access_token, expires_at: exp, refresh_token: refresh })).into_response()
}

#[derive(Debug, Deserialize)]
struct RefreshReq { refresh_token: String, jkt: Option<String> }
#[derive(Debug, Serialize)]
struct RefreshResp { access_token: String, expires_at: i64, refresh_token: String }

async fn refresh(State(state): State<AppState>, Json(req): Json<RefreshReq>) -> impl IntoResponse {
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
        if Argon2::default().verify_password(req.refresh_token.as_bytes(), &parsed).is_ok() {
            matched = Some((user_id, device_id));
            break;
        }
    }

    let Some((user_id, device_id)) = matched else { return (StatusCode::UNAUTHORIZED, "invalid_refresh").into_response() };

    // rotate: revoke all matching hashes for this device (reuse detection simplified)
    let _ = sqlx::query("UPDATE refresh_tokens SET revoked = 1, last_used_at = ? WHERE device_id = ? AND revoked = 0")
        .bind(OffsetDateTime::now_utc().unix_timestamp()).bind(&device_id).execute(&state.db).await;

    // issue new access
    let (access_token, exp) = match tokens::issue_access(&user_id, req.jkt.clone(), &state.cfg.jwt_secret, 15) {
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
        .bind(&hash).bind(&user_id).bind(&device_id).bind(now + 60*60*24*30).bind(now)
        .execute(&state.db).await;

    (StatusCode::OK, Json(RefreshResp { access_token, expires_at: exp, refresh_token: refresh })).into_response()
}

// Extractor that validates Bearer and DPoP
struct AuthCtx { pub sub: String }

async fn require_dpop(State(state): State<AppState>, headers: HeaderMap, req: Request) -> Result<AuthCtx, (StatusCode, &'static str)> {
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
    let method = req.method().as_str();
    let path_q = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or(req.uri().path());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());

    let now = OffsetDateTime::now_utc().unix_timestamp();
    validate_dpop(method, host, path_q, dpop, &jkt, None, &state.sec.replay, now)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid_dpop"))?;

    Ok(AuthCtx { sub })
}

async fn me(State(_state): State<AppState>, headers: HeaderMap, req: Request) -> impl IntoResponse {
    match require_dpop(State(_state.clone()), headers, req).await {
        Ok(ctx) => (StatusCode::OK, Json(serde_json::json!({"sub": ctx.sub }))).into_response(),
        Err(e) => e.into_response(),
    }
}

pub fn router(db: Db, cfg: Config) -> Router {
    let state = AppState { db, cfg, sec: Security { replay: ReplayCache::new(300) } };
    Router::new()
        .route("/auth/register", post(begin_register))
        .route("/auth/register/finish", post(finish_register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/me", get(me))
        .with_state(state)
}
