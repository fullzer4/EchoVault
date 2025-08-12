use anyhow::Context;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub listen: String,
    pub data_dir: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub public_origin: Option<String>,
    pub jwt_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
    pub rp_id: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen = std::env::var("EV_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let data_dir = std::env::var("EV_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
        let database_url = std::env::var("EV_DATABASE_URL").unwrap_or_else(|_| format!("sqlite:{}/echovault.db?mode=rwc", data_dir));
        let jwt_secret = std::env::var("EV_JWT_SECRET").context("EV_JWT_SECRET must be set for production")
            .unwrap_or_else(|_| "dev-secret-change-me".into());
        let public_origin = std::env::var("EV_PUBLIC_ORIGIN").ok();
        let jwt_ttl_secs = std::env::var("EV_JWT_TTL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900); // 15m
        let refresh_ttl_secs = std::env::var("EV_REFRESH_TTL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60*60*24*30); // 30d
        let rp_id = std::env::var("EV_RP_ID").ok();
        Ok(Self { listen, data_dir, database_url, jwt_secret, public_origin, jwt_ttl_secs, refresh_ttl_secs, rp_id })
    }
}
