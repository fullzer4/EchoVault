use anyhow::Context;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub listen: String,
    pub database_url: String,
    pub jwt_secret: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen = std::env::var("EV_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let database_url = std::env::var("EV_DATABASE_URL").unwrap_or_else(|_| "sqlite:./data/echovault.db?mode=rwc".to_string());
        let jwt_secret = std::env::var("EV_JWT_SECRET").context("EV_JWT_SECRET must be set for production")
            .unwrap_or_else(|_| "dev-secret-change-me".into());
        Ok(Self { listen, database_url, jwt_secret })
    }
}
