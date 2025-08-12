use axum::{routing::get, Router};

pub fn health_router() -> Router {
    Router::new().route("/health", get(|| async { "ok" }))
}
