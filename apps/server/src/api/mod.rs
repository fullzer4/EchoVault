use axum::Router;

use crate::telemetry::health_router;

pub fn router(db: crate::db::Db, cfg: crate::config::Config) -> Router {
    crate::auth::routes::router(db, cfg)
        .merge(health_router())
}
