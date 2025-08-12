use sqlx::{sqlite::SqlitePoolOptions, Sqlite, Pool};

pub type Db = Pool<Sqlite>;

fn ensure_sqlite_dir(url: &str) {
    let prefix = "sqlite:";
    if let Some(rest) = url.strip_prefix(prefix) {
        let path_and_q = rest;
        let path = path_and_q.split('?').next().unwrap_or("");
        if !path.is_empty() {
            let p = std::path::Path::new(path);
            let dir = if p.is_absolute() { p.parent().map(|x| x.to_path_buf()) } else { p.parent().map(|x| std::env::current_dir().unwrap().join(x)) };
            if let Some(dir) = dir { let _ = std::fs::create_dir_all(dir); }
        }
    }
}

pub async fn init_pool(url: &str) -> anyhow::Result<Db> {
    ensure_sqlite_dir(url);
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;

    // Ensure WAL mode
    sqlx::query("PRAGMA journal_mode=WAL;").execute(&pool).await?;
    sqlx::query("PRAGMA busy_timeout=5000;").execute(&pool).await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &Db) -> anyhow::Result<()> {
    // Minimal schema for auth with indices and audit fields
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            username TEXT UNIQUE NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            jkt TEXT,
            ua TEXT,
            ip TEXT,
            last_seen INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
        CREATE INDEX IF NOT EXISTS idx_devices_jkt ON devices(jkt);

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            last_used_at INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );
        CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_device ON refresh_tokens(device_id);
        "#
    ).execute(pool).await?;

    Ok(())
}
