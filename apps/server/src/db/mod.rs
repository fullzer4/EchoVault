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
    // Use SQLx migrations from src/sql/migrations
    sqlx::migrate!("./src/sql/migrations").run(pool).await?;
    Ok(())
}
