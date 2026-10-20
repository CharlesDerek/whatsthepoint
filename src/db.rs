use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, time::Duration};

pub async fn open(data_dir: &Path) -> anyhow::Result<SqlitePool> {
    std::fs::create_dir_all(data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let options = SqliteConnectOptions::new()
        .filename(data_dir.join("wtp.db"))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10));
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub async fn audit(
    pool: &SqlitePool,
    actor: &str,
    event: &str,
    detail: &str,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO audit(at, actor, event, detail) VALUES (?, ?, ?, ?)")
        .bind(crate::now())
        .bind(actor)
        .bind(event)
        .bind(detail)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn prune(pool: &SqlitePool, days: u32, max: u32) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM queries WHERE at < ?")
        .bind(crate::now() - i64::from(days) * 86400)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM queries WHERE id <= (SELECT id FROM queries ORDER BY id DESC LIMIT 1 OFFSET ?)")
        .bind(max).execute(pool).await?;
    sqlx::query("DELETE FROM browser_events WHERE at < ?")
        .bind(crate::now() - i64::from(days) * 86400)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM browser_events WHERE id <= (SELECT id FROM browser_events ORDER BY id DESC LIMIT 1 OFFSET ?)")
        .bind(max).execute(pool).await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(crate::now())
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 10000)")
        .execute(pool).await?;
    Ok(())
}
