use crate::{App, policy::parse_list};
use anyhow::{Context, bail};
use serde::Serialize;
use sqlx::{FromRow, QueryBuilder, Sqlite, SqlitePool};

pub const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Serialize, FromRow)]
pub struct List {
    pub id: i64,
    pub name: String,
    pub preset: Option<String>,
    pub updated_at: Option<i64>,
    pub error: Option<String>,
    pub count: i64,
}

pub fn preset_url(name: &str) -> Option<&'static str> {
    match name {
        "hagezi-light" => Some(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
        ),
        "hagezi-normal" => Some(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        ),
        _ => None,
    }
}

pub async fn replace(pool: &SqlitePool, id: i64, domains: &[String]) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM list_domains WHERE list_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for chunk in domains.chunks(500) {
        let mut query = QueryBuilder::<Sqlite>::new("INSERT INTO list_domains(list_id, domain) ");
        query.push_values(chunk, |mut b, domain| {
            b.push_bind(id).push_bind(domain);
        });
        query.build().execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE lists SET count = ?, updated_at = ?, error = NULL WHERE id = ?")
        .bind(domains.len() as i64)
        .bind(crate::now())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn download(preset: &str) -> anyhow::Result<Vec<String>> {
    let url = preset_url(preset).context("unknown feed preset")?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(45))
        .build()?;
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_LIST_BYTES {
            bail!("feed exceeds 16 MiB");
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_list(std::str::from_utf8(&bytes)?)
}

pub async fn refresh(app: &App, id: i64) -> anyhow::Result<()> {
    let preset: Option<String> = sqlx::query_scalar("SELECT preset FROM lists WHERE id = ?")
        .bind(id)
        .fetch_optional(&app.db)
        .await?
        .flatten();
    let domains = match download(&preset.context("list has no remote feed")?).await {
        Ok(domains) => domains,
        Err(error) => {
            sqlx::query("UPDATE lists SET error = ? WHERE id = ?")
                .bind(format!("{error:#}"))
                .bind(id)
                .execute(&app.db)
                .await?;
            return Err(error);
        }
    };
    let _guard = app.mutation.lock().await;
    // A list may have been deleted while its download was in flight.
    let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM lists WHERE id = ?")
        .bind(id)
        .fetch_one(&app.db)
        .await?;
    if exists == 0 {
        return Ok(());
    }
    replace(&app.db, id, &domains).await?;
    app.reload().await?;
    crate::db::audit(
        &app.db,
        "system",
        "feed.refresh",
        &format!("{id}: {} domains", domains.len()),
    )
    .await?;
    Ok(())
}

pub async fn maintenance(app: App, cancel: tokio_util::sync::CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut attempted = std::collections::HashMap::<i64, i64>::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                if let Err(error) = crate::db::prune(&app.db, app.config.retention_days, app.config.max_log_entries).await {
                    tracing::error!(%error, "database maintenance failed");
                }
                // Failures retry hourly; last good domains remain active.
                let lists: Vec<i64> = sqlx::query_scalar("SELECT id FROM lists WHERE preset IS NOT NULL AND (updated_at IS NULL OR updated_at < ?)")
                    .bind(crate::now() - 86400).fetch_all(&app.db).await.unwrap_or_default();
                attempted.retain(|id, _| lists.contains(id));
                for id in lists {
                    if attempted.get(&id).is_some_and(|at| crate::now() - at < 3600) { continue; }
                    attempted.insert(id, crate::now());
                    if let Err(error) = refresh(&app, id).await {
                        tracing::warn!(%error, id, "feed refresh failed; keeping last good policy");
                    }
                }
            }
        }
    }
}
