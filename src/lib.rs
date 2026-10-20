pub mod api;
pub mod auth;
pub mod browser;
pub mod browser_api;
pub mod config;
pub mod db;
pub mod dns;
pub mod endpoint_api;
pub mod feeds;
pub mod policy;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct App {
    pub db: sqlx::SqlitePool,
    pub policy: Arc<RwLock<policy::Policy>>,
    pub endpoint_key: Arc<wtp_endpoint::SigningKey>,
    pub browser_policy: Arc<RwLock<browser::BrowserPolicy>>,
    pub config: Arc<config::Config>,
    // Serializes policy mutations and snapshot publication.
    pub mutation: Arc<Mutex<()>>,
    pub login_limiter: Arc<Mutex<auth::LoginLimiter>>,
    pub auth_slots: Arc<tokio::sync::Semaphore>,
    pub started: std::time::Instant,
}

impl App {
    pub async fn new(db: sqlx::SqlitePool, config: config::Config) -> anyhow::Result<Self> {
        config.validate()?;
        let generated = wtp_endpoint::generate_key();
        sqlx::query("INSERT OR IGNORE INTO endpoint_signing_key(id,secret) VALUES (1,?)")
            .bind(hex::encode(generated.to_bytes()))
            .execute(&db)
            .await?;
        let secret: String =
            sqlx::query_scalar("SELECT secret FROM endpoint_signing_key WHERE id=1")
                .fetch_one(&db)
                .await?;
        let endpoint_key = Arc::new(wtp_endpoint::private_key(&secret)?);
        let policy = policy::Policy::load(&db).await?;
        let browser_policy = browser::BrowserPolicy::load(&db).await?;
        Ok(Self {
            db,
            endpoint_key,
            policy: Arc::new(RwLock::new(policy)),
            browser_policy: Arc::new(RwLock::new(browser_policy)),
            config: Arc::new(config),
            mutation: Arc::new(Mutex::new(())),
            login_limiter: Arc::new(Mutex::new(auth::LoginLimiter::default())),
            auth_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            started: std::time::Instant::now(),
        })
    }

    pub async fn reload(&self) -> anyhow::Result<()> {
        let policy = policy::Policy::load(&self.db).await?;
        *self.policy.write().await = policy;
        Ok(())
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
