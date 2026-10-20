pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod dns;
pub mod feeds;
pub mod policy;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct App {
    pub db: sqlx::SqlitePool,
    pub policy: Arc<RwLock<policy::Policy>>,
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
        let policy = policy::Policy::load(&db).await?;
        Ok(Self {
            db,
            policy: Arc::new(RwLock::new(policy)),
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
