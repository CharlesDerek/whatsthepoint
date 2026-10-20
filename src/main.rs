use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use whatsthepoint::{App, auth, config::Config, db, dns, policy};

#[derive(Parser)]
#[command(
    name = "wtp",
    version,
    about = "What's the Point — web filtering with a point."
)]
struct Cli {
    #[arg(long, global = true, default_value = "data")]
    data_dir: PathBuf,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create the first administrator. Password is prompted, or read from WTP_ADMIN_PASSWORD.
    Init {
        #[arg(long, default_value = "admin")]
        username: String,
    },
    /// Run the DNS resolver and embedded management console.
    Serve,
    /// Print a starter TOML configuration.
    Config,
    /// Explain the local policy decision for a domain without contacting an upstream.
    Check { domain: String },
    /// Recover an administrator password locally and revoke all their sessions.
    ResetPassword {
        #[arg(long, default_value = "admin")]
        username: String,
    },
}

fn read_password() -> anyhow::Result<String> {
    let password = match std::env::var("WTP_ADMIN_PASSWORD") {
        Ok(password) => password,
        Err(_) => {
            let password = rpassword::prompt_password("New password (at least 12 characters): ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;
            if password != confirm {
                bail!("passwords do not match");
            }
            password
        }
    };
    Ok(password)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "whatsthepoint=info,wtp=info".into()),
        )
        .init();
    let cli = Cli::parse();
    if matches!(cli.command, Command::Config) {
        println!("{}", toml::to_string_pretty(&Config::default())?);
        return Ok(());
    }
    let config = Config::load(cli.config.as_deref())?;
    let pool = db::open(&cli.data_dir).await?;
    match cli.command {
        Command::Init { username } => {
            if username.is_empty()
                || username.len() > 64
                || !username
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                bail!("invalid username");
            }
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM admins")
                .fetch_one(&pool)
                .await?;
            if count > 0 {
                bail!("already initialized; use reset-password for local recovery");
            }
            let hash = auth::hash_password(&read_password()?)?;
            sqlx::query("INSERT INTO admins(username, password_hash) VALUES (?, ?)")
                .bind(&username)
                .bind(hash)
                .execute(&pool)
                .await?;
            println!(
                "Administrator {username} created. Run `wtp serve` using this same data directory."
            );
        }
        Command::ResetPassword { username } => {
            let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM admins WHERE username = ?")
                .bind(&username)
                .fetch_one(&pool)
                .await?;
            if exists == 0 {
                bail!("administrator does not exist");
            }
            let hash = auth::hash_password(&read_password()?)?;
            let mut tx = pool.begin().await?;
            sqlx::query("UPDATE admins SET password_hash = ? WHERE username = ?")
                .bind(hash)
                .bind(&username)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM sessions WHERE username = ?")
                .bind(&username)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            db::audit(
                &pool,
                &username,
                "account.recovery",
                "Local password reset; sessions revoked",
            )
            .await?;
            println!("Password changed. All sessions for {username} revoked.");
        }
        Command::Check { domain } => {
            let domain = policy::normalize_domain(&domain)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&policy::Policy::load(&pool).await?.decide(&domain))?
            );
        }
        Command::Serve => serve(App::new(pool.clone(), config).await?).await?,
        Command::Config => unreachable!(),
    }
    pool.close().await;
    Ok(())
}

async fn serve(app: App) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM admins")
        .fetch_one(&app.db)
        .await?;
    if count == 0 {
        bail!("run `wtp init` first to create your administrator");
    }
    // Bind all listeners before declaring readiness.
    let udp = UdpSocket::bind(app.config.dns_bind)
        .await
        .context("bind DNS UDP listener")?;
    let tcp = TcpListener::bind(app.config.dns_bind)
        .await
        .context("bind DNS TCP listener")?;
    let http = TcpListener::bind(app.config.http_bind)
        .await
        .context("bind console listener")?;
    let cancel = CancellationToken::new();
    let tasks = TaskTracker::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4096);
    let resolver = Arc::new(dns::Resolver::new(app.clone(), tx)?);
    let logger = tokio::spawn(dns::log_writer(app.db.clone(), rx));
    let maintenance = tokio::spawn(whatsthepoint::feeds::maintenance(
        app.clone(),
        cancel.clone(),
    ));
    tracing::info!(dns = %app.config.dns_bind, console = %app.config.public_origin, "What's the Point is running");
    let http_cancel = cancel.clone();
    let mut http_server = tokio::spawn(async move {
        axum::serve(
            http,
            whatsthepoint::api::router(app)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { http_cancel.cancelled().await })
        .await
        .map_err(anyhow::Error::from)
    });
    let mut udp_server = tokio::spawn(dns::serve_udp(
        udp,
        resolver.clone(),
        cancel.clone(),
        tasks.clone(),
    ));
    let mut tcp_server = tokio::spawn(dns::serve_tcp(
        tcp,
        resolver.clone(),
        cancel.clone(),
        tasks.clone(),
    ));
    let result = tokio::select! {
        result = &mut udp_server => result.context("UDP task failed")?,
        result = &mut tcp_server => result.context("TCP task failed")?,
        result = &mut http_server => result.context("HTTP task failed")?,
        _ = shutdown_signal() => Ok(()),
    };
    cancel.cancel();
    maintenance.abort();
    // Allow in-flight API requests to commit before closing the database.
    if !http_server.is_finished()
        && tokio::time::timeout(std::time::Duration::from_secs(50), &mut http_server)
            .await
            .is_err()
    {
        http_server.abort();
    }
    if !udp_server.is_finished() {
        let _ = udp_server.await;
    }
    if !tcp_server.is_finished() {
        let _ = tcp_server.await;
    }
    tasks.close();
    tasks.wait().await;
    drop(resolver);
    let _ = logger.await;
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install signal handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
