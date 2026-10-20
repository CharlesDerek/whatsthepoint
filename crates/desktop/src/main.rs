//! A paired desktop console: the same web UI, served locally in a browser app window.
//! Only the Rust broker has network credentials; renderer requests remain on loopback.
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::to_bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use wtp_control::{Credential, PairBundle, vault};
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(
    name = "wtp-desktop",
    version,
    about = "Paired desktop console with a local encrypted credential pool"
)]
struct Cli {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Pair headlessly. Interactive pairing is available in the desktop window.
    Pair {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Start the desktop window. Unlock and select a saved master locally.
    Open {
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_open: bool,
    },
    /// Print nonsecret paired master identities after unlocking the vault.
    List,
}
#[derive(Clone)]
struct App {
    vault: PathBuf,
    origin: String,
    bootstrap: Arc<Mutex<Option<(String, Instant)>>>,
    session: Arc<Mutex<Option<String>>>,
    csrf: String,
    pool: Arc<Mutex<Vec<Credential>>>,
    selected: Arc<Mutex<Option<String>>>,
}
fn default_vault() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA missing")?);
    #[cfg(not(windows))]
    let base =
        PathBuf::from(std::env::var_os("HOME").context("HOME missing")?).join(".local/share");
    Ok(base.join("whatsthepoint/desktop-vault.json"))
}
fn prepare(path: &Path) -> anyhow::Result<()> {
    let parent = path.parent().context("Vault requires a parent directory")?;
    let new_directory = !parent.exists();
    std::fs::create_dir_all(parent)?;
    #[cfg(not(unix))]
    let _ = new_directory;
    #[cfg(unix)]
    if new_directory {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn password() -> anyhow::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(match std::env::var("WTP_VAULT_PASSWORD") {
        Ok(value) => value,
        Err(_) => rpassword::prompt_password("Local vault passphrase (12+ characters): ")?,
    }))
}
fn pair(path: &Path, password: &str, bundle: PairBundle) -> anyhow::Result<Credential> {
    ensure!(
        bundle.role == "console" && bundle.endpoint_id.is_none(),
        "Use a desktop console invitation"
    );
    // Unlock first so a wrong password never consumes a one-time invitation.
    let mut pool = if path.exists() {
        vault::load_pool(path, password)?
    } else {
        Vec::new()
    };
    ensure!(
        password.len() >= 12 && password.len() <= 1024,
        "Use a vault passphrase of 12–1024 bytes"
    );
    let credential = wtp_control::client::pair(&bundle, wtp_control::identity::node()?)?;
    ensure!(
        credential.role == "console",
        "This invitation is for an endpoint agent, not a desktop console"
    );
    pool.retain(|c| c.master.id != credential.master.id);
    pool.push(credential.clone());
    vault::save_pool(path, password, &pool)?;
    Ok(credential)
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = cli.vault.map(Ok).unwrap_or_else(default_vault)?;
    prepare(&path)?;
    match cli.command.unwrap_or(Command::Open {
        port: 0,
        no_open: false,
    }) {
        Command::Pair { bundle } => {
            let password = password()?;
            let invitation: PairBundle = serde_json::from_slice(&std::fs::read(bundle)?)?;
            let credential =
                tokio::task::spawn_blocking(move || pair(&path, &password, invitation)).await??;
            println!(
                "Paired {} · {} · {}",
                credential.master.name,
                credential.master.origin,
                credential.master.fingerprint()
            );
        }
        Command::List => {
            let password = password()?;
            let pool = vault::load_pool(&path, &password)?;
            for item in pool {
                println!(
                    "{} {} {}",
                    item.principal_id,
                    item.master.origin,
                    item.master.fingerprint()
                );
            }
        }
        Command::Open { port, no_open } => serve(path, port, no_open).await?,
    }
    Ok(())
}
async fn serve(vault: PathBuf, port: u16, no_open: bool) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let token = wtp_control::random_hex(32);
    let app = App {
        vault,
        origin: origin.clone(),
        bootstrap: Arc::new(Mutex::new(Some((token.clone(), Instant::now())))),
        session: Arc::new(Mutex::new(None)),
        csrf: wtp_control::random_hex(32),
        pool: Arc::new(Mutex::new(Vec::new())),
        selected: Arc::new(Mutex::new(None)),
    };
    let router = Router::new()
        .route("/", get(index))
        .route(
            "/desktop",
            get(|| async { Html(include_str!("../../../web/desktop.html")) }),
        )
        .route(
            "/desktop.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../../web/desktop.js"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../../web/app.js"),
                )
            }),
        )
        .route(
            "/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../../../web/app.css"),
                )
            }),
        )
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "image/svg+xml")],
                    include_str!("../../../web/favicon.svg"),
                )
            }),
        )
        .route("/desktop/session", post(session))
        .route("/desktop/state", get(local_state))
        .route("/desktop/unlock", post(unlock))
        .route("/desktop/pair", post(pair_ui))
        .route("/desktop/select", post(select))
        .route("/desktop/lock", post(lock))
        .route("/api/{*path}", axum::routing::any(proxy))
        .layer(DefaultBodyLimit::max(wtp_control::MAX_BODY))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app);
    let url = format!("{origin}/desktop#{token}");
    if no_open {
        println!("Desktop bootstrap URL: {url}");
    } else {
        open_window(&url)?;
        println!("Desktop console running. Close this process to lock the broker.");
    }
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
fn open_window(url: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        for exe in [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
        ] {
            if Path::new(exe).exists() {
                std::process::Command::new(exe)
                    .arg(format!("--app={url}"))
                    .arg("--new-window")
                    .spawn()?;
                return Ok(());
            }
        }
        std::process::Command::new("/usr/bin/xdg-open")
            .arg(url)
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .args(["-a", "Google Chrome", "--args", &format!("--app={url}")])
            .spawn()?;
    }
    #[cfg(windows)]
    {
        let base = PathBuf::from(
            std::env::var_os("ProgramFiles(x86)").context("ProgramFiles(x86) missing")?,
        );
        std::process::Command::new(base.join("Microsoft/Edge/Application/msedge.exe"))
            .arg(format!("--app={url}"))
            .spawn()?;
    }
    Ok(())
}
fn error(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({"error":message}))).into_response()
}
fn authenticated(app: &App, headers: &HeaderMap) -> bool {
    let expected = app.session.lock().unwrap().clone();
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|cookies| {
            cookies.split(';').any(|item| {
                item.trim()
                    .strip_prefix("wtp_desktop=")
                    .is_some_and(|value| expected.as_deref() == Some(value))
            })
        })
}
async fn guard(State(app): State<App>, request: Request, next: Next) -> Response {
    let host = app.origin.strip_prefix("http://").unwrap();
    let headers = request.headers();
    let path = request.uri().path();
    let valid_host = headers.get(header::HOST).and_then(|h| h.to_str().ok()) == Some(host);
    let valid_origin = headers
        .get(header::ORIGIN)
        .is_none_or(|h| h.to_str().ok() == Some(app.origin.as_str()));
    if !valid_host || !valid_origin {
        return error(StatusCode::FORBIDDEN, "Local console origin rejected");
    }
    let mutating = !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    );
    if mutating && headers.get("x-wtp-request").and_then(|v| v.to_str().ok()) != Some("1") {
        return error(StatusCode::FORBIDDEN, "Local request header required");
    }
    if (path.starts_with("/api/") || path.starts_with("/desktop/"))
        && path != "/desktop/session"
        && !authenticated(&app, headers)
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "Reopen the desktop launcher to establish a local session",
        );
    }
    if path.starts_with("/api/")
        && mutating
        && headers.get("x-csrf-token").and_then(|h| h.to_str().ok()) != Some(app.csrf.as_str())
    {
        return error(StatusCode::FORBIDDEN, "Local session verification failed");
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy",HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    response
}
async fn index(State(app): State<App>, headers: HeaderMap) -> Html<&'static str> {
    if authenticated(&app, &headers) && app.selected.lock().unwrap().is_some() {
        Html(include_str!("../../../web/index.html"))
    } else {
        Html(include_str!("../../../web/desktop.html"))
    }
}
async fn session(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = headers
        .get("x-wtp-bootstrap")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let mut pending = app.bootstrap.lock().unwrap();
    if !pending
        .as_ref()
        .is_some_and(|(expected, issued)| expected == token && issued.elapsed().as_secs() < 120)
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "Bootstrap link expired or already used. Reopen the desktop launcher.",
        );
    }
    *pending = None;
    let session = wtp_control::random_hex(32);
    *app.session.lock().unwrap() = Some(session.clone());
    (
        [(
            header::SET_COOKIE,
            format!("wtp_desktop={session}; HttpOnly; SameSite=Strict; Path=/"),
        )],
        axum::Json(json!({"ready":true})),
    )
        .into_response()
}
async fn local_state(State(app): State<App>) -> axum::Json<Value> {
    let pool = app.pool.lock().unwrap();
    axum::Json(
        json!({"vault_exists":app.vault.exists(),"principals":pool.iter().map(|c|json!({"id":c.principal_id,"name":c.master.name,"origin":c.master.origin,"master_hash":c.master.fingerprint(),"node_hash":c.node_hash,"expires_at":c.expires_at})).collect::<Vec<_>>()}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unlock {
    password: String,
}
async fn unlock(State(app): State<App>, axum::Json(input): axum::Json<Unlock>) -> Response {
    let path = app.vault.clone();
    let result = tokio::task::spawn_blocking(move || {
        vault::load_pool(&path, &Zeroizing::new(input.password))
    })
    .await;
    match result {
        Ok(Ok(pool)) => {
            *app.pool.lock().unwrap() = pool;
            axum::Json(json!({"unlocked":true})).into_response()
        }
        _ => error(
            StatusCode::UNAUTHORIZED,
            "Could not unlock the local vault. Check the passphrase.",
        ),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairInput {
    password: String,
    bundle: PairBundle,
}
async fn pair_ui(State(app): State<App>, axum::Json(input): axum::Json<PairInput>) -> Response {
    let path = app.vault.clone();
    let result = tokio::task::spawn_blocking(move || {
        let password = Zeroizing::new(input.password);
        let credential = pair(&path, &password, input.bundle)?;
        let pool = vault::load_pool(&path, &password)?;
        Ok::<_, anyhow::Error>((credential, pool))
    })
    .await;
    match result {
        Ok(Ok((credential, pool))) => {
            *app.pool.lock().unwrap() = pool;
            *app.selected.lock().unwrap() = Some(credential.principal_id);
            axum::Json(json!({"paired":true})).into_response()
        }
        Ok(Err(e)) => error(StatusCode::BAD_REQUEST, &format!("Pairing failed: {e}")),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Pairing task failed"),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    id: String,
}
async fn select(State(app): State<App>, axum::Json(input): axum::Json<Selection>) -> Response {
    let credential = app
        .pool
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.principal_id == input.id)
        .cloned();
    let Some(credential) = credential else {
        return error(StatusCode::NOT_FOUND, "Saved principal not found");
    };
    let result = tokio::task::spawn_blocking(move || {
        wtp_control::client::send(&credential, "GET", "/api/me", String::new())
    })
    .await;
    if !matches!(result,Ok(Ok(ref response))if response.status==200) {
        return error(
            StatusCode::UNAUTHORIZED,
            "Master rejected this credential or its pinned identity changed. Re-pair from the web portal.",
        );
    }
    *app.selected.lock().unwrap() = Some(input.id);
    axum::Json(json!({"connected":true})).into_response()
}
async fn lock(State(app): State<App>) -> axum::Json<Value> {
    app.pool.lock().unwrap().clear();
    *app.selected.lock().unwrap() = None;
    axum::Json(json!({"locked":true}))
}
async fn proxy(State(app): State<App>, request: Request) -> Response {
    let selected = app.selected.lock().unwrap().clone();
    let credential = app
        .pool
        .lock()
        .unwrap()
        .iter()
        .find(|c| Some(&c.principal_id) == selected.as_ref())
        .cloned();
    let Some(credential) = credential else {
        return error(
            StatusCode::UNAUTHORIZED,
            "Unlock and select a paired master in the desktop console",
        );
    };
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_owned();
    let method = request.method().as_str().to_owned();
    let is_me = path == "/api/me";
    let Ok(body) = to_bytes(request.into_body(), wtp_control::MAX_BODY).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "Request exceeds limit");
    };
    let Ok(body) = String::from_utf8(body.to_vec()) else {
        return error(StatusCode::BAD_REQUEST, "Request must be UTF-8");
    };
    let result = tokio::task::spawn_blocking(move || {
        wtp_control::client::send(&credential, &method, &path, body)
    })
    .await;
    match result {
        Ok(Ok(mut reply)) => {
            if is_me
                && reply.status == 200
                && let Ok(mut value) = serde_json::from_str::<Value>(&reply.body)
            {
                value["csrf"] = json!(app.csrf);
                value["desktop"] = json!(true);
                reply.body = value.to_string();
            }
            (
                StatusCode::from_u16(reply.status).unwrap_or(StatusCode::BAD_GATEWAY),
                [(header::CONTENT_TYPE, "application/json")],
                reply.body,
            )
                .into_response()
        }
        Ok(Err(e)) => error(
            StatusCode::BAD_GATEWAY,
            &format!("Paired connection failed: {e}"),
        ),
        Err(_) => error(StatusCode::BAD_GATEWAY, "Desktop broker task failed"),
    }
}
