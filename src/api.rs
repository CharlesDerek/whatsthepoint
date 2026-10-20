use crate::{
    App, auth, db, feeds,
    policy::{self, Rule},
};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use std::net::SocketAddr;

pub struct ApiError(StatusCode, String);
type Result<T> = std::result::Result<T, ApiError>;
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(%error, "API operation failed");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The operation failed. Check the service log.".into(),
        )
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        anyhow::Error::from(e).into()
    }
}
fn bad(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}
fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "Sign in to continue.".into())
}

#[derive(Clone, FromRow)]
struct Session {
    username: String,
    csrf: String,
}

pub fn router(app: App) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/app.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "image/svg+xml")],
                    include_str!("../web/favicon.svg"),
                )
            }),
        )
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/api/login", post(login).layer(DefaultBodyLimit::max(4096)))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route(
            "/api/password",
            post(password).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/api/stats", get(stats))
        .route("/api/queries", get(queries).delete(clear_queries))
        .route("/api/clients", get(clients))
        .route("/api/audit", get(audit))
        .route("/api/rules", get(rules).post(add_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/test", post(test))
        .route("/api/lists", get(lists).post(import_list))
        .route("/api/lists/preset", post(add_preset))
        .route("/api/lists/{id}", delete(delete_list))
        .route("/api/lists/{id}/refresh", post(refresh_list))
        .route("/api/settings", get(settings))
        .layer(DefaultBodyLimit::max(feeds::MAX_LIST_BYTES + 1024))
        .layer(middleware::from_fn_with_state(app.clone(), gate))
        .with_state(app)
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == "wtp_session"
                && value.len() == 64
                && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(value)
        })
}

async fn gate(State(app): State<App>, mut request: Request, next: Next) -> Response {
    let check = async {
        let expected_host = app.config.public_origin.split_once("://").unwrap().1;
        if request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            != Some(expected_host)
        {
            return Err(ApiError(
                StatusCode::MISDIRECTED_REQUEST,
                "Use the configured console address.".into(),
            ));
        }
        if let Some(origin) = request.headers().get(header::ORIGIN)
            && origin.to_str().ok() != Some(app.config.public_origin.as_str())
        {
            return Err(ApiError(StatusCode::FORBIDDEN, "Origin rejected.".into()));
        }
        let mutation = !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        );
        if mutation
            && request
                .headers()
                .get("x-wtp-request")
                .and_then(|v| v.to_str().ok())
                != Some("1")
        {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "Missing request header.".into(),
            ));
        }
        if request.uri().path().starts_with("/api/") && request.uri().path() != "/api/login" {
            let token = cookie_token(request.headers()).ok_or_else(unauthorized)?;
            let session = sqlx::query_as::<_, Session>(
                "SELECT username, csrf FROM sessions WHERE token_hash = ? AND expires_at > ?",
            )
            .bind(auth::digest(token))
            .bind(crate::now())
            .fetch_optional(&app.db)
            .await?
            .ok_or_else(unauthorized)?;
            if mutation
                && request
                    .headers()
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    != Some(session.csrf.as_str())
            {
                return Err(ApiError(
                    StatusCode::FORBIDDEN,
                    "Session verification failed. Refresh the page.".into(),
                ));
            }
            request.extensions_mut().insert(session);
        }
        Ok::<_, ApiError>(())
    }
    .await;
    let mut response = match check {
        Ok(()) => next.run(request).await,
        Err(e) => e.into_response(),
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"));
    response
}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}
async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response> {
    if input.username.len() > 64 || input.password.len() > 1024 {
        return Err(unauthorized());
    }
    if !app.login_limiter.lock().await.permit(peer.ip()) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Try again in five minutes.".into(),
        ));
    }
    let permit = app.auth_slots.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Sign-in is busy. Try again shortly.".into(),
        )
    })?;
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM admins WHERE username = ?")
            .bind(&input.username)
            .fetch_optional(&app.db)
            .await?;
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match hash {
            Some(hash) => auth::verify(&input.password, &hash),
            // Spend comparable work for nonexistent accounts.
            None => {
                let _ = auth::hash_password("unknown account dummy password");
                false
            }
        }
    })
    .await
    .map_err(anyhow::Error::from)?;
    if !valid {
        return Err(unauthorized());
    }
    let token = auth::token();
    let csrf = auth::token();
    let mut tx = app.db.begin().await?;
    if let Some(old) = cookie_token(&headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(auth::digest(old))
            .execute(&mut *tx)
            .await?;
    }
    // Bounded sessions per account; keep the nine newest plus this one.
    sqlx::query("DELETE FROM sessions WHERE username = ? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE username = ? ORDER BY expires_at DESC LIMIT 9)")
        .bind(&input.username).bind(&input.username).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO sessions(token_hash, username, csrf, expires_at) VALUES (?, ?, ?, ?)")
        .bind(auth::digest(&token))
        .bind(&input.username)
        .bind(&csrf)
        .bind(crate::now() + 28800)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    db::audit(
        &app.db,
        &input.username,
        "session.login",
        &peer.ip().to_string(),
    )
    .await?;
    Ok((
        [(header::SET_COOKIE, session_cookie(&app, &token, 28800))],
        Json(json!({"username": input.username, "csrf": csrf})),
    )
        .into_response())
}

fn session_cookie(app: &App, token: &str, age: u32) -> String {
    format!(
        "wtp_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if app.config.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    )
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> Result<Response> {
    if let Some(token) = cookie_token(&headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(auth::digest(token))
            .execute(&app.db)
            .await?;
    }
    Ok((
        [(header::SET_COOKIE, session_cookie(&app, "", 0))],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn me(Extension(session): Extension<Session>) -> Json<Value> {
    Json(json!({"username":session.username,"csrf":session.csrf}))
}

#[derive(Deserialize)]
struct PasswordChange {
    current: String,
    password: String,
}
async fn password(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<PasswordChange>,
) -> Result<Json<Value>> {
    if input.current.len() > 1024 {
        return Err(bad("Invalid password."));
    }
    let permit = app.auth_slots.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Password service is busy.".into(),
        )
    })?;
    let old: String = sqlx::query_scalar("SELECT password_hash FROM admins WHERE username = ?")
        .bind(&session.username)
        .fetch_one(&app.db)
        .await?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if !auth::verify(&input.current, &old) {
            return Err(anyhow::anyhow!("Current password is incorrect."));
        }
        auth::hash_password(&input.password)
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(|e| bad(e.to_string()))?;
    let mut tx = app.db.begin().await?;
    sqlx::query("UPDATE admins SET password_hash = ? WHERE username = ?")
        .bind(hash)
        .bind(&session.username)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE username = ?")
        .bind(&session.username)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    db::audit(
        &app.db,
        &session.username,
        "account.password",
        "All sessions revoked",
    )
    .await?;
    Ok(Json(json!({"ok":true})))
}

async fn rules(State(app): State<App>) -> Result<Json<Vec<Rule>>> {
    Ok(Json(
        sqlx::query_as("SELECT * FROM rules ORDER BY created_at DESC, id DESC")
            .fetch_all(&app.db)
            .await?,
    ))
}
#[derive(Deserialize)]
struct RuleInput {
    domain: String,
    action: String,
    #[serde(default)]
    note: String,
}
async fn add_rule(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<RuleInput>,
) -> Result<Json<Value>> {
    let domain = policy::normalize_domain(&input.domain).map_err(|e| bad(e.to_string()))?;
    if !matches!(input.action.as_str(), "allow" | "block") || input.note.len() > 256 {
        return Err(bad("Invalid action or note (maximum 256 bytes)."));
    }
    let _guard = app.mutation.lock().await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rules")
        .fetch_one(&app.db)
        .await?;
    if count >= 10000 {
        return Err(bad("Use a blocklist for more than 10,000 rules."));
    }
    sqlx::query("INSERT INTO rules(domain, action, note, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET action=excluded.action, note=excluded.note")
        .bind(&domain).bind(&input.action).bind(&input.note).bind(crate::now()).execute(&app.db).await?;
    app.reload().await?;
    db::audit(
        &app.db,
        &session.username,
        "rule.save",
        &format!("{} {domain}", input.action),
    )
    .await?;
    Ok(Json(json!({"ok":true})))
}
async fn delete_rule(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    sqlx::query("DELETE FROM rules WHERE id = ?")
        .bind(id)
        .execute(&app.db)
        .await?;
    app.reload().await?;
    db::audit(&app.db, &session.username, "rule.delete", &id.to_string()).await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
struct TestInput {
    domain: String,
}
async fn test(
    State(app): State<App>,
    Json(input): Json<TestInput>,
) -> Result<Json<policy::Decision>> {
    let domain = policy::normalize_domain(&input.domain).map_err(|e| bad(e.to_string()))?;
    Ok(Json(app.policy.read().await.decide(&domain)))
}

async fn lists(State(app): State<App>) -> Result<Json<Vec<feeds::List>>> {
    Ok(Json(
        sqlx::query_as("SELECT * FROM lists ORDER BY id")
            .fetch_all(&app.db)
            .await?,
    ))
}
#[derive(Deserialize)]
struct ImportInput {
    name: String,
    contents: String,
}
async fn import_list(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<ImportInput>,
) -> Result<Json<Value>> {
    if input.name.trim().is_empty()
        || input.name.len() > 80
        || input.contents.len() > feeds::MAX_LIST_BYTES
    {
        return Err(bad("Invalid list name or size."));
    }
    let domains = policy::parse_list(&input.contents).map_err(|e| bad(format!("{e:#}")))?;
    let _guard = app.mutation.lock().await;
    let existing: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, preset FROM lists WHERE name = ?")
            .bind(input.name.trim())
            .fetch_optional(&app.db)
            .await?;
    let id = match existing {
        Some((_, Some(_))) => return Err(bad("Choose a name different from a managed feed.")),
        Some((id, None)) => id,
        None => sqlx::query("INSERT INTO lists(name) VALUES (?)")
            .bind(input.name.trim())
            .execute(&app.db)
            .await?
            .last_insert_rowid(),
    };
    feeds::replace(&app.db, id, &domains).await?;
    app.reload().await?;
    db::audit(
        &app.db,
        &session.username,
        "list.import",
        &format!("{}: {} domains", input.name.trim(), domains.len()),
    )
    .await?;
    Ok(Json(json!({"ok":true, "count":domains.len()})))
}
#[derive(Deserialize)]
struct PresetInput {
    preset: String,
}
async fn add_preset(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<PresetInput>,
) -> Result<Json<Value>> {
    if feeds::preset_url(&input.preset).is_none() {
        return Err(bad("Unknown feed."));
    }
    let domains = feeds::download(&input.preset)
        .await
        .map_err(|e| bad(format!("Feed download failed: {e:#}")))?;
    let _guard = app.mutation.lock().await;
    let id: i64 = sqlx::query_scalar("INSERT INTO lists(name, preset) VALUES (?, ?) ON CONFLICT(preset) DO UPDATE SET preset=excluded.preset RETURNING id")
        .bind(format!("HaGeZi {}", input.preset.trim_start_matches("hagezi-"))).bind(&input.preset).fetch_one(&app.db).await?;
    feeds::replace(&app.db, id, &domains).await?;
    app.reload().await?;
    db::audit(&app.db, &session.username, "feed.add", &input.preset).await?;
    Ok(Json(json!({"ok":true, "count":domains.len()})))
}
async fn delete_list(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    sqlx::query("DELETE FROM lists WHERE id = ?")
        .bind(id)
        .execute(&app.db)
        .await?;
    app.reload().await?;
    db::audit(&app.db, &session.username, "list.delete", &id.to_string()).await?;
    Ok(Json(json!({"ok":true})))
}
async fn refresh_list(State(app): State<App>, Path(id): Path<i64>) -> Result<Json<Value>> {
    feeds::refresh(&app, id)
        .await
        .map_err(|e| bad(format!("Refresh failed; existing domains kept. {e:#}")))?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
struct QueryFilter {
    search: Option<String>,
    decision: Option<String>,
    before: Option<i64>,
}
#[derive(Serialize, FromRow)]
struct QueryRow {
    id: i64,
    at: i64,
    client: String,
    domain: String,
    qtype: String,
    decision: String,
    reason: String,
    elapsed_ms: i64,
    cached: bool,
    rcode: String,
}
async fn queries(
    State(app): State<App>,
    Query(filter): Query<QueryFilter>,
) -> Result<Json<Vec<QueryRow>>> {
    let search = filter.search.unwrap_or_default();
    if search.len() > 253 {
        return Err(bad("Search is too long."));
    }
    Ok(Json(sqlx::query_as("SELECT * FROM queries WHERE (instr(domain, ?) > 0 OR instr(client, ?) > 0) AND (? = '' OR decision = ?) AND id < ? ORDER BY id DESC LIMIT 100")
        .bind(&search).bind(&search).bind(filter.decision.as_deref().unwrap_or("")).bind(filter.decision.as_deref().unwrap_or(""))
        .bind(filter.before.unwrap_or(i64::MAX)).fetch_all(&app.db).await?))
}
async fn clear_queries(
    State(app): State<App>,
    Extension(session): Extension<Session>,
) -> Result<Json<Value>> {
    sqlx::query("DELETE FROM queries").execute(&app.db).await?;
    db::audit(
        &app.db,
        &session.username,
        "queries.clear",
        "Stored query history removed",
    )
    .await?;
    Ok(Json(json!({"ok":true})))
}
async fn stats(State(app): State<App>) -> Result<Json<Value>> {
    let since = crate::now() - 86400;
    let (total, blocked, errors, cached, latency, clients): (i64, i64, i64, i64, f64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(decision='blocked'),0), coalesce(sum(decision='error'),0), coalesce(sum(cached),0), coalesce(avg(elapsed_ms),0.0), count(DISTINCT client) FROM queries WHERE at >= ?"
    ).bind(since).fetch_one(&app.db).await?;
    let hourly: Vec<(i64, i64, i64)> = sqlx::query_as("SELECT (at/3600)*3600, count(*), sum(decision='blocked') FROM queries WHERE at >= ? GROUP BY at/3600 ORDER BY at/3600")
        .bind(since).fetch_all(&app.db).await?;
    let top: Vec<(String, i64)> = sqlx::query_as("SELECT domain, count(*) FROM queries WHERE at >= ? AND decision='blocked' GROUP BY domain ORDER BY count(*) DESC LIMIT 5")
        .bind(since).fetch_all(&app.db).await?;
    let policy = app.policy.read().await;
    Ok(Json(
        json!({"total":total,"blocked":blocked,"errors":errors,"cached":cached,"latency":latency,"clients":clients,
        "hourly":hourly,"top":top,"domains":policy.domains.len(),"rules":policy.rules.len(),
        "uptime":app.started.elapsed().as_secs(),"query_log":app.config.query_log}),
    ))
}
async fn clients(State(app): State<App>) -> Result<Json<Value>> {
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as("SELECT client, count(*), sum(decision='blocked'), max(at) FROM queries WHERE at >= ? GROUP BY client ORDER BY count(*) DESC LIMIT 250")
        .bind(crate::now()-86400).fetch_all(&app.db).await?;
    Ok(Json(json!(rows.into_iter().map(|(ip,total,blocked,last_seen)| json!({"ip":ip,"total":total,"blocked":blocked,"last_seen":last_seen})).collect::<Vec<_>>())))
}
#[derive(Serialize, FromRow)]
struct AuditRow {
    at: i64,
    actor: String,
    event: String,
    detail: String,
}
async fn audit(State(app): State<App>) -> Result<Json<Vec<AuditRow>>> {
    Ok(Json(
        sqlx::query_as("SELECT at, actor, event, detail FROM audit ORDER BY id DESC LIMIT 100")
            .fetch_all(&app.db)
            .await?,
    ))
}
async fn settings(State(app): State<App>) -> Json<Value> {
    Json(
        json!({"config":*app.config,"version":env!("CARGO_PKG_VERSION"),"uptime":app.started.elapsed().as_secs()}),
    )
}
