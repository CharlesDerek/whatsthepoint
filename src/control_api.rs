use crate::{
    App,
    api::{ApiError, Session, bad},
    auth, db,
    tls::TlsPeer,
};
use anyhow::Context;
use axum::{
    Extension, Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{Request as HttpRequest, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use std::{io::Write, net::SocketAddr, path::PathBuf};
use tower::ServiceExt;
use wtp_control::{
    Credential, Master, PairBundle, PairRequest, Request, Response,
    vault::{self, Sealed},
};
type Result<T> = std::result::Result<T, ApiError>;
#[derive(Clone)]
pub(crate) struct ConsoleSession {
    pub username: String,
}
#[derive(FromRow)]
struct Ticket {
    id: String,
    secret: String,
    name: String,
    role: String,
    owner: String,
    endpoint_id: Option<String>,
    expires_at: i64,
    used_at: Option<i64>,
}
#[derive(FromRow)]
pub(crate) struct Principal {
    pub id: String,
    pub role: String,
    pub owner: String,
    pub endpoint_id: Option<String>,
    pub master_hash: String,
    pub node_hash: String,
    pub secret: String,
    pub expires_at: i64,
    pub revoked: bool,
}
pub async fn initialize(
    pool: &sqlx::SqlitePool,
    config: &crate::config::Config,
    signing: &wtp_endpoint::SigningKey,
) -> anyhow::Result<([u8; 32], Option<Master>)> {
    let (_, _, file): (i64, String, String) = sqlx::query_as("PRAGMA database_list")
        .fetch_one(pool)
        .await?;
    let path = PathBuf::from(file)
        .parent()
        .context("Database parent missing")?
        .join("control-storage.key");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(wtp_control::random_hex(32).as_bytes())?;
            file.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let storage_key = wtp_control::key(std::fs::read_to_string(path)?.trim())?;
    sqlx::query("INSERT OR IGNORE INTO control_identity(id,server_id) VALUES (1,?)")
        .bind(wtp_control::random_hex(16))
        .execute(pool)
        .await?;
    let master = if let Some(cert) = &config.tls_certificate {
        let id: String = sqlx::query_scalar("SELECT server_id FROM control_identity WHERE id=1")
            .fetch_one(pool)
            .await?;
        let master = Master {
            id,
            name: config.master_name.clone(),
            origin: config.public_origin.clone(),
            control: config.http_bind,
            mac_addresses: wtp_control::identity::mac_addresses()?,
            certificate_pem: std::fs::read_to_string(cert)?,
            policy_key: hex::encode(signing.verifying_key().to_bytes()),
        };
        master.validate()?;
        Some(master)
    } else {
        None
    };
    Ok((storage_key, master))
}
fn master(app: &App) -> Result<&Master> {
    app.master.as_ref().ok_or_else(|| {
        bad("Pairing requires the native hybrid TLS listener. Configure native TLS first.")
    })
}
fn unauthorized() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "Invalid, expired, revoked, or replayed paired credential".into(),
    )
}
fn seal_secret(app: &App, id: &str, secret: &str) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&vault::seal(
        &app.control_key,
        secret.as_bytes(),
        id.as_bytes(),
    )?)?)
}
fn open_secret(app: &App, id: &str, sealed: &str) -> anyhow::Result<String> {
    let secret = vault::open(
        &app.control_key,
        &serde_json::from_str(sealed)?,
        id.as_bytes(),
    )?;
    Ok(std::str::from_utf8(&secret)?.to_owned())
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/.well-known/wtp-master", get(info))
        .route("/api/principals", get(list))
        .route("/api/pairing", post(create))
        .route("/api/principals/{id}/revoke", post(revoke))
        .route(
            "/control/pair",
            post(pair).layer(DefaultBodyLimit::max(32768)),
        )
        .route(
            "/control/request",
            post(control).layer(DefaultBodyLimit::max(wtp_control::MAX_BODY * 3)),
        )
        .route("/api/endpoints/{id}/uninstall", post(uninstall))
}
async fn info(State(app): State<App>) -> Result<Json<Value>> {
    Ok(Json(
        json!({"master":master(&app)?,"fingerprint":master(&app)?.fingerprint(),"suite":wtp_control::SUITE}),
    ))
}
async fn list(State(app): State<App>) -> Result<Json<Value>> {
    #[derive(Serialize, FromRow)]
    struct View {
        id: String,
        name: String,
        role: String,
        endpoint_id: Option<String>,
        master_hash: String,
        node_hash: String,
        node: String,
        created_at: i64,
        expires_at: i64,
        revoked: bool,
        last_seen: Option<i64>,
    }
    let principals = sqlx::query_as::<_, View>("SELECT * FROM principals ORDER BY created_at DESC")
        .fetch_all(&app.db)
        .await?;
    #[derive(Serialize, FromRow)]
    struct Command {
        id: i64,
        endpoint_id: String,
        kind: String,
        created_at: i64,
        expires_at: i64,
        state: String,
        detail: String,
    }
    let commands =
        sqlx::query_as::<_, Command>("SELECT * FROM endpoint_commands ORDER BY id DESC LIMIT 100")
            .fetch_all(&app.db)
            .await?;
    Ok(Json(
        json!({"master":app.master,"master_hash":app.master.as_ref().map(Master::fingerprint),"suite":wtp_control::SUITE,"principals":principals,"commands":commands}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    name: String,
}
async fn create(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<Invitation>,
) -> Result<Json<PairBundle>> {
    Ok(Json(
        issue(&app, &session.username, &input.name, "console", None).await?,
    ))
}
pub async fn issue(
    app: &App,
    owner: &str,
    name: &str,
    role: &str,
    endpoint_id: Option<&str>,
) -> Result<PairBundle> {
    if name.trim().is_empty() || name.len() > 80 {
        return Err(bad("Pairing name must be 1–80 bytes"));
    }
    let master = master(app)?.clone();
    let id = auth::token()[..32].to_owned();
    let secret = auth::token();
    let expires = crate::now() + 600;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pairing_tickets WHERE expires_at>? AND used_at IS NULL",
    )
    .bind(crate::now())
    .fetch_one(&app.db)
    .await?;
    if count >= 1000 {
        return Err(bad("Too many active pairing invitations"));
    }
    sqlx::query("INSERT INTO pairing_tickets(id,secret,name,role,owner,endpoint_id,expires_at) VALUES(?,?,?,?,?,?,?)").bind(&id).bind(seal_secret(app,&id,&secret)?).bind(name.trim()).bind(role).bind(owner).bind(endpoint_id).bind(expires).execute(&app.db).await?;
    db::audit(
        &app.db,
        owner,
        "pairing.invite",
        &format!("{id}: {role}, {name}"),
    )
    .await?;
    Ok(PairBundle {
        master,
        role: role.into(),
        endpoint_id: endpoint_id.map(str::to_owned),
        ticket_id: id,
        secret,
        expires_at: expires,
    })
}
async fn revoke(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let changed = sqlx::query("UPDATE principals SET revoked=1 WHERE id=? AND revoked=0")
        .bind(&id)
        .execute(&app.db)
        .await?;
    if changed.rows_affected() == 0 {
        return Err(bad("Active principal not found"));
    }
    db::audit(&app.db, &session.username, "principal.revoke", &id).await?;
    Ok(Json(json!({"revoked":true})))
}
async fn pair(
    State(app): State<App>,
    Extension(tls): Extension<TlsPeer>,
    Json(input): Json<PairRequest>,
) -> Result<Json<Sealed>> {
    if tls.suite != wtp_control::SUITE {
        return Err(unauthorized());
    }
    let ticket = sqlx::query_as::<_, Ticket>("SELECT * FROM pairing_tickets WHERE id=?")
        .bind(&input.ticket_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(unauthorized)?;
    if ticket.used_at.is_some() || ticket.expires_at <= crate::now() {
        return Err(unauthorized());
    }
    let secret = open_secret(&app, &ticket.id, &ticket.secret)?;
    input
        .verify(&secret, master(&app)?, crate::now())
        .map_err(|_| unauthorized())?;
    if let Some(endpoint) = &ticket.endpoint_id {
        let platform: String = sqlx::query_scalar("SELECT platform FROM endpoints WHERE id=?")
            .bind(endpoint)
            .fetch_one(&app.db)
            .await?;
        if platform != input.node.platform {
            return Err(unauthorized());
        }
    }
    let id = wtp_control::random_hex(16);
    let credential = Credential {
        principal_id: id.clone(),
        secret: auth::token(),
        master: master(&app)?.clone(),
        node: input.node.clone(),
        node_hash: input.node.fingerprint(master(&app)?),
        role: ticket.role.clone(),
        endpoint_id: ticket.endpoint_id.clone(),
        expires_at: crate::now() + 90 * 86400,
    };
    let sealed = vault::seal(
        &wtp_control::key(&secret)?,
        &serde_json::to_vec(&credential).map_err(anyhow::Error::from)?,
        &input.aad(),
    )?;
    let mut tx = app.db.begin().await?;
    let taken = sqlx::query(
        "UPDATE pairing_tickets SET used_at=? WHERE id=? AND used_at IS NULL AND expires_at>?",
    )
    .bind(crate::now())
    .bind(&ticket.id)
    .bind(crate::now())
    .execute(&mut *tx)
    .await?;
    if taken.rows_affected() != 1 {
        return Err(unauthorized());
    }
    if let Some(endpoint) = &ticket.endpoint_id {
        sqlx::query("UPDATE principals SET revoked=1 WHERE endpoint_id=?")
            .bind(endpoint)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("INSERT INTO principals(id,name,role,owner,endpoint_id,master_hash,node_hash,node,secret,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)").bind(&id).bind(&ticket.name).bind(&ticket.role).bind(&ticket.owner).bind(&ticket.endpoint_id).bind(credential.master.fingerprint()).bind(&credential.node_hash).bind(serde_json::to_string(&credential.node).map_err(anyhow::Error::from)?).bind(seal_secret(&app,&id,&credential.secret)?).bind(crate::now()).bind(credential.expires_at).execute(&mut *tx).await?;
    tx.commit().await?;
    db::audit(
        &app.db,
        &ticket.owner,
        "principal.paired",
        &format!("{id}: {}", ticket.name),
    )
    .await?;
    Ok(Json(sealed))
}
async fn control(
    State(app): State<App>,
    Extension(tls): Extension<TlsPeer>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(input): Json<Request>,
) -> Result<Json<Response>> {
    if tls.suite != wtp_control::SUITE {
        return Err(unauthorized());
    }
    let principal = sqlx::query_as::<_, Principal>("SELECT * FROM principals WHERE id=?")
        .bind(&input.principal_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(unauthorized)?;
    if principal.revoked
        || principal.expires_at <= crate::now()
        || principal.master_hash != master(&app)?.fingerprint()
    {
        return Err(unauthorized());
    }
    let secret = open_secret(&app, &principal.id, &principal.secret)?;
    input
        .verify(
            &secret,
            &principal.master_hash,
            &principal.node_hash,
            crate::now(),
        )
        .map_err(|_| unauthorized())?;
    // Durable nonce consumption precedes any operation. Concurrent duplicates and
    // captured traffic cannot repeat a mutation, including across server restarts.
    let accepted=sqlx::query("INSERT INTO control_nonces(principal_id,nonce,expires_at) SELECT id,?,? FROM principals WHERE id=? AND revoked=0 AND expires_at>? ON CONFLICT DO NOTHING").bind(&input.nonce).bind(crate::now()+2*wtp_control::CLOCK_WINDOW+1).bind(&principal.id).bind(crate::now()).execute(&app.db).await?;
    if accepted.rows_affected() != 1 {
        return Err(unauthorized());
    }
    sqlx::query("UPDATE principals SET last_seen=? WHERE id=?")
        .bind(crate::now())
        .bind(&principal.id)
        .execute(&app.db)
        .await?;
    let result = dispatch(&app, &principal, &input, peer).await;
    let (status, body) = match result {
        Ok(reply) => reply,
        Err(error) => {
            let status = error.0.as_u16();
            (status, json!({"error":error.1}).to_string())
        }
    };
    Ok(Json(Response::new(&secret, &input, status, body)?))
}
async fn dispatch(
    app: &App,
    principal: &Principal,
    input: &Request,
    peer: SocketAddr,
) -> Result<(u16, String)> {
    if principal.role == "console" {
        if !input.path.starts_with("/api/")
            || matches!(
                input.path.split('?').next(),
                Some("/api/login" | "/api/logout" | "/api/password")
            )
        {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "Operation unavailable from a paired console".into(),
            ));
        }
        let request = HttpRequest::builder()
            .method(input.method.as_str())
            .uri(&input.path)
            .header(
                "host",
                app.config.public_origin.split_once("://").unwrap().1,
            )
            .header("content-type", "application/json")
            .header("x-wtp-request", "1")
            .extension(ConsoleSession {
                username: principal.owner.clone(),
            })
            .extension(ConnectInfo(peer))
            .body(Body::from(input.body.clone()))
            .map_err(anyhow::Error::from)?;
        // Box the recursion boundary: only authenticated /api paths are admitted.
        let response = Box::pin(crate::api::router(app.clone()).oneshot(request))
            .await
            .map_err(anyhow::Error::from)?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), wtp_control::MAX_BODY)
            .await
            .map_err(anyhow::Error::from)?;
        Ok((
            status,
            String::from_utf8(body.to_vec()).map_err(anyhow::Error::from)?,
        ))
    } else if principal.role == "agent" && input.method == "POST" {
        let endpoint = principal.endpoint_id.as_deref().ok_or_else(unauthorized)?;
        match input.path.as_str() {
            "/endpoint/policy" => {
                let status: wtp_endpoint::runtime::Status =
                    serde_json::from_str(&input.body).map_err(|_| bad("Invalid agent status"))?;
                let reply = crate::endpoint_api::paired_policy(
                    app,
                    endpoint,
                    &principal.id,
                    &principal.node_hash,
                    status,
                )
                .await?;
                Ok((200, reply.to_string()))
            }
            "/endpoint/command-receipt" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Receipt {
                    id: i64,
                    state: String,
                    detail: String,
                }
                let receipt: Receipt = serde_json::from_str(&input.body)
                    .map_err(|_| bad("Invalid command receipt"))?;
                if !matches!(receipt.state.as_str(), "accepted" | "failed" | "completed")
                    || receipt.detail.len() > 512
                {
                    return Err(bad("Invalid receipt state"));
                }
                let changed=sqlx::query("UPDATE endpoint_commands SET state=?,detail=? WHERE id=? AND endpoint_id=? AND principal_id=? AND state IN ('queued','delivered','accepted')").bind(&receipt.state).bind(&receipt.detail).bind(receipt.id).bind(endpoint).bind(&principal.id).execute(&app.db).await?;
                if changed.rows_affected() != 1 {
                    return Err(bad("Command receipt is not pending for this principal"));
                }
                if receipt.state == "completed" {
                    sqlx::query("UPDATE principals SET revoked=1 WHERE id=?")
                        .bind(&principal.id)
                        .execute(&app.db)
                        .await?;
                }
                db::audit(
                    &app.db,
                    &principal.id,
                    "endpoint.command.receipt",
                    &format!("{}: {}", receipt.id, receipt.state),
                )
                .await?;
                Ok((200, json!({"received":true}).to_string()))
            }
            _ => Err(ApiError(
                StatusCode::FORBIDDEN,
                "Endpoint credential cannot call this operation".into(),
            )),
        }
    } else {
        Err(ApiError(
            StatusCode::FORBIDDEN,
            "Principal cannot call this operation".into(),
        ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Uninstall {
    revision: i64,
}
async fn uninstall(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(input): Json<Uninstall>,
) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let (revision, enabled): (i64, bool) =
        sqlx::query_as("SELECT revision,remote_uninstall_enabled FROM endpoints WHERE id=?")
            .bind(&id)
            .fetch_optional(&app.db)
            .await?
            .ok_or_else(|| bad("Endpoint not found"))?;
    if revision != input.revision {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Reload the endpoint before requesting uninstall".into(),
        ));
    }
    if !enabled {
        return Err(bad(
            "The installed agent has not opted into remote uninstall",
        ));
    }
    let principal=sqlx::query_as::<_,Principal>("SELECT * FROM principals WHERE endpoint_id=? AND role='agent' AND revoked=0 AND expires_at>? ORDER BY created_at DESC LIMIT 1").bind(&id).bind(crate::now()).fetch_optional(&app.db).await?.ok_or_else(||bad("Pair this endpoint first"))?;
    let pending:i64=sqlx::query_scalar("SELECT count(*) FROM endpoint_commands WHERE endpoint_id=? AND state IN ('queued','delivered','accepted') AND expires_at>?").bind(&id).bind(crate::now()).fetch_one(&app.db).await?;
    if pending > 0 {
        return Err(bad("An uninstall request is already pending"));
    }
    let command=sqlx::query("INSERT INTO endpoint_commands(endpoint_id,principal_id,node_hash,kind,created_at,expires_at) VALUES(?,?,?,'uninstall',?,?)").bind(&id).bind(&principal.id).bind(&principal.node_hash).bind(crate::now()).bind(crate::now()+600).execute(&app.db).await?.last_insert_rowid();
    db::audit(
        &app.db,
        &session.username,
        "endpoint.uninstall.request",
        &format!("{id}: command {command}"),
    )
    .await?;
    Ok(Json(json!({"command_id":command,"state":"queued"})))
}
