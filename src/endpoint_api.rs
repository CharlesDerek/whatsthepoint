use crate::{
    App,
    api::{ApiError, Session, bad},
    auth, db,
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use std::net::SocketAddr;
use wtp_endpoint::{AgentConfig, NetworkPolicy, POLICY_DOMAIN, Policy};
type Result<T> = std::result::Result<T, ApiError>;
#[derive(Serialize, FromRow)]
struct Endpoint {
    id: String,
    name: String,
    platform: String,
    control: String,
    revision: i64,
    network: String,
    quarantined: bool,
    last_seen: Option<i64>,
    reported_revision: i64,
    reported_state: String,
    detail: String,
    remote_uninstall_enabled: bool,
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/endpoints", get(list).post(enroll))
        .route("/api/endpoints/{id}", post(update))
        .route("/endpoint/policy", post(fetch))
        .layer(DefaultBodyLimit::max(65536))
}
async fn list(State(app): State<App>) -> Result<Json<Value>> {
    let devices = sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints ORDER BY name")
        .fetch_all(&app.db)
        .await?;
    Ok(Json(
        json!({"public_key":hex::encode(app.endpoint_key.verifying_key().to_bytes()),"devices":devices,"master_control":app.master.as_ref().map(|m|m.control.to_string())}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    name: String,
    platform: String,
    control: SocketAddr,
    network: NetworkPolicy,
    #[serde(default)]
    allow_remote_uninstall: bool,
}
async fn enroll(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<Enrollment>,
) -> Result<Json<Value>> {
    if input.name.trim().is_empty() || input.name.len() > 80 {
        return Err(bad("Enter an endpoint name up to 80 characters"));
    }
    input.network.validate().map_err(|e| bad(e.to_string()))?;
    if app
        .master
        .as_ref()
        .is_some_and(|m| m.control != input.control)
    {
        return Err(bad("Management address must match the paired master"));
    }
    let id = auth::token()[..32].to_owned();
    let token = auth::token();
    let mut config = AgentConfig {
        endpoint_id: id.clone(),
        platform: input.platform.clone(),
        portal: app.config.public_origin.clone(),
        control: input.control,
        token: token.clone(),
        public_key: hex::encode(app.endpoint_key.verifying_key().to_bytes()),
        interfaces: input.network.interfaces.clone(),
        dhcp: input.network.dhcp,
        pairing: None,
        paired_master: None,
        allow_remote_uninstall: input.allow_remote_uninstall,
    };
    config.validate().map_err(|e| {
        bad(format!(
            "{e}. Endpoint enrollment requires an HTTPS public_origin."
        ))
    })?;
    if !input.network.allowed_tcp.contains(&input.control) {
        return Err(bad(
            "Include the management control IP:port in approved TCP endpoints",
        ));
    }
    let _guard = app.mutation.lock().await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM endpoints")
        .fetch_one(&app.db)
        .await?;
    if count >= 10000 {
        return Err(bad("Endpoint limit reached"));
    }
    sqlx::query("INSERT INTO endpoints(id,name,platform,token_hash,control,revision,network) VALUES (?,?,?,?,?,1,?)")
        .bind(&id).bind(input.name.trim()).bind(&input.platform).bind(auth::digest(&token)).bind(input.control.to_string()).bind(serde_json::to_string(&input.network).map_err(anyhow::Error::from)?).execute(&app.db).await?;
    db::audit(
        &app.db,
        &session.username,
        "endpoint.enroll",
        &format!("{id}: {}", input.name),
    )
    .await?;
    if app.master.is_some() {
        config.pairing = Some(
            crate::control_api::issue(&app, &session.username, &input.name, "agent", Some(&id))
                .await?,
        );
    }
    let policy = Policy {
        endpoint_id: id,
        platform: input.platform,
        revision: 1,
        issued_at: crate::now(),
        expires_at: crate::now() + 300,
        network: input.network,
    };
    let envelope = wtp_endpoint::sign(&policy, POLICY_DOMAIN, &app.endpoint_key)?;
    Ok(Json(json!({"config":config,"policy":envelope})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    revision: i64,
    network: NetworkPolicy,
    quarantined: bool,
}
async fn update(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(input): Json<Update>,
) -> Result<Json<Value>> {
    input.network.validate().map_err(|e| bad(e.to_string()))?;
    let _guard = app.mutation.lock().await;
    let endpoint = sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE id=?")
        .bind(&id)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(|| bad("Endpoint not found"))?;
    if endpoint.revision != input.revision {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Endpoint policy changed. Reload before publishing.".into(),
        ));
    }
    let old: NetworkPolicy =
        serde_json::from_str(&endpoint.network).map_err(anyhow::Error::from)?;
    if old.interfaces != input.network.interfaces {
        return Err(bad(
            "Physical interface changes require administrator re-enrollment",
        ));
    }
    let control: SocketAddr = endpoint.control.parse().map_err(anyhow::Error::from)?;
    if !input.network.allowed_tcp.contains(&control) {
        return Err(bad("Policy must retain the management endpoint"));
    }
    sqlx::query("UPDATE endpoints SET network=?,quarantined=?,revision=revision+1 WHERE id=?")
        .bind(serde_json::to_string(&input.network).map_err(anyhow::Error::from)?)
        .bind(input.quarantined)
        .bind(&id)
        .execute(&app.db)
        .await?;
    db::audit(
        &app.db,
        &session.username,
        "endpoint.policy",
        &format!(
            "{id}: revision {}, quarantined={}",
            endpoint.revision + 1,
            input.quarantined
        ),
    )
    .await?;
    Ok(Json(json!({"revision":endpoint.revision+1})))
}
async fn fetch(
    State(app): State<App>,
    headers: HeaderMap,
    Json(status): Json<wtp_endpoint::runtime::Status>,
) -> Result<Json<Value>> {
    let unauthorized = || {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "Invalid endpoint credential".into(),
        )
    };
    let token = headers
        .get("authorization")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(unauthorized)?;
    let endpoint = sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE token_hash=?")
        .bind(auth::digest(token))
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(unauthorized)?;
    let paired: i64 = sqlx::query_scalar("SELECT count(*) FROM principals WHERE endpoint_id=?")
        .bind(&endpoint.id)
        .fetch_one(&app.db)
        .await?;
    if paired > 0 {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "This endpoint requires its paired control credential".into(),
        ));
    }
    if status.revision > i64::MAX as u64
        || status.detail.len() > 512
        || status.state.len() > 64
        || status.fingerprint.len() > 128
    {
        return Err(bad("Invalid status report"));
    }
    sqlx::query(
        "UPDATE endpoints SET last_seen=?,reported_revision=?,reported_state=?,detail=? WHERE id=?",
    )
    .bind(crate::now())
    .bind(status.revision as i64)
    .bind(&status.state)
    .bind(&status.detail)
    .bind(&endpoint.id)
    .execute(&app.db)
    .await?;
    let network: NetworkPolicy =
        serde_json::from_str(&endpoint.network).map_err(anyhow::Error::from)?;
    let network = if endpoint.quarantined {
        network.quarantine(endpoint.control.parse().map_err(anyhow::Error::from)?)
    } else {
        network
    };
    let policy = Policy {
        endpoint_id: endpoint.id,
        platform: endpoint.platform,
        revision: endpoint.revision as u64,
        issued_at: crate::now(),
        expires_at: crate::now() + 300,
        network,
    };
    Ok(Json(json!(wtp_endpoint::sign(
        &policy,
        POLICY_DOMAIN,
        &app.endpoint_key
    )?)))
}

pub(crate) async fn paired_policy(
    app: &App,
    id: &str,
    principal: &str,
    node_hash: &str,
    status: wtp_endpoint::runtime::Status,
) -> Result<Value> {
    let endpoint = sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE id=?")
        .bind(id)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(|| bad("Endpoint not found"))?;
    if status.revision > i64::MAX as u64
        || status.detail.len() > 512
        || status.state.len() > 64
        || status.fingerprint.len() > 128
    {
        return Err(bad("Invalid agent report"));
    }
    sqlx::query("UPDATE endpoints SET last_seen=?,reported_revision=?,reported_state=?,detail=?,remote_uninstall_enabled=? WHERE id=?").bind(crate::now()).bind(status.revision as i64).bind(&status.state).bind(&status.detail).bind(status.remote_uninstall).bind(id).execute(&app.db).await?;
    let network: NetworkPolicy =
        serde_json::from_str(&endpoint.network).map_err(anyhow::Error::from)?;
    let network = if endpoint.quarantined {
        network.quarantine(endpoint.control.parse().map_err(anyhow::Error::from)?)
    } else {
        network
    };
    let policy = Policy {
        endpoint_id: id.into(),
        platform: endpoint.platform,
        revision: endpoint.revision as u64,
        issued_at: crate::now(),
        expires_at: crate::now() + 300,
        network,
    };
    #[derive(FromRow)]
    struct Command {
        id: i64,
        kind: String,
        created_at: i64,
        expires_at: i64,
    }
    let pending=sqlx::query_as::<_,Command>("SELECT * FROM endpoint_commands WHERE endpoint_id=? AND principal_id=? AND node_hash=? AND state IN ('queued','delivered') AND expires_at>? ORDER BY id LIMIT 1").bind(id).bind(principal).bind(node_hash).bind(crate::now()).fetch_optional(&app.db).await?;
    let command = if let Some(command) = pending {
        let value = wtp_endpoint::RemoteCommand {
            id: command.id as u64,
            endpoint_id: id.into(),
            principal_id: principal.into(),
            node_hash: node_hash.into(),
            kind: command.kind,
            issued_at: command.created_at,
            expires_at: command.expires_at,
        };
        sqlx::query("UPDATE endpoint_commands SET state='delivered' WHERE id=? AND state='queued'")
            .bind(command.id)
            .execute(&app.db)
            .await?;
        Some(wtp_endpoint::sign(
            &value,
            wtp_endpoint::COMMAND_DOMAIN,
            &app.endpoint_key,
        )?)
    } else {
        None
    };
    Ok(json!(wtp_endpoint::ControlPolicy {
        policy: wtp_endpoint::sign(&policy, POLICY_DOMAIN, &app.endpoint_key)?,
        command
    }))
}
