use crate::{
    App,
    api::{ApiError, Session, bad},
    auth,
    browser::{BrowserPolicy, Check, Profile},
    db,
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
type Result<T> = std::result::Result<T, ApiError>;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/browser", get(overview))
        .route("/api/browser/policy", post(save_policy))
        .route("/api/browser/profiles", post(add_profile))
        .route("/api/browser/profiles/{id}", post(update_profile))
        .route("/api/browser/profiles/{id}/rotate", post(rotate))
        .route("/api/browser/profiles/{id}/revoke", post(revoke))
        .route("/api/browser/preview", post(preview))
        .route("/agent/policy", get(agent_policy))
        .route("/agent/check", post(agent_check))
        .layer(DefaultBodyLimit::max(256 * 1024))
}

async fn overview(State(app): State<App>) -> Result<Json<Value>> {
    let profiles = sqlx::query_as::<_, Profile>("SELECT * FROM browser_profiles ORDER BY id DESC")
        .fetch_all(&app.db)
        .await?;
    let events: Vec<(i64,String,String,String,String,String)> = sqlx::query_as("SELECT e.at, p.name, e.url, e.action, e.reason, e.categories FROM browser_events e JOIN browser_profiles p ON p.id=e.profile_id ORDER BY e.id DESC LIMIT 100").fetch_all(&app.db).await?;
    Ok(Json(
        json!({"policy":*app.browser_policy.read().await,"profiles":profiles,"events":events}),
    ))
}

async fn save_policy(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(mut policy): Json<BrowserPolicy>,
) -> Result<Json<Value>> {
    policy.validate().map_err(|e| bad(e.to_string()))?;
    let _guard = app.mutation.lock().await;
    if policy.revision != app.browser_policy.read().await.revision {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Policy changed in another session. Reload before saving.".into(),
        ));
    }
    policy.revision += 1;
    let document = serde_json::to_string(&policy).map_err(anyhow::Error::from)?;
    let mut tx = app.db.begin().await?;
    sqlx::query("INSERT INTO browser_policy VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, document=excluded.document")
        .bind(policy.revision).bind(document).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit(at,actor,event,detail) VALUES (?,?,'browser.policy',?)")
        .bind(crate::now())
        .bind(&session.username)
        .bind(format!(
            "Revision {}: {} rules",
            policy.revision,
            policy.rules.len()
        ))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    *app.browser_policy.write().await = policy.clone();
    Ok(Json(json!({"revision":policy.revision})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    name: String,
    group_name: String,
    os: String,
    account_id: String,
    require_native: bool,
}
fn validate_enrollment(input: &Enrollment) -> Result<()> {
    if input.name.trim().is_empty()
        || input.name.len() > 80
        || input.group_name.len() > 80
        || input.account_id.len() > 256
        || !matches!(input.os.as_str(), "" | "linux" | "windows" | "macos")
        || (input.require_native && (input.os.is_empty() || input.account_id.trim().is_empty()))
    {
        return Err(bad(
            "Enter a name, group, and (for native identity) an OS and account ID.",
        ));
    }
    Ok(())
}
async fn update_profile(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
    Json(input): Json<Enrollment>,
) -> Result<Json<Value>> {
    validate_enrollment(&input)?;
    let result=sqlx::query("UPDATE browser_profiles SET name=?,group_name=?,os=?,account_id=?,require_native=? WHERE id=?")
        .bind(input.name.trim()).bind(input.group_name.trim()).bind(input.os).bind(input.account_id.trim()).bind(input.require_native).bind(id).execute(&app.db).await?;
    if result.rows_affected() == 0 {
        return Err(bad("Profile not found"));
    }
    db::audit(
        &app.db,
        &session.username,
        "browser.profile",
        &format!("Updated profile {id}: {}", input.name),
    )
    .await?;
    Ok(Json(json!({"ok":true})))
}
async fn rotate(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
) -> Result<Json<Value>> {
    let token = auth::token();
    let result = sqlx::query("UPDATE browser_profiles SET token_hash=?,revoked=0 WHERE id=?")
        .bind(auth::digest(&token))
        .bind(id)
        .execute(&app.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(bad("Profile not found"));
    }
    db::audit(
        &app.db,
        &session.username,
        "browser.rotate",
        &format!("Replaced credential for profile {id}"),
    )
    .await?;
    Ok(Json(
        json!({"id":id,"token":token,"portal":app.config.public_origin}),
    ))
}
async fn add_profile(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Json(input): Json<Enrollment>,
) -> Result<Json<Value>> {
    validate_enrollment(&input)?;
    let _guard = app.mutation.lock().await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_profiles")
        .fetch_one(&app.db)
        .await?;
    if count >= 10000 {
        return Err(bad("Profile limit reached"));
    }
    let token = auth::token();
    let id = sqlx::query("INSERT INTO browser_profiles(name,group_name,os,account_id,require_native,token_hash,created_at) VALUES (?,?,?,?,?,?,?)")
        .bind(input.name.trim()).bind(input.group_name.trim()).bind(input.os).bind(input.account_id.trim()).bind(input.require_native).bind(auth::digest(&token)).bind(crate::now()).execute(&app.db).await?.last_insert_rowid();
    db::audit(
        &app.db,
        &session.username,
        "browser.enroll",
        &format!("Profile {id}: {}", input.name),
    )
    .await?;
    Ok(Json(
        json!({"id":id,"token":token,"portal":app.config.public_origin}),
    ))
}
async fn revoke(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    Path(id): Path<i64>,
) -> Result<Json<Value>> {
    sqlx::query("UPDATE browser_profiles SET revoked=1 WHERE id=?")
        .bind(id)
        .execute(&app.db)
        .await?;
    db::audit(
        &app.db,
        &session.username,
        "browser.revoke",
        &id.to_string(),
    )
    .await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    profile_id: i64,
    url: String,
    #[serde(default)]
    text: String,
}
async fn preview(State(app): State<App>, Json(input): Json<Preview>) -> Result<Json<Value>> {
    if input.text.len() > 32000 {
        return Err(bad("Preview text exceeds 32 KB"));
    }
    let profile = sqlx::query_as::<_, Profile>("SELECT * FROM browser_profiles WHERE id=?")
        .bind(input.profile_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(|| bad("Profile not found"))?;
    let policy = app.browser_policy.read().await;
    let url = crate::browser::clean_url(&input.url).map_err(|e| bad(e.to_string()))?;
    let categories = policy.classify(&url, &input.text, &[]);
    let check = Check {
        url: input.url,
        categories,
        identity: Some(crate::browser::Identity {
            os: profile.os.clone(),
            account_id: profile.account_id.clone(),
            username: String::new(),
        }),
    };
    let verdict = policy
        .decide(&profile, &check, &*app.policy.read().await)
        .map_err(|e| bad(e.to_string()))?;
    Ok(Json(json!({"verdict":verdict,"identity_assumed":true})))
}

async fn authenticate(app: &App, headers: &HeaderMap) -> Result<Profile> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "Enroll this browser profile to continue.".into(),
            )
        })?;
    sqlx::query_as::<_, Profile>("SELECT * FROM browser_profiles WHERE token_hash=? AND revoked=0")
        .bind(auth::digest(token))
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "Profile token is invalid or revoked.".into(),
            )
        })
}
async fn agent_policy(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>> {
    let profile = authenticate(&app, &headers).await?;
    let policy = app.browser_policy.read().await;
    Ok(Json(
        json!({"revision":policy.revision,"categories":policy.categories,"profile":profile}),
    ))
}
async fn agent_check(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Check>,
) -> Result<Json<Value>> {
    let profile = authenticate(&app, &headers).await?;
    let verdict = app
        .browser_policy
        .read()
        .await
        .decide(&profile, &input, &*app.policy.read().await)
        .map_err(|e| bad(e.to_string()))?;
    sqlx::query("UPDATE browser_profiles SET last_seen=? WHERE id=? AND (last_seen IS NULL OR last_seen < ?)").bind(crate::now()).bind(profile.id).bind(crate::now()-60).execute(&app.db).await?;
    if app.config.query_log {
        let mut logged = reqwest::Url::parse(&verdict.url).map_err(anyhow::Error::from)?;
        logged.set_query(None);
        logged.set_fragment(None);
        sqlx::query("INSERT INTO browser_events(at,profile_id,url,action,reason,categories) VALUES (?,?,?,?,?,?)")
            .bind(crate::now()).bind(profile.id).bind(logged.as_str()).bind(&verdict.action).bind(&verdict.reason).bind(verdict.categories.join(", ")).execute(&app.db).await?;
    }
    Ok(Json(json!(verdict)))
}
