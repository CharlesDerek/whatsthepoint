use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use whatsthepoint::{App, api, auth, config::Config, db};

async fn fixture() -> (tempfile::TempDir, App, axum::Router) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(dir.path()).await.unwrap();
    let hash = auth::hash_password("a strong test password").unwrap();
    sqlx::query("INSERT INTO admins VALUES ('admin', ?)")
        .bind(hash)
        .execute(&pool)
        .await
        .unwrap();
    let app = App::new(pool, Config::default()).await.unwrap();
    let router = api::router(app.clone()).layer(axum::Extension(ConnectInfo(
        "127.0.0.1:4567".parse::<std::net::SocketAddr>().unwrap(),
    )));
    (dir, app, router)
}

async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut req = Request::builder()
        .uri(path)
        .method(method)
        .header("host", "127.0.0.1:8080")
        .header("x-wtp-request", "1");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    if let Some(csrf) = csrf {
        req = req.header("x-csrf-token", csrf);
    }
    let response = router
        .clone()
        .oneshot(
            req.header("content-type", "application/json")
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn login(router: &axum::Router) -> (String, String) {
    let (status, headers, body) = request(
        router,
        "POST",
        "/api/login",
        Some(json!({"username":"admin","password":"a strong test password"})),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let set_cookie = headers["set-cookie"].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    (
        set_cookie.split(';').next().unwrap().to_owned(),
        body["csrf"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn authenticated_rules_csrf_logout_and_persistence() {
    let (_dir, app, router) = fixture().await;
    assert_eq!(
        request(&router, "GET", "/api/rules", None, None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf) = login(&router).await;
    let rule = json!({"domain":"EXAMPLE.com.","action":"block","note":"Test"});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/rules",
            Some(rule.clone()),
            Some(&cookie),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/rules",
            Some(rule),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(app.policy.read().await.decide("sub.example.com").blocked);
    let reload = whatsthepoint::policy::Policy::load(&app.db).await.unwrap();
    assert!(reload.decide("sub.example.com").blocked);
    let (_, _, rules) = request(&router, "GET", "/api/rules", None, Some(&cookie), None).await;
    let id = rules
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["domain"] == "example.com")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("/api/rules/{id}"),
            None,
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(!app.policy.read().await.decide("example.com").blocked);
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/logout",
            None,
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&router, "GET", "/api/me", None, Some(&cookie), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rejects_cross_origin_rebinding_and_invalid_login() {
    let (_dir, _app, router) = fixture().await;
    for (host, origin, expected) in [
        (
            "evil.example",
            "http://127.0.0.1:8080",
            StatusCode::MISDIRECTED_REQUEST,
        ),
        (
            "127.0.0.1:8080",
            "https://evil.example",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let req = Request::builder()
            .uri("/api/login")
            .method("POST")
            .header("host", host)
            .header("origin", origin)
            .header("x-wtp-request", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"a strong test password"}"#,
            ))
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["x-frame-options"], "DENY");
    }
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/login",
            Some(json!({"username":"admin","password":"wrong"})),
            None,
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn imports_are_atomic_and_allow_rules_override_lists() {
    let (_dir, app, router) = fixture().await;
    let (cookie, csrf) = login(&router).await;
    let good = json!({"name":"Test feed","contents":"ads.example.com\ntracker.example.com"});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/lists",
            Some(good),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(
        app.policy
            .read()
            .await
            .decide("sub.ads.example.com")
            .blocked
    );
    let bad = json!({"name":"Test feed","contents":"<html>not a blocklist</html>"});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/lists",
            Some(bad),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(app.policy.read().await.decide("ads.example.com").blocked);
    let allow = json!({"domain":"ads.example.com","action":"allow"});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/rules",
            Some(allow),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(!app.policy.read().await.decide("ads.example.com").blocked);
    assert!(
        app.policy
            .read()
            .await
            .decide("tracker.example.com")
            .blocked
    );
}

#[tokio::test]
async fn password_rotation_and_expiry_revoke_sessions() {
    let (_dir, app, router) = fixture().await;
    let (cookie, csrf) = login(&router).await;
    let input = json!({"current":"a strong test password","password":"a different long password"});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/password",
            Some(input),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&router, "GET", "/api/me", None, Some(&cookie), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, _) = request(
        &router,
        "POST",
        "/api/login",
        Some(json!({"username":"admin","password":"a different long password"})),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    sqlx::query("UPDATE sessions SET expires_at = 0")
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        request(&router, "GET", "/api/me", None, Some(cookie), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn retention_is_bounded() {
    let (_dir, app, _router) = fixture().await;
    for at in [
        0,
        whatsthepoint::now(),
        whatsthepoint::now(),
        whatsthepoint::now(),
    ] {
        sqlx::query("INSERT INTO queries(at, client, domain, qtype, decision, reason, elapsed_ms, cached, rcode) VALUES (?, '127.0.0.1', 'example.com','A','allowed','test',1,0,'NOERROR')")
            .bind(at).execute(&app.db).await.unwrap();
    }
    db::prune(&app.db, 7, 2).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM queries")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn configuration_rejects_unsafe_or_unknown_values() {
    let mut config = Config {
        http_bind: "0.0.0.0:8080".parse().unwrap(),
        ..Config::default()
    };
    assert!(config.validate().is_err());
    config.public_origin = "https://filter.example.com".into();
    assert!(config.validate().is_ok());
    config.upstreams[0].url = "http://dns.example.com/dns-query".into();
    assert!(config.validate().is_err());
    assert!(toml::from_str::<Config>("unknown_option = true").is_err());
}
