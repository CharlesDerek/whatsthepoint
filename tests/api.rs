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

async fn agent_request(
    router: &axum::Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
    origin: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(path)
        .method(method)
        .header("host", "127.0.0.1:8080")
        .header("origin", origin)
        .header("x-wtp-request", "1")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn browser_enrollment_hierarchy_identity_revocation_and_privacy() {
    let (_dir, app, router) = fixture().await;
    let origin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        request(&router, "GET", "/api/browser", None, None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf) = login(&router).await;
    let (status,_,enrollment)=request(&router,"POST","/api/browser/profiles",Some(json!({"name":"Student laptop","group_name":"Students","os":"linux","account_id":"1000","require_native":true})),Some(&cookie),Some(&csrf)).await;
    assert_eq!(status, StatusCode::OK, "{enrollment}");
    let token = enrollment["token"].as_str().unwrap();
    let id = enrollment["id"].as_i64().unwrap();
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM browser_profiles WHERE id=?")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_ne!(stored, token);
    let mut policy = json!(whatsthepoint::browser::BrowserPolicy::default());
    policy["rules"] = json!([
        {"id":"profile-allow","scope":"profile","target":id.to_string(),"priority":0,"kind":"all","pattern":"","action":"allow","enabled":true},
        {"id":"group-path","scope":"group","target":"Students","priority":10,"kind":"path","pattern":"https://example.com/private","action":"block","enabled":true},
        {"id":"global-category","scope":"global","target":"","priority":20,"kind":"category","pattern":"gambling","action":"block","enabled":true}
    ]);
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/browser/policy",
            Some(policy.clone()),
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
            "/api/browser/policy",
            Some(policy.clone()),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/browser/policy",
            Some(policy),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let identity = json!({"os":"linux","account_id":"1000","username":"student"});
    let (status,verdict)=agent_request(&router,"POST","/agent/check",token,Some(json!({"url":"https://example.com/private/report?session=secret&utm_source=ad","identity":identity})),origin).await;
    assert_eq!(status, StatusCode::OK, "{verdict}");
    assert_eq!(verdict["action"], "block");
    assert_eq!(verdict["rule_id"], "group-path");
    assert_eq!(
        verdict["url"],
        "https://example.com/private/report?session=secret"
    );
    let logged: String =
        sqlx::query_scalar("SELECT url FROM browser_events ORDER BY id DESC LIMIT 1")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(logged, "https://example.com/private/report");
    for (url, categories, rule) in [
        ("https://example.com/privateish", json!([]), "profile-allow"),
        (
            "https://example.com/ok",
            json!(["gambling"]),
            "global-category",
        ),
        ("https://example.com/%70rivate", json!([]), "group-path"),
    ] {
        let (_, verdict) = agent_request(
            &router,
            "POST",
            "/agent/check",
            token,
            Some(json!({"url":url,"identity":identity,"categories":categories})),
            origin,
        )
        .await;
        assert_eq!(verdict["rule_id"], rule, "{verdict}");
    }
    let (_, verdict) = agent_request(
        &router,
        "POST",
        "/agent/check",
        token,
        Some(json!({"url":"https://blocked.test","identity":identity})),
        origin,
    )
    .await;
    assert_eq!(verdict["action"], "block");
    assert!(
        verdict["reason"]
            .as_str()
            .unwrap()
            .starts_with("DNS baseline")
    );
    let (_, verdict) = agent_request(
        &router,
        "POST",
        "/agent/check",
        token,
        Some(json!({"url":"https://example.com/"})),
        origin,
    )
    .await;
    assert_eq!(verdict["action"], "block");
    assert!(verdict["reason"].as_str().unwrap().contains("identity"));
    assert_eq!(
        agent_request(
            &router,
            "GET",
            "/agent/policy",
            token,
            None,
            "https://evil.test"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        agent_request(&router, "GET", "/api/browser", token, None, origin)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        agent_request(
            &router,
            "POST",
            "/agent/check",
            token,
            Some(json!({"url":"file:///etc/passwd"})),
            origin
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        agent_request(
            &router,
            "POST",
            "/agent/check",
            token,
            Some(json!({"url":"https://example.com/private%2fsecret"})),
            origin
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let loaded = whatsthepoint::browser::BrowserPolicy::load(&app.db)
        .await
        .unwrap();
    assert_eq!(loaded.revision, 1);
    assert_eq!(loaded.rules[0].id, "global-category");
    assert_eq!(
        request(
            &router,
            "POST",
            &format!("/api/browser/profiles/{id}/revoke"),
            None,
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        agent_request(&router, "GET", "/agent/policy", token, None, origin)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, rotated) = request(
        &router,
        "POST",
        &format!("/api/browser/profiles/{id}/rotate"),
        None,
        Some(&cookie),
        Some(&csrf),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let replacement = rotated["token"].as_str().unwrap();
    assert_ne!(token, replacement);
    assert_eq!(
        agent_request(&router, "GET", "/agent/policy", token, None, origin)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        agent_request(&router, "GET", "/agent/policy", replacement, None, origin)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(request(&router,"POST",&format!("/api/browser/profiles/{id}"),Some(json!({"name":"Moved profile","group_name":"Staff","os":"linux","account_id":"1000","require_native":true})),Some(&cookie),Some(&csrf)).await.0,StatusCode::OK);
    let (_, verdict) = agent_request(
        &router,
        "POST",
        "/agent/check",
        replacement,
        Some(json!({"url":"https://example.com/private/report","identity":identity})),
        origin,
    )
    .await;
    assert_eq!(verdict["rule_id"], "profile-allow");
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_events")
        .fetch_one(&app.db)
        .await
        .unwrap();
    let quiet = App::new(
        app.db.clone(),
        Config {
            query_log: false,
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let quiet_router = api::router(quiet);
    assert_eq!(
        agent_request(
            &quiet_router,
            "POST",
            "/agent/check",
            replacement,
            Some(json!({"url":"https://example.org/","identity":identity})),
            origin
        )
        .await
        .0,
        StatusCode::OK
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_events")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(before, after);
    db::prune(&app.db, 7, 1).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM browser_events")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn browser_policy_preview_classification_and_validation() {
    let (_dir, _app, router) = fixture().await;
    let (cookie, csrf) = login(&router).await;
    let mut policy = json!(whatsthepoint::browser::BrowserPolicy::default());
    policy["rules"] = json!([{ "id":"unsafe-allow","scope":"global","target":"","priority":0,"kind":"category","pattern":"adult","action":"allow","enabled":true }]);
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/browser/policy",
            Some(policy.clone()),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    policy["rules"][0]["action"] = json!("sanitize");
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/browser/policy",
            Some(policy),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_,_,profile)=request(&router,"POST","/api/browser/profiles",Some(json!({"name":"Example","group_name":"","os":"","account_id":"","require_native":false})),Some(&cookie),Some(&csrf)).await;
    let (status,_,preview)=request(&router,"POST","/api/browser/preview",Some(json!({"profile_id":profile["id"],"url":"https://example.com/","text":"pornography and adult videos"})),Some(&cookie),Some(&csrf)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["verdict"]["action"], "sanitize");
    let (_, _, overview) = request(&router, "GET", "/api/browser", None, Some(&cookie), None).await;
    assert!(
        !overview
            .to_string()
            .contains(profile["token"].as_str().unwrap())
    );
}

#[tokio::test]
async fn endpoint_enrollment_signed_updates_quarantine_and_token_isolation() {
    let (_dir, app, _) = fixture().await;
    let config = Config {
        public_origin: "https://127.0.0.1:8080".into(),
        ..Config::default()
    };
    let app = App::new(app.db.clone(), config).await.unwrap();
    let router = api::router(app.clone()).layer(axum::Extension(ConnectInfo(
        "127.0.0.1:4567".parse::<std::net::SocketAddr>().unwrap(),
    )));
    let (cookie, csrf) = login(&router).await;
    let network = json!({"interfaces":["eth0"],"dhcp":true,"dns_servers":["192.0.2.53"],"allowed_tcp":["192.0.2.10:8080","192.0.2.20:443"],"allowed_udp":[]});
    let input = json!({"name":"Managed laptop","platform":"linux","control":"192.0.2.10:8080","network":network});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/endpoints",
            Some(input.clone()),
            Some(&cookie),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, body) = request(
        &router,
        "POST",
        "/api/endpoints",
        Some(input),
        Some(&cookie),
        Some(&csrf),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let config: wtp_endpoint::AgentConfig = serde_json::from_value(body["config"].clone()).unwrap();
    let envelope: wtp_endpoint::Envelope = serde_json::from_value(body["policy"].clone()).unwrap();
    let key = wtp_endpoint::public_key(&config.public_key).unwrap();
    let policy: wtp_endpoint::Policy =
        wtp_endpoint::verify(&envelope, wtp_endpoint::POLICY_DOMAIN, &key).unwrap();
    let watermark = wtp_endpoint::Watermark::default()
        .accept(&policy, &config, whatsthepoint::now())
        .unwrap();
    assert_eq!(policy.revision, 1);
    let list = request(&router, "GET", "/api/endpoints", None, Some(&cookie), None)
        .await
        .2;
    assert!(!list.to_string().contains(&config.token));
    assert!(!list.to_string().contains("token_hash"));
    let path = format!("/api/endpoints/{}", config.endpoint_id);
    let update = json!({"revision":1,"network":network,"quarantined":true});
    assert_eq!(
        request(
            &router,
            "POST",
            &path,
            Some(update.clone()),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            "POST",
            &path,
            Some(update),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut invalid = network.clone();
    invalid["allowed_tcp"] = json!([]);
    assert_eq!(
        request(
            &router,
            "POST",
            &path,
            Some(json!({"revision":2,"network":invalid,"quarantined":false})),
            Some(&cookie),
            Some(&csrf)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    async fn fetch(router: &axum::Router, token: &str, path: &str) -> (StatusCode, Value) {
        let status = wtp_endpoint::runtime::Status {
            state: "enforced".into(),
            revision: 1,
            checked_at: whatsthepoint::now(),
            detail: "Signed policy applied".into(),
            fingerprint: "0".repeat(64),
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "127.0.0.1:8080")
                    .header("x-wtp-request", "1")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(serde_json::to_vec(&status).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let code = response.status();
        let bytes = to_bytes(response.into_body(), 262144).await.unwrap();
        (code, serde_json::from_slice(&bytes).unwrap())
    }
    let (status, body) = fetch(&router, &config.token, "/endpoint/policy").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let envelope = serde_json::from_value(body).unwrap();
    let quarantine: wtp_endpoint::Policy =
        wtp_endpoint::verify(&envelope, wtp_endpoint::POLICY_DOMAIN, &key).unwrap();
    assert_eq!(quarantine.revision, 2);
    assert!(quarantine.network.dns_servers.is_empty());
    assert_eq!(quarantine.network.allowed_tcp, vec![config.control]);
    watermark
        .accept(&quarantine, &config, whatsthepoint::now())
        .unwrap();
    assert_eq!(
        fetch(&router, &auth::token(), "/endpoint/policy").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fetch(&router, &config.token, "/api/endpoints").await.0,
        StatusCode::UNAUTHORIZED
    );
    let list = request(&router, "GET", "/api/endpoints", None, Some(&cookie), None)
        .await
        .2;
    assert_eq!(list["devices"][0]["reported_revision"], 1);
    assert!(list["devices"][0]["last_seen"].is_number());
    let reloaded = App::new(app.db.clone(), app.config.as_ref().clone())
        .await
        .unwrap();
    assert_eq!(key, reloaded.endpoint_key.verifying_key());
}
