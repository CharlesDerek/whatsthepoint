use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use whatsthepoint::{App, api, config::Config, control_api, db, tls};
use wtp_control::{Credential, Request, Response, client};
struct Fixture {
    _dir: tempfile::TempDir,
    app: App,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_path = dir.path().join("master.crt");
    let key_path = dir.path().join("master.key");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Config {
        http_bind: address,
        public_origin: format!("https://{address}"),
        tls_certificate: Some(cert_path.clone()),
        tls_private_key: Some(key_path.clone()),
        ..Default::default()
    };
    let pool = db::open(dir.path()).await.unwrap();
    sqlx::query("INSERT INTO admins VALUES ('admin','unused-test-hash')")
        .execute(&pool)
        .await
        .unwrap();
    let app = App::new(pool, config).await.unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(tls::serve(
        listener,
        api::router(app.clone()),
        tls::server_config(&cert_path, &key_path).unwrap(),
        cancel.clone(),
    ));
    Fixture {
        _dir: dir,
        app,
        cancel,
        task,
    }
}
async fn pair(f: &Fixture, role: &str, endpoint: Option<&str>) -> Credential {
    let bundle = control_api::issue(&f.app, "admin", "paired test", role, endpoint)
        .await
        .unwrap_or_else(|e| panic!("{}", e.1));
    tokio::task::spawn_blocking(move || {
        client::pair(&bundle, wtp_control::identity::node().unwrap())
    })
    .await
    .unwrap()
    .unwrap()
}
async fn raw(credential: &Credential, request: Request) -> (u16, Value) {
    let credential = credential.clone();
    tokio::task::spawn_blocking(move || {
        let response = client::http(&credential.master)
            .unwrap()
            .post(format!("{}/control/request", credential.master.origin))
            .header("X-WTP-Request", "1")
            .json(&request)
            .send()
            .unwrap();
        let status = response.status().as_u16();
        (status, response.json().unwrap())
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_pq_tls_pairing_replay_protection_console_proxy_and_revocation() {
    let f = fixture().await;
    let credential = pair(&f, "console", None).await;
    let secret: String = sqlx::query_scalar("SELECT secret FROM principals WHERE id=?")
        .bind(&credential.principal_id)
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert!(!secret.contains(&credential.secret));
    let request = Request::new(
        &credential,
        "POST",
        "/api/rules",
        json!({"domain":"paired.test","action":"block","note":"signed desktop request"})
            .to_string(),
    )
    .unwrap();
    let (first, second) = tokio::join!(
        raw(&credential, request.clone()),
        raw(&credential, request.clone())
    );
    assert!((first.0 == 200 && second.0 == 401) || (first.0 == 401 && second.0 == 200));
    let body = if first.0 == 200 { first.1 } else { second.1 };
    let response: Response = serde_json::from_value(body).unwrap();
    response.verify(&credential.secret, &request).unwrap();
    assert_eq!(response.status, 200, "{}", response.body);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rules WHERE domain='paired.test'")
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mut tampered = Request::new(&credential, "GET", "/api/me", String::new()).unwrap();
    tampered.path = "/api/endpoints".into();
    assert_eq!(raw(&credential, tampered).await.0, 401);
    // Nonces survive application recreation; there is no in-memory-only replay cache.
    let reloaded = App::new(f.app.db.clone(), f.app.config.as_ref().clone())
        .await
        .unwrap();
    use tower::ServiceExt;
    let response = api::router(reloaded)
        .layer(axum::Extension(axum::extract::ConnectInfo(
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
        )))
        .layer(axum::Extension(tls::TlsPeer {
            suite: wtp_control::SUITE.into(),
        }))
        .oneshot(
            axum::http::Request::builder()
                .uri("/control/request")
                .method("POST")
                .header(
                    "host",
                    credential.master.origin.strip_prefix("https://").unwrap(),
                )
                .header("x-wtp-request", "1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let master = credential.master.clone();
    tokio::task::spawn_blocking(move || {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut master.certificate_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let http = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(tls)
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(
            http.get(format!("{}/healthz", master.origin))
                .send()
                .is_err(),
            "Classical-only downgrade accepted"
        );
    })
    .await
    .unwrap();
    sqlx::query("UPDATE principals SET revoked=1 WHERE id=?")
        .bind(&credential.principal_id)
        .execute(&f.app.db)
        .await
        .unwrap();
    assert_eq!(
        raw(
            &credential,
            Request::new(&credential, "GET", "/api/me", String::new()).unwrap()
        )
        .await
        .0,
        401
    );
    f.cancel.cancel();
    f.task.await.unwrap().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invitation_is_single_use_and_agent_cannot_administer_portal() {
    let f = fixture().await;
    let id = "e".repeat(32);
    let network = json!({"dns_servers":["192.0.2.53"],"allowed_tcp":["192.0.2.10:443"],"allowed_udp":[],"interfaces":["eth0"],"dhcp":false});
    sqlx::query("INSERT INTO endpoints(id,name,platform,token_hash,control,revision,network) VALUES(?,'test',?,'test-token','192.0.2.10:443',1,?)").bind(&id).bind(std::env::consts::OS).bind(network.to_string()).execute(&f.app.db).await.unwrap();
    let bundle = control_api::issue(&f.app, "admin", "agent", "agent", Some(&id))
        .await
        .unwrap_or_else(|e| panic!("{}", e.1));
    let copy = bundle.clone();
    let credential = tokio::task::spawn_blocking(move || {
        client::pair(&bundle, wtp_control::identity::node().unwrap())
    })
    .await
    .unwrap()
    .unwrap();
    tokio::task::spawn_blocking(move || {
        assert!(client::pair(&copy, wtp_control::identity::node().unwrap()).is_err())
    })
    .await
    .unwrap();
    let request = Request::new(&credential, "GET", "/api/endpoints", String::new()).unwrap();
    let (status, body) = raw(&credential, request.clone()).await;
    assert_eq!(status, 200);
    let response: Response = serde_json::from_value(body).unwrap();
    response.verify(&credential.secret, &request).unwrap();
    assert_eq!(response.status, 403);
    let status = wtp_endpoint::runtime::Status {
        state: "enforced".into(),
        remote_uninstall: true,
        ..Default::default()
    };
    let request = Request::new(
        &credential,
        "POST",
        "/endpoint/policy",
        serde_json::to_string(&status).unwrap(),
    )
    .unwrap();
    let (_, body) = raw(&credential, request.clone()).await;
    let response: Response = serde_json::from_value(body).unwrap();
    response.verify(&credential.secret, &request).unwrap();
    assert_eq!(response.status, 200);
    let console = pair(&f, "console", None).await;
    let request = Request::new(
        &console,
        "POST",
        &format!("/api/endpoints/{id}/uninstall"),
        json!({"revision":1}).to_string(),
    )
    .unwrap();
    let (_, body) = raw(&console, request).await;
    let response: Response = serde_json::from_value(body).unwrap();
    assert_eq!(response.status, 200, "{}", response.body);
    let request = Request::new(
        &credential,
        "POST",
        "/endpoint/policy",
        serde_json::to_string(&status).unwrap(),
    )
    .unwrap();
    let (_, body) = raw(&credential, request).await;
    let response: Response = serde_json::from_value(body).unwrap();
    let policy: wtp_endpoint::ControlPolicy = serde_json::from_str(&response.body).unwrap();
    assert!(policy.command.is_some());
    let command: wtp_endpoint::RemoteCommand = wtp_endpoint::verify(
        &policy.command.unwrap(),
        wtp_endpoint::COMMAND_DOMAIN,
        &f.app.endpoint_key.verifying_key(),
    )
    .unwrap();
    assert_eq!(command.endpoint_id, id);
    assert_eq!(command.principal_id, credential.principal_id);
    assert_eq!(command.node_hash, credential.node_hash);
    assert_eq!(command.kind, "uninstall");
    let receipt = json!({"id":command.id,"state":"completed","detail":"test receipt"});
    let request = Request::new(
        &credential,
        "POST",
        "/endpoint/command-receipt",
        receipt.to_string(),
    )
    .unwrap();
    assert_eq!(raw(&credential, request).await.0, 200);
    let request = Request::new(
        &credential,
        "POST",
        "/endpoint/policy",
        serde_json::to_string(&status).unwrap(),
    )
    .unwrap();
    assert_eq!(raw(&credential, request).await.0, 401);
    f.cancel.cancel();
    f.task.await.unwrap().unwrap();
}
