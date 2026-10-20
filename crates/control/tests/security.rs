use wtp_control::*;
fn master() -> Master {
    Master {
        id: "a".repeat(32),
        name: "test".into(),
        origin: "https://master.test:8443".into(),
        control: "192.0.2.10:8443".parse().unwrap(),
        mac_addresses: vec!["00:11:22:33:44:55".into()],
        certificate_pem: "test certificate".into(),
        policy_key: "c".repeat(64),
    }
}
fn node() -> Node {
    Node {
        installation_id: "b".repeat(32),
        platform: "linux".into(),
        account_id: "1000".into(),
        hostname: "test-desktop".into(),
        mac_addresses: vec!["10:11:22:33:44:55".into()],
    }
}
fn credential() -> Credential {
    let master = master();
    let node = node();
    Credential {
        principal_id: "d".repeat(32),
        secret: random_hex(32),
        node_hash: node.fingerprint(&master),
        master,
        node,
        role: "console".into(),
        endpoint_id: None,
        expires_at: now() + 3600,
    }
}
#[test]
fn authenticators_bind_method_path_body_principal_device_master_and_time() {
    let credential = credential();
    let request = Request::new(
        &credential,
        "POST",
        "/api/rules",
        r#"{"domain":"blocked.test","action":"block"}"#.into(),
    )
    .unwrap();
    request
        .verify(
            &credential.secret,
            &credential.master.fingerprint(),
            &credential.node_hash,
            now(),
        )
        .unwrap();
    for field in [
        "method",
        "path",
        "body",
        "nonce",
        "principal_id",
        "master_hash",
        "node_hash",
    ] {
        let mut altered = request.clone();
        match field {
            "method" => altered.method = "DELETE".into(),
            "path" => altered.path = "/api/endpoints".into(),
            "body" => altered.body = "{}".into(),
            "nonce" => altered.nonce = random_hex(32),
            "principal_id" => altered.principal_id = random_hex(16),
            "master_hash" => altered.master_hash = random_hex(32),
            _ => altered.node_hash = random_hex(32),
        }
        assert!(
            altered
                .verify(
                    &credential.secret,
                    &credential.master.fingerprint(),
                    &credential.node_hash,
                    now()
                )
                .is_err(),
            "{field}"
        );
    }
    assert!(
        request
            .verify(
                &credential.secret,
                &credential.master.fingerprint(),
                &credential.node_hash,
                now() + 121
            )
            .is_err()
    );
    assert!(
        request
            .verify(
                &random_hex(32),
                &credential.master.fingerprint(),
                &credential.node_hash,
                now()
            )
            .is_err()
    );
}
#[test]
fn response_cannot_be_changed_or_replayed_into_another_request() {
    let credential = credential();
    let request = Request::new(&credential, "GET", "/api/me", String::new()).unwrap();
    let mut response = Response::new(&credential.secret, &request, 200, "{}".into()).unwrap();
    response.verify(&credential.secret, &request).unwrap();
    let other = Request::new(&credential, "GET", "/api/me", String::new()).unwrap();
    assert!(response.verify(&credential.secret, &other).is_err());
    response.status = 201;
    assert!(response.verify(&credential.secret, &request).is_err());
    response.status = 200;
    response.body = "tampered".into();
    assert!(response.verify(&credential.secret, &request).is_err());
}
#[test]
fn pairing_proof_and_node_fingerprint_bind_public_context_to_secret() {
    let bundle = PairBundle {
        role: "console".into(),
        endpoint_id: None,
        master: master(),
        ticket_id: random_hex(16),
        secret: random_hex(32),
        expires_at: now() + 300,
    };
    let mut request = PairRequest::new(&bundle, node()).unwrap();
    request
        .verify(&bundle.secret, &bundle.master, now())
        .unwrap();
    let original = request.node.fingerprint(&bundle.master);
    request.node.mac_addresses = vec!["20:11:22:33:44:55".into()];
    assert_ne!(original, request.node.fingerprint(&bundle.master));
    assert!(
        request
            .verify(&bundle.secret, &bundle.master, now())
            .is_err()
    );
    let mut another = bundle.master.clone();
    another.policy_key = random_hex(32);
    assert_ne!(bundle.master.fingerprint(), another.fingerprint());
}
#[test]
fn vault_is_authenticated_encrypted_and_wrong_password_cannot_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pool.json");
    let credential = credential();
    let password = "a long local vault passphrase";
    vault::save_pool(&path, password, std::slice::from_ref(&credential)).unwrap();
    let bytes = std::fs::read_to_string(&path).unwrap();
    assert!(!bytes.contains(&credential.secret));
    assert!(!bytes.contains(&credential.master.origin));
    let pool = vault::load_pool(&path, password).unwrap();
    assert_eq!(pool[0].principal_id, credential.principal_id);
    assert!(vault::load_pool(&path, "another wrong passphrase").is_err());
    let key = key(&random_hex(32)).unwrap();
    let value = vault::seal(&key, b"private credential", b"device-one/master-one").unwrap();
    assert!(vault::open(&key, &value, b"device-two/master-one").is_err());
    let mut value = value;
    value.ciphertext.replace_range(
        0..2,
        if &value.ciphertext[..2] == "00" {
            "ff"
        } else {
            "00"
        },
    );
    assert!(vault::open(&key, &value, b"device-one/master-one").is_err());
}
#[test]
fn only_hybrid_pq_key_exchange_and_aes256_are_advertised() {
    let provider = client::provider();
    assert_eq!(provider.kx_groups.len(), 1);
    assert_eq!(
        provider.kx_groups[0].name(),
        rustls::NamedGroup::X25519MLKEM768
    );
    assert_eq!(provider.cipher_suites.len(), 1);
    assert_eq!(
        provider.cipher_suites[0].suite(),
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
    );
}
