use wtp_endpoint::*;
fn network() -> NetworkPolicy {
    NetworkPolicy {
        dns_servers: vec!["10.0.0.53".parse().unwrap()],
        allowed_tcp: vec!["10.0.0.10:443".parse().unwrap()],
        allowed_udp: vec![],
        interfaces: vec!["eth0".into()],
        dhcp: true,
    }
}
fn config(key: &SigningKey) -> AgentConfig {
    AgentConfig {
        endpoint_id: "a".repeat(32),
        platform: "linux".into(),
        portal: "https://portal.test".into(),
        control: "10.0.0.10:443".parse().unwrap(),
        token: "b".repeat(64),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        interfaces: vec!["eth0".into()],
        dhcp: true,
        pairing: None,
        paired_master: None,
        allow_remote_uninstall: false,
    }
}
fn policy() -> Policy {
    Policy {
        endpoint_id: "a".repeat(32),
        platform: "linux".into(),
        revision: 1,
        issued_at: 1000,
        expires_at: 1300,
        network: network(),
    }
}
#[test]
fn remote_removal_requires_local_opt_in_target_binding_freshness_and_new_sequence() {
    let key = generate_key();
    let mut config = config(&key);
    let node = wtp_control::Node {
        installation_id: "1".repeat(32),
        platform: "linux".into(),
        account_id: "0".into(),
        hostname: "test".into(),
        mac_addresses: vec![],
    };
    let master = wtp_control::Master {
        id: "2".repeat(32),
        name: "test".into(),
        origin: config.portal.clone(),
        control: config.control,
        mac_addresses: vec![],
        certificate_pem: "fixture".into(),
        policy_key: config.public_key.clone(),
    };
    let credential = wtp_control::Credential {
        principal_id: "3".repeat(32),
        secret: "4".repeat(64),
        node_hash: node.fingerprint(&master),
        node,
        master,
        role: "agent".into(),
        endpoint_id: Some(config.endpoint_id.clone()),
        expires_at: now() + 1000,
    };
    let command = RemoteCommand {
        id: 2,
        endpoint_id: config.endpoint_id.clone(),
        principal_id: credential.principal_id.clone(),
        node_hash: credential.node_hash.clone(),
        kind: "uninstall".into(),
        issued_at: 1000,
        expires_at: 1600,
    };
    assert!(command.validate(&config, &credential, 1, 1100).is_err());
    config.allow_remote_uninstall = true;
    assert!(command.validate(&config, &credential, 1, 1100).is_ok());
    assert!(command.validate(&config, &credential, 2, 1100).is_err());
    assert!(command.validate(&config, &credential, 1, 1600).is_err());
    assert!(command.validate(&config, &credential, 1, 900).is_err());
    for field in ["endpoint_id", "principal_id", "node_hash", "kind"] {
        let mut value = serde_json::to_value(&command).unwrap();
        value[field] = serde_json::Value::String("attacker-controlled".into());
        let changed: RemoteCommand = serde_json::from_value(value).unwrap();
        assert!(
            changed.validate(&config, &credential, 1, 1100).is_err(),
            "{field}"
        );
    }
    let signed = sign(&command, COMMAND_DOMAIN, &key).unwrap();
    assert!(verify::<RemoteCommand>(&signed, POLICY_DOMAIN, &key.verifying_key()).is_err());
}
#[test]
fn signatures_bind_payload_domain_key_and_identity() {
    let key = generate_key();
    let mut envelope = sign(&policy(), POLICY_DOMAIN, &key).unwrap();
    let decoded: Policy = verify(&envelope, POLICY_DOMAIN, &key.verifying_key()).unwrap();
    assert_eq!(decoded.revision, 1);
    assert!(verify::<Policy>(&envelope, RELEASE_DOMAIN, &key.verifying_key()).is_err());
    assert!(verify::<Policy>(&envelope, POLICY_DOMAIN, &generate_key().verifying_key()).is_err());
    envelope.payload.replace_range(0..2, "00");
    assert!(verify::<Policy>(&envelope, POLICY_DOMAIN, &key.verifying_key()).is_err());
    assert!(decoded.validate(&"c".repeat(32), "linux", 1100).is_err());
    assert!(decoded.validate(&"a".repeat(32), "windows", 1100).is_err());
}
#[test]
fn rejects_expiry_replay_clock_rollback_revision_reuse_and_management_lockout() {
    let key = generate_key();
    let config = config(&key);
    let mut p = policy();
    let saved = Watermark::default().accept(&p, &config, 1100).unwrap();
    assert!(saved.accept(&p, &config, 1400).is_err());
    assert!(saved.accept(&p, &config, 1000).is_err());
    p.network.dns_servers.clear();
    assert!(saved.accept(&p, &config, 1110).is_err());
    p.revision = 2;
    assert!(saved.accept(&p, &config, 1110).is_ok());
    p.network.allowed_tcp.clear();
    assert!(saved.accept(&p, &config, 1110).is_err());
    let saved = Watermark {
        revision: 3,
        ..saved
    };
    assert!(saved.accept(&policy(), &config, 1110).is_err());
}
#[test]
fn compiler_rejects_injection_wildcard_uplinks_and_tunnel_interfaces() {
    for name in [
        "eth0; flush ruleset",
        "*",
        "tun0",
        "wg0",
        "utun2",
        "ppp1",
        "eth0\naccept",
    ] {
        let mut p = network();
        p.interfaces = vec![name.into()];
        assert!(p.validate().is_err(), "{name}");
    }
    let mut p = network();
    p.allowed_tcp.push("0.0.0.0:443".parse().unwrap());
    assert!(p.validate().is_err());
    let linux = platform::render(&network(), "linux").unwrap();
    assert!(!linux.contains("flush ruleset"));
    assert!(linux.contains("policy drop"));
    assert!(!linux.contains("ct state established"));
    let windows = platform::render(&network(), "windows").unwrap();
    assert!(windows.contains("DefaultOutboundAction Block"));
    assert!(windows.contains("Nonlocal allow rules conflict"));
    let mac = platform::render(&network(), "macos").unwrap();
    assert!(mac.ends_with("block drop quick all\n"));
}
#[test]
fn quarantine_retains_only_control_and_trusted_uplinks() {
    let p = network().quarantine("10.0.0.10:443".parse().unwrap());
    assert!(p.dns_servers.is_empty());
    assert!(p.allowed_udp.is_empty());
    assert_eq!(p.allowed_tcp.len(), 1);
    assert_eq!(p.interfaces, vec!["eth0"]);
}
#[test]
fn release_claims_detect_changed_bytes_and_persisted_state_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("release.tar");
    runtime::atomic_write(&file, b"release").unwrap();
    let original = file_claim(&file).unwrap();
    let key = generate_key();
    let signed = sign(&original, RELEASE_DOMAIN, &key).unwrap();
    let verified: FileClaim = verify(&signed, RELEASE_DOMAIN, &key.verifying_key()).unwrap();
    assert_eq!(verified.sha256, original.sha256);
    runtime::atomic_write(&file, b"tampered").unwrap();
    assert_ne!(file_claim(&file).unwrap().sha256, verified.sha256);
}
