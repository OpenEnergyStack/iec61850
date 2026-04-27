//! Integration tests for IEC 61850 server discovery responses.
//!
//! Each test starts a server loaded with the TestIED model (5 logical devices)
//! on an ephemeral port and verifies the responses returned by the client
//! discovery methods.

use std::time::Duration;

use iec_61850::{
    client::ClientBuilder,
    server::{Mapping, Server},
};

const SETTLE: Duration = Duration::from_millis(100);

const DEMO_MODEL: &str = r#"{
    "ied_name": "TestIED",
    "logical_devices": [
        {"inst": "Array",       "name": "MyArray",       "logical_nodes": []},
        {"inst": "SwitchGear",  "name": "mySwitchGear",  "logical_nodes": []},
        {"inst": "Measurement", "name": "MyMeasurement", "logical_nodes": []},
        {"inst": "Protection",  "name": "MyProtection",  "logical_nodes": []},
        {"inst": "Transformer", "name": "MyTransformer", "logical_nodes": []}
    ],
    "config": {"max_associations": 5}
}"#;

async fn bind_demo_server() -> (Server, u16) {
    let server = Server::bind(Mapping::Mms, "127.0.0.1", 0)
        .await
        .expect("bind failed");
    let port = server.local_addr().unwrap().port();
    (server, port)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `get_server_directory` returns an entry for every logical device in the model.
#[tokio::test(flavor = "multi_thread")]
async fn get_server_directory_returns_all_logical_devices() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_server_directory()
        .await
        .expect("get_server_directory failed");

    assert_eq!(
        directory.len(),
        5,
        "expected 5 logical devices, got: {directory:?}"
    );
}

/// The server directory entries are composed of `ied_name + ld_inst`
/// and match the exact names defined in the TestIED model.
#[tokio::test(flavor = "multi_thread")]
async fn get_server_directory_contains_expected_names() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_server_directory()
        .await
        .expect("get_server_directory failed");

    let expected = [
        "TestIEDArray",
        "TestIEDSwitchGear",
        "TestIEDMeasurement",
        "TestIEDProtection",
        "TestIEDTransformer",
    ];

    for name in &expected {
        assert!(
            directory.contains(&name.to_string()),
            "missing logical device '{name}' in directory: {directory:?}"
        );
    }
}

/// The order of logical devices in the server directory matches the order
/// in which they are declared in the model.
#[tokio::test(flavor = "multi_thread")]
async fn get_server_directory_preserves_declaration_order() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_server_directory()
        .await
        .expect("get_server_directory failed");

    assert_eq!(
        directory,
        vec![
            "TestIEDArray",
            "TestIEDSwitchGear",
            "TestIEDMeasurement",
            "TestIEDProtection",
            "TestIEDTransformer",
        ]
    );
}

/// Calling `get_server_directory` twice on the same connection returns
/// identical results (the response is stateless / idempotent).
#[tokio::test(flavor = "multi_thread")]
async fn get_server_directory_is_idempotent() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let first = client
        .get_server_directory()
        .await
        .expect("first get_server_directory failed");

    let second = client
        .get_server_directory()
        .await
        .expect("second get_server_directory failed");

    assert_eq!(
        first, second,
        "successive calls should return identical results"
    );
}

/// Two independent clients connected to the same server both receive the
/// correct server directory.
#[tokio::test(flavor = "multi_thread")]
async fn get_server_directory_consistent_across_clients() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client_a = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client A connect failed");

    let client_b = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client B connect failed");

    tokio::time::sleep(SETTLE).await;

    let dir_a = client_a
        .get_server_directory()
        .await
        .expect("client A get_server_directory failed");

    let dir_b = client_b
        .get_server_directory()
        .await
        .expect("client B get_server_directory failed");

    assert_eq!(
        dir_a, dir_b,
        "both clients should see the same server directory"
    );
}
