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
        {
            "inst": "Array",
            "logical_nodes": [
                {
                    "prefix": "", "ln_class": "LLN0", "inst": "",
                    "data_objects": [
                        { "name": "Beh", "children": [
                            { "type": "Attribute", "fc": "ST", "name": "stVal", "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "q",     "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "t",     "children": [] }
                        ]}
                    ]
                }
            ]
        },
        {
            "inst": "SwitchGear",
            "logical_nodes": [
                {
                    "prefix": "", "ln_class": "LLN0", "inst": "",
                    "data_objects": [
                        { "name": "Beh", "children": [
                            { "type": "Attribute", "fc": "ST", "name": "stVal", "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "q",     "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "t",     "children": [] }
                        ]}
                    ]
                }
            ]
        },
        {
            "inst": "Measurement",
            "logical_nodes": [
                {
                    "prefix": "", "ln_class": "LLN0", "inst": "",
                    "data_objects": [
                        { "name": "Beh", "children": [
                            { "type": "Attribute", "fc": "ST", "name": "stVal", "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "q",     "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "t",     "children": [] }
                        ]}
                    ]
                },
                {
                    "prefix": "My", "ln_class": "MMXU", "inst": "1",
                    "data_objects": [
                        { "name": "A", "children": [
                            { "type": "SubObject", "name": "phsA", "children": [
                                { "type": "Attribute", "name": "cVal", "fc": "MX", "children": [
                                    { "name": "mag", "fc": "MX", "children": [
                                        { "name": "f", "fc": "MX", "children": [] }
                                    ]},
                                    { "name": "ang", "fc": "MX", "children": [
                                        { "name": "f", "fc": "MX", "children": [] }
                                    ]}
                                ]},
                                { "type": "Attribute", "name": "q", "fc": "MX", "children": [] },
                                { "type": "Attribute", "name": "t", "fc": "MX", "children": [] }
                            ]}
                        ]}
                    ]
                }
            ]
        },
        {
            "inst": "Protection",
            "logical_nodes": [
                {
                    "prefix": "", "ln_class": "LLN0", "inst": "",
                    "data_objects": [
                        { "name": "Beh", "children": [
                            { "type": "Attribute", "fc": "ST", "name": "stVal", "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "q",     "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "t",     "children": [] }
                        ]}
                    ]
                }
            ]
        },
        {
            "inst": "Transformer",
            "logical_nodes": [
                {
                    "prefix": "", "ln_class": "LLN0", "inst": "",
                    "data_objects": [
                        { "name": "Beh", "children": [
                            { "type": "Attribute", "fc": "ST", "name": "stVal", "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "q",     "children": [] },
                            { "type": "Attribute", "fc": "ST", "name": "t",     "children": [] }
                        ]}
                    ]
                }
            ]
        }
    ],
    "config": { "max_associations": 5 }
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

// ── get_logical_device_directory tests ───────────────────────────────────────

/// A simple LD (LLN0 + Beh DO) returns exactly the three leaf DA paths.
#[tokio::test(flavor = "multi_thread")]
async fn get_logical_device_directory_returns_leaf_paths_for_simple_ld() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_logical_device_directory("TestIEDArray".to_string())
        .await
        .expect("get_logical_device_directory failed");

    assert_eq!(
        directory,
        vec!["LLN0$ST$Beh$stVal", "LLN0$ST$Beh$q", "LLN0$ST$Beh$t"],
        "unexpected directory for TestIEDArray: {directory:?}"
    );
}

/// The FC is inserted after the LN name and before the DO path.
#[tokio::test(flavor = "multi_thread")]
async fn get_logical_device_directory_fc_position_is_correct() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_logical_device_directory("TestIEDArray".to_string())
        .await
        .expect("get_logical_device_directory failed");

    for entry in &directory {
        let parts: Vec<&str> = entry.splitn(3, '$').collect();
        assert_eq!(
            parts.len(),
            3,
            "entry '{entry}' does not have 3 dollar-delimited segments"
        );
        // parts[0] = LN name, parts[1] = FC, parts[2] = DO$...$DA
        assert!(
            [
                "ST", "MX", "SP", "CF", "DC", "EX", "BR", "RP", "LG", "GO", "SV", "TI", "IN", "CO",
                "SE", "SF"
            ]
            .contains(&parts[1]),
            "second segment '{p}' in '{entry}' is not a valid FC",
            p = parts[1]
        );
    }
}

/// An LD with two LNs (LLN0 and MyMMXU1) returns entries for both,
/// including correct paths through an SDO and a struct-typed DA.
#[tokio::test(flavor = "multi_thread")]
async fn get_logical_device_directory_with_sdo_and_struct_da() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_logical_device_directory("TestIEDMeasurement".to_string())
        .await
        .expect("get_logical_device_directory failed");

    // LLN0 entries come first
    assert!(directory.contains(&"LLN0$ST$Beh$stVal".to_string()));
    assert!(directory.contains(&"LLN0$ST$Beh$q".to_string()));
    assert!(directory.contains(&"LLN0$ST$Beh$t".to_string()));

    // MyMMXU1: SDO phsA, struct DA cVal with BDAs mag.f and ang.f, plus leaf q and t
    assert!(directory.contains(&"MyMMXU1$MX$A$phsA$cVal$mag$f".to_string()));
    assert!(directory.contains(&"MyMMXU1$MX$A$phsA$cVal$ang$f".to_string()));
    assert!(directory.contains(&"MyMMXU1$MX$A$phsA$q".to_string()));
    assert!(directory.contains(&"MyMMXU1$MX$A$phsA$t".to_string()));

    assert_eq!(directory.len(), 7, "unexpected entry count: {directory:?}");
}

/// The declaration order of LN → DO → DA is preserved in the response.
#[tokio::test(flavor = "multi_thread")]
async fn get_logical_device_directory_preserves_declaration_order() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_logical_device_directory("TestIEDMeasurement".to_string())
        .await
        .expect("get_logical_device_directory failed");

    assert_eq!(
        directory,
        vec![
            "LLN0$ST$Beh$stVal",
            "LLN0$ST$Beh$q",
            "LLN0$ST$Beh$t",
            "MyMMXU1$MX$A$phsA$cVal$mag$f",
            "MyMMXU1$MX$A$phsA$cVal$ang$f",
            "MyMMXU1$MX$A$phsA$q",
            "MyMMXU1$MX$A$phsA$t",
        ]
    );
}

/// Querying an LD that does not exist returns an empty list.
#[tokio::test(flavor = "multi_thread")]
async fn get_logical_device_directory_unknown_ld_returns_empty() {
    let (server, port) = bind_demo_server().await;
    tokio::spawn(server.run(DEMO_MODEL.to_string()));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;

    let directory = client
        .get_logical_device_directory("TestIEDDoesNotExist".to_string())
        .await
        .expect("get_logical_device_directory failed");

    assert!(
        directory.is_empty(),
        "expected empty list for unknown LD, got: {directory:?}"
    );
}
