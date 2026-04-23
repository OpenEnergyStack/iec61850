//! Back-to-back tests: IEC 61850 client ↔ server association handshake.
//!
//! Each test spins up a `Server` bound to an ephemeral port, connects one or
//! more clients with `ClientBuilder`, and asserts the expected association-map
//! state. A short `sleep` after each operation gives the spawned server task
//! time to process the event.

use std::time::Duration;

use iec_61850::{
    client::ClientBuilder,
    server::{Mapping, Server, ServerModel},
};

const SETTLE: Duration = Duration::from_millis(100);

fn model(max_associations: u8) -> ServerModel {
    ServerModel::new("TEST_IED".into(), max_associations)
}

/// Bind an ephemeral server, return it together with the chosen port.
async fn bind_server() -> (Server, u16) {
    let server = Server::bind(Mapping::Mms, "127.0.0.1", 0)
        .await
        .expect("bind failed");
    let port = server.local_addr().unwrap().port();
    (server, port)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Connecting a single client results in exactly one entry in the association map.
#[tokio::test(flavor = "multi_thread")]
async fn bare_connect_establishes_association() {
    let (server, port) = bind_server().await;
    let associations = server.associations();

    tokio::spawn(server.run(model(10)));

    let _client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        associations.read().len(),
        1,
        "expected exactly one association after connect"
    );
}

/// Dropping the client closes the TCP connection; the server removes the
/// association from the map.
#[tokio::test(flavor = "multi_thread")]
async fn disconnect_removes_association() {
    let (server, port) = bind_server().await;
    let associations = server.associations();

    tokio::spawn(server.run(model(10)));

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("client connect failed");

    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        associations.read().len(),
        1,
        "association should be present"
    );

    drop(client);

    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        associations.read().len(),
        0,
        "association should be removed after disconnect"
    );
}

/// When `max_associations` is 1 the server silently drops the second MMS
/// Initiate exchange, causing the second client connect to fail.
#[tokio::test(flavor = "multi_thread")]
async fn server_enforces_max_associations() {
    let (server, port) = bind_server().await;
    let associations = server.associations();

    tokio::spawn(server.run(model(1)));

    // First client succeeds.
    let _first = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1", port)
        .await
        .expect("first client should connect");

    tokio::time::sleep(SETTLE).await;
    assert_eq!(associations.read().len(), 1);

    // Second client must be rejected — the server closes the socket before
    // sending Initiate-ResponsePDU, so the MMS handshake returns an error.
    let result = ClientBuilder::new()
        .timeout(Duration::from_secs(2))
        .connect("127.0.0.1", port)
        .await;

    assert!(
        result.is_err(),
        "second connect should fail when max_associations is reached"
    );

    // First association is still alive.
    assert_eq!(associations.read().len(), 1);
}
