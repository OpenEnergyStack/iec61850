use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::server::model::ServerModel;
use crate::server::server_mms_mapping::MmsServer;

// ── Association ───────────────────────────────────────────────────────────────

/// Opaque identifier for an active IEC 61850 association.
/// Generated when a connection is accepted; used as the key in [`AssociationMap`].
pub type AssociationId = u32;

/// Metadata for one active client association.
pub struct Association {
    /// Remote address of the connected client.
    pub peer_addr: SocketAddr,
    /// When the association was established (Initiate-ResponsePDU sent).
    pub established_at: Instant,
}

/// Live map of all active associations, keyed by [`AssociationId`].
///
/// Clone the `Arc` before calling [`Server::run`] to keep the map observable
/// after `run` consumes the server.
pub type AssociationMap = Arc<RwLock<HashMap<AssociationId, Association>>>;

// ── TLS config ────────────────────────────────────────────────────────────────

/// Server-side TLS configuration.
///
/// Build a [`rustls::ServerConfig`] with your certificate chain and private key
/// and pass it to [`ServerTlsConfig::new`].
pub struct ServerTlsConfig {
    pub(crate) config: Arc<rustls::ServerConfig>,
}

impl ServerTlsConfig {
    pub fn new(config: rustls::ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

// Internal server implementations must implement this trait. The public [`Server`]
#[allow(async_fn_in_trait)]
pub(crate) trait Backend: Sized {
    async fn bind(host: &str, port: u16) -> Result<Self, std::io::Error>;
    fn with_tls(self, config: ServerTlsConfig) -> Self;
    async fn run(self, model: ServerModel) -> Result<(), std::io::Error>;
    fn associations(&self) -> AssociationMap;
}

// ── Mapping ───────────────────────────────────────────────────────────────────

/// Selects the IEC 61850 transport mapping to use.
#[non_exhaustive]
pub enum Mapping {
    /// IEC 61850-8-1: MMS over TPKT / COTP / TCP
    Mms,
}

// ── Server ────────────────────────────────────────────────────────────────────

enum Inner {
    Mms(MmsServer),
}

pub struct Server {
    inner: Inner,
}

impl Server {
    /// Bind to `host:port` using the given transport `mapping`.
    pub async fn bind(mapping: Mapping, host: &str, port: u16) -> Result<Self, std::io::Error> {
        match mapping {
            Mapping::Mms => Ok(Self {
                inner: Inner::Mms(MmsServer::bind(host, port).await?),
            }),
        }
    }

    /// Attach TLS. Call before [`run`](Server::run).
    pub fn with_tls(self, config: ServerTlsConfig) -> Self {
        Self {
            inner: match self.inner {
                Inner::Mms(s) => Inner::Mms(s.with_tls(config)),
            },
        }
    }

    // Start the server
    pub async fn run(self, model: ServerModel) -> Result<(), std::io::Error> {
        match self.inner {
            Inner::Mms(s) => s.run(model).await,
        }
    }

    /// Returns the shared association map.
    pub fn associations(&self) -> AssociationMap {
        match &self.inner {
            Inner::Mms(s) => s.associations(),
        }
    }

    /// Returns the local address this server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match &self.inner {
            Inner::Mms(s) => s.local_addr(),
        }
    }
}
