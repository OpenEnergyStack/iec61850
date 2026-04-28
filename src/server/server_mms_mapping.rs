use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Instant;

use futures::{SinkExt as _, StreamExt as _};
use mms::{
    protocol::{self, tpkt::TpktCodec, transport, ProtocolParams},
    ConfirmedResponsePDU, ConfirmedServiceRequest, ConfirmedServiceResponse,
    GetNameListRequestObjectScope, GetNameListResponse, Identifier, InitiateRequestPDU,
    InitiateResponsePDU, InitiateResponsePDUInitResponseDetail, MMSpdu, Unsigned32, VisibleString,
};
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;

use super::server::{Association, AssociationMap, Backend, ServerTlsConfig};
use crate::server::model::{
    DataAttributeNode, DataObjectChild, FunctionalConstraint, LogicalDeviceNode, ServerModel,
};

// ── MMS service vocabulary ───────────────────────────────────────────────────────────────

/// Per-request correlation handle — the MMS `invokeID` field.
type InvokeId = u32;

/// A decoded IEC 61850 service request.
enum ServiceRequest {
    GetServerDirectory {
        invoke_id: InvokeId,
    },
    GetLogicalDeviceDirectory {
        invoke_id: InvokeId,
        ld_name: String,
    },
    Unknown {
        _invoke_id: InvokeId,
    },
}

/// An IEC 61850 service response to encode and send.
#[allow(dead_code)]
enum ServiceResponse {
    NameList {
        invoke_id: InvokeId,
        names: Vec<String>,
    },
    // TODO: DataValues, Success, ServiceError, …
}

// ── MmsServer ────────────────────────────────────────────────────────────────────

/// IEC 61850 server using the standard MMS / TPKT / COTP / TCP mapping (IEC 61850-8-1).
pub struct MmsServer {
    listener: TcpListener,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    associations: AssociationMap,
}

impl MmsServer {
    /// Returns the local address this server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

impl Backend for MmsServer {
    async fn bind(host: &str, port: u16) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind((host, port)).await?;
        Ok(Self {
            listener,
            tls_config: None,
            associations: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn with_tls(mut self, config: ServerTlsConfig) -> Self {
        self.tls_config = Some(config.config);
        self
    }

    fn associations(&self) -> AssociationMap {
        Arc::clone(&self.associations)
    }

    async fn run(self, model: ServerModel) -> Result<(), std::io::Error> {
        let Self {
            listener,
            tls_config,
            associations,
        } = self;
        let model = Arc::new(model);
        let association_slots = Arc::new(Semaphore::new(model.config.max_associations as usize));
        let next_id = Arc::new(AtomicU32::new(1));

        loop {
            let (stream, peer_addr) = listener.accept().await?;

            let model = Arc::clone(&model);
            let association_slots = Arc::clone(&association_slots);
            let associations = Arc::clone(&associations);
            let next_id = Arc::clone(&next_id);
            let tls = tls_config.clone();

            tokio::spawn(async move {
                // Wrap in the unified transport type before the MMS handshake.
                let transport = match tls {
                    Some(cfg) => match TlsAcceptor::from(cfg).accept(stream).await {
                        Ok(s) => TransportStream::Tls(Box::new(s)),
                        Err(e) => {
                            eprintln!("[iec61850] TLS error: {e}");
                            return;
                        }
                    },
                    None => TransportStream::Plain(stream),
                };

                // Step 1: COTP handshake + read Initiate-RequestPDU.
                // Dropping `pending` silently closes the connection — no response sent.
                let pending = match associate_listener(transport).await {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[iec61850] associate error: {e}");
                        return;
                    }
                };

                // Step 2: IEC 61850 policy — check association limit.
                let Ok(_permit) = association_slots.try_acquire() else {
                    return;
                };

                // Step 3: send Initiate-ResponsePDU.
                let conn = match complete_association(pending).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[iec61850] complete error: {e}");
                        return;
                    }
                };

                // Register the association in the shared map.
                let assoc_id = next_id.fetch_add(1, Ordering::Relaxed);
                associations.write().insert(
                    assoc_id,
                    Association {
                        peer_addr,
                        established_at: Instant::now(),
                    },
                );

                if let Err(e) = serve(conn, model).await {
                    eprintln!("[iec61850] connection error: {e}");
                }

                // Remove association when the connection ends.
                associations.write().remove(&assoc_id);
            });
        }
    }
}

// ── Per-connection service loop ───────────────────────────────────────────────

async fn serve(mut conn: Connection, model: Arc<ServerModel>) -> Result<(), Error> {
    loop {
        let req = conn.recv().await?;
        if let Some(resp) = dispatch(req, &model) {
            conn.send(resp).await?;
        }
    }
}

fn dispatch(req: ServiceRequest, model: &ServerModel) -> Option<ServiceResponse> {
    match req {
        ServiceRequest::GetServerDirectory { invoke_id } => Some(ServiceResponse::NameList {
            invoke_id,
            names: model.get_server_directory(),
        }),
        ServiceRequest::GetLogicalDeviceDirectory { invoke_id, ld_name } => {
            Some(ServiceResponse::NameList {
                invoke_id,
                names: ld_directory(&model.ied_name, &model.logical_devices, &ld_name),
            })
        }
        ServiceRequest::Unknown { .. } => None,
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Error {
    Io(io::Error),
    Protocol(String),
    ConnectionClosed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(s) => write!(f, "Protocol error: {s}"),
            Self::ConnectionClosed => write!(f, "Connection closed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<mms::Error> for Error {
    fn from(e: mms::Error) -> Self {
        match e {
            mms::Error::ConnectionClosed => Self::ConnectionClosed,
            other => Self::Protocol(other.to_string()),
        }
    }
}

// ── Transport stream (plain TCP or TLS) ───────────────────────────────────────

enum TransportStream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// ── Connection ────────────────────────────────────────────────────────────────

struct Connection {
    inner: transport::Connection<Framed<TransportStream, TpktCodec>>,
    params: ProtocolParams,
}

struct PendingConnection {
    conn: transport::Connection<Framed<TransportStream, TpktCodec>>,
    req: InitiateRequestPDU,
    params: ProtocolParams,
}

async fn associate_listener(stream: TransportStream) -> Result<PendingConnection, Error> {
    let mut params = ProtocolParams::default();
    let framed = Framed::new(stream, TpktCodec);
    let mut conn = transport::accept(framed, params.transport.clone())
        .await
        .map_err(Error::from)?;

    let frame = conn
        .next()
        .await
        .ok_or(Error::ConnectionClosed)?
        .map_err(Error::from)?;
    let pdu = protocol::decode(frame, &mut params).map_err(Error::from)?;
    let req = match pdu {
        MMSpdu::initiate_RequestPDU(req) => req,
        other => {
            return Err(Error::Protocol(format!(
                "expected Initiate-RequestPDU, got {:?}",
                std::mem::discriminant(&other)
            )))
        }
    };

    Ok(PendingConnection { conn, req, params })
}

async fn complete_association(mut pending: PendingConnection) -> Result<Connection, Error> {
    let response_pdu = MMSpdu::initiate_ResponsePDU(build_initiate_response(&pending.req));
    let response_bytes = protocol::encode(&response_pdu, &pending.params).map_err(Error::from)?;
    pending
        .conn
        .send(response_bytes)
        .await
        .map_err(Error::from)?;
    Ok(Connection {
        inner: pending.conn,
        params: pending.params,
    })
}

impl Connection {
    async fn recv(&mut self) -> Result<ServiceRequest, Error> {
        loop {
            let bytes = self
                .inner
                .next()
                .await
                .ok_or(Error::ConnectionClosed)?
                .map_err(Error::from)?;
            let pdu = protocol::decode(bytes, &mut self.params).map_err(Error::from)?;
            if let Some(req) = mms_to_service(pdu) {
                return Ok(req);
            }
        }
    }

    async fn send(&mut self, resp: ServiceResponse) -> Result<(), Error> {
        if let Some(pdu) = service_to_mms(resp) {
            let bytes = protocol::encode(&pdu, &self.params).map_err(Error::from)?;
            self.inner.send(bytes).await.map_err(Error::from)?;
        }
        Ok(())
    }
}

fn mms_to_service(pdu: MMSpdu) -> Option<ServiceRequest> {
    match pdu {
        MMSpdu::confirmed_RequestPDU(req) => {
            let invoke_id = req.invoke_id.0;
            match req.service {
                ConfirmedServiceRequest::getNameList(name_req) => match name_req.object_scope {
                    GetNameListRequestObjectScope::vmdSpecific(_) => {
                        Some(ServiceRequest::GetServerDirectory { invoke_id })
                    }
                    GetNameListRequestObjectScope::domainSpecific(id) => {
                        Some(ServiceRequest::GetLogicalDeviceDirectory {
                            invoke_id,
                            ld_name: id.0.to_string(),
                        })
                    }
                    _ => Some(ServiceRequest::Unknown {
                        _invoke_id: invoke_id,
                    }),
                },
                _ => Some(ServiceRequest::Unknown {
                    _invoke_id: invoke_id,
                }),
            }
        }
        _ => None,
    }
}

fn service_to_mms(resp: ServiceResponse) -> Option<MMSpdu> {
    match resp {
        ServiceResponse::NameList { invoke_id, names } => {
            let list_of_identifier = names
                .iter()
                .map(|n| Identifier(VisibleString::try_from(n.as_str()).expect("valid identifier")))
                .collect();
            Some(MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
                invoke_id: Unsigned32(invoke_id),
                service: ConfirmedServiceResponse::getNameList(GetNameListResponse {
                    list_of_identifier,
                    more_follows: false,
                }),
            }))
        }
    }
}

// ── MMS logical-device directory ─────────────────────────────────────────────

/// Build the MMS GetNameList response list for a logical device.
///
/// Walks the structural tree and returns one entry per leaf DA in
/// MMS dollar-notation: `{LN}${FC}${DO}[${SDO}]*${DA}[${BDA}]*`
///
/// Example: `LLN0$ST$Beh$stVal`, `MMXU1$MX$A$phsA$instVal$mag$f`
fn ld_directory(
    ied_name: &str,
    logical_devices: &[LogicalDeviceNode],
    ld_domain: &str,
) -> Vec<String> {
    let ld_inst = ld_domain.strip_prefix(ied_name).unwrap_or(ld_domain);
    let Some(ld) = logical_devices.iter().find(|ld| ld.inst == ld_inst) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for ln in &ld.logical_nodes {
        let ln_name = format!("{}{}{}", ln.prefix, ln.ln_class, ln.inst);
        for do_ in &ln.data_objects {
            collect_do_paths(&ln_name, &do_.name, &do_.children, &mut result);
        }
    }
    result
}

/// Walk the children of a DO or SDO, accumulating leaf DA paths.
fn collect_do_paths(
    ln_name: &str,
    do_path: &str,
    children: &[DataObjectChild],
    result: &mut Vec<String>,
) {
    for child in children {
        match child {
            DataObjectChild::Attribute(da) => collect_da_paths(ln_name, do_path, da.fc, da, result),
            DataObjectChild::SubObject(sdo) => {
                let sub_path = format!("{}${}", do_path, sdo.name);
                collect_do_paths(ln_name, &sub_path, &sdo.children, result);
            }
        }
    }
}

/// Walk a DA node, emitting one path entry per leaf.
/// The FC is the functional constraint of the top-level DA ancestor and is
/// inserted between the LN name and the DO path.
fn collect_da_paths(
    ln_name: &str,
    parent_path: &str,
    fc: FunctionalConstraint,
    da: &DataAttributeNode,
    result: &mut Vec<String>,
) {
    let da_path = format!("{}${}", parent_path, da.name);
    if da.children.is_empty() {
        result.push(format!("{}${}${}", ln_name, fc.as_str(), da_path));
    } else {
        for child in &da.children {
            collect_da_paths(ln_name, &da_path, fc, child, result);
        }
    }
}

fn build_initiate_response(req: &InitiateRequestPDU) -> InitiateResponsePDU {
    InitiateResponsePDU {
        local_detail_called: req.local_detail_calling.clone(),
        negotiated_max_serv_outstanding_calling: req.proposed_max_serv_outstanding_calling.clone(),
        negotiated_max_serv_outstanding_called: req.proposed_max_serv_outstanding_called.clone(),
        negotiated_data_structure_nesting_level: req.proposed_data_structure_nesting_level.clone(),
        init_response_detail: InitiateResponsePDUInitResponseDetail {
            negotiated_version_number: req.init_request_detail.proposed_version_number.clone(),
            negotiated_parameter_cbb: req.init_request_detail.proposed_parameter_cbb.clone(),
            services_supported_called: req.init_request_detail.services_supported_calling.clone(),
        },
    }
}
