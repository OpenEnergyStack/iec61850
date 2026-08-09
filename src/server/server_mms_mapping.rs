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
    AccessResult, AlternateAccess, AlternateAccessSelection, AlternateAccessSelectionSelectAccess,
    AlternateAccessSelectionSelectAlternateAccessAccessSelection, AnonymousAlternateAccess,
    AnonymousTypeDescriptionStructureComponents, ConfirmedResponsePDU, ConfirmedServiceRequest,
    ConfirmedServiceResponse, Data, DataAccessError, FixedOctetString, FloatingPoint,
    GetNameListRequestObjectScope, GetNameListResponse, GetVariableAccessAttributesRequest,
    GetVariableAccessAttributesResponse, Identifier, InitiateRequestPDU, InitiateResponsePDU,
    InitiateResponsePDUInitResponseDetail, Integer32, MMSString, MMSpdu, ObjectClass, ObjectName,
    ReadResponse, TypeDescription, TypeDescriptionArray, TypeDescriptionFloatingPoint,
    TypeDescriptionStructure, TypeDescriptionStructureComponents, TypeSpecification, Unsigned32,
    Unsigned8, UtcTime, VisibleString,
};
use parking_lot::RwLock;
use rasn::types::{BitString, OctetString};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;

use super::server::{Association, AssociationMap, Backend, ServerTlsConfig};
use crate::server::model::{
    DataAttributeNode, DataObjectChild, DataObjectNode, FunctionalConstraint, LogicalDeviceNode,
    ServerModel,
};
use crate::server::types::DataValue;
use crate::types::{DataDefinition, DataType};

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
    GetEmptyDirectory {
        invoke_id: InvokeId,
    },
    GetDataValues {
        invoke_id: InvokeId,
        specification: mms::VariableAccessSpecification,
    },
    GetDataDefinition {
        invoke_id: InvokeId,
        name: ObjectName,
    },
    Unknown {
        _invoke_id: InvokeId,
    },
}

/// An IEC 61850 service response to encode and send.
#[allow(dead_code)]
#[derive(Debug)]
enum ServiceResponse {
    NameList {
        invoke_id: InvokeId,
        names: Vec<String>,
    },
    DataValues {
        invoke_id: InvokeId,
        results: Vec<AccessResult>,
    },
    DataDefinition {
        invoke_id: InvokeId,
        response: GetVariableAccessAttributesResponse,
    },
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
        ServiceRequest::GetEmptyDirectory { invoke_id } => Some(ServiceResponse::NameList {
            invoke_id,
            names: Vec::new(),
        }),
        ServiceRequest::GetDataValues {
            invoke_id,
            specification,
        } => Some(ServiceResponse::DataValues {
            invoke_id,
            results: read_data_values(specification, model),
        }),
        ServiceRequest::GetDataDefinition { invoke_id, name } => {
            Some(read_data_definition(invoke_id, name, model))
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

/// IEC 61850 directory category derived from an MMS `GetNameList` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryType {
    /// `vmdSpecific` scope with `domain(9)` object class → logical devices.
    ServerLogicalDevices,
    /// `domainSpecific` scope with `namedVariable(0)` object class → LN contents.
    LogicalDeviceVariables,
    /// `namedVariableList(2)` object class → data sets (not modelled; empty list).
    DataSets,
    /// `journal(8)` object class → journals (not modelled; empty list).
    Journals,
    /// No IEC 61850 directory mapping for this class/scope combination.
    Unsupported,
}

/// Classifies an MMS `GetNameList` request according to IEC 61850-8-1.
///
/// - GetServerDirectory: `vmdSpecific` scope + `domain(9)`.
/// - GetLogicalDeviceDirectory: `domainSpecific` scope + `namedVariable(0)`.
/// - Data sets (`namedVariableList`, 2) and journals (`journal`, 8) are valid
///   object classes for both scopes but are not represented in the runtime
///   model, so they yield empty directory responses.
fn classify_directory_request(
    object_class: &ObjectClass,
    scope: &GetNameListRequestObjectScope,
) -> DirectoryType {
    match object_class {
        ObjectClass::basicObjectClass(9)
            if matches!(scope, GetNameListRequestObjectScope::vmdSpecific(_)) =>
        {
            DirectoryType::ServerLogicalDevices
        }
        ObjectClass::basicObjectClass(0)
            if matches!(scope, GetNameListRequestObjectScope::domainSpecific(_)) =>
        {
            DirectoryType::LogicalDeviceVariables
        }
        ObjectClass::basicObjectClass(2) => DirectoryType::DataSets,
        ObjectClass::basicObjectClass(8) => DirectoryType::Journals,
        _ => DirectoryType::Unsupported,
    }
}

fn mms_to_service(pdu: MMSpdu) -> Option<ServiceRequest> {
    match pdu {
        MMSpdu::confirmed_RequestPDU(req) => {
            let invoke_id = req.invoke_id.0;
            match req.service {
                ConfirmedServiceRequest::getNameList(name_req) => {
                    match classify_directory_request(&name_req.object_class, &name_req.object_scope)
                    {
                        DirectoryType::ServerLogicalDevices => {
                            Some(ServiceRequest::GetServerDirectory { invoke_id })
                        }
                        DirectoryType::LogicalDeviceVariables => {
                            let GetNameListRequestObjectScope::domainSpecific(id) =
                                name_req.object_scope
                            else {
                                return Some(ServiceRequest::Unknown {
                                    _invoke_id: invoke_id,
                                });
                            };
                            Some(ServiceRequest::GetLogicalDeviceDirectory {
                                invoke_id,
                                ld_name: id.0.to_string(),
                            })
                        }
                        DirectoryType::DataSets | DirectoryType::Journals => {
                            Some(ServiceRequest::GetEmptyDirectory { invoke_id })
                        }
                        DirectoryType::Unsupported => Some(ServiceRequest::Unknown {
                            _invoke_id: invoke_id,
                        }),
                    }
                }
                ConfirmedServiceRequest::read(read_req) => Some(ServiceRequest::GetDataValues {
                    invoke_id,
                    specification: read_req.variable_access_specification,
                }),
                ConfirmedServiceRequest::getVariableAccessAttributes(req) => match req {
                    GetVariableAccessAttributesRequest::name(name) => {
                        Some(ServiceRequest::GetDataDefinition { invoke_id, name })
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
        ServiceResponse::DataValues { invoke_id, results } => {
            let read_response = ReadResponse {
                variable_access_specification: None,
                list_of_access_result: results.into(),
            };
            Some(MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
                invoke_id: Unsigned32(invoke_id),
                service: ConfirmedServiceResponse::read(read_response),
            }))
        }
        ServiceResponse::DataDefinition {
            invoke_id,
            response,
        } => Some(MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
            invoke_id: Unsigned32(invoke_id),
            service: ConfirmedServiceResponse::getVariableAccessAttributes(response),
        })),
    }
}

// ── MMS logical-device directory ─────────────────────────────────────────────

/// Build the MMS GetNameList response list for a logical device.
///
/// Walks the structural tree and emits every named level in IEC 61850
/// dollar-notation: `{LN}` and `{LN}${FC}${DO}[${SDO}]*${DA}[${BDA}]*`.
/// Each LN, FC group, DO/SDO, structural DA and leaf DA appears as its own
/// entry, matching the IEC 61850-7-2 GetLogicalDeviceDirectory response.
///
/// Example:
/// ```text
/// LLN0
/// LLN0$ST
/// LLN0$ST$Beh
/// LLN0$ST$Beh$stVal
/// ```
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
        let ln_name = format!("{}{}{}", ln.ln_prefix, ln.ln_class, ln.inst);
        result.push(ln_name.clone());
        for do_ in &ln.data_objects {
            let fc = fc_for_path(do_);
            result.push(format!("{}${}", ln_name, fc));
            let do_path = &do_.name;
            result.push(format!("{}${}${}", ln_name, fc, do_path));
            collect_do_paths(&ln_name, do_path, &do_.children, &mut result);
        }
    }
    result
}

/// Walk the children of a DO or SDO, emitting each child path and recursing
/// into sub-objects/structural attributes.
fn collect_do_paths(
    ln_name: &str,
    do_path: &str,
    children: &[DataObjectChild],
    result: &mut Vec<String>,
) {
    for child in children {
        match child {
            DataObjectChild::Attribute(da) => {
                collect_da_paths(ln_name, do_path, da.fc(), da, result)
            }
            DataObjectChild::SubObject(sdo) => {
                let sub_path = format!("{}${}", do_path, sdo.name);
                result.push(format!("{}${}${}", ln_name, fc_for_path(sdo), sub_path));
                collect_do_paths(ln_name, &sub_path, &sdo.children, result);
            }
            // Arrays are accessed through MMS alternate access and are not
            // flattened into a plain name-list entry.
            DataObjectChild::AttributeArray { .. } | DataObjectChild::SubObjectArray { .. } => {}
        }
    }
}

/// Walk a DA node, emitting every structural level and one entry per leaf.
/// The FC is the functional constraint of the top-level DA ancestor and is
/// inserted between the LN name and the DO path.
fn collect_da_paths(
    ln_name: &str,
    parent_path: &str,
    fc: FunctionalConstraint,
    da: &DataAttributeNode,
    result: &mut Vec<String>,
) {
    let da_path = format!("{}${}", parent_path, da.name());
    match da {
        DataAttributeNode::Leaf { .. } => {
            result.push(format!("{}${}${}", ln_name, fc.as_str(), da_path));
        }
        DataAttributeNode::Struct { children, .. } => {
            result.push(format!("{}${}${}", ln_name, fc.as_str(), da_path));
            for child in children {
                collect_da_paths(ln_name, &da_path, fc, child, result);
            }
        }
        // Arrays are accessed through MMS alternate access and are not
        // flattened into a plain name-list entry.
        DataAttributeNode::Array { .. } => {}
    }
}

/// Returns the functional constraint used as the directory separator for a
/// sub-object path. Sub-objects inherit the FC of their first attribute child.
fn fc_for_path(sdo: &DataObjectNode) -> &'static str {
    sdo.children
        .iter()
        .find_map(|child| match child {
            DataObjectChild::Attribute(da) => Some(da.fc().as_str()),
            DataObjectChild::AttributeArray { fc, .. } => Some(fc.as_str()),
            DataObjectChild::SubObject(sdo) => Some(fc_for_path(sdo)),
            DataObjectChild::SubObjectArray { .. } => None,
        })
        .unwrap_or("ST")
}

// ── GetDataValues implementation ──────────────────────────────────────────────

/// A single step in an MMS alternate-access path.
#[derive(Debug, Clone)]
enum AccessStep {
    Component(String),
    Index(u32),
}

/// Resolve a GetDataValues request against the runtime value store.
///
/// Every `variableSpecification` in the MMS `listOfVariable` is mapped to an
/// IEC 61850 reference and read independently. The returned vector contains
/// one [`AccessResult`] per requested reference, preserving the order of the
/// request. Unknown or unsupported references produce a failure access result.
fn read_data_values(
    specification: mms::VariableAccessSpecification,
    model: &ServerModel,
) -> Vec<AccessResult> {
    let mms::VariableAccessSpecification::listOfVariable(list) = specification else {
        return vec![AccessResult::failure(DataAccessError(9))]; // object-access-unsupported
    };

    list.0
        .into_iter()
        .map(|item| match mms_list_item_to_iec_reference(item) {
            Some(reference) => match model.read_by_path(&reference) {
                Some(value) => AccessResult::success(data_value_to_mms(&value)),
                None => AccessResult::failure(DataAccessError(10)), // object-non-existent
            },
            None => AccessResult::failure(DataAccessError(9)), // object-access-unsupported
        })
        .collect()
}

/// Resolve a GetDataDefinition request against the runtime model.
///
/// The referenced object is mapped to a model path and its [`DataDefinition`]
/// is returned as a `GetVariableAccessAttributes` response. Unknown or
/// unsupported references return a response with an opaque `VisibleString`
/// type so that the service completes rather than leaving the caller hanging.
///
/// Note: IEC 61850-8-1 encodes array indices in `GetDataValues` through MMS
/// `AlternateAccessSpecification`, but `GetVariableAccessAttributes-Request`
/// only carries an `ObjectName` without alternate access. Array indices must
/// therefore be embedded in the `itemID` string (e.g. `LN$FC$DO$DA(1)`) for
/// this server implementation to resolve them.
fn read_data_definition(
    invoke_id: InvokeId,
    name: ObjectName,
    model: &ServerModel,
) -> ServiceResponse {
    let definition = match mms_object_name_to_iec_reference(name, None) {
        Some(reference) => model.get_data_definition_by_path(&reference),
        None => None,
    };

    let definition = definition.unwrap_or_else(|| DataDefinition {
        name: String::new(),
        data_type: DataType::VisibleString,
    });

    ServiceResponse::DataDefinition {
        invoke_id,
        response: data_definition_to_get_variable_access_attributes_response(definition),
    }
}

fn mms_list_item_to_iec_reference(
    item: mms::AnonymousVariableAccessSpecificationListOfVariable,
) -> Option<String> {
    if let mms::VariableSpecification::name(name) = item.variable_specification {
        mms_object_name_to_iec_reference(name, item.alternate_access.as_ref())
    } else {
        None
    }
}

/// Converts an MMS `ObjectName` (and optional alternate access) into the
/// internal IEC 61850 reference notation used by [`ServerModel`].
fn mms_object_name_to_iec_reference(
    name: ObjectName,
    alternate_access: Option<&AlternateAccess>,
) -> Option<String> {
    let ObjectName::domain_specific(ds) = name else {
        return None;
    };
    let domain_id = ds.domain_id.0.to_string();
    let item_id = ds.item_id.0.to_string();

    // Start with the components encoded in the MMS itemId.
    let mut steps: Vec<AccessStep> = item_id
        .split('$')
        .map(|s| AccessStep::Component(s.to_string()))
        .collect();

    // Append any alternate-access steps (FC, nested components, array indices).
    if let Some(access) = alternate_access {
        steps.extend(flatten_alternate_access(access)?);
    }

    // The first step is the LN. References that stop at the LN level are valid
    // for GetDataDefinition and have no FC component.
    let ln = match steps.first()? {
        AccessStep::Component(n) => n,
        AccessStep::Index(_) => return None,
    };

    if steps.len() == 1 {
        return Some(format!("{domain_id}/{ln}"));
    }

    // The second step is the FC, everything else is the path.
    let fc = match steps.get(1)? {
        AccessStep::Component(n) => n,
        AccessStep::Index(_) => return None,
    };

    let mut path = String::new();
    for step in &steps[2..] {
        match step {
            AccessStep::Component(name) => {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(name);
            }
            AccessStep::Index(idx) => {
                path.push_str(&format!("({idx})"));
            }
        }
    }

    if path.is_empty() {
        Some(format!("{domain_id}/{ln}[{fc}]"))
    } else {
        Some(format!("{domain_id}/{ln}.{path}[{fc}]"))
    }
}

/// Convert a nested MMS `AlternateAccess` description into a flat list of
/// component/index steps. Returns `None` for unsupported selections such as
/// index ranges or all-elements.
fn flatten_alternate_access(access: &AlternateAccess) -> Option<Vec<AccessStep>> {
    let mut steps = Vec::with_capacity(access.0.len());
    for entry in &access.0 {
        match entry {
            AnonymousAlternateAccess::unnamed(selection) => {
                steps.extend(flatten_alternate_selection(selection)?);
            }
            AnonymousAlternateAccess::named(named) => {
                steps.push(AccessStep::Component(named.component_name.0.to_string()));
                steps.extend(flatten_alternate_selection(&named.access)?);
            }
        }
    }
    Some(steps)
}

fn flatten_alternate_selection(selection: &AlternateAccessSelection) -> Option<Vec<AccessStep>> {
    match selection {
        AlternateAccessSelection::selectAccess(sa) => Some(vec![select_access_step(sa)?]),
        AlternateAccessSelection::selectAlternateAccess(sa) => {
            let mut steps = vec![select_alternate_access_step(&sa.access_selection)?];
            steps.extend(flatten_alternate_access(&sa.alternate_access)?);
            Some(steps)
        }
    }
}

fn select_access_step(sa: &AlternateAccessSelectionSelectAccess) -> Option<AccessStep> {
    match sa {
        AlternateAccessSelectionSelectAccess::component(id) => {
            Some(AccessStep::Component(id.0.to_string()))
        }
        AlternateAccessSelectionSelectAccess::index(idx) => Some(AccessStep::Index(idx.0)),
        _ => None,
    }
}

fn select_alternate_access_step(
    sa: &AlternateAccessSelectionSelectAlternateAccessAccessSelection,
) -> Option<AccessStep> {
    match sa {
        AlternateAccessSelectionSelectAlternateAccessAccessSelection::component(id) => {
            Some(AccessStep::Component(id.0.to_string()))
        }
        AlternateAccessSelectionSelectAlternateAccessAccessSelection::index(idx) => {
            Some(AccessStep::Index(idx.0))
        }
        _ => None,
    }
}

/// Convert a server-side [`DataValue`] into an MMS [`Data`] value.
fn data_value_to_mms(value: &DataValue) -> Data {
    match value {
        DataValue::Bool(b) => Data::boolean(*b),
        DataValue::Int8(v) => Data::integer((*v).into()),
        DataValue::Int16(v) => Data::integer((*v).into()),
        DataValue::Int32(v) => Data::integer((*v).into()),
        DataValue::Int64(v) => Data::integer((*v).into()),
        DataValue::Int8u(v) => Data::unsigned((*v).into()),
        DataValue::Int16u(v) => Data::unsigned((*v).into()),
        DataValue::Int32u(v) => Data::unsigned((*v).into()),
        DataValue::Float32(f) => {
            let mut bytes = vec![0x08]; // IEEE 754 32-bit float format
            bytes.extend_from_slice(&f.to_be_bytes());
            Data::floating_point(FloatingPoint(OctetString::from(bytes)))
        }
        DataValue::OctetString(bytes) => Data::octet_string(OctetString::from(bytes.clone())),
        DataValue::VisibleString(s) => {
            Data::visible_string(VisibleString::try_from(s.as_str()).unwrap_or_default())
        }
        DataValue::UnicodeString(s) => {
            let visible = VisibleString::try_from(s.as_str()).unwrap_or_default();
            Data::mMSString(MMSString(visible))
        }
        DataValue::Quality(q) => {
            let raw = q.to_u16().to_be_bytes();
            Data::bit_string(BitString::from_vec(raw.to_vec()))
        }
        DataValue::Timestamp(ts) => {
            let bytes = ts.to_bytes();
            Data::utc_time(UtcTime(FixedOctetString::from(bytes)))
        }
        DataValue::Array(elements) => Data::array(elements.iter().map(data_value_to_mms).collect()),
        DataValue::Struct(fields) => {
            Data::structure(fields.iter().map(data_value_to_mms).collect())
        }
    }
}

/// Builds a `GetVariableAccessAttributes` response from a [`DataDefinition`].
///
/// Server-side IEC 61850 objects are never MMS-deletable, so `mmsDeletable`
/// is always `false` and no address is advertised.
fn data_definition_to_get_variable_access_attributes_response(
    definition: DataDefinition,
) -> GetVariableAccessAttributesResponse {
    GetVariableAccessAttributesResponse {
        mms_deletable: false,
        address: None,
        type_description: data_type_to_type_description(&definition.data_type),
    }
}

/// Recursively maps a [`DataType`] to the equivalent MMS [`TypeDescription`].
fn data_type_to_type_description(data_type: &DataType) -> TypeDescription {
    match data_type {
        DataType::Structure(children) => {
            let components = children
                .iter()
                .map(|child| AnonymousTypeDescriptionStructureComponents {
                    component_name: Some(Identifier(
                        VisibleString::try_from(child.name.as_str()).unwrap_or_default(),
                    )),
                    component_type: TypeSpecification::typeDescription(Box::new(
                        data_type_to_type_description(&child.data_type),
                    )),
                })
                .collect();
            TypeDescription::structure(TypeDescriptionStructure {
                packed: false,
                components: TypeDescriptionStructureComponents(components),
            })
        }
        DataType::Array {
            count,
            element_type,
        } => TypeDescription::array(TypeDescriptionArray {
            packed: false,
            number_of_elements: Unsigned32(*count),
            element_type: TypeSpecification::typeDescription(Box::new(
                data_type_to_type_description(element_type),
            )),
        }),
        DataType::Boolean => TypeDescription::boolean(()),
        DataType::BitString => TypeDescription::bit_string(Integer32(13)),
        DataType::Int => TypeDescription::integer(Unsigned8(4)),
        DataType::UInt => TypeDescription::unsigned(Unsigned8(4)),
        DataType::Float => TypeDescription::floating_point(TypeDescriptionFloatingPoint {
            format_width: Unsigned8(32),
            exponent_width: Unsigned8(8),
        }),
        DataType::OctetString => TypeDescription::octet_string(Integer32(0)),
        DataType::VisibleString => TypeDescription::visible_string(Integer32(255)),
        DataType::MmsString => TypeDescription::mMSString(Integer32(255)),
        DataType::Timestamp => TypeDescription::utc_time(()),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::server::data_value_store::DataRef;

    fn domain_object_name(domain: &str, item_id: &str) -> ObjectName {
        mms::ObjectName::domain_specific(mms::ObjectNameDomainSpecific {
            domain_id: Identifier(VisibleString::try_from(domain).unwrap_or_default()),
            item_id: Identifier(VisibleString::try_from(item_id).unwrap_or_default()),
        })
    }

    fn build_alternate_access(components: &[&str]) -> AlternateAccess {
        if components.is_empty() {
            return AlternateAccess(Vec::new());
        }

        let mut selection = AlternateAccessSelection::selectAccess(
            AlternateAccessSelectionSelectAccess::component(Identifier(
                VisibleString::try_from(components[components.len() - 1]).unwrap_or_default(),
            )),
        );

        for component in components.iter().rev().skip(1) {
            let access_selection =
                AlternateAccessSelectionSelectAlternateAccessAccessSelection::component(
                    Identifier(VisibleString::try_from(*component).unwrap_or_default()),
                );
            selection = AlternateAccessSelection::selectAlternateAccess(
                mms::AlternateAccessSelectionSelectAlternateAccess::new(
                    access_selection,
                    AlternateAccess(vec![AnonymousAlternateAccess::unnamed(selection)]),
                ),
            );
        }
        AlternateAccess(vec![AnonymousAlternateAccess::unnamed(selection)])
    }

    fn build_alternate_access_with_index(components: &[&str], index: u32) -> AlternateAccess {
        let terminal = AlternateAccessSelection::selectAccess(
            AlternateAccessSelectionSelectAccess::index(Unsigned32(index)),
        );
        let mut selection = terminal;
        for component in components.iter().rev() {
            let access_selection =
                AlternateAccessSelectionSelectAlternateAccessAccessSelection::component(
                    Identifier(VisibleString::try_from(*component).unwrap_or_default()),
                );
            selection = AlternateAccessSelection::selectAlternateAccess(
                mms::AlternateAccessSelectionSelectAlternateAccess::new(
                    access_selection,
                    AlternateAccess(vec![AnonymousAlternateAccess::unnamed(selection)]),
                ),
            );
        }
        AlternateAccess(vec![AnonymousAlternateAccess::unnamed(selection)])
    }

    fn as_f32(data: &Data) -> f32 {
        match data {
            Data::floating_point(fp) => {
                let bytes = fp.0.as_ref();
                assert_eq!(bytes[0], 0x08, "expected 32-bit IEEE 754 tag");
                f32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])
            }
            other => panic!("expected floating point, got {:?}", other),
        }
    }

    #[test]
    fn standard_ln_fc_do_da_reference_still_works() {
        let model = ServerModel::from_json(
            r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "LLN0",
                    "inst": "",
                    "data_objects": [{
                        "name": "Mod",
                        "children": [
                            { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "bool" }
                        ]
                    }]
                }]
            }]
        }"#,
        )
        .expect("valid model");

        model
            .value_store
            .write(
                &DataRef::new("IED1LD0/LLN0.Mod.stVal"),
                DataValue::Bool(true),
            )
            .unwrap();

        let spec = mms::VariableAccessSpecification::listOfVariable(
            mms::VariableAccessSpecificationListOfVariable(vec![
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name(
                        "IED1LD0",
                        "LLN0$ST$Mod$stVal",
                    )),
                    None,
                ),
            ]),
        );
        let result = read_data_values(spec, &model);

        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], AccessResult::success(Data::boolean(true))),
            "expected boolean true, got {:?}",
            result
        );
    }

    #[test]
    fn multiple_variable_specifications_return_matching_access_results() {
        let model = ServerModel::from_json(r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "LLN0",
                    "inst": "",
                    "data_objects": [
                        {
                            "name": "Mod",
                            "children": [
                                { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "bool" }
                            ]
                        },
                        {
                            "name": "NamPlt",
                            "children": [
                                { "type": "Attribute", "name": "vendor", "fc": "DC", "da_type": "visible_string" }
                            ]
                        }
                    ]
                }]
            }]
        }"#)
        .expect("valid model");

        model
            .value_store
            .write(
                &DataRef::new("IED1LD0/LLN0.Mod.stVal"),
                DataValue::Bool(true),
            )
            .unwrap();
        model
            .value_store
            .write(
                &DataRef::new("IED1LD0/LLN0.NamPlt.vendor"),
                DataValue::VisibleString("OpenEnergyStack".to_string()),
            )
            .unwrap();

        let spec = mms::VariableAccessSpecification::listOfVariable(
            mms::VariableAccessSpecificationListOfVariable(vec![
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name(
                        "IED1LD0",
                        "LLN0$ST$Mod$stVal",
                    )),
                    None,
                ),
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name(
                        "IED1LD0",
                        "LLN0$DC$NamPlt$vendor",
                    )),
                    None,
                ),
            ]),
        );
        let result = read_data_values(spec, &model);

        assert_eq!(result.len(), 2);
        assert!(
            matches!(&result[0], AccessResult::success(Data::boolean(true))),
            "expected first result boolean true, got {:?}",
            result
        );
        match &result[1] {
            AccessResult::success(Data::visible_string(s)) => {
                assert_eq!(s.to_string(), "OpenEnergyStack");
            }
            other => panic!("expected second result visible string, got {:?}", other),
        }
    }

    #[test]
    fn alternate_access_with_fc_do_da_resolves_leaf() {
        let model = ServerModel::from_json(r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "LLN0",
                    "inst": "",
                    "data_objects": [{
                        "name": "NamPlt",
                        "children": [
                            { "type": "Attribute", "name": "vendor", "fc": "DC", "da_type": "visible_string" }
                        ]
                    }]
                }]
            }]
        }"#)
        .expect("valid model");

        model
            .value_store
            .write(
                &DataRef::new("IED1LD0/LLN0.NamPlt.vendor"),
                DataValue::VisibleString("OpenEnergyStack".to_string()),
            )
            .unwrap();

        let access = build_alternate_access(&["DC", "NamPlt", "vendor"]);
        let spec = mms::VariableAccessSpecification::listOfVariable(
            mms::VariableAccessSpecificationListOfVariable(vec![
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name("IED1LD0", "LLN0")),
                    Some(access),
                ),
            ]),
        );
        let result = read_data_values(spec, &model);

        assert_eq!(result.len(), 1);
        match &result[0] {
            AccessResult::success(Data::visible_string(s)) => {
                assert_eq!(s.to_string(), "OpenEnergyStack");
            }
            other => panic!("expected visible string, got {:?}", other),
        }
    }

    #[test]
    fn alternate_access_array_index_selects_element() {
        let model = ServerModel::from_json(r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "MHAI",
                    "inst": "1",
                    "data_objects": [{
                        "name": "HA",
                        "children": [
                            { "type": "Attribute", "name": "phsAHar", "fc": "MX", "da_type": "float32" }
                        ]
                    }]
                }]
            }]
        }"#)
        .expect("valid model");

        model
            .value_store
            .write(
                &DataRef::new("IED1LD0/MHAI1.HA.phsAHar"),
                DataValue::Array(Arc::new(vec![
                    DataValue::Float32(1.0),
                    DataValue::Float32(2.0),
                    DataValue::Float32(3.0),
                ])),
            )
            .unwrap();

        let access = build_alternate_access_with_index(&["MX", "HA", "phsAHar"], 2);
        let spec = mms::VariableAccessSpecification::listOfVariable(
            mms::VariableAccessSpecificationListOfVariable(vec![
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name("IED1LD0", "MHAI1")),
                    Some(access),
                ),
            ]),
        );
        let result = read_data_values(spec, &model);

        assert_eq!(result.len(), 1);
        match &result[0] {
            AccessResult::success(data) => assert_eq!(as_f32(data), 3.0),
            other => panic!("expected success, got {:?}", other),
        }
    }

    #[test]
    fn alternate_access_structured_path_resolves_nested_leaf() {
        let model = ServerModel::from_json(
            r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "MMXU",
                    "inst": "1",
                    "data_objects": [{
                        "name": "A",
                        "children": [{
                            "type": "SubObject",
                            "name": "phsA",
                            "children": [{
                                "type": "Attribute",
                                "name": "cVal",
                                "fc": "MX",
                                "children": [{
                                    "name": "mag",
                                    "fc": "MX",
                                    "children": [
                                        { "name": "f", "fc": "MX", "da_type": "float32" }
                                    ]
                                }]
                            }]
                        }]
                    }]
                }]
            }]
        }"#,
        )
        .expect("valid model");

        model
            .value_store
            .write(
                &DataRef::new("IED1LD0/MMXU1.A.phsA.cVal.mag.f"),
                DataValue::Float32(50.0),
            )
            .unwrap();

        let access = build_alternate_access(&["MX", "A", "phsA", "cVal", "mag", "f"]);
        let spec = mms::VariableAccessSpecification::listOfVariable(
            mms::VariableAccessSpecificationListOfVariable(vec![
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name("IED1LD0", "MMXU1")),
                    Some(access),
                ),
            ]),
        );
        let result = read_data_values(spec, &model);

        assert_eq!(result.len(), 1);
        match &result[0] {
            AccessResult::success(data) => assert_eq!(as_f32(data), 50.0),
            other => panic!("expected success, got {:?}", other),
        }
    }

    #[test]
    fn unknown_reference_returns_object_non_existent() {
        let model = ServerModel::from_json(
            r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": []
        }"#,
        )
        .expect("valid model");

        let spec = mms::VariableAccessSpecification::listOfVariable(
            mms::VariableAccessSpecificationListOfVariable(vec![
                mms::AnonymousVariableAccessSpecificationListOfVariable::new(
                    mms::VariableSpecification::name(domain_object_name(
                        "IED1LD0",
                        "LLN0$ST$Mod$stVal",
                    )),
                    None,
                ),
            ]),
        );
        let result = read_data_values(spec, &model);

        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], AccessResult::failure(DataAccessError(10))),
            "expected object-non-existent, got {:?}",
            result
        );
    }

    #[test]
    fn get_data_definition_resolves_leaf_type() {
        let model = ServerModel::from_json(
            r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "LLN0",
                    "inst": "",
                    "data_objects": [{
                        "name": "Mod",
                        "children": [
                            { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "bool" }
                        ]
                    }]
                }]
            }]
        }"#,
        )
        .expect("valid model");

        let name = domain_object_name("IED1LD0", "LLN0$ST$Mod$stVal");
        let response = match read_data_definition(7, name, &model) {
            ServiceResponse::DataDefinition {
                invoke_id,
                response,
            } => {
                assert_eq!(invoke_id, 7);
                response
            }
            other => panic!("expected DataDefinition response, got {:?}", other),
        };

        assert!(!response.mms_deletable);
        assert!(response.address.is_none());
        assert!(matches!(
            response.type_description,
            TypeDescription::boolean(())
        ));
    }

    #[test]
    fn get_data_definition_resolves_structure_type() {
        let model = ServerModel::from_json(
            r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "MMXU",
                    "inst": "1",
                    "data_objects": [{
                        "name": "A",
                        "children": [{
                            "type": "Attribute",
                            "name": "phsA",
                            "fc": "MX",
                            "children": [{
                                "name": "cVal",
                                "fc": "MX",
                                "children": [{
                                    "name": "mag",
                                    "fc": "MX",
                                    "children": [
                                        { "name": "f", "fc": "MX", "da_type": "float32" }
                                    ]
                                }]
                            }]
                        }]
                    }]
                }]
            }]
        }"#,
        )
        .expect("valid model");

        let name = domain_object_name("IED1LD0", "MMXU1$MX$A$phsA$cVal");
        let response = match read_data_definition(8, name, &model) {
            ServiceResponse::DataDefinition {
                invoke_id,
                response,
            } => {
                assert_eq!(invoke_id, 8);
                response
            }
            other => panic!("expected DataDefinition response, got {:?}", other),
        };

        match response.type_description {
            TypeDescription::structure(structure) => {
                assert_eq!(structure.components.0.len(), 1);
                assert_eq!(
                    structure.components.0[0]
                        .component_name
                        .as_ref()
                        .map(|i| i.0.to_string()),
                    Some("mag".to_string())
                );
            }
            other => panic!("expected structure type, got {:?}", other),
        }
    }

    #[test]
    fn get_data_definition_resolves_logical_node() {
        let model = ServerModel::from_json(
            r#"{
            "ied_name": "IED1",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "LD0",
                "logical_nodes": [{
                    "ln_class": "LLN0",
                    "inst": "",
                    "data_objects": [
                        {
                            "name": "Mod",
                            "children": [
                                { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "bool" }
                            ]
                        },
                        {
                            "name": "Beh",
                            "children": [
                                { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "int32" }
                            ]
                        },
                        {
                            "name": "Health",
                            "children": [
                                { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "int32" }
                            ]
                        },
                        {
                            "name": "NamPlt",
                            "children": [
                                { "type": "Attribute", "name": "vendor", "fc": "DC", "da_type": "visible_string" }
                            ]
                        }
                    ]
                }]
            }]
        }"#,
        )
        .expect("valid model");

        let name = domain_object_name("IED1LD0", "LLN0");
        let response = match read_data_definition(9, name, &model) {
            ServiceResponse::DataDefinition {
                invoke_id,
                response,
            } => {
                assert_eq!(invoke_id, 9);
                response
            }
            other => panic!("expected DataDefinition response, got {:?}", other),
        };

        match response.type_description {
            TypeDescription::structure(structure) => {
                assert_eq!(structure.components.0.len(), 2);

                let st_name = structure.components.0[0]
                    .component_name
                    .as_ref()
                    .map(|i| i.0.to_string());
                assert_eq!(st_name, Some("ST".to_string()));

                let dc_name = structure.components.0[1]
                    .component_name
                    .as_ref()
                    .map(|i| i.0.to_string());
                assert_eq!(dc_name, Some("DC".to_string()));
            }
            other => panic!("expected structure type, got {:?}", other),
        }
    }

    #[test]
    fn data_type_to_type_description_maps_leaf_types() {
        assert!(matches!(
            data_type_to_type_description(&DataType::Boolean),
            TypeDescription::boolean(())
        ));
        assert!(matches!(
            data_type_to_type_description(&DataType::Int),
            TypeDescription::integer(Unsigned8(4))
        ));
        assert!(matches!(
            data_type_to_type_description(&DataType::Float),
            TypeDescription::floating_point(TypeDescriptionFloatingPoint {
                format_width: Unsigned8(32),
                exponent_width: Unsigned8(8),
            })
        ));
        assert!(matches!(
            data_type_to_type_description(&DataType::Timestamp),
            TypeDescription::utc_time(())
        ));
    }

    #[test]
    fn directory_request_classification() {
        use GetNameListRequestObjectScope::*;

        assert_eq!(
            classify_directory_request(&ObjectClass::basicObjectClass(9), &vmdSpecific(())),
            DirectoryType::ServerLogicalDevices
        );
        assert_eq!(
            classify_directory_request(
                &ObjectClass::basicObjectClass(0),
                &domainSpecific(Identifier(VisibleString::try_from("IED1LD0").unwrap()))
            ),
            DirectoryType::LogicalDeviceVariables
        );
        assert_eq!(
            classify_directory_request(&ObjectClass::basicObjectClass(2), &vmdSpecific(())),
            DirectoryType::DataSets
        );
        assert_eq!(
            classify_directory_request(
                &ObjectClass::basicObjectClass(2),
                &domainSpecific(Identifier(VisibleString::try_from("IED1LD0").unwrap()))
            ),
            DirectoryType::DataSets
        );
        assert_eq!(
            classify_directory_request(&ObjectClass::basicObjectClass(8), &vmdSpecific(())),
            DirectoryType::Journals
        );
        assert_eq!(
            classify_directory_request(&ObjectClass::basicObjectClass(0), &vmdSpecific(())),
            DirectoryType::Unsupported
        );
        assert_eq!(
            classify_directory_request(
                &ObjectClass::basicObjectClass(9),
                &domainSpecific(Identifier(VisibleString::try_from("IED1LD0").unwrap()))
            ),
            DirectoryType::Unsupported
        );
    }

    #[test]
    fn logical_device_directory_lists_full_tree() {
        let model = ServerModel::from_json(r#"{
            "ied_name": "DEMO",
            "config": { "max_associations": 5 },
            "logical_devices": [{
                "inst": "Array",
                "logical_nodes": [{
                    "ln_class": "LLN0",
                    "inst": "",
                    "data_objects": [{
                        "name": "Beh",
                        "children": [
                            { "type": "Attribute", "name": "stVal", "fc": "ST", "da_type": "bool" },
                            { "type": "Attribute", "name": "q", "fc": "ST", "da_type": "quality" },
                            { "type": "Attribute", "name": "t", "fc": "ST", "da_type": "timestamp" }
                        ]
                    }]
                },{
                    "prefix": "My",
                    "ln_class": "MMXU",
                    "inst": "1",
                    "data_objects": [{
                        "name": "A",
                        "children": [{
                            "type": "SubObject",
                            "name": "phsA",
                            "children": [
                                { "type": "Attribute", "name": "cVal", "fc": "MX", "children": [
                                    { "name": "mag", "fc": "MX", "children": [
                                        { "name": "f", "fc": "MX", "da_type": "float32" }
                                    ]},
                                    { "name": "ang", "fc": "MX", "children": [
                                        { "name": "f", "fc": "MX", "da_type": "float32" }
                                    ]}
                                ]},
                                { "type": "Attribute", "name": "q", "fc": "MX", "da_type": "quality" },
                                { "type": "Attribute", "name": "t", "fc": "MX", "da_type": "timestamp" }
                            ]
                        }]
                    }]
                }]
            }]
        }"#)
        .expect("valid model");

        let names = ld_directory("DEMO", &model.logical_devices, "DEMOArray");

        let expected = [
            "LLN0",
            "LLN0$ST",
            "LLN0$ST$Beh",
            "LLN0$ST$Beh$stVal",
            "LLN0$ST$Beh$q",
            "LLN0$ST$Beh$t",
            "MyMMXU1",
            "MyMMXU1$MX",
            "MyMMXU1$MX$A",
            "MyMMXU1$MX$A$phsA",
            "MyMMXU1$MX$A$phsA$cVal",
            "MyMMXU1$MX$A$phsA$cVal$mag",
            "MyMMXU1$MX$A$phsA$cVal$mag$f",
            "MyMMXU1$MX$A$phsA$cVal$ang",
            "MyMMXU1$MX$A$phsA$cVal$ang$f",
            "MyMMXU1$MX$A$phsA$q",
            "MyMMXU1$MX$A$phsA$t",
        ];

        assert_eq!(names, expected.to_vec());
    }
}
