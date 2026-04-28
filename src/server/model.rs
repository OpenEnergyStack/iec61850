use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CompiledIedConfig {
    max_associations: u8,
}

#[derive(Debug, Deserialize)]
struct CompiledModel {
    ied_name: String,
    config: CompiledIedConfig,
    #[serde(default)]
    logical_devices: Vec<CompiledLogicalDevice>,
}

#[derive(Debug, Deserialize)]
struct CompiledLogicalDevice {
    inst: String,
    #[serde(default)]
    logical_nodes: Vec<CompiledLogicalNode>,
}

#[derive(Debug, Deserialize)]
struct CompiledLogicalNode {
    ln_class: String,
    inst: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    data_objects: Vec<CompiledDataObject>,
}

#[derive(Debug, Deserialize)]
struct CompiledDataObject {
    name: String,
    #[serde(default)]
    children: Vec<CompiledDataObjectChild>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum CompiledDataObjectChild {
    Attribute(CompiledDataAttribute),
    SubObject(CompiledDataObject),
}

#[derive(Debug, Deserialize)]
struct CompiledDataAttribute {
    name: String,
    fc: FunctionalConstraint,
    #[serde(default)]
    children: Vec<CompiledDataAttribute>,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ModelLoadError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ModelLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Failed to read model file: {e}"),
            Self::Json(e) => write!(f, "Failed to parse model JSON: {e}"),
        }
    }
}

impl std::error::Error for ModelLoadError {}

impl From<std::io::Error> for ModelLoadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ModelLoadError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// IEC 61850 functional constraint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum FunctionalConstraint {
    ST,
    MX,
    SP,
    SE,
    SF,
    CF,
    DC,
    EX,
    BR,
    RP,
    LG,
    GO,
    SV,
    TI,
    IN,
    CO,
}

impl FunctionalConstraint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ST => "ST",
            Self::MX => "MX",
            Self::SP => "SP",
            Self::SE => "SE",
            Self::SF => "SF",
            Self::CF => "CF",
            Self::DC => "DC",
            Self::EX => "EX",
            Self::BR => "BR",
            Self::RP => "RP",
            Self::LG => "LG",
            Self::GO => "GO",
            Self::SV => "SV",
            Self::TI => "TI",
            Self::IN => "IN",
            Self::CO => "CO",
        }
    }
}

/// A Data Attribute node in the structural tree.
///
/// For struct-typed DAs (e.g. `cVal` of type `Vector`) the `children` list
/// contains the BDA sub-attributes. For leaf DAs, `children` is empty.
#[derive(Debug, Clone)]
pub struct DataAttributeNode {
    pub name: String,
    pub fc: FunctionalConstraint,
    pub children: Vec<DataAttributeNode>,
}

/// A child of a Data Object — either a leaf DA or a Sub-Data Object.
#[derive(Debug, Clone)]
pub enum DataObjectChild {
    Attribute(DataAttributeNode),
    SubObject(DataObjectNode),
}

/// A Data Object node in the structural tree.
#[derive(Debug, Clone)]
pub struct DataObjectNode {
    pub name: String,
    pub children: Vec<DataObjectChild>,
}

/// A Logical Node in the structural tree.
#[derive(Debug, Clone)]
pub struct LogicalNodeNode {
    pub ln_class: String,
    pub inst: String,
    pub prefix: String,
    pub data_objects: Vec<DataObjectNode>,
}

/// A Logical Device in the structural tree.
#[derive(Debug, Clone)]
pub struct LogicalDeviceNode {
    pub inst: String,
    pub logical_nodes: Vec<LogicalNodeNode>,
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct IedConfig {
    pub max_associations: u8,
}

/// The central runtime data model of an IEC 61850 server.
#[derive(Clone)]
pub struct ServerModel {
    pub ied_name: String,
    pub config: IedConfig,
    pub logical_devices: Vec<LogicalDeviceNode>,
}

impl ServerModel {
    /// Loads a `ServerModel` from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, ModelLoadError> {
        let model: CompiledModel = serde_json::from_str(json)?;
        let logical_devices = model.logical_devices.into_iter().map(build_ld).collect();
        Ok(Self {
            ied_name: model.ied_name,
            config: IedConfig {
                max_associations: model.config.max_associations,
            },
            logical_devices,
        })
    }

    /// Returns all logical device names as `{ied_name}{ld_inst}` strings.
    pub fn get_server_directory(&self) -> Vec<String> {
        self.logical_devices
            .iter()
            .map(|ld| format!("{}{}", self.ied_name, ld.inst))
            .collect()
    }
}

// ─── Builders ────────────────────────────────────────────────────────────────

fn build_ld(ld: CompiledLogicalDevice) -> LogicalDeviceNode {
    LogicalDeviceNode {
        inst: ld.inst,
        logical_nodes: ld.logical_nodes.into_iter().map(build_ln).collect(),
    }
}

fn build_ln(ln: CompiledLogicalNode) -> LogicalNodeNode {
    LogicalNodeNode {
        ln_class: ln.ln_class,
        inst: ln.inst,
        prefix: ln.prefix,
        data_objects: ln.data_objects.into_iter().map(build_do).collect(),
    }
}

fn build_do(do_: CompiledDataObject) -> DataObjectNode {
    DataObjectNode {
        name: do_.name,
        children: do_.children.into_iter().map(build_do_child).collect(),
    }
}

fn build_do_child(child: CompiledDataObjectChild) -> DataObjectChild {
    match child {
        CompiledDataObjectChild::Attribute(da) => DataObjectChild::Attribute(build_da(da)),
        CompiledDataObjectChild::SubObject(sdo) => DataObjectChild::SubObject(build_do(sdo)),
    }
}

fn build_da(da: CompiledDataAttribute) -> DataAttributeNode {
    DataAttributeNode {
        name: da.name,
        fc: da.fc,
        children: da.children.into_iter().map(build_da).collect(),
    }
}
