use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CompiledIedConfig {
    max_associations: u8,
}

#[derive(Debug, Deserialize)]
struct CompiledLogicalDeviceNode {
    inst: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CompiledModel {
    ied_name: String,
    config: CompiledIedConfig,
    #[serde(default)]
    logical_devices: Vec<CompiledLogicalDeviceNode>,
}

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

/// Server configuration.
#[derive(Debug, Clone)]
pub struct IedConfig {
    /// Maximum number of simultaneous associations. The transport layer
    /// enforces this limit and rejects new connections beyond it.
    pub max_associations: u8,
}

/// A Logical Device node in the read-only structural tree.
#[derive(Debug, Clone)]
pub struct LogicalDeviceNode {
    pub inst: String,
    pub _name: String,
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
        let logical_devices: Vec<LogicalDeviceNode> = model
            .logical_devices
            .into_iter()
            .map(|ld| LogicalDeviceNode {
                inst: ld.inst,
                _name: ld.name,
            })
            .collect();
        Ok(Self {
            ied_name: model.ied_name,
            config: IedConfig {
                max_associations: model.config.max_associations,
            },
            logical_devices,
        })
    }

    /// Returns the names of all logical devices as `ied_name + ld_inst` strings.
    pub fn get_server_directory(&self) -> Vec<String> {
        self.logical_devices
            .iter()
            .map(|ld| format!("{}{}", self.ied_name, ld.inst))
            .collect()
    }
}
