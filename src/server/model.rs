use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CompiledIedConfig {
    max_associations: u8,
}

#[derive(Debug, Deserialize)]
struct CompiledModel {
    ied_name: String,
    config: CompiledIedConfig,
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

/// The central runtime data model of an IEC 61850 server.
#[derive(Clone)]
pub struct ServerModel {
    pub ied_name: String,
    pub config: IedConfig,
}

impl ServerModel {
    pub fn new(ied_name: String, max_associations: u8) -> Self {
        Self {
            ied_name,
            config: IedConfig { max_associations },
        }
    }

    /// Loads a `ServerModel` from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, ModelLoadError> {
        let model: CompiledModel = serde_json::from_str(json)?;
        Ok(Self {
            ied_name: model.ied_name,
            config: IedConfig {
                max_associations: model.config.max_associations,
            },
        })
    }

    /// Loads a `ServerModel` from a JSON file on disk.
    pub fn from_json_file(path: &str) -> Result<Self, ModelLoadError> {
        let json = std::fs::read_to_string(path)?;
        Self::from_json(&json)
    }
}
