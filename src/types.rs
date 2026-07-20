pub mod control;
pub mod enumerations;
pub mod report;
pub mod rt_services;

// The file is still physically named `types/types.rs` for now, but we expose
// it as `common` to avoid `clippy::module_inception` (`types::types`).
#[path = "types/types.rs"]
pub mod common;

// Re-export items from submodules so `crate::types::*` keeps working.
pub use common::*;
pub use control::*;
pub use enumerations::*;
pub use report::*;
pub use rt_services::*;

use core::str;

use serde::{Deserialize, Serialize};

/// The type and structural shape of a data element, as returned by MMS
/// GetDataDefinition (GetVariableAccessAttributes). Leaf variants carry no
/// value payload — the actual value lives in the corresponding [`IECData`]
/// node at the same positional index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DataType {
    /// Ordered, named fields — paired positionally with [`IECData::Structure`]
    Structure(Vec<DataDefinition>),

    /// Homogeneous sequence — paired positionally with [`IECData::Array`]
    Array {
        count: u32,
        element_type: Box<DataType>,
    },

    // ── leaf types (no children, no value) ──────────────────────────────
    Boolean,
    BitString,
    Int,
    UInt,
    Float,
    OctetString,
    VisibleString,
    MmsString,
    Timestamp,
}

/// Schema node produced by the MMS GetDataDefinition service.
///
/// Combines the element name (from the service response) with a [`DataType`]
/// that mirrors the structural shape of [`IECData`], enabling positional
/// resolution of received values without an additional schema look-up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataDefinition {
    pub name: String,
    pub data_type: DataType,
}

#[derive(Debug)]
pub enum EncodeError {
    General {
        message: String,
        buffer_index: usize,
    },
    BufferTooSmall {
        required: usize,
        available: usize,
    },
}

impl EncodeError {
    pub fn new(msg: &str, buffer_index: usize) -> Self {
        let mut chart = ['\0'; 128];
        for (i, c) in msg.chars().take(128).enumerate() {
            chart[i] = c;
        }
        EncodeError::General {
            message: chart.iter().collect(),
            buffer_index,
        }
    }
}

#[derive(Debug)]
pub struct DecodeError {
    pub message: String,
    pub buffer_index: usize,
}

impl DecodeError {
    pub fn new(msg: &str, buffer_index: usize) -> Self {
        let mut chars = ['\0'; 128];
        for (i, c) in msg.chars().take(128).enumerate() {
            chars[i] = c;
        }

        DecodeError {
            message: chars.iter().collect(),
            buffer_index,
        }
    }
}
