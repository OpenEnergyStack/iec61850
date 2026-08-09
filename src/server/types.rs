use std::sync::Arc;

use crate::types::{Quality, Timestamp};

/// A runtime value of an IEC 61850 DataAttribute.
#[derive(Debug, Clone, PartialEq)]
pub enum DataValue {
    Bool(bool),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Int8u(u8),
    Int16u(u16),
    Int32u(u32),
    Float32(f32),
    OctetString(Vec<u8>), // MmsString would need encoding
    VisibleString(String),
    UnicodeString(String),
    Quality(Quality),
    Timestamp(Timestamp),
    /// A structured DataAttribute or a DataObject read as a collection of values.
    Struct(Arc<Vec<DataValue>>),
    Array(Arc<Vec<DataValue>>),
}

impl DataValue {
    /// Returns a default placeholder for unknown initial values.
    pub fn default_placeholder() -> Self {
        Self::Bool(false)
    }
}
