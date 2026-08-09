//! Runtime store for IEC 61850 DataAttribute values.
//!
//! The store is keyed by [`DataRef`], which currently is a path string. The model
//! assigns a stable [`DataRef`] to every leaf DataAttribute when it is loaded.
//! Future extensions can add token-based interning without changing callers.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::server::types::DataValue;

/// Errors that can occur when accessing the value store.
#[derive(Debug)]
pub enum StoreError {
    UnknownRef(DataRef),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRef(r) => write!(f, "Unknown data reference: {}", r.0),
        }
    }
}

impl std::error::Error for StoreError {}

/// Stable reference to a leaf DataAttribute.
///
/// Today this is the full IEC 61850 path (`LD0/MMXU1.A.phsA.cVal.mag.f`).
/// It is intentionally cheap to clone as an `Arc<str>` if paths become long,
/// but `String` keeps the first iteration simple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataRef(pub String);

impl DataRef {
    /// Creates a new reference from an owned or borrowed path.
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }
}

impl AsRef<str> for DataRef {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A live value cell for one leaf DataAttribute.
///
/// Each cell holds exactly one IEC 61850 DataValue. Timestamp and quality
/// are not stored here; in the model they are separate leaf DAs such as `t`
/// and `q` within the same CDC.
pub struct ValueCell {
    value: RwLock<DataValue>,
}

impl ValueCell {
    fn new(initial: DataValue) -> Self {
        Self {
            value: RwLock::new(initial),
        }
    }

    /// Reads the current value.
    pub fn read(&self) -> DataValue {
        self.value.read().clone()
    }

    /// Overwrites the current value.
    pub fn write(&self, value: DataValue) {
        *self.value.write() = value;
    }
}

/// Central runtime store for all leaf DataAttribute values.
///
/// The store is cheaply cloneable because it holds its data behind an `Arc`,
/// allowing it to be shared between the model, the MMS server task, and
/// real-time update loops.
#[derive(Default, Clone)]
pub struct LeafDataStore {
    inner: Arc<DataValueStoreInner>,
}

#[derive(Default)]
struct DataValueStoreInner {
    cells: RwLock<HashMap<DataRef, ValueCell>>,
}

impl LeafDataStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// If the path already exists, the existing cell is left unchanged.
    pub fn register(&self, reference: DataRef, initial: DataValue) {
        let mut cells = self.inner.cells.write();
        cells
            .entry(reference)
            .or_insert_with(|| ValueCell::new(initial));
    }

    /// Returns the current value of a leaf attribute, if it exists.
    pub fn read(&self, reference: &DataRef) -> Result<DataValue, StoreError> {
        let cells = self.inner.cells.read();
        cells
            .get(reference)
            .map(|cell| cell.read())
            .ok_or_else(|| StoreError::UnknownRef(reference.clone()))
    }

    /// Overwrites the value of a leaf attribute.
    pub fn write(&self, reference: &DataRef, value: DataValue) -> Result<(), StoreError> {
        let cells = self.inner.cells.read();
        let cell = cells
            .get(reference)
            .ok_or_else(|| StoreError::UnknownRef(reference.clone()))?;
        cell.write(value);
        Ok(())
    }

    /// Returns a cloned copy of all registered references.
    pub fn references(&self) -> Vec<DataRef> {
        self.inner.cells.read().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let store = LeafDataStore::new();
        let reference = DataRef::new("LD0/LLN0.NamPlt.vendor");

        store.register(reference.clone(), DataValue::Bool(false));
        assert!(matches!(
            store.read(&reference).unwrap(),
            DataValue::Bool(false)
        ));

        store
            .write(
                &reference,
                DataValue::VisibleString("OpenEnergyStack".to_string()),
            )
            .unwrap();

        assert_eq!(
            store.read(&reference).unwrap(),
            DataValue::VisibleString("OpenEnergyStack".to_string())
        );
    }

    #[test]
    fn unknown_reference_returns_error() {
        let store = LeafDataStore::new();
        let reference = DataRef::new("LD0/LLN0.NamPlt.vendor");
        assert!(store.read(&reference).is_err());
    }
}
