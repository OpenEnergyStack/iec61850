use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::server::data_value_store::{DataRef, LeafDataStore};
use crate::server::types::DataValue;
use crate::types::{DataDefinition, DataType, Quality, TimeQuality, Timestamp};

/// A single step in a parsed IEC 61850 model path.
#[derive(Debug, Clone)]
enum PathStep {
    Component(String),
    Index(u32),
}

/// Parse a dot-separated path that may contain array indices in parentheses.
fn parse_model_path(path: &str) -> Vec<PathStep> {
    let mut steps = Vec::new();
    let mut current = String::new();
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                if !current.is_empty() {
                    steps.push(PathStep::Component(current));
                    current = String::new();
                }
            }
            '(' => {
                if !current.is_empty() {
                    steps.push(PathStep::Component(current));
                    current = String::new();
                }
                let mut idx = String::new();
                for c in chars.by_ref() {
                    if c == ')' {
                        break;
                    }
                    idx.push(c);
                }
                if let Ok(parsed) = idx.parse::<u32>() {
                    steps.push(PathStep::Index(parsed));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        steps.push(PathStep::Component(current));
    }

    steps
}

/// Apply an array index to a value, then any remaining path steps.
fn apply_index_to_value(value: &DataValue, idx: u32, remaining: &[PathStep]) -> Option<DataValue> {
    match value {
        DataValue::Array(arr) => {
            let elem = arr.get(idx as usize)?.clone();
            apply_value_steps(&elem, remaining)
        }
        _ => None,
    }
}

/// Apply remaining path steps to a plain runtime value.
fn apply_value_steps(value: &DataValue, steps: &[PathStep]) -> Option<DataValue> {
    match steps.first() {
        None => Some(value.clone()),
        Some(PathStep::Index(idx)) => match value {
            DataValue::Array(arr) => {
                let elem = arr.get(*idx as usize)?.clone();
                apply_value_steps(&elem, &steps[1..])
            }
            _ => None,
        },
        Some(PathStep::Component(_)) => None,
    }
}

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

#[derive(Debug, Deserialize, Clone)]
struct CompiledDataObject {
    name: String,
    /// Array size from SCL (`count`). `0` or missing means a single object.
    #[serde(default)]
    count: u32,
    #[serde(default)]
    children: Vec<CompiledDataObjectChild>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum CompiledDataObjectChild {
    Attribute(CompiledDataAttribute),
    SubObject(CompiledDataObject),
}

#[derive(Debug, Deserialize, Clone)]
struct CompiledDataAttribute {
    name: String,
    fc: FunctionalConstraint,
    /// Array size from SCL (`count`). `0` or missing means a single attribute.
    #[serde(default)]
    count: u32,
    /// Leaf attribute type. When `da_type` is missing for a leaf (no children)
    /// an error is reported so that the model cannot load with an untyped leaf.
    #[serde(rename = "da_type")]
    attribute_type: Option<AttributeType>,
    #[serde(default)]
    children: Vec<CompiledDataAttribute>,
}

/// IEC 61850 leaf data attribute type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    Bool,
    Int32,
    Float32,
    Quality,
    Timestamp,
    VisibleString,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ModelLoadError {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// A data attribute lacks the required `da_type` field.
    MissingAttributeType {
        path: String,
    },
}

impl std::fmt::Display for ModelLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Failed to read model file: {e}"),
            Self::Json(e) => write!(f, "Failed to parse model JSON: {e}"),
            Self::MissingAttributeType { path } => {
                write!(f, "Missing 'da_type' for leaf data attribute at {path}")
            }
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

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "ST" => Some(Self::ST),
            "MX" => Some(Self::MX),
            "SP" => Some(Self::SP),
            "SE" => Some(Self::SE),
            "SF" => Some(Self::SF),
            "CF" => Some(Self::CF),
            "DC" => Some(Self::DC),
            "EX" => Some(Self::EX),
            "BR" => Some(Self::BR),
            "RP" => Some(Self::RP),
            "LG" => Some(Self::LG),
            "GO" => Some(Self::GO),
            "SV" => Some(Self::SV),
            "TI" => Some(Self::TI),
            "IN" => Some(Self::IN),
            "CO" => Some(Self::CO),
            _ => None,
        }
    }
}

/// A Data Attribute node in the structural tree.
///
/// A DA is either a structural node that contains sub-attributes (e.g. `cVal`
/// of type `Vector`), a leaf node that maps to a value cell in the runtime
/// store, or an array of either of those. These cases are mutually exclusive.
#[derive(Debug, Clone)]
pub enum DataAttributeNode {
    /// A leaf DataAttribute backed by a value cell in [`ServerModel::value_store`].
    Leaf {
        name: String,
        fc: FunctionalConstraint,
        reference: DataRef,
        attribute_type: Option<AttributeType>,
    },
    /// A structural DataAttribute that contains nested Basic Data Attributes.
    Struct {
        name: String,
        fc: FunctionalConstraint,
        children: Vec<DataAttributeNode>,
    },
    /// A homogeneous array of DataAttributes.
    Array {
        name: String,
        fc: FunctionalConstraint,
        count: u32,
        elements: Vec<DataAttributeNode>,
    },
}

impl DataAttributeNode {
    /// Returns the name of this DataAttribute.
    pub fn name(&self) -> &str {
        match self {
            Self::Leaf { name, .. } | Self::Struct { name, .. } | Self::Array { name, .. } => name,
        }
    }

    /// Returns the functional constraint of this DataAttribute.
    pub fn fc(&self) -> FunctionalConstraint {
        match self {
            Self::Leaf { fc, .. } | Self::Struct { fc, .. } | Self::Array { fc, .. } => *fc,
        }
    }

    /// Reads this DataAttribute as a value.
    ///
    /// For leaf attributes the value is read from the runtime store. For
    /// structural attributes a `DataValue::Struct` is built recursively from
    /// the child attributes. For arrays a `DataValue::Array` is built from the
    /// element attributes.
    pub fn read_values(&self, store: &LeafDataStore) -> Option<DataValue> {
        match self {
            Self::Leaf { reference, .. } => store.read(reference).ok(),
            Self::Struct { children, .. } => {
                let fields: Vec<DataValue> = children
                    .iter()
                    .map(|child| child.read_values(store))
                    .collect::<Option<Vec<_>>>()?;
                Some(DataValue::Struct(Arc::new(fields)))
            }
            Self::Array { elements, .. } => {
                let values: Vec<DataValue> = elements
                    .iter()
                    .map(|elem| elem.read_values(store))
                    .collect::<Option<Vec<_>>>()?;
                Some(DataValue::Array(Arc::new(values)))
            }
        }
    }
}

/// A child of a Data Object — a DA, a Sub-Data Object, or an array of either.
#[derive(Debug, Clone)]
pub enum DataObjectChild {
    Attribute(DataAttributeNode),
    SubObject(DataObjectNode),
    /// A homogeneous array of DataAttributes.
    AttributeArray {
        name: String,
        fc: FunctionalConstraint,
        count: u32,
        elements: Vec<DataAttributeNode>,
    },
    /// A homogeneous array of Sub-Data Objects.
    SubObjectArray {
        name: String,
        count: u32,
        elements: Vec<DataObjectNode>,
    },
}

impl DataObjectChild {
    /// Reads the value of this child.
    pub fn read_values(&self, store: &LeafDataStore) -> Option<DataValue> {
        match self {
            DataObjectChild::Attribute(da) => da.read_values(store),
            DataObjectChild::SubObject(sdo) => sdo.read_values(store),
            DataObjectChild::AttributeArray { elements, .. } => {
                let values: Vec<DataValue> = elements
                    .iter()
                    .map(|elem| elem.read_values(store))
                    .collect::<Option<Vec<_>>>()?;
                Some(DataValue::Array(Arc::new(values)))
            }
            DataObjectChild::SubObjectArray { elements, .. } => {
                let values: Vec<DataValue> = elements
                    .iter()
                    .map(|elem| elem.read_values(store))
                    .collect::<Option<Vec<_>>>()?;
                Some(DataValue::Array(Arc::new(values)))
            }
        }
    }

    /// Looks up a nested DataObject child by name.
    pub fn as_sub_object(&self) -> Option<&DataObjectNode> {
        match self {
            DataObjectChild::SubObject(sdo) => Some(sdo),
            _ => None,
        }
    }
}

/// A Data Object node in the structural tree.
#[derive(Debug, Clone)]
pub struct DataObjectNode {
    pub name: String,
    pub children: Vec<DataObjectChild>,
}

impl DataObjectNode {
    /// Looks up an immediate child by name.
    pub fn find_child(&self, name: &str) -> Option<&DataObjectChild> {
        self.children.iter().find(|child| match child {
            DataObjectChild::Attribute(da) => da.name() == name,
            DataObjectChild::SubObject(sdo) => sdo.name == name,
            DataObjectChild::AttributeArray { name: n, .. } => n == name,
            DataObjectChild::SubObjectArray { name: n, .. } => n == name,
        })
    }

    /// Reads the values of all leaf DAs under this DataObject as a structure.
    pub fn read_values(&self, store: &LeafDataStore) -> Option<DataValue> {
        let fields: Vec<DataValue> = self
            .children
            .iter()
            .map(|child| child.read_values(store))
            .collect::<Option<Vec<_>>>()?;
        Some(DataValue::Struct(Arc::new(fields)))
    }
}

/// A Logical Node in the structural tree.
#[derive(Debug, Clone)]
pub struct LogicalNodeNode {
    pub ln_class: String,
    pub inst: String,
    pub ln_prefix: String,
    pub data_objects: Vec<DataObjectNode>,
}

impl LogicalNodeNode {
    /// Looks up an immediate child DataObject by name.
    pub fn find_data_object(&self, name: &str) -> Option<&DataObjectNode> {
        self.data_objects.iter().find(|do_| do_.name == name)
    }
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
    /// Runtime value store for every leaf DataAttribute.
    pub value_store: LeafDataStore,
    /// Maps a DataAttribute [`DataRef`] back to its full IEC 61850 path.
    /// Useful for diagnostics and for external RT functions that discover
    /// references at runtime.
    pub reference_to_path: HashMap<DataRef, String>,
}

impl ServerModel {
    /// Looks up a Logical Node by its path segment within a Logical Device.
    ///
    /// `ln_name` is the full LN name as used in MMS item IDs, e.g. `LLN0` or
    /// `Pref_MMXU1`.
    pub fn find_logical_node(&self, ld_inst: &str, ln_name: &str) -> Option<&LogicalNodeNode> {
        let ld = self.logical_devices.iter().find(|ld| ld.inst == ld_inst)?;
        ld.logical_nodes.iter().find(|ln| {
            let expected = format!("{}{}{}", ln.ln_prefix, ln.ln_class, ln.inst);
            expected == ln_name
        })
    }

    /// Reads the value at a model path.
    ///
    /// The path uses the internal model notation:
    /// `{ied_name}{ld_inst}/{ln_name}.{do_name}[.{child_name}]*`
    ///
    /// An optional trailing `[FC]` (as produced by the MMS mapping) is ignored;
    /// the functional constraint is resolved from the model itself.
    ///
    /// Array indices may be embedded using parentheses, e.g.
    /// `{ied_name}{ld_inst}/{ln_name}.HA.phsAHar(7).cVal.mag.f`.
    ///
    /// The path may target a leaf DataAttribute, a structured DataAttribute, an
    /// array, or a DataObject/SubDataObject. In the latter cases the result is a
    /// `DataValue::Struct` or `DataValue::Array` built from the leaf values.
    pub fn read_by_path(&self, path: &str) -> Option<DataValue> {
        let (domain, rest) = path.split_once('/')?;
        let ld_inst = domain.strip_prefix(&self.ied_name).unwrap_or(domain);

        // The MMS mapping may append a trailing `[FC]`; capture it if present.
        let rest = rest.trim_end();
        let (rest, fc) = match rest.rfind('[') {
            Some(idx) => {
                let fc = FunctionalConstraint::from_str(&rest[idx + 1..rest.len() - 1]);
                (&rest[..idx], fc)
            }
            None => (rest, None),
        };

        let steps = parse_model_path(rest);
        let ln_name = match steps.first()? {
            PathStep::Component(name) => name,
            PathStep::Index(_) => return None,
        };
        let ln = self.find_logical_node(ld_inst, ln_name)?;

        // LN-level reference with optional FC group: read the matching FC group.
        if steps.len() == 1 {
            return fc.and_then(|fc: FunctionalConstraint| self.read_ln_fc_group(ln, fc));
        }

        let do_name = match steps.get(1)? {
            PathStep::Component(name) => name,
            PathStep::Index(_) => return None,
        };
        let current_do = ln.find_data_object(do_name)?;

        self.read_data_object_steps(current_do, &steps[2..])
    }

    /// Reads all data objects under an LN that belong to the given functional
    /// constraint as a single structure. Each matching data object becomes a
    /// named component whose value is a structure of its leaf children.
    fn read_ln_fc_group(
        &self,
        ln: &LogicalNodeNode,
        fc: FunctionalConstraint,
    ) -> Option<DataValue> {
        let values: Vec<DataValue> = ln
            .data_objects
            .iter()
            .filter(|do_| fc_for_data_object(do_).map_or(false, |do_fc| do_fc == fc))
            .map(|do_| do_.read_values(&self.value_store))
            .collect::<Option<Vec<_>>>()?;
        Some(DataValue::Struct(Arc::new(values)))
    }

    fn read_data_object_steps(
        &self,
        do_node: &DataObjectNode,
        steps: &[PathStep],
    ) -> Option<DataValue> {
        if steps.is_empty() {
            return do_node.read_values(&self.value_store);
        }

        let name = match steps.first()? {
            PathStep::Component(name) => name,
            PathStep::Index(_) => return None,
        };

        match do_node.find_child(name)? {
            DataObjectChild::Attribute(da) => self.read_attribute_with_steps(da, &steps[1..]),
            DataObjectChild::SubObject(sdo) => self.read_data_object_steps(sdo, &steps[1..]),
            DataObjectChild::AttributeArray { elements, .. } => match steps.get(1) {
                None => {
                    let values: Vec<DataValue> = elements
                        .iter()
                        .map(|elem| elem.read_values(&self.value_store))
                        .collect::<Option<Vec<_>>>()?;
                    Some(DataValue::Array(Arc::new(values)))
                }
                Some(PathStep::Index(idx)) => {
                    let elem = elements.get(*idx as usize)?;
                    self.read_attribute_with_steps(elem, &steps[2..])
                }
                Some(PathStep::Component(_)) => None,
            },
            DataObjectChild::SubObjectArray { elements, .. } => match steps.get(1) {
                None => {
                    let values: Vec<DataValue> = elements
                        .iter()
                        .map(|elem| elem.read_values(&self.value_store))
                        .collect::<Option<Vec<_>>>()?;
                    Some(DataValue::Array(Arc::new(values)))
                }
                Some(PathStep::Index(idx)) => {
                    let elem = elements.get(*idx as usize)?;
                    self.read_data_object_steps(elem, &steps[2..])
                }
                Some(PathStep::Component(_)) => None,
            },
        }
    }

    fn read_attribute_with_steps(
        &self,
        da: &DataAttributeNode,
        steps: &[PathStep],
    ) -> Option<DataValue> {
        match steps.first() {
            None => da.read_values(&self.value_store),
            Some(PathStep::Component(name)) => match da {
                DataAttributeNode::Struct { children, .. } => {
                    let child = children.iter().find(|c| c.name() == name)?;
                    self.read_attribute_with_steps(child, &steps[1..])
                }
                _ => None,
            },
            Some(PathStep::Index(idx)) => match da {
                DataAttributeNode::Leaf { reference, .. } => {
                    let value = self.value_store.read(reference).ok()?;
                    apply_index_to_value(&value, *idx, &steps[1..])
                }
                DataAttributeNode::Array { elements, .. } => {
                    let elem = elements.get(*idx as usize)?;
                    self.read_attribute_with_steps(elem, &steps[1..])
                }
                _ => None,
            },
        }
    }

    /// Resolves the data definition at a model path.
    ///
    /// The path uses the same internal model notation as [`Self::read_by_path`]:
    /// `{ied_name}{ld_inst}/{ln_name}.{do_name}[.{child_name}]*`
    ///
    /// An optional trailing `[FC]` is ignored. Array indices may be embedded
    /// using parentheses. The method returns the type definition of the node
    /// referenced by the path, which may be a leaf, a structure, or an array.
    ///
    /// Per IEC 61850-7-2, a reference that stops at the Logical Node level
    /// (`{ied_name}{ld_inst}/{ln_name}`) is also valid. The response describes
    /// the LN as a structure whose first-level components are the functional
    /// constraints, each containing the DOs/DAs that share that FC.
    pub fn get_data_definition_by_path(&self, path: &str) -> Option<DataDefinition> {
        let (domain, rest) = path.split_once('/')?;
        let ld_inst = domain.strip_prefix(&self.ied_name).unwrap_or(domain);

        let rest = rest.trim_end();
        let rest = match rest.rfind('[') {
            Some(idx) => &rest[..idx],
            None => rest,
        };

        let steps = parse_model_path(rest);
        let ln_name = match steps.first()? {
            PathStep::Component(name) => name,
            PathStep::Index(_) => return None,
        };
        let ln = self.find_logical_node(ld_inst, ln_name)?;

        match steps.get(1) {
            None => Some(self.get_logical_node_definition(ln)),
            Some(PathStep::Component(do_name)) => {
                let current_do = ln.find_data_object(do_name)?;
                self.get_data_object_definition(current_do, &steps[2..])
            }
            Some(PathStep::Index(_)) => None,
        }
    }

    /// Builds the data definition for a whole Logical Node.
    ///
    /// All data objects of the LN are grouped by their functional constraint.
    /// The returned structure has one component per distinct FC, in first-seen
    /// order, and each FC component is itself a structure containing the
    /// matching data objects. A data object that contains children with
    /// different functional constraints may appear under multiple FC groups,
    /// once for each FC, containing only the children that share that FC.
    fn get_logical_node_definition(&self, ln: &LogicalNodeNode) -> DataDefinition {
        let mut fc_groups: Vec<(FunctionalConstraint, Vec<DataDefinition>)> = Vec::new();

        for do_node in &ln.data_objects {
            let do_fcs = fc_set_for_data_object(do_node);
            for fc in do_fcs {
                let filtered = filter_children_by_fc(&do_node.children, fc);
                if filtered.is_empty() {
                    continue;
                }
                let children = self.data_object_children_to_data_type(&filtered);
                push_to_fc_group(
                    &mut fc_groups,
                    fc,
                    DataDefinition {
                        name: do_node.name.clone(),
                        data_type: children,
                    },
                );
            }
        }

        let fc_components = fc_groups
            .into_iter()
            .map(|(fc, children)| DataDefinition {
                name: fc.as_str().to_string(),
                data_type: DataType::Structure(children),
            })
            .collect();

        DataDefinition {
            name: format!("{}{}{}", ln.ln_prefix, ln.ln_class, ln.inst),
            data_type: DataType::Structure(fc_components),
        }
    }

    fn get_data_object_definition(
        &self,
        do_node: &DataObjectNode,
        steps: &[PathStep],
    ) -> Option<DataDefinition> {
        if steps.is_empty() {
            return Some(DataDefinition {
                name: do_node.name.clone(),
                data_type: self.data_object_children_to_data_type(&do_node.children),
            });
        }

        match steps.first()? {
            PathStep::Component(name) => match do_node.find_child(name)? {
                DataObjectChild::Attribute(da) => {
                    self.get_data_attribute_definition(da, &steps[1..])
                }
                DataObjectChild::SubObject(sdo) => {
                    self.get_data_object_definition(sdo, &steps[1..])
                }
                DataObjectChild::AttributeArray {
                    name: array_name,
                    count,
                    elements,
                    ..
                } => match steps.get(1) {
                    None => Some(DataDefinition {
                        name: array_name.clone(),
                        data_type: DataType::Array {
                            count: *count,
                            element_type: Box::new(
                                self.get_data_attribute_definition(&elements[0], &[])?
                                    .data_type,
                            ),
                        },
                    }),
                    Some(PathStep::Index(idx)) => self
                        .get_data_attribute_definition(elements.get(*idx as usize)?, &steps[2..]),
                    Some(PathStep::Component(_)) => None,
                },
                DataObjectChild::SubObjectArray {
                    name: array_name,
                    count,
                    elements,
                    ..
                } => match steps.get(1) {
                    None => Some(DataDefinition {
                        name: array_name.clone(),
                        data_type: DataType::Array {
                            count: *count,
                            element_type: Box::new(
                                self.get_data_object_definition(&elements[0], &[])?
                                    .data_type,
                            ),
                        },
                    }),
                    Some(PathStep::Index(idx)) => {
                        self.get_data_object_definition(elements.get(*idx as usize)?, &steps[2..])
                    }
                    Some(PathStep::Component(_)) => None,
                },
            },
            PathStep::Index(_) => None,
        }
    }

    fn get_data_attribute_definition(
        &self,
        da: &DataAttributeNode,
        steps: &[PathStep],
    ) -> Option<DataDefinition> {
        match steps.first() {
            None => Some(DataDefinition {
                name: da.name().to_string(),
                data_type: self.data_attribute_node_to_data_type(da),
            }),
            Some(PathStep::Component(name)) => match da {
                DataAttributeNode::Struct { children, .. } => {
                    let child = children.iter().find(|c| c.name() == name)?;
                    self.get_data_attribute_definition(child, &steps[1..])
                }
                _ => None,
            },
            Some(PathStep::Index(idx)) => match da {
                DataAttributeNode::Array { elements, .. } => {
                    let elem = elements.get(*idx as usize)?;
                    self.get_data_attribute_definition(elem, &steps[1..])
                }
                _ => None,
            },
        }
    }

    fn data_attribute_node_to_data_type(&self, da: &DataAttributeNode) -> DataType {
        match da {
            DataAttributeNode::Leaf { attribute_type, .. } => {
                attribute_type_to_data_type(*attribute_type)
            }
            DataAttributeNode::Struct { children, .. } => DataType::Structure(
                children
                    .iter()
                    .map(|child| {
                        self.get_data_attribute_definition(child, &[])
                            .expect("child resolves")
                    })
                    .collect(),
            ),
            DataAttributeNode::Array {
                count, elements, ..
            } => DataType::Array {
                count: *count,
                element_type: Box::new(
                    self.get_data_attribute_definition(&elements[0], &[])
                        .expect("array has element")
                        .data_type,
                ),
            },
        }
    }

    fn data_object_children_to_data_type(&self, children: &[DataObjectChild]) -> DataType {
        DataType::Structure(
            children
                .iter()
                .map(|child| match child {
                    DataObjectChild::Attribute(da) => self
                        .get_data_attribute_definition(da, &[])
                        .expect("child resolves"),
                    DataObjectChild::SubObject(sdo) => self
                        .get_data_object_definition(sdo, &[])
                        .expect("child resolves"),
                    DataObjectChild::AttributeArray {
                        name,
                        count,
                        elements,
                        ..
                    } => DataDefinition {
                        name: name.clone(),
                        data_type: DataType::Array {
                            count: *count,
                            element_type: Box::new(
                                self.get_data_attribute_definition(&elements[0], &[])
                                    .expect("array has element")
                                    .data_type,
                            ),
                        },
                    },
                    DataObjectChild::SubObjectArray {
                        name,
                        count,
                        elements,
                        ..
                    } => DataDefinition {
                        name: name.clone(),
                        data_type: DataType::Array {
                            count: *count,
                            element_type: Box::new(
                                self.get_data_object_definition(&elements[0], &[])
                                    .expect("array has element")
                                    .data_type,
                            ),
                        },
                    },
                })
                .collect(),
        )
    }

    /// Loads a `ServerModel` from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, ModelLoadError> {
        let model: CompiledModel = serde_json::from_str(json)?;
        let ied_name = model.ied_name.clone();

        let mut builder = ModelBuilder::new(ied_name.clone());

        let logical_devices: Result<Vec<_>, _> = model
            .logical_devices
            .into_iter()
            .map(|ld| builder.build_logical_device(ld))
            .collect();

        Ok(Self {
            ied_name,
            config: IedConfig {
                max_associations: model.config.max_associations,
            },
            logical_devices: logical_devices?,
            value_store: builder.value_store,
            reference_to_path: builder.reference_to_path,
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

/// Collects all leaf/structural definitions under a set of DO children into
/// FC-ordered groups. The `parent_name` is prepended to sub-object names so
/// that `A.phsA.cVal.mag.f` stays distinguishable from `A.phsA.cVal.ang.f`.
/// Determines the functional constraint of a DataObject from its children.
fn fc_for_data_object(do_node: &DataObjectNode) -> Option<FunctionalConstraint> {
    do_node.children.iter().find_map(|child| match child {
        DataObjectChild::Attribute(da) => Some(da.fc()),
        DataObjectChild::AttributeArray { fc, .. } => Some(*fc),
        DataObjectChild::SubObject(sdo) => fc_for_data_object(sdo),
        DataObjectChild::SubObjectArray { elements, .. } => {
            elements.first().and_then(fc_for_data_object)
        }
    })
}

/// Returns every distinct functional constraint used by any child of the
/// data object, preserving first-seen order.
fn fc_set_for_data_object(do_node: &DataObjectNode) -> Vec<FunctionalConstraint> {
    let mut fcs = Vec::new();
    for child in &do_node.children {
        let child_fcs: Vec<FunctionalConstraint> = match child {
            DataObjectChild::Attribute(da) => vec![da.fc()],
            DataObjectChild::AttributeArray { fc, .. } => vec![*fc],
            DataObjectChild::SubObject(sdo) => fc_set_for_data_object(sdo),
            DataObjectChild::SubObjectArray { elements, .. } => elements
                .first()
                .map(|e| fc_set_for_data_object(e))
                .unwrap_or_default(),
        };
        for fc in child_fcs {
            if !fcs.contains(&fc) {
                fcs.push(fc);
            }
        }
    }
    fcs
}

/// Filters the children of a data object, keeping only the children (and their
/// nested descendants) whose functional constraint matches `fc`.
fn filter_children_by_fc(
    children: &[DataObjectChild],
    fc: FunctionalConstraint,
) -> Vec<DataObjectChild> {
    children
        .iter()
        .filter_map(|child| match child {
            DataObjectChild::Attribute(da) if da.fc() == fc => {
                Some(DataObjectChild::Attribute(da.clone()))
            }
            DataObjectChild::AttributeArray {
                name,
                fc: array_fc,
                count,
                elements,
            } if *array_fc == fc => Some(DataObjectChild::AttributeArray {
                name: name.clone(),
                fc: *array_fc,
                count: *count,
                elements: elements.clone(),
            }),
            DataObjectChild::SubObject(sdo) => {
                let filtered = filter_children_by_fc(&sdo.children, fc);
                if filtered.is_empty() {
                    None
                } else {
                    Some(DataObjectChild::SubObject(DataObjectNode {
                        name: sdo.name.clone(),
                        children: filtered,
                    }))
                }
            }
            DataObjectChild::SubObjectArray {
                name,
                count,
                elements,
            } => {
                let filtered_elements: Vec<_> = elements
                    .iter()
                    .map(|e| {
                        let filtered = filter_children_by_fc(&e.children, fc);
                        DataObjectNode {
                            name: e.name.clone(),
                            children: filtered,
                        }
                    })
                    .filter(|e| !e.children.is_empty())
                    .collect();
                if filtered_elements.is_empty() {
                    None
                } else {
                    Some(DataObjectChild::SubObjectArray {
                        name: name.clone(),
                        count: *count,
                        elements: filtered_elements,
                    })
                }
            }
            _ => None,
        })
        .collect()
}

fn push_to_fc_group(
    fc_groups: &mut Vec<(FunctionalConstraint, Vec<DataDefinition>)>,
    fc: FunctionalConstraint,
    def: DataDefinition,
) {
    match fc_groups
        .iter_mut()
        .find(|(existing_fc, _)| *existing_fc == fc)
    {
        Some((_, group)) => group.push(def),
        None => fc_groups.push((fc, vec![def])),
    }
}

/// Builder that constructs the runtime [`ServerModel`] from a compiled model.
///
/// While walking the structural tree, the builder registers every leaf
/// DataAttribute in the [`LeafDataStore`] and records the mapping from
/// [`DataRef`] back to the original IEC 61850 path.
struct ModelBuilder {
    ied_name: String,
    value_store: LeafDataStore,
    reference_to_path: HashMap<DataRef, String>,
}

impl ModelBuilder {
    fn new(ied_name: String) -> Self {
        Self {
            ied_name,
            value_store: LeafDataStore::new(),
            reference_to_path: HashMap::new(),
        }
    }

    fn build_logical_device(
        &mut self,
        ld: CompiledLogicalDevice,
    ) -> Result<LogicalDeviceNode, ModelLoadError> {
        let inst = ld.inst.clone();
        let mut logical_nodes = Vec::with_capacity(ld.logical_nodes.len());
        for ln in ld.logical_nodes {
            logical_nodes.push(self.build_logical_node(&inst, ln)?);
        }
        Ok(LogicalDeviceNode {
            inst,
            logical_nodes,
        })
    }

    fn build_logical_node(
        &mut self,
        ld_inst: &str,
        ln: CompiledLogicalNode,
    ) -> Result<LogicalNodeNode, ModelLoadError> {
        let ln_prefix = ln.prefix.clone();
        let ln_class = ln.ln_class.clone();
        let inst = ln.inst.clone();

        let ln_path = format!(
            "{}{}/{}{}{}",
            self.ied_name.clone(),
            ld_inst,
            ln_prefix,
            ln_class,
            inst
        );

        let mut data_objects = Vec::with_capacity(ln.data_objects.len());
        for do_ in ln.data_objects {
            data_objects.push(self.build_data_object(&ln_path, do_)?);
        }

        Ok(LogicalNodeNode {
            ln_class,
            inst,
            ln_prefix,
            data_objects,
        })
    }

    fn build_data_object(
        &mut self,
        parent_path: &str,
        do_: CompiledDataObject,
    ) -> Result<DataObjectNode, ModelLoadError> {
        self.build_data_object_with_index(parent_path, do_, None)
    }

    fn build_data_object_with_index(
        &mut self,
        parent_path: &str,
        do_: CompiledDataObject,
        index: Option<u32>,
    ) -> Result<DataObjectNode, ModelLoadError> {
        let path = match index {
            Some(i) => format!("{parent_path}.{}({i})", do_.name),
            None => format!("{parent_path}.{}", do_.name),
        };
        Ok(DataObjectNode {
            name: do_.name.clone(),
            children: do_
                .children
                .into_iter()
                .map(|child| self.build_data_object_child(&path, child))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn build_data_object_child(
        &mut self,
        parent_path: &str,
        child: CompiledDataObjectChild,
    ) -> Result<DataObjectChild, ModelLoadError> {
        match child {
            CompiledDataObjectChild::Attribute(da) => {
                let count = if da.count == 0 { 1 } else { da.count };
                if count > 1 {
                    let name = da.name.clone();
                    let fc = da.fc;
                    let elements: Result<Vec<_>, _> = (0..count)
                        .map(|i| {
                            self.build_data_attribute_with_index(parent_path, da.clone(), Some(i))
                        })
                        .collect();
                    Ok(DataObjectChild::AttributeArray {
                        name,
                        fc,
                        count,
                        elements: elements?,
                    })
                } else {
                    Ok(DataObjectChild::Attribute(
                        self.build_data_attribute(parent_path, da)?,
                    ))
                }
            }
            CompiledDataObjectChild::SubObject(sdo) => {
                let count = if sdo.count == 0 { 1 } else { sdo.count };
                if count > 1 {
                    let name = sdo.name.clone();
                    let elements: Result<Vec<_>, _> = (0..count)
                        .map(|i| {
                            self.build_data_object_with_index(parent_path, sdo.clone(), Some(i))
                        })
                        .collect();
                    Ok(DataObjectChild::SubObjectArray {
                        name,
                        count,
                        elements: elements?,
                    })
                } else {
                    Ok(DataObjectChild::SubObject(
                        self.build_data_object(parent_path, sdo)?,
                    ))
                }
            }
        }
    }

    fn build_data_attribute(
        &mut self,
        parent_path: &str,
        da: CompiledDataAttribute,
    ) -> Result<DataAttributeNode, ModelLoadError> {
        self.build_data_attribute_with_index(parent_path, da, None)
    }

    fn build_data_attribute_with_index(
        &mut self,
        parent_path: &str,
        da: CompiledDataAttribute,
        index: Option<u32>,
    ) -> Result<DataAttributeNode, ModelLoadError> {
        // Clone the name up-front so the descriptor can be reused when
        // expanding an array into multiple elements.
        let name = da.name.clone();
        let fc = da.fc;
        let count = if da.count == 0 { 1 } else { da.count };

        if count > 1 && index.is_none() {
            let elements: Result<Vec<_>, _> = (0..count)
                .map(|i| self.build_data_attribute_with_index(parent_path, da.clone(), Some(i)))
                .collect();
            return Ok(DataAttributeNode::Array {
                name,
                fc,
                count,
                elements: elements?,
            });
        }

        let path = match index {
            Some(i) => format!("{parent_path}.{}({i})", name),
            None => format!("{parent_path}.{name}"),
        };

        if da.children.is_empty() {
            let attribute_type = match da.attribute_type {
                Some(t) => Some(t),
                None => {
                    return Err(ModelLoadError::MissingAttributeType { path });
                }
            };
            let reference = DataRef::new(&path);
            let initial = default_value_for_type(attribute_type);

            self.value_store.register(reference.clone(), initial);
            self.reference_to_path
                .insert(reference.clone(), path.clone());

            Ok(DataAttributeNode::Leaf {
                name,
                fc,
                reference,
                attribute_type,
            })
        } else {
            let children: Result<Vec<_>, _> = da
                .children
                .into_iter()
                .map(|child| self.build_data_attribute(&path, child))
                .collect();
            Ok(DataAttributeNode::Struct {
                name,
                fc,
                children: children?,
            })
        }
    }
}

/// Returns a sensible default value for a leaf based on its declared type.
/// When no type is given, the generic boolean placeholder is used.
fn default_value_for_type(attribute_type: Option<AttributeType>) -> DataValue {
    match attribute_type {
        Some(AttributeType::Bool) => DataValue::Bool(false),
        Some(AttributeType::Int32) => DataValue::Int32(0),
        Some(AttributeType::Float32) => DataValue::Float32(0.0),
        Some(AttributeType::Quality) => DataValue::Quality(Quality::default()),
        Some(AttributeType::Timestamp) => {
            DataValue::Timestamp(Timestamp::from_unix_timestamp(0.0, TimeQuality::default()))
        }
        Some(AttributeType::VisibleString) => DataValue::VisibleString(String::new()),
        None => DataValue::default_placeholder(),
    }
}

/// Maps a compiled leaf attribute type to its public [`DataType`] representation.
///
/// `None` falls back to [`DataType::VisibleString`] so that untyped leaves can
/// still be described without failing the service.
fn attribute_type_to_data_type(attribute_type: Option<AttributeType>) -> DataType {
    match attribute_type {
        Some(AttributeType::Bool) => DataType::Boolean,
        Some(AttributeType::Int32) => DataType::Int,
        Some(AttributeType::Float32) => DataType::Float,
        Some(AttributeType::Quality) => DataType::BitString,
        Some(AttributeType::Timestamp) => DataType::Timestamp,
        Some(AttributeType::VisibleString) => DataType::VisibleString,
        None => DataType::VisibleString,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MODEL: &str = r#"{
        "ied_name": "TEMPLATE",
        "config": { "max_associations": 5 },
        "logical_devices": [
            {
                "inst": "LD0",
                "logical_nodes": [
                    {
                        "ln_class": "LLN0",
                        "inst": "0",
                        "data_objects": [
                            {
                                "name": "NamPlt",
                                "children": [
                                    { "type": "Attribute", "name": "vendor", "fc": "DC", "da_type": "visible_string" }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    #[test]
    fn model_loads_and_registers_leaf_reference() {
        let model = ServerModel::from_json(TEST_MODEL).expect("valid model");
        let reference = DataRef::new("TEMPLATELD0/LLN00.NamPlt.vendor");

        assert_eq!(model.ied_name, "TEMPLATE");
        assert!(model.value_store.read(&reference).is_ok());
    }

    #[test]
    fn model_builds_nested_sdo_and_da_paths() {
        let json = r#"{
            "ied_name": "IED",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "MMXU",
                            "inst": "1",
                            "prefix": "Pref",
                            "data_objects": [
                                {
                                    "name": "A",
                                    "children": [
                                        {
                                            "type": "SubObject",
                                            "name": "phsA",
                                            "children": [
                                                {
                                                    "type": "Attribute",
                                                    "name": "cVal",
                                                    "fc": "MX",
                                                    "children": [
                                                        {
                                                            "name": "mag",
                                                            "fc": "MX",
                                                            "children": [
                                                                { "name": "f", "fc": "MX", "da_type": "float32" }
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");
        let reference = DataRef::new("IEDLD0/PrefMMXU1.A.phsA.cVal.mag.f");

        assert!(model.value_store.read(&reference).is_ok());
        assert_eq!(
            model.reference_to_path.get(&reference),
            Some(&"IEDLD0/PrefMMXU1.A.phsA.cVal.mag.f".to_string())
        );
    }

    #[test]
    fn model_builds_array_of_leaf_attributes() {
        let json = r#"{
            "ied_name": "ARRAY",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "LLN0",
                            "inst": "0",
                            "data_objects": [
                                {
                                    "name": "Hrs",
                                    "children": [
                                        {
                                            "type": "Attribute",
                                            "name": "hr",
                                            "fc": "ST",
                                            "count": 3,
                                            "da_type": "int32"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");

        for i in 0..3 {
            let reference = DataRef::new(format!("ARRAYLD0/LLN00.Hrs.hr({i})"));
            assert!(model.value_store.read(&reference).is_ok());
        }

        assert_eq!(
            model.read_by_path("ARRAYLD0/LLN00.Hrs.hr(1)"),
            Some(DataValue::Int32(0))
        );

        assert_eq!(
            model.read_by_path("ARRAYLD0/LLN00.Hrs.hr[ST]"),
            Some(DataValue::Array(Arc::new(vec![
                DataValue::Int32(0),
                DataValue::Int32(0),
                DataValue::Int32(0),
            ])))
        );
    }

    #[test]
    fn model_builds_array_of_sub_objects() {
        let json = r#"{
            "ied_name": "FCSD",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "FCSD",
                            "inst": "1",
                            "data_objects": [
                                {
                                    "name": "Crv",
                                    "children": [
                                        {
                                            "type": "SubObject",
                                            "name": "crvPts",
                                            "count": 2,
                                            "children": [
                                                {
                                                    "type": "Attribute",
                                                    "name": "x",
                                                    "fc": "CF",
                                                    "da_type": "int32"
                                                },
                                                {
                                                    "type": "Attribute",
                                                    "name": "y",
                                                    "fc": "CF",
                                                    "da_type": "int32"
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");

        for i in 0..2 {
            let x_ref = DataRef::new(format!("FCSDLD0/FCSD1.Crv.crvPts({i}).x"));
            let y_ref = DataRef::new(format!("FCSDLD0/FCSD1.Crv.crvPts({i}).y"));
            assert!(model.value_store.read(&x_ref).is_ok());
            assert!(model.value_store.read(&y_ref).is_ok());
        }

        assert_eq!(
            model.read_by_path("FCSDLD0/FCSD1.Crv.crvPts(1).x[CF]"),
            Some(DataValue::Int32(0))
        );

        let element = DataValue::Struct(Arc::new(vec![DataValue::Int32(0), DataValue::Int32(0)]));
        assert_eq!(
            model.read_by_path("FCSDLD0/FCSD1.Crv.crvPts"),
            Some(DataValue::Array(Arc::new(vec![element.clone(), element])))
        );
    }

    #[test]
    fn model_returns_data_definition_for_leaf() {
        let json = r#"{
            "ied_name": "IED",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "MMXU",
                            "inst": "1",
                            "data_objects": [
                                {
                                    "name": "A",
                                    "children": [
                                        {
                                            "type": "Attribute",
                                            "name": "phsA",
                                            "fc": "MX",
                                            "children": [
                                                {
                                                    "name": "cVal",
                                                    "fc": "MX",
                                                    "children": [
                                                        {
                                                            "name": "mag",
                                                            "fc": "MX",
                                                            "children": [
                                                                { "name": "f", "fc": "MX", "da_type": "float32" }
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");
        let def = model
            .get_data_definition_by_path("IEDLD0/MMXU1.A.phsA.cVal.mag.f[MX]")
            .expect("definition exists");

        assert_eq!(def.name, "f");
        assert_eq!(def.data_type, DataType::Float);
    }

    #[test]
    fn model_returns_data_definition_for_structure() {
        let json = r#"{
            "ied_name": "IED",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "MMXU",
                            "inst": "1",
                            "data_objects": [
                                {
                                    "name": "A",
                                    "children": [
                                        {
                                            "type": "Attribute",
                                            "name": "phsA",
                                            "fc": "MX",
                                            "children": [
                                                {
                                                    "name": "cVal",
                                                    "fc": "MX",
                                                    "children": [
                                                        {
                                                            "name": "mag",
                                                            "fc": "MX",
                                                            "children": [
                                                                { "name": "f", "fc": "MX", "da_type": "float32" }
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");
        let def = model
            .get_data_definition_by_path("IEDLD0/MMXU1.A.phsA.cVal[MX]")
            .expect("definition exists");

        assert_eq!(def.name, "cVal");
        assert!(
            matches!(def.data_type, DataType::Structure(ref children) if children.len() == 1 && children[0].name == "mag")
        );
    }

    #[test]
    fn model_returns_data_definition_for_array() {
        let json = r#"{
            "ied_name": "ARRAY",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "LLN0",
                            "inst": "0",
                            "data_objects": [
                                {
                                    "name": "Hrs",
                                    "children": [
                                        {
                                            "type": "Attribute",
                                            "name": "hr",
                                            "fc": "ST",
                                            "count": 3,
                                            "da_type": "int32"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");

        let array_def = model
            .get_data_definition_by_path("ARRAYLD0/LLN00.Hrs.hr[ST]")
            .expect("array definition exists");
        assert_eq!(array_def.name, "hr");
        assert!(
            matches!(array_def.data_type, DataType::Array { count: 3, ref element_type } if *element_type.as_ref() == DataType::Int)
        );

        let element_def = model
            .get_data_definition_by_path("ARRAYLD0/LLN00.Hrs.hr(1)[ST]")
            .expect("element definition exists");
        assert_eq!(element_def.name, "hr");
        assert_eq!(element_def.data_type, DataType::Int);
    }

    #[test]
    fn model_returns_data_definition_for_logical_node() {
        let json = r#"{
            "ied_name": "IED",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
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
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");
        let def = model
            .get_data_definition_by_path("IEDLD0/LLN0")
            .expect("definition exists");

        assert_eq!(def.name, "LLN0");
        match def.data_type {
            DataType::Structure(fc_groups) => {
                assert_eq!(fc_groups.len(), 2);
                assert_eq!(fc_groups[0].name, "ST");
                assert_eq!(fc_groups[1].name, "DC");

                // ST group contains one DO: Mod
                match &fc_groups[0].data_type {
                    DataType::Structure(dos) => {
                        assert_eq!(dos.len(), 1);
                        assert_eq!(dos[0].name, "Mod");
                    }
                    other => panic!("expected ST to be structure of DOs, got {:?}", other),
                }

                // DC group contains one DO: NamPlt
                match &fc_groups[1].data_type {
                    DataType::Structure(dos) => {
                        assert_eq!(dos.len(), 1);
                        assert_eq!(dos[0].name, "NamPlt");
                    }
                    other => panic!("expected DC to be structure of DOs, got {:?}", other),
                }
            }
            other => panic!("expected structure, got {:?}", other),
        }
    }

    #[test]
    fn model_groups_data_object_children_by_fc_in_logical_node_definition() {
        let json = r#"{
            "ied_name": "IED",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "MHAI",
                            "inst": "1",
                            "data_objects": [
                                {
                                    "name": "HA",
                                    "children": [
                                        {
                                            "type": "SubObject",
                                            "name": "phsAHar",
                                            "count": 16,
                                            "children": [
                                                {
                                                    "type": "Attribute",
                                                    "name": "cVal",
                                                    "fc": "MX",
                                                    "children": [
                                                        {
                                                            "name": "mag",
                                                            "fc": "MX",
                                                            "children": [
                                                                { "name": "f", "fc": "MX", "da_type": "float32" }
                                                            ]
                                                        }
                                                    ]
                                                },
                                                {
                                                    "type": "Attribute",
                                                    "name": "q",
                                                    "fc": "MX",
                                                    "da_type": "quality"
                                                }
                                            ]
                                        },
                                        {
                                            "type": "Attribute",
                                            "name": "numHar",
                                            "fc": "CF",
                                            "da_type": "int32"
                                        },
                                        {
                                            "type": "Attribute",
                                            "name": "numCyc",
                                            "fc": "CF",
                                            "da_type": "int32"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let model = ServerModel::from_json(json).expect("valid model");
        let def = model
            .get_data_definition_by_path("IEDLD0/MHAI1")
            .expect("definition exists");

        assert_eq!(def.name, "MHAI1");
        match def.data_type {
            DataType::Structure(fc_groups) => {
                assert_eq!(fc_groups.len(), 2);
                assert_eq!(fc_groups[0].name, "MX");
                assert_eq!(fc_groups[1].name, "CF");

                // MX group contains HA with only phsAHar
                match &fc_groups[0].data_type {
                    DataType::Structure(dos) => {
                        assert_eq!(dos.len(), 1);
                        assert_eq!(dos[0].name, "HA");
                        match &dos[0].data_type {
                            DataType::Structure(children) => {
                                assert_eq!(children.len(), 1);
                                assert_eq!(children[0].name, "phsAHar");
                            }
                            other => panic!("expected HA to be a structure, got {:?}", other),
                        }
                    }
                    other => panic!("expected MX to be structure of DOs, got {:?}", other),
                }

                // CF group contains HA with only numHar and numCyc
                match &fc_groups[1].data_type {
                    DataType::Structure(dos) => {
                        assert_eq!(dos.len(), 1);
                        assert_eq!(dos[0].name, "HA");
                        match &dos[0].data_type {
                            DataType::Structure(children) => {
                                assert_eq!(children.len(), 2);
                                assert_eq!(children[0].name, "numHar");
                                assert_eq!(children[1].name, "numCyc");
                            }
                            other => panic!("expected HA to be a structure, got {:?}", other),
                        }
                    }
                    other => panic!("expected CF to be structure of DOs, got {:?}", other),
                }
            }
            other => panic!("expected structure, got {:?}", other),
        }
    }

    #[test]
    fn model_rejects_missing_da_type_on_leaf() {
        let json = r#"{
            "ied_name": "IED",
            "config": { "max_associations": 5 },
            "logical_devices": [
                {
                    "inst": "LD0",
                    "logical_nodes": [
                        {
                            "ln_class": "LLN0",
                            "inst": "0",
                            "data_objects": [
                                {
                                    "name": "Mod",
                                    "children": [
                                        { "type": "Attribute", "name": "stVal", "fc": "ST" }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        match ServerModel::from_json(json) {
            Err(ModelLoadError::MissingAttributeType { path }) => {
                assert!(path.ends_with(".stVal"), "unexpected path: {path}");
            }
            Err(other) => panic!("expected MissingAttributeType, got {other}"),
            Ok(_) => panic!("missing da_type should fail"),
        }
    }
}
