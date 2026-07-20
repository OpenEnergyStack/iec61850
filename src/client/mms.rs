use crate::client::client::Transport;
use crate::client::error::Error;
use crate::client::types::DataReference;
use crate::types::{
    AddCause, AnalogueValue, BufferedReportControlBlock, CancelObject, CancelResponse, Check,
    ControlObject, ControlResponse, CtlVal, DataDefinition, DataType, EntryTime, IECData,
    OriginCategory, Originator, ReasonForInclusion, Report, ReportDataPoint, ReportMetadata,
    ReportOptFields, ReportType, SetBrcbValuesSettings, SetUrcbValuesSettings, Tcmd, TimeQuality,
    Timestamp, TriggerOptions, UnbufferedReportControlBlock, UnbufferedReportOptFields,
};
use async_trait::async_trait;
use mms::messages::iso_9506_mms_1::{AnonymousWriteResponse, TypeSpecification, UtcTime};
use mms::{
    client::{Client as MmsClient, TLSConfig},
    AccessResult, Data, TimeOfDay,
};
use mms::{
    AlternateAccess, AlternateAccessSelection, AlternateAccessSelectionSelectAccess,
    AlternateAccessSelectionSelectAlternateAccess,
    AlternateAccessSelectionSelectAlternateAccessAccessSelection, AnonymousAlternateAccess,
    AnonymousVariableAccessSpecificationListOfVariable, GetNameListRequestObjectScope,
    GetVariableAccessAttributesRequest, Identifier, ObjectClass, ObjectName,
    ObjectNameDomainSpecific, TypeDescription, TypeDescriptionStructure, Unsigned32,
    VariableAccessSpecification, VariableAccessSpecificationListOfVariable, VariableSpecification,
    VisibleString,
};
use std::time::Duration;
use Error::ParseError;

/// MMS error (field 2 in LastAppError) — only used for debug logging.
#[derive(Debug, Clone, Copy)]
enum CtlError {
    NoError = 0,
    Unknown = 1,
    TimeoutTestNotOk = 2,
    OperatorTestNotOk = 3,
}

impl CtlError {
    fn from_i64(v: i64) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::Unknown,
            2 => Self::TimeoutTestNotOk,
            3 => Self::OperatorTestNotOk,
            _ => Self::Unknown,
        }
    }
}

/// Decoded LastAppError information report — only used for debug logging.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct LastAppError {
    ctrl_obj: String,
    error: CtlError,
    origin: Originator,
    ctl_num: u8,
    add_cause: AddCause,
}

/// Converts MMS Data type to IEC 61850 IECData type
///
/// # Mapping Notes:
/// - `TimeOfDay` (binary-time) -> `Timestamp` (converted from MMS time format)
/// - `GeneralizedTime` -> `Timestamp` (parsed from ISO 8601 format)
/// - `booleanArray` -> `BitString` (packed boolean array)
/// - `objId` -> `VisibleString` (OID as string, rarely used in IEC 61850)
/// - `bcd` -> `Int` (BCD decoded to integer, not used in IEC 61850)
pub fn mms_data_to_iec(data: &Data) -> IECData {
    match data {
        Data::array(arr) => IECData::Array(arr.iter().map(mms_data_to_iec).collect()),
        Data::structure(structure) => {
            IECData::Structure(structure.iter().map(mms_data_to_iec).collect())
        }
        Data::boolean(b) => IECData::Boolean(*b),
        Data::bit_string(bits) => {
            let bytes = bits.as_raw_slice();
            let mut binary_string = String::new();
            for byte in bytes {
                binary_string.push_str(&format!("{:08b}", byte));
            }
            IECData::BitString(binary_string)
        }
        Data::integer(i) => IECData::Int(i64::try_from(i).unwrap_or(0)),
        Data::unsigned(u) => IECData::UInt(u64::try_from(u).unwrap_or(0)),
        Data::floating_point(fp) => {
            let bytes = fp.0.as_ref();
            // MMS FloatingPoint: first byte is format (0x08 = FLOAT32, 0x0B = FLOAT64)
            if bytes.len() == 5 && bytes[0] == 0x08 {
                let value = f32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                IECData::Float(value as f64)
            } else if bytes.len() == 9 && bytes[0] == 0x0B {
                let value = f64::from_be_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                IECData::Float(value)
            } else {
                IECData::Float(0.0)
            }
        }
        Data::octet_string(octets) => IECData::OctetString(hex::encode(octets.as_ref())),
        Data::visible_string(s) => IECData::VisibleString(s.to_string()),
        Data::generalized_time(gt) => IECData::Timestamp(generalized_time_to_timestamp(gt)),
        Data::binary_time(tod) => IECData::Timestamp(time_of_day_to_timestamp(tod)),
        Data::bcd(bcd_int) => IECData::Int(i64::try_from(bcd_int).unwrap_or(0)),
        Data::booleanArray(bits) => {
            let bytes = bits.as_raw_slice();
            let mut binary_string = String::new();
            for byte in bytes {
                binary_string.push_str(&format!("{:08b}", byte));
            }
            IECData::BitString(binary_string)
        }
        Data::objId(oid) => {
            let components: Vec<String> = oid.iter().map(|n| n.to_string()).collect();
            IECData::VisibleString(components.join("."))
        }
        Data::mMSString(mms_str) => IECData::MmsString(mms_str.0.to_string()),
        // Catch any future additions to the MMS Data enum
        Data::utc_time(uct_time) => IECData::Timestamp(utc_time_to_timestamp(uct_time)),
        _ => IECData::VisibleString("Unsupported MMS data type".to_string()),
    }
}

/// Converts IEC 61850 IECData type to MMS Data type
///
/// # Mapping Notes:
/// - `Array` -> MMS array of Data
/// - `Structure` -> MMS structure of Data
/// - `Boolean` -> MMS boolean
/// - `BitString` -> MMS bit_string (parsed from binary string representation)
/// - `Int` -> MMS integer
/// - `UInt` -> MMS unsigned
/// - `Float` -> MMS floating_point (64-bit double)
/// - `OctetString` -> MMS octet_string (hex decoded)
/// - `VisibleString` -> MMS visible_string
/// - `MmsString` -> MMS mMSString
/// - `Timestamp` -> MMS utc_time (8 bytes with seconds, fraction, and quality)
pub fn iec_data_to_mms(data: &IECData) -> Result<Data, Error> {
    match data {
        IECData::Array(arr) => {
            let mms_arr: Result<Vec<Data>, Error> = arr.iter().map(iec_data_to_mms).collect();
            mms_arr.map(Data::array)
        }
        IECData::Structure(structure) => {
            let mms_struct: Result<Vec<Data>, Error> =
                structure.iter().map(iec_data_to_mms).collect();
            mms_struct.map(Data::structure)
        }
        IECData::Boolean(b) => Ok(Data::boolean(*b)),
        IECData::BitString(bits) => {
            // Parse binary string to bytes
            let mut bytes = Vec::new();
            for chunk in bits.chars().collect::<Vec<_>>().chunks(8) {
                let byte_str: String = chunk.iter().collect();
                if byte_str.len() == 8 {
                    if let Ok(byte) = u8::from_str_radix(&byte_str, 2) {
                        bytes.push(byte);
                    } else {
                        return Err(Error::ParseError(
                            "Invalid bit string: contains non-binary characters".to_string(),
                        ));
                    }
                } else if !byte_str.is_empty() {
                    // Pad the last byte with zeros on the right
                    let padded = format!("{:<8}", byte_str).replace(' ', "0");
                    if let Ok(byte) = u8::from_str_radix(&padded, 2) {
                        bytes.push(byte);
                    }
                }
            }
            Ok(Data::bit_string(rasn::types::BitString::from_vec(bytes)))
        }
        IECData::Int(i) => {
            // Convert i64 to i128 for MMS integer
            Ok(Data::integer((*i).into()))
        }
        IECData::UInt(u) => {
            // Convert u64 to u128 for MMS unsigned
            Ok(Data::unsigned((*u).into()))
        }
        IECData::Float(f) => {
            // MMS FLOAT32: first byte = 0x08 (8-bit exponent, IEEE 754 single), then 4 data bytes
            let mut bytes = vec![0x08u8];
            bytes.extend_from_slice(&(*f as f32).to_be_bytes());
            Ok(Data::floating_point(mms::FloatingPoint(
                rasn::types::OctetString::from(bytes),
            )))
        }
        IECData::OctetString(hex_str) => {
            // Decode hex string to bytes
            match hex::decode(hex_str) {
                Ok(bytes) => Ok(Data::octet_string(rasn::types::OctetString::from(bytes))),
                Err(_) => Err(Error::ParseError(
                    "Invalid hex string in OctetString".to_string(),
                )),
            }
        }
        IECData::VisibleString(s) => match VisibleString::try_from(s.as_str()) {
            Ok(vs) => Ok(Data::visible_string(vs)),
            Err(_) => Err(Error::ParseError("Invalid visible string".to_string())),
        },
        IECData::MmsString(s) => match VisibleString::try_from(s.as_str()) {
            Ok(vs) => Ok(Data::mMSString(mms::MMSString(vs))),
            Err(_) => Err(Error::ParseError("Invalid MMS string".to_string())),
        },
        IECData::Timestamp(ts) => {
            // Convert Timestamp to UtcTime (8 bytes)
            let mut bytes = [0u8; 8];

            // Bytes 0-3: Seconds since Unix epoch (big-endian)
            bytes[0..4].copy_from_slice(&ts.seconds.to_be_bytes());

            // Bytes 4-6: 24-bit fraction of second (big-endian)
            let fraction_bytes = ts.fraction.to_be_bytes();
            bytes[4..7].copy_from_slice(&fraction_bytes[1..4]);

            // Byte 7: Time quality flags
            bytes[7] = ts.quality.to_byte();

            Ok(Data::utc_time(UtcTime(mms::FixedOctetString::from(bytes))))
        }
    }
}

/// Converts a named MMS type description into a [`DataDefinition`].
///
/// This is the primary entry point when processing a GetDataDefinition
/// service response: `name` is the element name from the response and
/// `type_description` carries the structural type information.
pub fn type_description_to_data_definition(
    name: String,
    type_description: &TypeDescription,
) -> DataDefinition {
    DataDefinition {
        name,
        data_type: type_description_to_data_type(type_description),
    }
}

/// Recursively maps a [`TypeDescription`] to the equivalent [`DataType`].
fn type_description_to_data_type(type_description: &TypeDescription) -> DataType {
    match type_description {
        TypeDescription::structure(struct_desc) => {
            DataType::Structure(get_structure_children(struct_desc))
        }
        TypeDescription::array(arr_desc) => {
            let count = arr_desc.number_of_elements.0;
            let element_type = match &arr_desc.element_type {
                TypeSpecification::typeDescription(td) => type_description_to_data_type(td),
                // Named type reference: not resolvable without a type dictionary;
                // treat as opaque visible string for now.
                _ => DataType::VisibleString,
            };
            DataType::Array {
                count,
                element_type: Box::new(element_type),
            }
        }
        TypeDescription::boolean(_) => DataType::Boolean,
        TypeDescription::bit_string(_) => DataType::BitString,
        TypeDescription::integer(_) => DataType::Int,
        TypeDescription::unsigned(_) => DataType::UInt,
        TypeDescription::floating_point(_) => DataType::Float,
        TypeDescription::octet_string(_) => DataType::OctetString,
        TypeDescription::visible_string(_) => DataType::VisibleString,
        TypeDescription::mMSString(_) => DataType::MmsString,
        // All time variants resolve to the unified Timestamp type
        TypeDescription::utc_time(_)
        | TypeDescription::generalized_time(_)
        | TypeDescription::binary_time(_) => DataType::Timestamp,
        // bcd and objId have no direct IEC 61850 equivalent; treat as opaque
        _ => DataType::VisibleString,
    }
}

/// Expands the components of an MMS structure type into a [`Vec<DataDefinition>`].
fn get_structure_children(struct_desc: &TypeDescriptionStructure) -> Vec<DataDefinition> {
    struct_desc
        .components
        .0
        .iter()
        .map(|component| {
            let name = component
                .component_name
                .as_ref()
                .map(|id| id.0.to_string())
                .unwrap_or_default();
            let data_type = match &component.component_type {
                TypeSpecification::typeDescription(td) => type_description_to_data_type(td),
                _ => DataType::VisibleString,
            };
            DataDefinition { name, data_type }
        })
        .collect()
}

/// Converts MMS GeneralizedTime to IEC 61850 Timestamp
fn generalized_time_to_timestamp(gt: &rasn::types::GeneralizedTime) -> Timestamp {
    use chrono::DateTime;

    let raw = gt.to_string();

    // First, try to parse the raw string in a tolerant way (replace space with 'T').
    let iso_like = raw.replace(' ', "T");
    if let Ok(dt) = DateTime::parse_from_rfc3339(&iso_like) {
        let timestamp = dt.timestamp() as u32;
        let nanos = dt.timestamp_subsec_nanos();
        let fraction = ((nanos as u64 * 16777216) / 1_000_000_000) as u32;
        return Timestamp {
            seconds: timestamp,
            fraction,
            quality: TimeQuality::default(),
        };
    }

    // Fallback: handle compact YYYYMMDDHHMMSS[.fff][Z] form.
    if raw.len() >= 14 && raw.chars().take(14).all(|c| c.is_ascii_digit()) {
        let iso_str = format!(
            "{}-{}-{}T{}:{}:{}{}",
            &raw[0..4],   // YYYY
            &raw[4..6],   // MM
            &raw[6..8],   // DD
            &raw[8..10],  // HH
            &raw[10..12], // MM
            &raw[12..14], // SS
            if raw.len() > 14 && raw.chars().nth(14) == Some('.') {
                let frac_end = raw[14..].find('Z').unwrap_or(raw.len() - 14) + 14;
                &raw[14..frac_end]
            } else {
                ""
            }
        );

        if let Ok(dt) = DateTime::parse_from_rfc3339(&format!("{}Z", iso_str.trim_end_matches('Z')))
        {
            let timestamp = dt.timestamp() as u32;
            let nanos = dt.timestamp_subsec_nanos();
            let fraction = ((nanos as u64 * 16777216) / 1_000_000_000) as u32;
            return Timestamp {
                seconds: timestamp,
                fraction,
                quality: TimeQuality::default(),
            };
        }
    }

    Timestamp {
        seconds: 0,
        fraction: 0,
        quality: TimeQuality {
            leap_second_known: false,
            clock_failure: true,
            clock_not_synchronized: true,
            time_accuracy: 31,
        },
    }
}

/// Converts MMS TimeOfDay to IEC 61850 Timestamp
fn time_of_day_to_timestamp(tod: &TimeOfDay) -> Timestamp {
    // TimeOfDay format (IEC 9506):
    // 4 bytes: milliseconds since midnight (0-86399999)
    // Optional 2 bytes: days since January 1, 1984

    let bytes = tod.0.as_ref();

    if bytes.len() >= 4 {
        let millis_since_midnight = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let mut days_since_1984 = 0u16;
        if bytes.len() >= 6 {
            days_since_1984 = u16::from_be_bytes([bytes[4], bytes[5]]);
        }

        // Convert to Unix timestamp
        // Days from Unix epoch (Jan 1, 1970) to Jan 1, 1984 = 5113 days
        const DAYS_1970_TO_1984: u32 = 5113;
        let total_days = days_since_1984 as u32 + DAYS_1970_TO_1984;
        let seconds_from_days = total_days * 86400;
        let seconds_from_millis = millis_since_midnight / 1000;
        let remaining_millis = millis_since_midnight % 1000;

        // Convert milliseconds to 24-bit fraction
        let fraction = ((remaining_millis as u64 * 16777216) / 1000) as u32;

        Timestamp {
            seconds: seconds_from_days + seconds_from_millis,
            fraction,
            quality: TimeQuality::default(),
        }
    } else {
        Timestamp {
            seconds: 0,
            fraction: 0,
            quality: TimeQuality {
                leap_second_known: false,
                clock_failure: true,
                clock_not_synchronized: true,
                time_accuracy: 31,
            },
        }
    }
}

pub fn utc_time_to_timestamp(utc: &UtcTime) -> Timestamp {
    let bytes = utc.0.as_ref();

    // Bytes 0-3: Seconds since Unix epoch (Jan 1, 1970)
    let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // Bytes 4-6: 24-bit fraction of second (0-16777215)
    let fraction = u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]]);

    // Byte 7: Time quality flags
    let quality = TimeQuality::from_byte(bytes[7]);

    Timestamp {
        seconds,
        fraction,
        quality,
    }
}

pub struct MmsTransport {
    client: MmsClient,
}

impl MmsTransport {
    pub async fn connect(
        host: &str,
        port: u16,
        timeout: Duration,
        tls_config: Option<TLSConfig>,
    ) -> Result<Self, Error> {
        // MMS-specific connection logic belongs HERE
        let mut mms_builder = MmsClient::builder();

        if let Some(tls) = tls_config {
            mms_builder = mms_builder.use_tls(tls);
        }

        let somesome = mms_builder.timeout_after(timeout).connect(host, port).await;

        println!("MMS connection result: {:?}", somesome);

        let client = somesome.map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        Ok(Self { client })
    }
}

// Parses client DataReferences into MMS VariableAccessSpecification
fn parse_references(
    data_references: &[DataReference],
) -> Result<VariableAccessSpecification, Error> {
    let mut variables = Vec::with_capacity(data_references.len());

    for data_reference in data_references {
        let fc = &data_reference.fc;
        let (domain_id, data_path) = parse_paths(data_reference)?;
        let data_object_path = &data_path[1..];

        let domain_object = ObjectNameDomainSpecific {
            domain_id: Identifier(VisibleString::try_from(domain_id).unwrap_or_default()),
            item_id: Identifier(
                VisibleString::try_from(build_item_id(fc, data_path.clone())).unwrap_or_default(),
            ),
        };
        let object_name = ObjectName::domain_specific(domain_object);

        let variable_specification = VariableSpecification::name(object_name);

        let list_of_variable = AnonymousVariableAccessSpecificationListOfVariable::new(
            variable_specification,
            build_alternate_access(fc, data_object_path.to_vec())?, // array mapped to alternate access see IEC 61850-8-1
        );

        variables.push(list_of_variable);
    }

    let list_of_variable = VariableAccessSpecificationListOfVariable(variables);
    Ok(VariableAccessSpecification::listOfVariable(
        list_of_variable,
    ))
}

fn parse_paths(data_reference: &DataReference) -> Result<(String, Vec<&str>), Error> {
    let parts: Vec<&str> = data_reference.reference.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::ParseError(format!(
            "Invalid reference format. Expected 'Domain/Path[FC]', found: {}",
            data_reference.reference
        )));
    }

    let domain_id = parts[0].to_string();
    let data_path = parts[1].split('.').collect::<Vec<&str>>();

    Ok((domain_id, data_path))
}

// return itemId for a given reference, e.g., "IED1/LLN0$ST$Val" -> "LLN0$ST$Val"
fn build_item_id(fc: &str, item_id_path: Vec<&str>) -> String {
    let logical_node = item_id_path[0];

    if is_array(&item_id_path) {
        return logical_node.to_string(); // For array itemId is simple logical node. Rest in the alternate access
    };

    let mut item_id = format!("{}${}", logical_node, fc);
    for part in &item_id_path[1..] {
        item_id.push('$');
        item_id.push_str(part);
    }

    item_id
}

// returns AlternateAccess for an IEC 61850 array reference in other case return None
fn build_alternate_access(
    fc: &str,
    item_id_path: Vec<&str>,
) -> Result<Option<AlternateAccess>, Error> {
    #[derive(Debug, Clone)]
    enum AccessElement {
        Component(String),
        Index(u32),
    }

    if !is_array(&item_id_path) {
        return Ok(None);
    };

    let mut elements = Vec::new();
    elements.push(AccessElement::Component(fc.to_string()));

    for segment in item_id_path {
        elements.extend(extract_array_index(segment)?);
    }

    fn extract_array_index(segment: &str) -> Result<Vec<AccessElement>, Error> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut chars = segment.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '(' => {
                    if !current.is_empty() {
                        parts.push(AccessElement::Component(current.clone()));
                        current.clear();
                    }

                    let mut idx = String::new();
                    for c in chars.by_ref() {
                        if c == ')' {
                            break;
                        }
                        idx.push(c);
                    }

                    if !idx.is_empty() {
                        let parsed = idx.parse::<u32>().map_err(|e| {
                            Error::ParseError(format!("Invalid array index '{}': {}", idx, e))
                        })?;
                        parts.push(AccessElement::Index(parsed));
                    }
                }
                _ => current.push(ch),
            }
        }

        if !current.is_empty() {
            parts.push(AccessElement::Component(current));
        }

        if parts.is_empty() {
            parts.push(AccessElement::Component(segment.to_string()));
        }

        Ok(parts)
    }

    fn alternate_access(elements: &[AccessElement]) -> Result<Option<AlternateAccess>, Error> {
        if elements.is_empty() {
            return Ok(None);
        }

        fn identifier(value: &str) -> Identifier {
            Identifier(VisibleString::try_from(value).unwrap_or_default())
        }

        fn to_select_access(element: &AccessElement) -> AlternateAccessSelectionSelectAccess {
            match element {
                AccessElement::Component(name) => {
                    AlternateAccessSelectionSelectAccess::component(identifier(name))
                }
                AccessElement::Index(idx) => {
                    AlternateAccessSelectionSelectAccess::index(Unsigned32(*idx))
                }
            }
        }

        fn to_select_alternate_access(
            element: &AccessElement,
        ) -> AlternateAccessSelectionSelectAlternateAccessAccessSelection {
            match element {
                AccessElement::Component(name) => {
                    AlternateAccessSelectionSelectAlternateAccessAccessSelection::component(
                        identifier(name),
                    )
                }
                AccessElement::Index(idx) => {
                    AlternateAccessSelectionSelectAlternateAccessAccessSelection::index(Unsigned32(
                        *idx,
                    ))
                }
            }
        }

        fn build_chain(elems: &[AccessElement]) -> AlternateAccessSelection {
            if elems.len() == 1 {
                return AlternateAccessSelection::selectAccess(to_select_access(&elems[0]));
            }

            let (first, rest) = elems.split_first().unwrap();
            let nested = build_chain(rest);
            let select_alt = AlternateAccessSelectionSelectAlternateAccess::new(
                to_select_alternate_access(first),
                AlternateAccess(vec![AnonymousAlternateAccess::unnamed(nested.clone())]),
            );

            AlternateAccessSelection::selectAlternateAccess(select_alt)
        }

        let selection = build_chain(elements);

        Ok(Some(AlternateAccess(vec![
            AnonymousAlternateAccess::unnamed(selection),
        ])))
    }

    let alternate_access = alternate_access(&elements);
    println!("Constructed alternate access: {:?}", alternate_access);
    alternate_access
}

// whether the reference contains an array access, e.g., "LLN0$DataSet1$Val(3)" or "LLN0$DataSet1$Val(3).SubData(2)"
fn is_array(item_id_path: &[&str]) -> bool {
    for segment in item_id_path {
        let mut seen_open = false;
        let mut has_digit = false;

        for ch in segment.chars() {
            match ch {
                '(' => {
                    seen_open = true;
                    has_digit = false;
                }
                ')' => {
                    if seen_open && has_digit {
                        return true;
                    }
                    seen_open = false;
                    has_digit = false;
                }
                c if seen_open && c.is_ascii_digit() => {
                    has_digit = true;
                }
                _ => {}
            }
        }
    }

    false
}

fn timestamp_to_utc_time(ts: &Timestamp) -> UtcTime {
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&ts.seconds.to_be_bytes());
    let fraction_bytes = ts.fraction.to_be_bytes();
    bytes[4..7].copy_from_slice(&fraction_bytes[1..4]);
    bytes[7] = ts.quality.to_byte();
    UtcTime(mms::FixedOctetString::from(bytes))
}

/// Builds the MMS Data structure shared by all control services.
/// When `check` is `Some`, it is appended as the final bit-string field
/// (Oper / SBOw). When `None`, it is omitted (Cancel).
fn ctl_fields_to_data(
    ctl_val: &CtlVal,
    oper_tm: Option<&Timestamp>,
    origin: &Originator,
    ctl_num: u8,
    t: &Timestamp,
    test: bool,
    check: Option<&Check>,
) -> Data {
    let mut fields: Vec<Data> = Vec::new();

    fields.push(match ctl_val {
        CtlVal::Bool(b) => Data::boolean(*b),
        CtlVal::Int(i) => Data::integer((*i as i64).into()),
        CtlVal::Analogue(av) => {
            let mut av_fields: Vec<Data> = Vec::new();
            if let Some(f) = av.f {
                av_fields.push(Data::floating_point(mms::FloatingPoint(
                    rasn::types::OctetString::from({
                        let mut b = vec![0x08u8];
                        b.extend_from_slice(&f.to_be_bytes());
                        b
                    }),
                )));
            }
            if let Some(i) = av.i {
                av_fields.push(Data::integer((i as i64).into()));
            }
            Data::structure(av_fields)
        }
        CtlVal::BinaryStep(s) => {
            // Tcmd is a 2-bit coded enum. Per ASN.1 DER canonical encoding, a
            // bit string must contain no trailing zero bits beyond the minimum
            // size required — exactly 2 bits here (unused-bits count = 6).
            let val = *s as u8;
            let mut bits = rasn::types::BitString::default();
            bits.push((val & 0x02) != 0); // MSB
            bits.push((val & 0x01) != 0); // LSB
            Data::bit_string(bits)
        }
    });

    if let Some(ts) = oper_tm {
        fields.push(Data::utc_time(timestamp_to_utc_time(ts)));
    }

    fields.push(Data::structure(vec![
        Data::integer((origin.or_cat as i64).into()),
        Data::octet_string(rasn::types::OctetString::from(origin.or_ident.clone())),
    ]));

    fields.push(Data::unsigned((ctl_num as u64).into()));
    fields.push(Data::utc_time(timestamp_to_utc_time(t)));
    fields.push(Data::boolean(test));

    if let Some(chk) = check {
        let bits_str = chk.to_bit_string();
        let mut bytes = Vec::new();
        for chunk in bits_str.as_bytes().chunks(8) {
            let padded = format!("{:<8}", std::str::from_utf8(chunk).unwrap_or("00000000"))
                .replace(' ', "0");
            if let Ok(byte) = u8::from_str_radix(&padded, 2) {
                bytes.push(byte);
            }
        }
        fields.push(Data::bit_string(rasn::types::BitString::from_vec(bytes)));
    }

    Data::structure(fields)
}

/// Builds the MMS Data structure for a `ControlObject` (Oper / SBOw).
fn control_object_to_data(obj: &ControlObject) -> Data {
    ctl_fields_to_data(
        &obj.ctl_val,
        obj.oper_tm.as_ref(),
        &obj.origin,
        obj.ctl_num,
        &obj.t,
        obj.test,
        Some(&obj.check),
    )
}

/// Builds the MMS Data structure for a `CancelObject` (Cancel — no Check field).
fn cancel_object_to_data(obj: &CancelObject) -> Data {
    ctl_fields_to_data(
        &obj.ctl_val,
        obj.oper_tm.as_ref(),
        &obj.origin,
        obj.ctl_num,
        &obj.t,
        obj.test,
        None,
    )
}

/// Shared client control logic for operate, select_with_value and timed_operate.
async fn control_write(
    client: &mms::client::Client,
    ctrl_obj: ControlObject,
    data: Data,
    service: &str,
) -> Result<ControlResponse, Error> {
    let ControlObject {
        ctrl_obj_ref,
        ctl_val,
        oper_tm,
        origin,
        ctl_num,
        t,
        test,
        check,
    } = ctrl_obj;
    let reference = DataReference {
        reference: format!("{}.{}", ctrl_obj_ref, service),
        fc: "CO".to_string(),
    };
    let variable = parse_references(&[reference])?;

    // Subscribe BEFORE the write so the LastAppError report (which arrives first) is buffered.
    let mut bcast = client.handle_unconfirmed();

    let write_results = client
        .write(variable, vec![data])
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    match write_results.into_iter().next() {
        Some(AnonymousWriteResponse::success(())) => {
            return Ok(ControlResponse {
                ctrl_obj_ref,
                ctl_val,
                oper_tm,
                origin,
                ctl_num,
                t,
                test,
                check,
                add_cause: None,
            });
        }
        Some(AnonymousWriteResponse::failure(e)) => e.0,
        None => return Err(ParseError("No write response received".into())),
    };

    // Try to receive the LastAppError info report that should already be buffered.
    let last_app_error = subscribe_last_appl_error(&mut bcast).await;

    let add_cause = last_app_error
        .as_ref()
        .map(|e| e.add_cause)
        .unwrap_or(AddCause::Unknown);

    Ok(ControlResponse {
        ctrl_obj_ref,
        ctl_val,
        oper_tm,
        origin,
        ctl_num,
        t,
        test,
        check,
        add_cause: Some(add_cause),
    })
}

/// Drains the unconfirmed broadcast channel looking for a `LastAppError` information
async fn subscribe_last_appl_error(
    bcast: &mut tokio::sync::broadcast::Receiver<mms::messages::iso_9506_mms_1::UnconfirmedService>,
) -> Option<LastAppError> {
    use mms::messages::iso_9506_mms_1::UnconfirmedService;

    let receive = async {
        loop {
            match bcast.recv().await {
                Ok(UnconfirmedService::informationReport(ir)) => {
                    if is_last_app_error_report(&ir.variable_access_specification) {
                        return parse_last_app_error(&ir.list_of_access_result);
                    }
                    // Not the LastAppError report — keep waiting within the timeout.
                    // Broadcast channels copy to all subscribers, so continuing here
                    // does not steal messages from other receivers.
                    continue;
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    };

    tokio::time::timeout(std::time::Duration::from_millis(50), receive)
        .await
        .unwrap_or(None)
}

/// Returns `true` when `spec` identifies a `LastApplError` information report.
fn is_last_app_error_report(spec: &VariableAccessSpecification) -> bool {
    fn is_last_appl_error_name(name: &ObjectName) -> bool {
        matches!(name, ObjectName::vmd_specific(id) if id.0.to_string() == "LastApplError")
    }
    match spec {
        VariableAccessSpecification::variableListName(name) => is_last_appl_error_name(name),
        VariableAccessSpecification::listOfVariable(list) => {
            list.0.len() == 1
                && matches!(&list.0[0].variable_specification,
                    VariableSpecification::name(n) if is_last_appl_error_name(n))
        }
    }
}

/// Parses the `list_of_access_result` of a `LastApplError` information report.
fn parse_last_app_error(results: &rasn::types::SequenceOf<AccessResult>) -> Option<LastAppError> {
    let fields = match results.first()? {
        AccessResult::success(Data::structure(s)) => s,
        other => {
            println!("LastApplError: unexpected AccessResult layout: {:?}", other);
            return None;
        }
    };

    if fields.len() < 5 {
        println!(
            "LastApplError: structure has {} fields, expected ≥5",
            fields.len()
        );
        return None;
    }

    let ctrl_obj = match &fields[0] {
        Data::visible_string(s) => s.to_string(),
        Data::mMSString(s) => s.0.to_string(),
        _ => return None,
    };

    let error = match &fields[1] {
        Data::integer(i) => CtlError::from_i64(i64::try_from(i).unwrap_or(0)),
        Data::unsigned(u) => CtlError::from_i64(u64::try_from(u).unwrap_or(0) as i64),
        _ => return None,
    };

    let origin = match &fields[2] {
        Data::structure(origin_fields) if origin_fields.len() >= 2 => {
            let or_cat = match &origin_fields[0] {
                Data::integer(i) => OriginCategory::from_i64(i64::try_from(i).unwrap_or(0)),
                Data::unsigned(u) => OriginCategory::from_i64(u64::try_from(u).unwrap_or(0) as i64),
                _ => OriginCategory::NotSupported,
            };
            let or_ident = match &origin_fields[1] {
                Data::octet_string(o) => o.as_ref().to_vec(),
                _ => vec![],
            };
            Originator { or_cat, or_ident }
        }
        _ => return None,
    };

    let ctl_num = match &fields[3] {
        Data::unsigned(u) => u64::try_from(u).unwrap_or(0) as u8,
        Data::integer(i) => i64::try_from(i).unwrap_or(0) as u8,
        _ => return None,
    };

    let add_cause = match &fields[4] {
        Data::integer(i) => AddCause::from_i64(i64::try_from(i).unwrap_or(0)),
        Data::unsigned(u) => AddCause::from_i64(u64::try_from(u).unwrap_or(0) as i64),
        _ => return None,
    };

    Some(LastAppError {
        ctrl_obj,
        error,
        origin,
        ctl_num,
        add_cause,
    })
}

#[async_trait]
impl Transport for MmsTransport {
    async fn get_data_values(&self, refs: Vec<DataReference>) -> Result<Vec<IECData>, Error> {
        let variable: VariableAccessSpecification = parse_references(&refs)?;

        let results = self
            .client
            .read(variable)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        println!("MMS read results: {:?}", results);

        if results.len() != refs.len() {
            return Err(Error::ParseError(format!(
                "Expected {} results, got {}",
                refs.len(),
                results.len()
            )));
        }

        let mut values = Vec::with_capacity(refs.len());

        for (idx, result) in results.into_iter().enumerate() {
            println!("MMS read result for idx {}: {:?}", idx, result);

            match result {
                AccessResult::success(data) => values.push(mms_data_to_iec(&data)),
                AccessResult::failure(_code) => {
                    return Err(Error::ParseError(format!(
                        "Access failed for reference index {}",
                        idx
                    )))
                }
            }
        }

        Ok(values)
    }

    async fn get_server_directory(&self) -> Result<Vec<String>, Error> {
        let object_class = ObjectClass::basicObjectClass(9);
        let object_scope = GetNameListRequestObjectScope::vmdSpecific(());

        let results = self
            .client
            .get_name_list(object_class, object_scope)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        Ok(results.iter().map(|s| s.0.to_string()).collect())
    }

    async fn get_logical_device_directory(&self, ld_name: String) -> Result<Vec<String>, Error> {
        let object_class = ObjectClass::basicObjectClass(0);
        let object_scope = GetNameListRequestObjectScope::domainSpecific(Identifier(
            VisibleString::try_from(ld_name).unwrap_or_default(),
        ));

        let results = self
            .client
            .get_name_list(object_class, object_scope)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        Ok(results.iter().map(|s| s.0.to_string()).collect())
    }

    async fn get_data_definition(&self, data_ref: DataReference) -> Result<DataDefinition, Error> {
        let fc = &data_ref.fc;
        // Extract the leaf name from the reference, e.g. "IED1/XCBR1.Pos" -> "Pos"
        let name = data_ref
            .reference
            .rsplit(['/', '.'])
            .next()
            .unwrap_or(&data_ref.reference)
            .to_string();

        let (domain_id, data_path) = parse_paths(&data_ref)?;

        let domain_object = ObjectNameDomainSpecific {
            domain_id: Identifier(VisibleString::try_from(domain_id).unwrap_or_default()),
            item_id: Identifier(
                VisibleString::try_from(build_item_id(fc, data_path.clone())).unwrap_or_default(),
            ),
        };
        let object_name = ObjectName::domain_specific(domain_object);

        let request = GetVariableAccessAttributesRequest::name(object_name);

        let result = self
            .client
            .get_variable_access_attributes(request)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        Ok(type_description_to_data_definition(
            name,
            &result.type_description,
        ))
    }

    async fn set_brcb_values(
        &self,
        brcb_ref: String,
        settings: SetBrcbValuesSettings,
    ) -> Result<Vec<Result<(), Error>>, Error> {
        let mut refs: Vec<DataReference> = Vec::new();
        let mut values: Vec<IECData> = Vec::new();

        macro_rules! push {
            ($attr:expr, $value:expr) => {
                refs.push(DataReference {
                    reference: format!("{}.{}", brcb_ref, $attr),
                    fc: "BR".to_string(),
                });
                values.push($value);
            };
        }

        if let Some(v) = settings.rpt_id {
            push!("RptID", IECData::VisibleString(v));
        }
        if let Some(v) = settings.dat_set {
            push!("DatSet", IECData::VisibleString(v));
        }
        if let Some(v) = settings.opt_flds {
            push!("OptFlds", IECData::BitString(v.to_bit_string()));
        }
        if let Some(v) = settings.buf_tm {
            push!("BufTm", IECData::UInt(v as u64));
        }
        if let Some(v) = settings.trg_ops {
            push!("TrgOps", IECData::BitString(v.to_bit_string()));
        }
        if let Some(v) = settings.intg_pd {
            push!("IntgPd", IECData::UInt(v as u64));
        }
        if let Some(v) = settings.gi {
            push!("GI", IECData::Boolean(v));
        }
        if let Some(v) = settings.purge_buf {
            push!("PurgeBuf", IECData::Boolean(v));
        }
        if let Some(v) = settings.entry_id {
            push!("EntryID", IECData::OctetString(hex::encode(v)));
        }
        if let Some(v) = settings.resv_tms {
            push!("ResvTms", IECData::Int(v as i64));
        }
        // RptEna is always the last value to be written. This ensures that all
        // other settings are applied before the report control block is enabled.
        if let Some(v) = settings.rpt_ena {
            push!("RptEna", IECData::Boolean(v));
        }

        if refs.is_empty() {
            return Err(Error::ParseError("No BRCB settings provided".into()));
        }

        let variable: VariableAccessSpecification = parse_references(&refs)?;
        let data: Result<Vec<Data>, Error> = values.iter().map(iec_data_to_mms).collect();
        let data = data?;

        println!("set_brcb_values variable: {:#?}", variable);
        println!("set_brcb_values data: {:#?}", data);

        let write_results = self
            .client
            .write(variable, data)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        println!("set_brcb_values result: {:#?}", write_results);

        let results: Vec<Result<(), Error>> = write_results
            .into_iter()
            .map(|r| match r {
                AnonymousWriteResponse::success(()) => Ok(()),
                AnonymousWriteResponse::failure(e) => Err(Error::DataAccessError(e.0)),
            })
            .collect();

        Ok(results)
    }

    async fn set_urcb_values(
        &self,
        urcb_ref: String,
        settings: SetUrcbValuesSettings,
    ) -> Result<Vec<Result<(), Error>>, Error> {
        let mut refs: Vec<DataReference> = Vec::new();
        let mut values: Vec<IECData> = Vec::new();

        macro_rules! push {
            ($attr:expr, $value:expr) => {
                refs.push(DataReference {
                    reference: format!("{}.{}", urcb_ref, $attr),
                    fc: "RP".to_string(),
                });
                values.push($value);
            };
        }

        if let Some(v) = settings.rpt_id {
            push!("RptID", IECData::VisibleString(v));
        }
        if let Some(v) = settings.dat_set {
            push!("DatSet", IECData::VisibleString(v));
        }
        if let Some(v) = settings.opt_flds {
            push!("OptFlds", IECData::BitString(v.to_bit_string()));
        }
        if let Some(v) = settings.buf_tm {
            push!("BufTm", IECData::UInt(v as u64));
        }
        if let Some(v) = settings.trg_ops {
            push!("TrgOps", IECData::BitString(v.to_bit_string()));
        }
        if let Some(v) = settings.intg_pd {
            push!("IntgPd", IECData::UInt(v as u64));
        }
        if let Some(v) = settings.gi {
            push!("GI", IECData::Boolean(v));
        }
        if let Some(v) = settings.resv {
            push!("Resv", IECData::Boolean(v));
        }
        // RptEna is always written last so all other settings are applied first.
        if let Some(v) = settings.rpt_ena {
            push!("RptEna", IECData::Boolean(v));
        }

        if refs.is_empty() {
            return Err(Error::ParseError("No URCB settings provided".into()));
        }

        let variable: VariableAccessSpecification = parse_references(&refs)?;
        let data: Result<Vec<Data>, Error> = values.iter().map(iec_data_to_mms).collect();
        let data = data?;

        let write_results = self
            .client
            .write(variable, data)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        let results: Vec<Result<(), Error>> = write_results
            .into_iter()
            .map(|r| match r {
                AnonymousWriteResponse::success(()) => Ok(()),
                AnonymousWriteResponse::failure(e) => Err(Error::DataAccessError(e.0)),
            })
            .collect();

        Ok(results)
    }
    async fn get_brcb_values(&self, brcb_ref: String) -> Result<BufferedReportControlBlock, Error> {
        let refs = vec![DataReference {
            reference: brcb_ref,
            fc: "BR".to_string(),
        }];
        let variable: VariableAccessSpecification = parse_references(&refs)?;

        let results = self
            .client
            .read(variable)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        let fields = match results.into_iter().next() {
            Some(AccessResult::success(data)) => match data {
                Data::structure(s) => s,
                _ => {
                    return Err(Error::ParseError(
                        "Expected structure response for BRCB".into(),
                    ))
                }
            },
            Some(AccessResult::failure(e)) => return Err(Error::DataAccessError(e.0)),
            None => return Err(Error::ParseError("Empty response for BRCB read".into())),
        };

        if fields.len() < 14 {
            return Err(Error::ParseError(format!(
                "Expected 14 or 15 structure fields, got {}",
                fields.len()
            )));
        }

        fn as_string(data: &Data, name: &'static str) -> Result<String, Error> {
            match data {
                Data::visible_string(s) => Ok(s.to_string()),
                Data::mMSString(s) => Ok(s.0.to_string()),
                _ => Err(Error::ParseError(format!("{name}: expected string"))),
            }
        }
        fn as_bool(data: &Data, name: &'static str) -> Result<bool, Error> {
            match data {
                Data::boolean(b) => Ok(*b),
                _ => Err(Error::ParseError(format!("{name}: expected bool"))),
            }
        }
        fn as_u32(data: &Data, name: &'static str) -> Result<u32, Error> {
            match data {
                Data::unsigned(u) => Ok(u64::try_from(u).unwrap_or(0) as u32),
                Data::integer(i) => Ok(i64::try_from(i).unwrap_or(0) as u32),
                _ => Err(Error::ParseError(format!("{name}: expected uint"))),
            }
        }
        fn as_i16(data: &Data, name: &'static str) -> Result<i16, Error> {
            match data {
                Data::integer(i) => Ok(i64::try_from(i).unwrap_or(0) as i16),
                Data::unsigned(u) => Ok(u64::try_from(u).unwrap_or(0) as i16),
                _ => Err(Error::ParseError(format!("{name}: expected int16"))),
            }
        }
        fn as_bytes(data: &Data, name: &'static str) -> Result<Vec<u8>, Error> {
            match data {
                Data::octet_string(octets) => Ok(octets.as_ref().to_vec()),
                _ => Err(Error::ParseError(format!("{name}: expected octet string"))),
            }
        }
        fn as_opt_flds(data: &Data) -> Result<ReportOptFields, Error> {
            match data {
                Data::bit_string(bits) => {
                    let s: String = bits
                        .as_raw_slice()
                        .iter()
                        .flat_map(|b| {
                            (0..8)
                                .rev()
                                .map(move |i| if b & (1 << i) != 0 { '1' } else { '0' })
                        })
                        .collect();
                    Ok(ReportOptFields::from_bit_string(&s))
                }
                _ => Err(Error::ParseError("OptFlds: expected bit string".into())),
            }
        }
        fn as_trg_ops(data: &Data) -> Result<TriggerOptions, Error> {
            match data {
                Data::bit_string(bits) => {
                    let s: String = bits
                        .as_raw_slice()
                        .iter()
                        .flat_map(|b| {
                            (0..8)
                                .rev()
                                .map(move |i| if b & (1 << i) != 0 { '1' } else { '0' })
                        })
                        .collect();
                    Ok(TriggerOptions::from_bit_string(&s))
                }
                _ => Err(Error::ParseError("TrgOps: expected bit string".into())),
            }
        }

        Ok(BufferedReportControlBlock {
            rpt_id: as_string(&fields[0], "RptID")?,
            rpt_ena: as_bool(&fields[1], "RptEna")?,
            dat_set: as_string(&fields[2], "DatSet")?,
            conf_rev: as_u32(&fields[3], "ConfRev")?,
            opt_flds: as_opt_flds(&fields[4])?,
            buf_tm: as_u32(&fields[5], "BufTm")?,
            sq_num: as_u32(&fields[6], "SqNum")?,
            trg_ops: as_trg_ops(&fields[7])?,
            intg_pd: as_u32(&fields[8], "IntgPd")?,
            gi: as_bool(&fields[9], "GI")?,
            purge_buf: as_bool(&fields[10], "PurgeBuf")?,
            entry_id: as_bytes(&fields[11], "EntryID")?,
            time_of_entry: match &fields[12] {
                Data::binary_time(t) => EntryTime(t.0.as_ref().to_vec()),
                other => {
                    return Err(Error::ParseError(format!(
                        "TimeOfEntry: expected binary_time, got: {other:#?}"
                    )))
                }
            },
            resv_tms: as_i16(&fields[13], "ResvTms")?,
            owner: if fields.len() > 14 {
                Some(as_bytes(&fields[14], "Owner")?)
            } else {
                None
            },
        })
    }

    async fn get_urcb_values(
        &self,
        urcb_ref: String,
    ) -> Result<UnbufferedReportControlBlock, Error> {
        let refs = vec![DataReference {
            reference: urcb_ref,
            fc: "RP".to_string(),
        }];
        let variable: VariableAccessSpecification = parse_references(&refs)?;

        let results = self
            .client
            .read(variable)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        let fields = match results.into_iter().next() {
            Some(AccessResult::success(data)) => match data {
                Data::structure(s) => s,
                _ => {
                    return Err(Error::ParseError(
                        "Expected structure response for URCB".into(),
                    ))
                }
            },
            Some(AccessResult::failure(e)) => return Err(Error::DataAccessError(e.0)),
            None => return Err(Error::ParseError("Empty response for URCB read".into())),
        };

        // URCB has 11 mandatory fields + optional Owner = 11 or 12
        if fields.len() < 11 {
            for (i, f) in fields.iter().enumerate() {
                println!("  [{i}]: {f:#?}");
            }
            return Err(Error::ParseError(format!(
                "Expected 11 or 12 structure fields for URCB, got {}",
                fields.len()
            )));
        }

        fn as_string(data: &Data, name: &'static str) -> Result<String, Error> {
            match data {
                Data::visible_string(s) => Ok(s.to_string()),
                Data::mMSString(s) => Ok(s.0.to_string()),
                _ => Err(Error::ParseError(format!("{name}: expected string"))),
            }
        }
        fn as_bool(data: &Data, name: &'static str) -> Result<bool, Error> {
            match data {
                Data::boolean(b) => Ok(*b),
                _ => Err(Error::ParseError(format!("{name}: expected bool"))),
            }
        }
        fn as_u32(data: &Data, name: &'static str) -> Result<u32, Error> {
            match data {
                Data::unsigned(u) => Ok(u64::try_from(u).unwrap_or(0) as u32),
                Data::integer(i) => Ok(i64::try_from(i).unwrap_or(0) as u32),
                _ => Err(Error::ParseError(format!("{name}: expected uint"))),
            }
        }
        fn as_bytes(data: &Data, name: &'static str) -> Result<Vec<u8>, Error> {
            match data {
                Data::octet_string(octets) => Ok(octets.as_ref().to_vec()),
                _ => Err(Error::ParseError(format!("{name}: expected octet string"))),
            }
        }
        fn as_urcb_opt_flds(data: &Data) -> Result<UnbufferedReportOptFields, Error> {
            match data {
                Data::bit_string(bits) => {
                    let s: String = bits
                        .as_raw_slice()
                        .iter()
                        .flat_map(|b| {
                            (0..8)
                                .rev()
                                .map(move |i| if b & (1 << i) != 0 { '1' } else { '0' })
                        })
                        .collect();
                    Ok(UnbufferedReportOptFields::from_bit_string(&s))
                }
                _ => Err(Error::ParseError("OptFlds: expected bit string".into())),
            }
        }
        fn as_trg_ops(data: &Data) -> Result<TriggerOptions, Error> {
            match data {
                Data::bit_string(bits) => {
                    let s: String = bits
                        .as_raw_slice()
                        .iter()
                        .flat_map(|b| {
                            (0..8)
                                .rev()
                                .map(move |i| if b & (1 << i) != 0 { '1' } else { '0' })
                        })
                        .collect();
                    Ok(TriggerOptions::from_bit_string(&s))
                }
                _ => Err(Error::ParseError("TrgOps: expected bit string".into())),
            }
        }

        // URCB field order: RptID, RptEna, Resv, DatSet, ConfRev, OptFlds,
        //                   BufTm, SqNum, TrgOps, IntgPd, GI, [Owner]
        Ok(UnbufferedReportControlBlock {
            rpt_id: as_string(&fields[0], "RptID")?,
            rpt_ena: as_bool(&fields[1], "RptEna")?,
            resv: as_bool(&fields[2], "Resv")?,
            dat_set: as_string(&fields[3], "DatSet")?,
            conf_rev: as_u32(&fields[4], "ConfRev")?,
            opt_flds: as_urcb_opt_flds(&fields[5])?,
            buf_tm: as_u32(&fields[6], "BufTm")?,
            sq_num: as_u32(&fields[7], "SqNum")?,
            trg_ops: as_trg_ops(&fields[8])?,
            intg_pd: as_u32(&fields[9], "IntgPd")?,
            gi: as_bool(&fields[10], "GI")?,
            owner: if fields.len() > 11 {
                Some(as_bytes(&fields[11], "Owner")?)
            } else {
                None
            },
        })
    }

    fn subscribe_reports(
        &self,
        control_block_ref: String,
        rpt_id: String,
        report_type: ReportType,
    ) -> tokio::sync::mpsc::Receiver<Report> {
        use mms::messages::iso_9506_mms_1::UnconfirmedService;

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let mut bcast = self.client.handle_unconfirmed();

        tokio::spawn(async move {
            loop {
                let msg = match bcast.recv().await {
                    Ok(m) => m,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                let UnconfirmedService::informationReport(ir) = msg else {
                    continue;
                };

                // The list_of_access_result is the flat list of all report fields
                let fields: Vec<&Data> = ir
                    .list_of_access_result
                    .iter()
                    .filter_map(|ar| {
                        if let AccessResult::success(d) = ar {
                            Some(d)
                        } else {
                            None
                        }
                    })
                    .collect();

                if fields.len() < 2 {
                    continue;
                }

                // --- Part 1: Header fields ---

                // Field 0: RptID (VisibleString, always present)
                let report_rpt_id = match &fields[0] {
                    Data::visible_string(s) => s.to_string(),
                    Data::mMSString(s) => s.0.to_string(),
                    other => {
                        let _ = other;
                        continue;
                    }
                };

                // Filter: only process reports matching the requested RptID
                if report_rpt_id != rpt_id {
                    continue;
                }

                // Field 1: OptFlds (BitString, always present)
                let opt_flds = match &fields[1] {
                    Data::bit_string(bits) => {
                        let s: String = bits.iter().map(|b| if *b { '1' } else { '0' }).collect();
                        ReportOptFields::from_bit_string(&s)
                    }
                    other => {
                        let _ = other;
                        continue;
                    }
                };

                let mut idx = 2usize;

                let seq_num = if opt_flds.sequence_number {
                    let v = match fields.get(idx) {
                        Some(Data::unsigned(u)) => u32::try_from(u).ok(),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                let time_stamp = if opt_flds.report_time_stamp {
                    let v = match fields.get(idx) {
                        Some(Data::binary_time(t)) => time_of_day_to_timestamp(t),
                        other => {
                            let _ = other;
                            continue;
                        }
                    };
                    idx += 1;
                    Some(v)
                } else {
                    None
                };

                let dat_set = if opt_flds.data_set_name {
                    let v = match fields.get(idx) {
                        Some(Data::visible_string(s)) => Some(s.to_string()),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                let buf_ovfl = if opt_flds.buffer_overflow {
                    let v = match fields.get(idx) {
                        Some(Data::boolean(b)) => Some(*b),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                let entry_id = if opt_flds.entry_id {
                    let v = match fields.get(idx) {
                        Some(Data::octet_string(o)) => Some(EntryTime(o.as_ref().to_vec())),
                        Some(Data::binary_time(t)) => Some(EntryTime(t.0.as_ref().to_vec())),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                let conf_rev = if opt_flds.conf_revision {
                    let v = match fields.get(idx) {
                        Some(Data::unsigned(u)) => u32::try_from(u).ok(),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                let sub_seq_num = if opt_flds.segmentation {
                    let v = match fields.get(idx) {
                        Some(Data::unsigned(u)) => u32::try_from(u).ok(),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                let more_segments_follow = if opt_flds.segmentation {
                    let v = match fields.get(idx) {
                        Some(Data::boolean(b)) => Some(*b),
                        _ => None,
                    };
                    idx += 1;
                    v
                } else {
                    None
                };

                // Inclusion bitstring (always present) — each set bit means that
                // dataset member is included in this report
                let n = match fields.get(idx) {
                    Some(Data::bit_string(bits)) => {
                        idx += 1;
                        bits.iter().filter(|b| **b).count()
                    }
                    other => {
                        let _ = other;
                        continue;
                    }
                };

                // --- Part 2: Data references (one per included member, if enabled) ---
                let mut data_refs: Vec<Option<String>> = Vec::with_capacity(n);
                if opt_flds.data_reference {
                    for _ in 0..n {
                        let r = match fields.get(idx) {
                            Some(Data::visible_string(s)) => Some(s.to_string()),
                            _ => None,
                        };
                        data_refs.push(r);
                        idx += 1;
                    }
                } else {
                    data_refs.resize(n, None);
                }

                // --- Part 3: Data values (one per included member) ---
                let mut values: Vec<IECData> = Vec::with_capacity(n);
                for _ in 0..n {
                    if let Some(field) = fields.get(idx) {
                        values.push(mms_data_to_iec(field));
                    }
                    idx += 1;
                }

                // --- Part 4: Reason codes (one per included member, if enabled) ---
                let mut reasons: Vec<Option<ReasonForInclusion>> = Vec::with_capacity(n);
                if opt_flds.reason_for_inclusion {
                    for _ in 0..n {
                        let reason = match fields.get(idx) {
                            Some(Data::bit_string(bits)) => {
                                let byte = bits.as_raw_slice().first().copied().unwrap_or(0);
                                Some(ReasonForInclusion::from_byte(byte))
                            }
                            _ => None,
                        };
                        reasons.push(reason);
                        idx += 1;
                    }
                } else {
                    reasons.resize(n, None);
                }

                // Combine into data points
                let data: Vec<ReportDataPoint> = data_refs
                    .into_iter()
                    .zip(values)
                    .zip(reasons)
                    .map(|((data_reference, value), reason)| ReportDataPoint {
                        data_reference,
                        value,
                        reason,
                    })
                    .collect();

                let report = Report {
                    metadata: ReportMetadata {
                        report_type: report_type.clone(),
                        control_block_ref: control_block_ref.clone(),
                        rpt_id: report_rpt_id,
                        opt_flds,
                        seq_num,
                        time_stamp,
                        dat_set,
                        buf_ovfl,
                        entry_id,
                        conf_rev,
                        sub_seq_num,
                        more_segments_follow,
                    },
                    data,
                };

                if tx.send(report).await.is_err() {
                    break;
                }
            }
        });

        rx
    }

    async fn select(&self, ctrl_obj_ref: String) -> Result<(), Error> {
        let refs = parse_references(&[DataReference {
            reference: format!("{}.SBO", ctrl_obj_ref),
            fc: "CO".to_string(),
        }])?;
        let results = self
            .client
            .read(refs)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
        match results.into_iter().next() {
            Some(AccessResult::success(_)) => Ok(()),
            Some(AccessResult::failure(e)) => Err(Error::DataAccessError(e.0)),
            None => Err(Error::ParseError("select: empty response".into())),
        }
    }

    async fn operate(&self, ctrl_obj: ControlObject) -> Result<ControlResponse, Error> {
        let data = control_object_to_data(&ctrl_obj);
        control_write(&self.client, ctrl_obj, data, "Oper").await
    }

    async fn select_with_value(&self, ctrl_obj: ControlObject) -> Result<ControlResponse, Error> {
        let data = control_object_to_data(&ctrl_obj);
        control_write(&self.client, ctrl_obj, data, "SBOw").await
    }

    async fn cancel(&self, ctrl_obj: CancelObject) -> Result<CancelResponse, Error> {
        let data = cancel_object_to_data(&ctrl_obj);
        let ctrl_obj_ref = ctrl_obj.ctrl_obj_ref;
        let reference = DataReference {
            reference: format!("{}.Cancel", ctrl_obj_ref),
            fc: "CO".to_string(),
        };
        let variable = parse_references(&[reference])?;

        let mut bcast = self.client.handle_unconfirmed();

        let write_results = self
            .client
            .write(variable, vec![data])
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        match write_results.into_iter().next() {
            Some(AnonymousWriteResponse::success(())) => {
                return Ok(CancelResponse {
                    ctrl_obj_ref,
                    ctl_val: ctrl_obj.ctl_val,
                    oper_tm: ctrl_obj.oper_tm,
                    origin: ctrl_obj.origin,
                    ctl_num: ctrl_obj.ctl_num,
                    t: ctrl_obj.t,
                    test: ctrl_obj.test,
                    add_cause: None,
                });
            }
            Some(AnonymousWriteResponse::failure(e)) => e.0,
            None => return Err(Error::ParseError("No write response received".into())),
        };

        let last_app_error = subscribe_last_appl_error(&mut bcast).await;

        let add_cause = last_app_error
            .as_ref()
            .map(|e| e.add_cause)
            .unwrap_or(AddCause::Unknown);

        Ok(CancelResponse {
            ctrl_obj_ref,
            ctl_val: ctrl_obj.ctl_val,
            oper_tm: ctrl_obj.oper_tm,
            origin: ctrl_obj.origin,
            ctl_num: ctrl_obj.ctl_num,
            t: ctrl_obj.t,
            test: ctrl_obj.test,
            add_cause: Some(add_cause),
        })
    }

    fn subscribe_command_termination(
        &self,
        ctrl_obj_ref: String,
    ) -> tokio::sync::mpsc::Receiver<Result<ControlResponse, Error>> {
        use mms::messages::iso_9506_mms_1::UnconfirmedService;

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut bcast = self.client.handle_unconfirmed();

        tokio::spawn(async move {
            // Derive the MMS domain and Oper item ID from the IEC 61850 reference.
            // e.g. "IEDLD/CSWI1.Pos" → domain="IEDLD", item_id="CSWI1$CO$Pos$Oper"
            let Some((expected_domain, expected_item_id)) =
                ctrl_obj_ref.split_once('/').and_then(|(domain, path)| {
                    let parts: Vec<&str> = path.split('.').collect();
                    if parts.is_empty() {
                        return None;
                    }
                    let mut item_id = format!("{}$CO", parts[0]);
                    for part in &parts[1..] {
                        item_id.push('$');
                        item_id.push_str(part);
                    }
                    item_id.push_str("$Oper");
                    Some((domain.to_string(), item_id))
                })
            else {
                return;
            };

            loop {
                let msg = match bcast.recv().await {
                    Ok(m) => m,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        println!("CommandTermination listener: lagged by {} messages", n);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                let UnconfirmedService::informationReport(ir) = msg else {
                    continue;
                };

                // Check if the report is a CommandTermination for this control object.
                // Positive CT: only the Oper variable is listed.
                // Negative CT: both LastApplError (vmd-specific) and Oper are listed.
                let positive = {
                    let list = match &ir.variable_access_specification {
                        VariableAccessSpecification::listOfVariable(v) => &v.0,
                        _ => continue,
                    };
                    let mut has_last_appl_error = false;
                    let mut has_oper_match = false;
                    for entry in list {
                        match &entry.variable_specification {
                            VariableSpecification::name(ObjectName::vmd_specific(id))
                                if id.0.to_string() == "LastApplError" =>
                            {
                                has_last_appl_error = true;
                            }
                            VariableSpecification::name(ObjectName::domain_specific(ds))
                                if ds.domain_id.0.to_string() == expected_domain
                                    && ds.item_id.0.to_string() == expected_item_id =>
                            {
                                has_oper_match = true;
                            }
                            _ => {}
                        }
                    }
                    if !has_oper_match {
                        continue;
                    }
                    !has_last_appl_error
                };

                // The Oper AccessResult is always the last success structure.
                // Positive CT: single entry (6 fields).
                // Negative CT: two entries — LastApplError first, Oper last (7 fields).
                let Some(fields) = ir.list_of_access_result.iter().rev().find_map(|ar| {
                    if let AccessResult::success(Data::structure(s)) = ar {
                        Some(s.as_slice())
                    } else {
                        None
                    }
                }) else {
                    if tx
                        .send(Err(Error::ParseError(
                            "CommandTermination: no Oper structure in access results".into(),
                        )))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                };

                // Parse the Oper structure fields: ctlVal, origin, ctlNum, T, Test, Check.
                if fields.len() < 6 {
                    if tx
                        .send(Err(Error::ParseError(format!(
                            "CommandTermination: Oper structure has {} fields, expected >=6",
                            fields.len()
                        ))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let ctl_val: CtlVal = match &fields[0] {
                    Data::boolean(b) => CtlVal::Bool(*b),
                    Data::integer(i) => CtlVal::Int(i64::try_from(i).unwrap_or(0) as i32),
                    Data::unsigned(u) => CtlVal::Int(u64::try_from(u).unwrap_or(0) as i32),
                    Data::bit_string(bits) => {
                        let b0 = bits.iter().next().map(|b| *b).unwrap_or(false);
                        let b1 = bits.iter().nth(1).map(|b| *b).unwrap_or(false);
                        let step = match (b0 as u8) << 1 | (b1 as u8) {
                            0 => Tcmd::Stop,
                            1 => Tcmd::Lower,
                            2 => Tcmd::Higher,
                            _ => Tcmd::Reserved,
                        };
                        CtlVal::BinaryStep(step)
                    }
                    Data::structure(s) => {
                        let mut av = AnalogueValue::default();
                        for elem in s.iter() {
                            match elem {
                                Data::floating_point(fp) => {
                                    let bytes = fp.0.as_ref();
                                    if bytes.len() == 5 && bytes[0] == 0x08 {
                                        av.f = Some(f32::from_be_bytes([
                                            bytes[1], bytes[2], bytes[3], bytes[4],
                                        ]));
                                    }
                                }
                                Data::integer(i) => {
                                    av.i = Some(i64::try_from(i).unwrap_or(0) as i32);
                                }
                                _ => {}
                            }
                        }
                        CtlVal::Analogue(av)
                    }
                    _ => {
                        if tx
                            .send(Err(Error::ParseError(
                                "CommandTermination: unexpected ctlVal data type".into(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let origin = match &fields[1] {
                    Data::structure(s) if s.len() >= 2 => {
                        let or_cat = match &s[0] {
                            Data::integer(i) => {
                                OriginCategory::from_i64(i64::try_from(i).unwrap_or(0))
                            }
                            Data::unsigned(u) => {
                                OriginCategory::from_i64(u64::try_from(u).unwrap_or(0) as i64)
                            }
                            _ => OriginCategory::NotSupported,
                        };
                        let or_ident = match &s[1] {
                            Data::octet_string(o) => o.as_ref().to_vec(),
                            _ => vec![],
                        };
                        Originator { or_cat, or_ident }
                    }
                    _ => {
                        if tx
                            .send(Err(Error::ParseError(
                                "CommandTermination: unexpected origin data type".into(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let ctl_num = match &fields[2] {
                    Data::unsigned(u) => u64::try_from(u).unwrap_or(0) as u8,
                    Data::integer(i) => i64::try_from(i).unwrap_or(0) as u8,
                    _ => {
                        if tx
                            .send(Err(Error::ParseError(
                                "CommandTermination: unexpected ctlNum data type".into(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let t = match &fields[3] {
                    Data::utc_time(ut) => utc_time_to_timestamp(ut),
                    _ => {
                        if tx
                            .send(Err(Error::ParseError(
                                "CommandTermination: unexpected T (timestamp) data type".into(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let test = match &fields[4] {
                    Data::boolean(b) => *b,
                    _ => {
                        if tx
                            .send(Err(Error::ParseError(
                                "CommandTermination: unexpected Test data type".into(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let check = match &fields[5] {
                    Data::bit_string(bits) => {
                        let synchrocheck = bits.iter().next().map(|b| *b).unwrap_or(false);
                        let interlock_check = bits.iter().nth(1).map(|b| *b).unwrap_or(false);
                        Check {
                            synchrocheck,
                            interlock_check,
                        }
                    }
                    _ => {
                        if tx
                            .send(Err(Error::ParseError(
                                "CommandTermination: unexpected Check data type".into(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };

                let add_cause = if positive {
                    None
                } else {
                    Some(match fields.get(6) {
                        Some(Data::integer(i)) => AddCause::from_i64(i64::try_from(i).unwrap_or(0)),
                        Some(Data::unsigned(u)) => {
                            AddCause::from_i64(u64::try_from(u).unwrap_or(0) as i64)
                        }
                        _ => AddCause::Unknown,
                    })
                };

                let ct = ControlResponse {
                    ctrl_obj_ref: ctrl_obj_ref.clone(),
                    ctl_val,
                    oper_tm: None,
                    origin,
                    ctl_num,
                    t,
                    test,
                    check,
                    add_cause,
                };

                if tx.send(Ok(ct)).await.is_err() {
                    break;
                }
            }
        });

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::types::DataReference;
    use rasn::types::{OctetString, SequenceOf};

    fn unwrap_item_id(spec: &VariableAccessSpecification) -> String {
        match spec {
            VariableAccessSpecification::listOfVariable(list) => {
                let first = list.0.get(0).expect("expected at least one variable");

                match &first.variable_specification {
                    VariableSpecification::name(object_name) => {
                        if let ObjectName::domain_specific(ds) = object_name {
                            return ds.item_id.0.to_string();
                        }
                        panic!("unexpected object name variant");
                    }
                    _ => panic!("unexpected variable specification variant"),
                }
            }
            _ => panic!("unexpected variable access spec variant"),
        }
    }

    #[test]
    fn mms_data_to_iec_basic_scalars() {
        // boolean
        assert_eq!(
            mms_data_to_iec(&Data::boolean(true)),
            IECData::Boolean(true)
        );

        // integer
        assert_eq!(
            mms_data_to_iec(&Data::integer(5i64.into())),
            IECData::Int(5)
        );

        // unsigned
        assert_eq!(
            mms_data_to_iec(&Data::unsigned(7u64.into())),
            IECData::UInt(7)
        );

        // visible string
        let vis = mms::VisibleString::try_from("abc").unwrap();
        assert_eq!(
            mms_data_to_iec(&Data::visible_string(vis)),
            IECData::VisibleString("abc".to_string())
        );

        // octet string -> hex
        let oct = OctetString::from(vec![0xDE, 0xAD]);
        assert_eq!(
            mms_data_to_iec(&Data::octet_string(oct)),
            IECData::OctetString("dead".to_string())
        );
    }

    #[test]
    fn mms_data_to_iec_float_array_structure() {
        // 4-byte float for 3.0f
        let fp4 = mms::FloatingPoint(OctetString::from(vec![0x08, 0x40, 0x40, 0x00, 0x00]));
        match mms_data_to_iec(&Data::floating_point(fp4)) {
            IECData::Float(v) => assert!((v - 3.0).abs() < 1e-6),
            other => panic!("expected float, got {:?}", other),
        }

        // array of booleans
        let arr = SequenceOf::from(vec![Data::boolean(true), Data::boolean(false)]);
        match mms_data_to_iec(&Data::array(arr)) {
            IECData::Array(values) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0], IECData::Boolean(true));
                assert_eq!(values[1], IECData::Boolean(false));
            }
            other => panic!("expected array, got {:?}", other),
        }

        // structure of ints
        let s = SequenceOf::from(vec![Data::integer(1i64.into()), Data::integer(2i64.into())]);
        match mms_data_to_iec(&Data::structure(s)) {
            IECData::Structure(values) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0], IECData::Int(1));
                assert_eq!(values[1], IECData::Int(2));
            }
            other => panic!("expected structure, got {:?}", other),
        }
    }

    #[test]
    fn mms_data_to_iec_time_conversions() {
        // binary_time (TimeOfDay) -> Timestamp
        let tod_bytes = vec![0x00, 0x01, 0xE2, 0x40]; // 123,456 ms since midnight
        let tod = TimeOfDay(OctetString::from(tod_bytes));
        match mms_data_to_iec(&Data::binary_time(tod)) {
            IECData::Timestamp(ts) => {
                // 123456 ms = 123s, fraction from remaining millis
                assert_eq!(ts.seconds % 86400, 123);
                assert!(ts.fraction > 0);
            }
            other => panic!("expected timestamp, got {:?}", other),
        }

        // utc_time -> Timestamp
        let utc_bytes = [0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x00];
        let utc = UtcTime(mms::FixedOctetString::from(utc_bytes));
        match mms_data_to_iec(&Data::utc_time(utc)) {
            IECData::Timestamp(ts) => {
                assert_eq!(ts.seconds, 100);
                assert_eq!(ts.fraction, 0x000001);
            }
            other => panic!("expected timestamp, got {:?}", other),
        }

        // generalized_time -> Timestamp
        let dt = chrono::DateTime::parse_from_rfc3339("2023-01-01T12:00:00Z")
            .expect("valid datetime")
            .with_timezone(&chrono::Utc);
        let gt_str = rasn::types::GeneralizedTime::from(dt);

        match mms_data_to_iec(&Data::generalized_time(gt_str)) {
            IECData::Timestamp(ts) => {
                assert_eq!(ts.quality.clock_failure, true);
            }
            other => panic!("expected timestamp, got {:?}", other),
        }
    }

    #[test]
    fn parse_references_accepts_valid_non_array() {
        let refs = vec![DataReference {
            reference: "IED1/LLN0.Mod.stVal".to_string(),
            fc: "ST".to_string(),
        }];

        let spec = parse_references(&refs).expect("should parse non-array reference");

        let item_id = unwrap_item_id(&spec);
        assert_eq!(item_id, "LLN0$ST$Mod$stVal");

        let alternate = unwrap_alternate_access(&spec);
        assert!(
            alternate.is_none(),
            "non-array should not build alternate access"
        );
    }

    #[test]
    fn parse_references_rejects_invalid_format() {
        let refs = vec![DataReference {
            reference: "IED1.LLN0.Mod.stVal".to_string(), // missing '/'
            fc: "ST".to_string(),
        }];

        let err = parse_references(&refs).expect_err("invalid format should fail");
        match err {
            Error::ParseError(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn parse_references_builds_alternate_access_for_array() {
        let refs = vec![DataReference {
            reference: "IEDIED/MHAI1.HA.phsAHar(7).cVal.mag.f".to_string(),
            fc: "MX".to_string(),
        }];

        let spec = parse_references(&refs).expect("should parse array reference");

        let item_id = unwrap_item_id(&spec);
        assert_eq!(
            item_id, "MHAI1",
            "array item id should be logical node only"
        );

        let alternate = unwrap_alternate_access(&spec).expect("alternate access expected");

        let mut indices = Vec::new();
        collect_indices_from_alternate(&alternate, &mut indices);
        assert!(indices.contains(&7), "expected index 7 in alternate access");
    }

    fn unwrap_alternate_access(spec: &VariableAccessSpecification) -> Option<AlternateAccess> {
        match spec {
            VariableAccessSpecification::listOfVariable(list) => {
                let first = list.0.get(0).expect("expected at least one variable");
                first.alternate_access.clone()
            }
            _ => None,
        }
    }

    fn collect_indices_from_alternate(alternate: &AlternateAccess, out: &mut Vec<u32>) {
        for entry in &alternate.0 {
            if let AnonymousAlternateAccess::unnamed(selection) = entry {
                collect_indices_from_selection(selection, out);
            }
        }
    }

    fn collect_indices_from_selection(selection: &AlternateAccessSelection, out: &mut Vec<u32>) {
        match selection {
            AlternateAccessSelection::selectAccess(sa) => {
                if let AlternateAccessSelectionSelectAccess::index(idx) = sa {
                    out.push(idx.0);
                }
            }
            AlternateAccessSelection::selectAlternateAccess(sa) => {
                match &sa.access_selection {
                    AlternateAccessSelectionSelectAlternateAccessAccessSelection::index(idx) => {
                        out.push(idx.0);
                    }
                    _ => {}
                }

                for entry in &sa.alternate_access.0 {
                    if let AnonymousAlternateAccess::unnamed(next) = entry {
                        collect_indices_from_selection(next, out);
                    }
                }
            }
        }
    }
}
