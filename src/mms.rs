use crate::client::{DataReference, Error, Transport};
use crate::types::{IECData, TimeQuality, Timestamp};
use async_trait::async_trait;
use mms::messages::iso_9506_mms_1::UtcTime;
use mms::{
    client::{Client as MmsClient, TLSConfig},
    AccessResult, Data, TimeOfDay,
};
use mms::{
    AlternateAccess, AlternateAccessSelection, AlternateAccessSelectionSelectAccess,
    AlternateAccessSelectionSelectAlternateAccess,
    AlternateAccessSelectionSelectAlternateAccessAccessSelection, AnonymousAlternateAccess,
    AnonymousVariableAccessSpecificationListOfVariable, GetNameListRequestObjectScope, Identifier,
    ObjectClass, ObjectName, ObjectNameDomainSpecific, Unsigned32, VariableAccessSpecification,
    VariableAccessSpecificationListOfVariable, VariableSpecification, VisibleString,
};
use std::time::Duration;

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
            if bytes.len() == 4 {
                let value = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                IECData::Float(value as f64)
            } else if bytes.len() == 8 {
                let value = f64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
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
        let parts: Vec<&str> = data_reference.reference.split('/').collect();
        if parts.len() != 2 {
            return Err(Error::ParseError(format!(
                "Invalid reference format. Expected 'Domain/Path[FC]', found: {}",
                data_reference.reference
            )));
        }

        let domain_id = parts[0];
        let ln_reference = parts[1];

        let fc = &data_reference.fc;
        let logical_node_path: Vec<&str> = ln_reference.split('.').collect();
        let data_object_path = &logical_node_path[1..];

        let domain_object = ObjectNameDomainSpecific {
            domain_id: Identifier(VisibleString::try_from(domain_id).unwrap_or_default()),
            item_id: Identifier(
                VisibleString::try_from(build_item_id(fc, logical_node_path.clone()))
                    .unwrap_or_default(),
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
                    while let Some(c) = chars.next() {
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

#[async_trait]
impl Transport for MmsTransport {
    async fn get_data_values(
        &self,
        refs: Vec<DataReference>,
    ) -> Result<Vec<IECData>, crate::client::Error> {
        let variable: VariableAccessSpecification = parse_references(&refs)?;

        let results = self
            .client
            .read(variable)
            .await
            .map_err(|e| crate::client::Error::ConnectionFailed(e.to_string()))?;

        println!("MMS read results: {:?}", results);

        if results.len() != refs.len() {
            return Err(crate::client::Error::ParseError(format!(
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
                    return Err(crate::client::Error::ParseError(format!(
                        "Access failed for reference index {}",
                        idx
                    )))
                }
            }
        }

        Ok(values)
    }

    async fn get_server_directory(&self) -> Result<Vec<String>, crate::client::Error> {
        let object_class = ObjectClass::basicObjectClass(9);
        let object_scope = GetNameListRequestObjectScope::vmdSpecific(());

        let results = self
            .client
            .get_name_list(object_class, object_scope)
            .await
            .map_err(|e| crate::client::Error::ConnectionFailed(e.to_string()))?;

        Ok(results.iter().map(|s| s.0.to_string()).collect())
    }

    async fn get_logical_device_directory(
        &self,
        ld_name: String,
    ) -> Result<Vec<String>, crate::client::Error> {
        let object_class = ObjectClass::basicObjectClass(0);
        let object_scope = GetNameListRequestObjectScope::domainSpecific(Identifier(
            VisibleString::try_from(ld_name).unwrap_or_default(),
        ));

        let results = self
            .client
            .get_name_list(object_class, object_scope)
            .await
            .map_err(|e| crate::client::Error::ConnectionFailed(e.to_string()))?;

        Ok(results.iter().map(|s| s.0.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::DataReference;
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
        let fp4 = mms::FloatingPoint(OctetString::from(vec![0x40, 0x40, 0x00, 0x00]));
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
