use mms::OctetString;
use rasn::{AsnType, Decode, Encode};

use crate::types::{IECData, IECGoosePdu, TimeQuality, Timestamp};
use rasn::types::*;

#[derive(AsnType, Debug, Decode, Encode, PartialEq)]
#[rasn(delegate)]
pub struct MMSString(pub VisibleString);

#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct FloatingPoint(pub OctetString);

#[derive(AsnType, Debug, Decode, Encode, PartialEq)]
#[rasn(delegate)]
pub struct TimestampRasn(pub OctetString);

impl TimestampRasn {
    /// Creates a new Timestamp from raw 8 bytes
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        TimestampRasn(OctetString::from(bytes.to_vec()))
    }

    /// Gets the raw 8 bytes
    pub fn as_bytes(&self) -> Result<[u8; 8], &'static str> {
        if self.0.len() == 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.0);
            Ok(bytes)
        } else {
            Err("Timestamp must be exactly 8 bytes")
        }
    }

    /// Gets seconds since epoch (Jan 1, 1970)
    pub fn seconds(&self) -> u32 {
        let bytes = self.0.as_ref();
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Gets fraction of second (0-16777215, representing 0.0 to 0.999999940...)
    pub fn fraction(&self) -> u32 {
        let bytes = self.0.as_ref();
        u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]])
    }

    /// Gets the time quality byte
    pub fn quality(&self) -> TimeQuality {
        TimeQuality::from_byte(self.0.as_ref()[7])
    }

    /// Gets fraction as nanoseconds
    pub fn fraction_as_nanos(&self) -> u32 {
        // Convert 24-bit fraction to nanoseconds
        // fraction / 2^24 * 10^9
        let fraction = self.fraction();
        ((fraction as u64 * 1_000_000_000) >> 24) as u32
    }
}

impl From<&TimestampRasn> for Timestamp {
    fn from(rasn_ts: &TimestampRasn) -> Self {
        Timestamp {
            seconds: rasn_ts.seconds(),
            fraction: rasn_ts.fraction(),
            quality: rasn_ts.quality(),
        }
    }
}

impl From<&Timestamp> for TimestampRasn {
    fn from(ts: &Timestamp) -> Self {
        TimestampRasn::from_bytes(ts.to_bytes())
    }
}

#[non_exhaustive]
#[derive(AsnType, Debug, Decode, Encode, PartialEq)]
#[rasn(choice)]
pub enum IECDataRasn {
    #[rasn(tag(context, 1))]
    Array(Vec<IECDataRasn>),

    #[rasn(tag(context, 2))]
    Structure(Vec<IECDataRasn>),

    // Boolean - 0x83
    #[rasn(tag(context, 3))]
    Boolean(bool),

    // BitString - 0x84 (used for CodedEnum and Quality)
    #[rasn(tag(context, 4))]
    BitString(BitString),

    // Signed integers - 0x85 (cannot differentiate by tag alone)
    #[rasn(tag(context, 5))]
    Int(Integer),

    // Unsigned integers - 0x86
    #[rasn(tag(context, 6))]
    UInt(Integer),

    // Float - 0x87
    #[rasn(tag(context, 7))]
    Float(FloatingPoint),

    // OctetString - 0x89
    #[rasn(tag(context, 9))]
    OctetString(OctetString),

    // VisibleString - 0x8a
    #[rasn(tag(context, 10))]
    VisibleString(VisibleString),

    // MMSString - extension addition, 0x90 (context 16)
    #[rasn(extension_addition, tag(context, 16))]
    MmsString(MMSString),

    // UtcTime (Timestamp) - 0x91
    #[rasn(tag(context, 17))]
    Timestamp(TimestampRasn),
}

impl From<&IECDataRasn> for IECData {
    fn from(data: &IECDataRasn) -> Self {
        match data {
            IECDataRasn::Array(arr) => IECData::Array(arr.iter().map(IECData::from).collect()),
            IECDataRasn::Structure(structure) => {
                IECData::Structure(structure.iter().map(IECData::from).collect())
            }
            IECDataRasn::Boolean(b) => IECData::Boolean(*b),
            IECDataRasn::BitString(bits) => {
                // Convert BitString to binary string
                let bytes = bits.as_raw_slice();
                let mut binary_string = String::new();
                for byte in bytes {
                    binary_string.push_str(&format!("{:08b}", byte));
                }
                IECData::BitString(binary_string)
            }
            IECDataRasn::Int(i) => IECData::Int(i64::try_from(i).unwrap_or(0)),
            IECDataRasn::UInt(u) => IECData::UInt(u64::try_from(u).unwrap_or(0)),
            IECDataRasn::Float(fp) => {
                // Decode FloatingPoint to f64
                let bytes = fp.0.as_ref();
                if bytes.len() == 4 {
                    let value = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    IECData::Float(value as f64)
                } else if bytes.len() == 8 {
                    let value = f64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    IECData::Float(value)
                } else {
                    IECData::Float(0.0)
                }
            }
            IECDataRasn::OctetString(octets) => IECData::OctetString(hex::encode(octets.as_ref())),
            IECDataRasn::VisibleString(s) => IECData::VisibleString(s.to_string()),
            IECDataRasn::MmsString(mms) => IECData::MmsString(mms.0.to_string()),
            IECDataRasn::Timestamp(ts) => IECData::Timestamp(Timestamp::from(ts)),
        }
    }
}

impl From<&IECData> for IECDataRasn {
    fn from(data: &IECData) -> Self {
        match data {
            IECData::Array(arr) => IECDataRasn::Array(arr.iter().map(IECDataRasn::from).collect()),
            IECData::Structure(structure) => {
                IECDataRasn::Structure(structure.iter().map(IECDataRasn::from).collect())
            }
            IECData::Boolean(b) => IECDataRasn::Boolean(*b),
            IECData::BitString(binary_str) => {
                // Parse binary string to BitString
                let mut bytes = Vec::new();
                for chunk in binary_str.as_bytes().chunks(8) {
                    let byte_str = std::str::from_utf8(chunk).unwrap_or("00000000");
                    if let Ok(byte) = u8::from_str_radix(byte_str, 2) {
                        bytes.push(byte);
                    }
                }
                IECDataRasn::BitString(BitString::from_vec(bytes))
            }
            IECData::Int(i) => IECDataRasn::Int(Integer::from(*i)),
            IECData::UInt(u) => IECDataRasn::UInt(Integer::from(*u as i64)),
            IECData::Float(f) => {
                // Encode f64 to FloatingPoint (8 bytes)
                let bytes = f.to_be_bytes();
                IECDataRasn::Float(FloatingPoint(OctetString::from(bytes.to_vec())))
            }
            IECData::OctetString(hex_str) => {
                let bytes = hex::decode(hex_str).unwrap_or_default();
                IECDataRasn::OctetString(OctetString::from(bytes))
            }
            IECData::VisibleString(s) => {
                IECDataRasn::VisibleString(VisibleString::try_from(s.as_str()).unwrap_or_default())
            }
            IECData::MmsString(s) => IECDataRasn::MmsString(MMSString(
                VisibleString::try_from(s.as_str()).unwrap_or_default(),
            )),
            IECData::Timestamp(ts) => IECDataRasn::Timestamp(TimestampRasn::from(ts)),
        }
    }
}

#[derive(AsnType, Debug, Decode, Encode, PartialEq)]
#[rasn(tag(application, 1))] // <-- ADD THIS! GOOSE uses APPLICATION tag class
pub struct IECGoosePduRasn {
    /// Reference to GOOSE control block in the data model of the sending IED
    #[rasn(tag(context, 0))]
    pub go_cb_ref: VisibleString,
    /// Time allowed to live until the next GOOSE packet
    #[rasn(tag(context, 1))]
    pub time_allowed_to_live: Integer,
    /// Reference to the data set the GOOSE is shipping
    #[rasn(tag(context, 2))]
    pub dat_set: VisibleString,
    /// GOOSE ID as defined in GSEControl.appID
    #[rasn(tag(context, 3))]
    pub go_id: VisibleString,
    /// Time stamp of the GOOSE creation
    #[rasn(tag(context, 4))]
    pub t: TimestampRasn,
    /// Status number - counter for repeating GOOSE packets
    #[rasn(tag(context, 5))]
    pub st_num: Integer,
    /// Sequence number - counter for changes in GOOSE data
    #[rasn(tag(context, 6))]
    pub sq_num: Integer,
    /// Whether the GOOSE is simulated (default: false)
    #[rasn(tag(context, 7))]
    pub simulation: bool,
    /// Configuration revision of the GOOSE control block
    #[rasn(tag(context, 8))]
    pub conf_rev: Integer,
    /// Whether the GOOSE needs commissioning (default: false)
    #[rasn(tag(context, 9))]
    pub nds_com: bool,
    /// Number of data set entries in the GOOSE
    #[rasn(tag(context, 10))]
    pub num_dat_set_entries: Integer,
    /// All data sent with the GOOSE
    #[rasn(tag(context, 11))]
    pub all_data: SequenceOf<IECDataRasn>,
}

impl From<&IECGoosePduRasn> for IECGoosePdu {
    fn from(pdu: &IECGoosePduRasn) -> Self {
        IECGoosePdu {
            go_cb_ref: pdu.go_cb_ref.to_string(),
            time_allowed_to_live: u32::try_from(&pdu.time_allowed_to_live).unwrap_or(0),
            dat_set: pdu.dat_set.to_string(),
            go_id: pdu.go_id.to_string(),
            t: Timestamp::from(&pdu.t),
            st_num: u32::try_from(&pdu.st_num).unwrap_or(0),
            sq_num: u32::try_from(&pdu.sq_num).unwrap_or(0),
            simulation: pdu.simulation,
            conf_rev: u32::try_from(&pdu.conf_rev).unwrap_or(0),
            nds_com: pdu.nds_com,
            num_dat_set_entries: u32::try_from(&pdu.num_dat_set_entries).unwrap_or(0),
            all_data: pdu.all_data.iter().map(IECData::from).collect(),
        }
    }
}

impl From<&IECGoosePdu> for IECGoosePduRasn {
    fn from(pdu: &IECGoosePdu) -> Self {
        IECGoosePduRasn {
            go_cb_ref: VisibleString::try_from(pdu.go_cb_ref.as_str())
                .unwrap_or_else(|_| VisibleString::try_from("").unwrap()),
            time_allowed_to_live: Integer::from(pdu.time_allowed_to_live as i64),
            dat_set: VisibleString::try_from(pdu.dat_set.as_str())
                .unwrap_or_else(|_| VisibleString::try_from("").unwrap()),
            go_id: VisibleString::try_from(pdu.go_id.as_str())
                .unwrap_or_else(|_| VisibleString::try_from("").unwrap()),
            t: TimestampRasn::from(&pdu.t),
            st_num: Integer::from(pdu.st_num as i64),
            sq_num: Integer::from(pdu.sq_num as i64),
            simulation: pdu.simulation,
            conf_rev: Integer::from(pdu.conf_rev as i64),
            nds_com: pdu.nds_com,
            num_dat_set_entries: Integer::from(pdu.num_dat_set_entries as i64),
            all_data: pdu.all_data.iter().map(IECDataRasn::from).collect(),
        }
    }
}

#[cfg(test)]
mod iec_data_conversion_tests {
    use crate::types::TimeQuality;

    use super::*;

    #[test]
    fn test_boolean_conversion() {
        let rasn = IECDataRasn::Boolean(true);
        let data = IECData::from(&rasn);

        assert_eq!(data, IECData::Boolean(true));

        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_int_conversion() {
        let values = vec![-128i64, -1, 0, 1, 127, 128, 32767, -32768, 2147483647];

        for val in values {
            let rasn = IECDataRasn::Int(Integer::from(val));
            let data = IECData::from(&rasn);

            match data {
                IECData::Int(v) => assert_eq!(v, val),
                _ => panic!("Expected Int variant"),
            }

            let back = IECDataRasn::from(&data);
            assert_eq!(rasn, back);
        }
    }

    #[test]
    fn test_uint_conversion() {
        let values = vec![0u64, 1, 127, 128, 255, 256, 65535, 4294967295];

        for val in values {
            let rasn = IECDataRasn::UInt(Integer::from(val as i64));
            let data = IECData::from(&rasn);

            match data {
                IECData::UInt(v) => assert_eq!(v, val),
                _ => panic!("Expected UInt variant"),
            }

            let back = IECDataRasn::from(&data);
            assert_eq!(rasn, back);
        }
    }

    #[test]
    fn test_float32_conversion() {
        let value = 3.14159f32;
        let bytes = value.to_be_bytes();
        let rasn = IECDataRasn::Float(FloatingPoint(OctetString::from(bytes.to_vec())));
        let data = IECData::from(&rasn);

        match data {
            IECData::Float(f) => assert!((f - value as f64).abs() < 0.0001),
            _ => panic!("Expected Float variant"),
        }
    }

    #[test]
    fn test_float64_conversion() {
        let value = 3.141592653589793f64;
        let bytes = value.to_be_bytes();
        let rasn = IECDataRasn::Float(FloatingPoint(OctetString::from(bytes.to_vec())));
        let data = IECData::from(&rasn);

        match data {
            IECData::Float(f) => assert!((f - value).abs() < 0.0000001),
            _ => panic!("Expected Float variant"),
        }

        let back = IECDataRasn::from(&data);
        // Verify it encodes as 8 bytes
        match back {
            IECDataRasn::Float(fp) => assert_eq!(fp.0.as_ref().len(), 8),
            _ => panic!("Expected Float variant"),
        }
    }

    #[test]
    fn test_float_edge_cases() {
        let values = vec![0.0f64, -0.0, 1.0, -1.0, f64::MIN, f64::MAX];

        for val in values {
            let data = IECData::Float(val);
            let rasn = IECDataRasn::from(&data);
            let back = IECData::from(&rasn);

            match back {
                IECData::Float(f) => {
                    if val.is_nan() {
                        assert!(f.is_nan());
                    } else {
                        assert_eq!(f, val);
                    }
                }
                _ => panic!("Expected Float variant"),
            }
        }
    }

    #[test]
    fn test_visible_string_conversion() {
        let strings = vec!["", "test", "IED1/LLN0$GO$gcb1", "Hello World 123!"];

        for s in strings {
            let rasn = IECDataRasn::VisibleString(VisibleString::try_from(s).unwrap());
            let data = IECData::from(&rasn);

            assert_eq!(data, IECData::VisibleString(s.to_string()));

            let back = IECDataRasn::from(&data);
            assert_eq!(rasn, back);
        }
    }

    #[test]
    fn test_mms_string_conversion() {
        let strings = vec!["", "test", "UTF-8 string"];

        for s in strings {
            let rasn = IECDataRasn::MmsString(MMSString(VisibleString::try_from(s).unwrap()));
            let data = IECData::from(&rasn);

            assert_eq!(data, IECData::MmsString(s.to_string()));

            let back = IECDataRasn::from(&data);
            assert_eq!(rasn, back);
        }
    }

    #[test]
    fn test_octet_string_conversion() {
        let test_data = vec![
            vec![],
            vec![0x00],
            vec![0xFF],
            vec![0x01, 0x02, 0x03, 0x04],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        ];

        for bytes in test_data {
            let rasn = IECDataRasn::OctetString(OctetString::from(bytes.clone()));
            let data = IECData::from(&rasn);

            match &data {
                IECData::OctetString(hex) => {
                    assert_eq!(hex::decode(hex).unwrap(), bytes);
                }
                _ => panic!("Expected OctetString variant"),
            }

            let back = IECDataRasn::from(&data);
            assert_eq!(rasn, back);
        }
    }

    #[test]
    fn test_bitstring_conversion() {
        let test_cases = vec![
            // (bytes, expected_binary_string)
            (vec![0b10101010], "10101010"),
            (vec![0xFF, 0x00], "1111111100000000"),
            (vec![0x00, 0x00, 0x00], "000000000000000000000000"),
            (vec![0b11110000, 0b00001111], "1111000000001111"),
            (vec![0x00, 0x08], "0000000000001000"), // The example from user: 0x0008
        ];

        for (bytes, expected_binary) in test_cases {
            let rasn = IECDataRasn::BitString(BitString::from_vec(bytes.clone()));
            let data = IECData::from(&rasn);

            match &data {
                IECData::BitString(binary_str) => {
                    assert_eq!(
                        binary_str, expected_binary,
                        "Binary string mismatch for bytes {:?}",
                        bytes
                    );
                }
                _ => panic!("Expected BitString variant"),
            }

            let back = IECDataRasn::from(&data);
            match back {
                IECDataRasn::BitString(bs) => {
                    assert_eq!(
                        bs.as_raw_slice(),
                        bytes.as_slice(),
                        "Round-trip conversion failed for bytes {:?}",
                        bytes
                    );
                }
                _ => panic!("Expected BitString variant"),
            }
        }
    }

    #[test]
    fn test_array_conversion() {
        let rasn = IECDataRasn::Array(vec![
            IECDataRasn::Boolean(true),
            IECDataRasn::Int(Integer::from(42)),
            IECDataRasn::VisibleString(VisibleString::try_from("test").unwrap()),
        ]);

        let data = IECData::from(&rasn);

        match &data {
            IECData::Array(arr) => {
                assert_eq!(arr.len(), 3);
                assert_eq!(arr[0], IECData::Boolean(true));
                assert_eq!(arr[1], IECData::Int(42));
                assert_eq!(arr[2], IECData::VisibleString("test".to_string()));
            }
            _ => panic!("Expected Array variant"),
        }

        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_structure_conversion() {
        let rasn = IECDataRasn::Structure(vec![
            IECDataRasn::Boolean(false),
            IECDataRasn::UInt(Integer::from(128)),
        ]);

        let data = IECData::from(&rasn);

        match &data {
            IECData::Structure(structure) => {
                assert_eq!(structure.len(), 2);
                assert_eq!(structure[0], IECData::Boolean(false));
                assert_eq!(structure[1], IECData::UInt(128));
            }
            _ => panic!("Expected Structure variant"),
        }

        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_nested_array_conversion() {
        let rasn = IECDataRasn::Array(vec![
            IECDataRasn::Array(vec![
                IECDataRasn::Int(Integer::from(1)),
                IECDataRasn::Int(Integer::from(2)),
            ]),
            IECDataRasn::Array(vec![
                IECDataRasn::Int(Integer::from(3)),
                IECDataRasn::Int(Integer::from(4)),
            ]),
        ]);

        let data = IECData::from(&rasn);
        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_nested_structure_conversion() {
        let rasn = IECDataRasn::Structure(vec![
            IECDataRasn::Boolean(true),
            IECDataRasn::Structure(vec![
                IECDataRasn::Int(Integer::from(42)),
                IECDataRasn::VisibleString(VisibleString::try_from("nested").unwrap()),
            ]),
        ]);

        let data = IECData::from(&rasn);
        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_timestamp_in_iec_data() {
        let timestamp = Timestamp {
            seconds: 1698502245,
            fraction: 2097152,
            quality: TimeQuality {
                leap_second_known: false,
                clock_failure: false,
                clock_not_synchronized: false,
                time_accuracy: 10,
            },
        };

        let rasn = IECDataRasn::Timestamp(TimestampRasn::from(&timestamp));
        let data = IECData::from(&rasn);

        match &data {
            IECData::Timestamp(ts) => {
                assert_eq!(ts.seconds, timestamp.seconds);
                assert_eq!(ts.fraction, timestamp.fraction);
                assert_eq!(ts.quality, timestamp.quality);
            }
            _ => panic!("Expected Timestamp variant"),
        }

        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_empty_array_conversion() {
        let rasn = IECDataRasn::Array(vec![]);
        let data = IECData::from(&rasn);

        match &data {
            IECData::Array(arr) => assert_eq!(arr.len(), 0),
            _ => panic!("Expected Array variant"),
        }

        let back = IECDataRasn::from(&data);
        assert_eq!(rasn, back);
    }

    #[test]
    fn test_iec_data_json_serialization() {
        let test_data = vec![
            IECData::Boolean(true),
            IECData::Int(-42),
            IECData::UInt(128),
            IECData::Float(3.14159),
            IECData::VisibleString("test".to_string()),
            IECData::Array(vec![IECData::Int(1), IECData::Int(2)]),
        ];

        for data in test_data {
            let json = serde_json::to_string(&data).unwrap();
            let deserialized: IECData = serde_json::from_str(&json).unwrap();
            assert_eq!(data, deserialized);
        }
    }
}

#[cfg(test)]
mod goose_pdu_conversion_tests {
    use crate::types::TimeQuality;

    use super::*;

    #[test]
    fn test_goose_pdu_conversion() {
        let timestamp = Timestamp {
            seconds: 1698502245,
            fraction: 2097152,
            quality: TimeQuality::default(),
        };

        let rasn_pdu = IECGoosePduRasn {
            go_cb_ref: VisibleString::try_from("IED1/LLN0$GO$gcb1").unwrap(),
            time_allowed_to_live: Integer::from(2000),
            dat_set: VisibleString::try_from("IED1/LLN0$DATASET1").unwrap(),
            go_id: VisibleString::try_from("GOOSE1").unwrap(),
            t: TimestampRasn::from(&timestamp),
            st_num: Integer::from(1),
            sq_num: Integer::from(42),
            simulation: false,
            conf_rev: Integer::from(128),
            nds_com: false,
            num_dat_set_entries: Integer::from(2),
            all_data: vec![
                IECDataRasn::Boolean(true),
                IECDataRasn::Int(Integer::from(42)),
            ],
        };

        let pdu = IECGoosePdu::from(&rasn_pdu);

        assert_eq!(pdu.go_cb_ref, "IED1/LLN0$GO$gcb1");
        assert_eq!(pdu.time_allowed_to_live, 2000);
        assert_eq!(pdu.dat_set, "IED1/LLN0$DATASET1");
        assert_eq!(pdu.go_id, "GOOSE1");
        assert_eq!(pdu.t.seconds, timestamp.seconds);
        assert_eq!(pdu.st_num, 1);
        assert_eq!(pdu.sq_num, 42);
        assert_eq!(pdu.simulation, false);
        assert_eq!(pdu.conf_rev, 128);
        assert_eq!(pdu.nds_com, false);
        assert_eq!(pdu.num_dat_set_entries, 2);
        assert_eq!(pdu.all_data.len(), 2);

        let back = IECGoosePduRasn::from(&pdu);
        assert_eq!(rasn_pdu, back);
    }

    #[test]
    fn test_goose_pdu_json_serialization() {
        let timestamp = Timestamp {
            seconds: 1698502245,
            fraction: 2097152,
            quality: TimeQuality::default(),
        };

        let pdu = IECGoosePdu {
            go_cb_ref: "IED1/LLN0$GO$gcb1".to_string(),
            time_allowed_to_live: 2000,
            dat_set: "IED1/LLN0$DATASET1".to_string(),
            go_id: "GOOSE1".to_string(),
            t: timestamp,
            st_num: 1,
            sq_num: 42,
            simulation: false,
            conf_rev: 128,
            nds_com: false,
            num_dat_set_entries: 2,
            all_data: vec![IECData::Boolean(true), IECData::Int(42)],
        };

        let json = serde_json::to_string_pretty(&pdu).unwrap();
        println!("GOOSE PDU JSON:\n{}", json);

        let deserialized: IECGoosePdu = serde_json::from_str(&json).unwrap();
        assert_eq!(pdu, deserialized);
    }
}
