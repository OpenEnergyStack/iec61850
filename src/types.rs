use core::str;

use rasn::{types::*, AsnType, Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(AsnType, Debug, Decode, Encode, PartialEq)]
#[rasn(delegate)]
pub struct MMSString(pub VisibleString);

#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct FloatingPoint(pub OctetString);

/// Time quality flags according to IEC 61850-7-2 Table 30
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TimeQuality {
    pub leap_second_known: bool,
    pub clock_failure: bool,
    pub clock_not_synchronized: bool,
    pub time_accuracy: u8, // 5 bits (0-31)
}

impl TimeQuality {
    pub fn from_byte(byte: u8) -> Self {
        TimeQuality {
            leap_second_known: (byte & 0x80) != 0,      // Bit 0 (MSB)
            clock_failure: (byte & 0x40) != 0,          // Bit 1
            clock_not_synchronized: (byte & 0x20) != 0, // Bit 2
            time_accuracy: byte & 0x1F,                 // Bits 3-7
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.leap_second_known {
            byte |= 0x80;
        }
        if self.clock_failure {
            byte |= 0x40;
        }
        if self.clock_not_synchronized {
            byte |= 0x20;
        }
        byte |= self.time_accuracy & 0x1F;
        byte
    }

    /// Gets time accuracy in bits of accuracy (0-25 valid)
    pub fn accuracy_bits(&self) -> Option<u8> {
        match self.time_accuracy {
            0..=25 => Some(self.time_accuracy),
            26..=30 => None, // Invalid range
            31 => None,      // Unspecified
            _ => None,
        }
    }
}

/// Quality flags for IEC 61850 sampled values - 13 bits total
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Quality {
    // Validity (2 bits) - bits 0-1
    pub validity: Validity,

    // Detail quality flags (8 bits) - bits 2-9
    pub overflow: bool,
    pub out_of_range: bool,
    pub bad_reference: bool,
    pub oscillatory: bool,
    pub failure: bool,
    pub old_data: bool,
    pub inconsistent: bool,
    pub inaccurate: bool,

    // Source (1 bit) - bit 10
    pub source_substituted: bool,

    // Test mode (1 bit) - bit 11
    pub test: bool,

    // Operator blocked (1 bit) - bit 12
    pub operator_blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Validity {
    #[default]
    Good = 0,
    Invalid = 1,
    Reserved = 2,
    Questionable = 3,
}

impl Quality {
    /// Decodes quality from a 16-bit value (13 bits used)
    /// The bitstring is transmitted MSB first in the encoding
    pub fn from_u16(value: u16) -> Self {
        Quality {
            // Validity is bits 0-1 (most significant bits)
            validity: match (value >> 14) & 0x03 {
                0 => Validity::Good,
                1 => Validity::Invalid,
                2 => Validity::Reserved,
                3 => Validity::Questionable,
                _ => Validity::Good,
            },

            // Detail quality flags (bits 2-9)
            overflow: (value & (1 << 13)) != 0,
            out_of_range: (value & (1 << 12)) != 0,
            bad_reference: (value & (1 << 11)) != 0,
            oscillatory: (value & (1 << 10)) != 0,
            failure: (value & (1 << 9)) != 0,
            old_data: (value & (1 << 8)) != 0,
            inconsistent: (value & (1 << 7)) != 0,
            inaccurate: (value & (1 << 6)) != 0,

            // Source (bit 10)
            source_substituted: (value & (1 << 5)) != 0,

            // Test (bit 11)
            test: (value & (1 << 4)) != 0,

            // Operator blocked (bit 12)
            operator_blocked: (value & (1 << 3)) != 0,
        }
    }

    /// Encodes quality to a 16-bit value
    pub fn to_u16(&self) -> u16 {
        let mut value = 0u16;

        // Validity (bits 0-1)
        value |= (self.validity as u16) << 14;

        // Detail quality flags
        if self.overflow {
            value |= 1 << 13;
        }
        if self.out_of_range {
            value |= 1 << 12;
        }
        if self.bad_reference {
            value |= 1 << 11;
        }
        if self.oscillatory {
            value |= 1 << 10;
        }
        if self.failure {
            value |= 1 << 9;
        }
        if self.old_data {
            value |= 1 << 8;
        }
        if self.inconsistent {
            value |= 1 << 7;
        }
        if self.inaccurate {
            value |= 1 << 6;
        }

        // Source
        if self.source_substituted {
            value |= 1 << 5;
        }

        // Test
        if self.test {
            value |= 1 << 4;
        }

        // Operator blocked
        if self.operator_blocked {
            value |= 1 << 3;
        }

        value
    }

    /// Returns true if quality is good (validity=good and no detail quality flags set)
    pub fn is_good(&self) -> bool {
        matches!(self.validity, Validity::Good)
            && !self.overflow
            && !self.out_of_range
            && !self.bad_reference
            && !self.oscillatory
            && !self.failure
            && !self.old_data
            && !self.inconsistent
            && !self.inaccurate
            && !self.source_substituted
            && !self.test
            && !self.operator_blocked
    }
}

/// IEC 61850 UtcTime - 8 bytes with specific structure
/// Bytes 0-3: Seconds since epoch (Jan 1, 1970)
/// Bytes 4-6: Fraction of second (24 bits)
/// Byte 7: Time quality flags
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timestamp {
    /// Seconds since Unix epoch (January 1, 1970)
    pub seconds: u32,

    /// Fraction of second (0-16777215, representing 24-bit precision)
    pub fraction: u32,

    /// Time quality flags
    pub quality: TimeQuality,
}

impl Timestamp {
    /// Creates a new Timestamp from raw 8 bytes
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fraction = u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]]);
        let quality = TimeQuality::from_byte(bytes[7]);

        Timestamp {
            seconds,
            fraction,
            quality,
        }
    }

    /// Converts the timestamp to raw 8 bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.seconds.to_be_bytes());
        let fraction_bytes = self.fraction.to_be_bytes();
        bytes[4] = fraction_bytes[1];
        bytes[5] = fraction_bytes[2];
        bytes[6] = fraction_bytes[3];
        bytes[7] = self.quality.to_byte();
        bytes
    }

    /// Gets fraction as nanoseconds
    pub fn fraction_as_nanos(&self) -> u32 {
        // Convert 24-bit fraction to nanoseconds
        // fraction / 2^24 * 10^9
        ((self.fraction as u64 * 1_000_000_000) >> 24) as u32
    }

    /// Converts the timestamp to a UTC datetime string in ISO 8601 format
    /// Example: "2024-10-28T14:30:45.123456Z"
    pub fn to_utc_string(&self) -> String {
        let nanos = self.fraction_as_nanos();

        // Calculate date components from Unix epoch
        const SECONDS_PER_DAY: u32 = 86400;
        const DAYS_PER_YEAR: u32 = 365;
        const DAYS_PER_4_YEARS: u32 = DAYS_PER_YEAR * 4 + 1;

        let mut days = self.seconds / SECONDS_PER_DAY;
        let remaining_seconds = self.seconds % SECONDS_PER_DAY;

        // Start from 1970
        let mut year = 1970;

        // Handle 400-year cycles
        while days >= 146097 {
            days -= 146097;
            year += 400;
        }

        // Handle 100-year cycles
        while days >= 36524 {
            if days == 36524 && Self::is_leap_year(year) {
                break;
            }
            days -= 36524;
            year += 100;
        }

        // Handle 4-year cycles
        while days >= DAYS_PER_4_YEARS {
            days -= DAYS_PER_4_YEARS;
            year += 4;
        }

        // Handle individual years
        while days >= DAYS_PER_YEAR {
            if days == DAYS_PER_YEAR && Self::is_leap_year(year) {
                break;
            }
            days -= DAYS_PER_YEAR;
            year += 1;
        }

        // Calculate month and day
        let is_leap = Self::is_leap_year(year);
        let days_in_months = if is_leap {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut month = 1;
        for &days_in_month in &days_in_months {
            if days < days_in_month {
                break;
            }
            days -= days_in_month;
            month += 1;
        }
        let day = days + 1;

        // Calculate time components
        let hours = remaining_seconds / 3600;
        let minutes = (remaining_seconds % 3600) / 60;
        let secs = remaining_seconds % 60;
        let micros = nanos / 1000;

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            year, month, day, hours, minutes, secs, micros
        )
    }

    /// Helper function to check if a year is a leap year
    #[allow(unknown_lints)]
    #[allow(clippy::manual_is_multiple_of)]
    fn is_leap_year(year: u32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    /// Converts timestamp to Unix timestamp (seconds since epoch) as f64
    pub fn to_unix_timestamp(&self) -> f64 {
        let seconds = self.seconds as f64;
        let nanos = self.fraction_as_nanos() as f64;
        seconds + (nanos / 1_000_000_000.0)
    }

    /// Creates a Timestamp from a Unix timestamp (seconds since epoch)
    pub fn from_unix_timestamp(unix_timestamp: f64, quality: TimeQuality) -> Self {
        let seconds = unix_timestamp.floor() as u32;
        let fraction = ((unix_timestamp.fract() * 16_777_216.0) as u32).min(16_777_215);

        Timestamp {
            seconds,
            fraction,
            quality,
        }
    }
}

// Add this conversion implementation
impl From<&TimestampRasn> for Timestamp {
    fn from(rasn_ts: &TimestampRasn) -> Self {
        Timestamp {
            seconds: rasn_ts.seconds(),
            fraction: rasn_ts.fraction(),
            quality: rasn_ts.quality(),
        }
    }
}

// Also add the reverse conversion for encoding
impl From<&Timestamp> for TimestampRasn {
    fn from(ts: &Timestamp) -> Self {
        TimestampRasn::from_bytes(ts.to_bytes())
    }
}

/** Data types allowed with a GOOSE */
#[non_exhaustive]
#[derive(AsnType, Debug, Decode, Encode, PartialEq)]
#[rasn(choice)]
pub enum IECDataRasn {
    // Array and Structure
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

/// Serializable IEC data types for JSON/external use
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum IECData {
    /// Array of IEC data elements
    Array(Vec<IECData>),

    /// Structure containing IEC data elements
    Structure(Vec<IECData>),

    /// Boolean value
    Boolean(bool),

    /// Bit string (binary encoded, e.g. "0000000000001000")
    BitString(String),

    /// Signed integer
    Int(i64),

    /// Unsigned integer
    UInt(u64),

    /// Floating point number
    Float(f64),

    /// Octet string (hex encoded)
    OctetString(String),

    /// Visible string (ASCII printable)
    VisibleString(String),

    /// MMS string
    MmsString(String),

    /// UTC timestamp
    Timestamp(Timestamp),
}

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

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EthernetHeader {
    /** Source MAC-Address */
    pub dst_addr: [u8; 6],
    /** Destination MAC-Address */
    pub src_addr: [u8; 6],
    /** Tag Protocol Identifier (0x8100) */
    pub tpid: Option<[u8; 2]>,
    /** Tag Control Information - VLAN-ID and VLAN-Priority */
    pub tci: Option<[u8; 2]>,
    /** Ethertype for the GOOSE (88-B8 or 88-B9) */
    pub ether_type: [u8; 2],
    /** APPID */
    pub appid: [u8; 2],
    /** Length of the GOOSE PDU */
    pub length: [u8; 2],
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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct IECGoosePdu {
    /** Reference to GOOSE control block in the data model of the sending IED */
    pub go_cb_ref: String,
    /** Time allowed to live until the next GOOSE packet */
    pub time_allowed_to_live: u32,
    /** Reference to the data set the GOOSE is shipping */
    pub dat_set: String,
    /** GOOSE ID as defined in GSEControl.appID */
    pub go_id: String,
    /** Time stamp of the GOOSE creation */
    pub t: Timestamp,
    /** Status number - counter for repeating GOOSE packets */
    pub st_num: u32,
    /** Sequence number - counter for changes in GOOSE data  */
    pub sq_num: u32,
    /** Whether the GOOSE is a simulated */
    pub simulation: bool,
    /** Configuration revision of the GOOSE control block */
    pub conf_rev: u32,
    /** Whether the GOOSE needs commissioning */
    pub nds_com: bool,
    /** Number of data set entries in the GOOSE */
    pub num_dat_set_entries: u32,
    /** All data send with the GOOSE */
    pub all_data: Vec<IECData>,
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

/// A single sampled value with its quality
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// The integer value (before scaling)
    pub value: i32,
    /// The quality flags
    pub quality: Quality,
}

impl Sample {
    /// Creates a new sample from raw value and quality bitstring (16-bit)
    pub fn new(value: i32, quality_bits: u16) -> Self {
        Sample {
            value,
            quality: Quality::from_u16(quality_bits),
        }
    }

    /// Creates a new sample from value and quality
    pub fn from_parts(value: i32, quality: Quality) -> Self {
        Sample { value, quality }
    }

    /// Scales the integer value by a factor
    pub fn scaled_value(&self, scale: f32) -> f32 {
        self.value as f32 * scale
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SavAsdu {
    /** Multicast Sampled Values ID as defined in tSampledValueControl.svId*/
    pub msv_id: String,
    /** Reference to the data set the GOOSE is shipping */
    pub dat_set: Option<String>,
    /** Increments with each sampled value taken */
    pub smp_cnt: u16,
    /** Configuration revision of the GOOSE control block */
    pub conf_rev: u32,
    /** Transmission time of the ASDU */
    pub refr_tm: Option<[u8; 8]>,
    /** How the sample value stream is time synchronized 0 = not, 1 = locally and 2 globally */
    pub smp_synch: u8,
    pub smp_rate: Option<u16>,
    /** All sampled data with quality */
    pub all_data: Vec<Sample>,
    pub smp_mod: Option<u16>,
    pub gm_identity: Option<[u8; 8]>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SavPdu {
    /** Whether the sampled value stream is simulated */
    pub sim: bool,
    /** Number of ASDU in the packet*/
    pub no_asdu: u16,
    /** Security field - ANY OPTIONAL type reserved for future definition (e.g., digital signature) */
    pub security: Option<Vec<u8>>,
    /** All data send with the GOOSE */
    pub sav_asdu: Vec<SavAsdu>,
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

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn test_timestamp_from_bytes() {
        let bytes = [0x65, 0x4a, 0x2c, 0x80, 0x12, 0x34, 0x56, 0x0A];
        let timestamp = Timestamp::from_bytes(bytes);

        assert_eq!(timestamp.seconds, 0x654a2c80);
        assert_eq!(timestamp.fraction, 0x123456);
        assert_eq!(timestamp.quality.time_accuracy, 10);
    }

    #[test]
    fn test_timestamp_to_bytes() {
        let timestamp = Timestamp {
            seconds: 0x654a2c80,
            fraction: 0x123456,
            quality: TimeQuality {
                leap_second_known: false,
                clock_failure: false,
                clock_not_synchronized: false,
                time_accuracy: 10,
            },
        };

        let bytes = timestamp.to_bytes();
        assert_eq!(bytes, [0x65, 0x4a, 0x2c, 0x80, 0x12, 0x34, 0x56, 0x0A]);
    }

    #[test]
    fn test_timestamp_roundtrip() {
        let original = [0x20, 0x21, 0x06, 0x12, 0x0A, 0x30, 0x00, 0x00];
        let timestamp = Timestamp::from_bytes(original);
        let result = timestamp.to_bytes();
        assert_eq!(original, result);
    }

    #[test]
    fn test_timestamp_fraction_as_nanos() {
        let timestamp = Timestamp {
            seconds: 1000,
            fraction: 8388608, // 0x800000 = 1/2 of 2^24
            quality: TimeQuality::default(),
        };

        let nanos = timestamp.fraction_as_nanos();
        // Should be approximately 500,000,000 (0.5 seconds)
        assert!((nanos as i32 - 500_000_000).abs() < 100);
    }

    #[test]
    fn test_timestamp_unix_timestamp() {
        let timestamp = Timestamp {
            seconds: 1698502245,
            fraction: 2097152, // 1/8 of 2^24
            quality: TimeQuality::default(),
        };

        let unix_ts = timestamp.to_unix_timestamp();
        assert!((unix_ts - 1698502245.125).abs() < 0.001);
    }

    #[test]
    fn test_timestamp_from_unix_timestamp() {
        let unix_ts = 1698502245.5;
        let quality = TimeQuality::default();
        let timestamp = Timestamp::from_unix_timestamp(unix_ts, quality);

        assert_eq!(timestamp.seconds, 1698502245);
        // Fraction should be approximately 0.5 * 2^24
        let expected_fraction = (0.5 * 16777216.0) as u32;
        assert!((timestamp.fraction as i32 - expected_fraction as i32).abs() < 100);
    }

    #[test]
    fn test_timestamp_utc_string_format() {
        let timestamp = Timestamp {
            seconds: 1698502245, // October 28, 2023
            fraction: 0,
            quality: TimeQuality::default(),
        };

        let utc_string = timestamp.to_utc_string();
        assert!(utc_string.starts_with("2023-10-28"));
        assert!(utc_string.ends_with("Z"));
        assert!(utc_string.contains("T"));
    }

    #[test]
    fn test_timestamp_serialization() {
        let timestamp = Timestamp {
            seconds: 1698502245,
            fraction: 2097152,
            quality: TimeQuality {
                leap_second_known: true,
                clock_failure: false,
                clock_not_synchronized: false,
                time_accuracy: 10,
            },
        };

        let json = serde_json::to_string(&timestamp).unwrap();
        let deserialized: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(timestamp, deserialized);
    }
}

#[cfg(test)]
mod time_quality_tests {
    use super::*;

    #[test]
    fn test_time_quality_from_byte() {
        let byte = 0b10110101; // leap=1, failure=0, not_sync=1, accuracy=10101
        let quality = TimeQuality::from_byte(byte);

        assert_eq!(quality.leap_second_known, true);
        assert_eq!(quality.clock_failure, false);
        assert_eq!(quality.clock_not_synchronized, true);
        assert_eq!(quality.time_accuracy, 0b10101);
    }

    #[test]
    fn test_time_quality_to_byte() {
        let quality = TimeQuality {
            leap_second_known: true,
            clock_failure: false,
            clock_not_synchronized: true,
            time_accuracy: 0b10101,
        };

        let byte = quality.to_byte();
        assert_eq!(byte, 0b10110101);
    }

    #[test]
    fn test_time_quality_roundtrip() {
        for byte in 0u8..=255 {
            let quality = TimeQuality::from_byte(byte);
            let result = quality.to_byte();
            assert_eq!(byte, result);
        }
    }

    #[test]
    fn test_time_quality_accuracy_bits_valid() {
        let quality = TimeQuality {
            leap_second_known: false,
            clock_failure: false,
            clock_not_synchronized: false,
            time_accuracy: 10,
        };

        assert_eq!(quality.accuracy_bits(), Some(10));
    }

    #[test]
    fn test_time_quality_accuracy_bits_invalid() {
        let quality = TimeQuality {
            leap_second_known: false,
            clock_failure: false,
            clock_not_synchronized: false,
            time_accuracy: 26, // Invalid
        };

        assert_eq!(quality.accuracy_bits(), None);
    }

    #[test]
    fn test_time_quality_accuracy_bits_unspecified() {
        let quality = TimeQuality {
            leap_second_known: false,
            clock_failure: false,
            clock_not_synchronized: false,
            time_accuracy: 31, // Unspecified
        };

        assert_eq!(quality.accuracy_bits(), None);
    }
}

#[cfg(test)]
mod iec_data_conversion_tests {
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
