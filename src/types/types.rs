use serde::{Deserialize, Serialize};

use crate::types::{OriginCategory, Validity};

// ----------------- basic types ---------------

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

// ----------------- structured types ----------

/// Analogue value for APC (Analog Process Control).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AnalogueValue {
    /// IEEE 754 FLOAT32
    pub f: Option<f32>,
    /// INT32
    pub i: Option<i32>,
}

/// Entry time as defined in IEC 61850 / MMS (ISO 9506).
///
/// Encoded as 6 bytes (BinaryTime6):
/// - Bytes 0–3: milliseconds since midnight (big-endian `u32`)
/// - Bytes 4–5: days since **1 January 1984** (big-endian `u16`)
///
/// This differs from `UtcTime`/`TimeStamp` which uses the Unix epoch (1 Jan 1970).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryTime(pub Vec<u8>);

impl EntryTime {
    /// The IEC 61850 epoch (1984-01-01) as Unix timestamp in seconds.
    const IEC61850_EPOCH_SECS: u64 = 441763200;

    /// Converts to Unix timestamp in milliseconds, or `None` if the raw bytes are not exactly 6 bytes.
    pub fn to_unix_ms(&self) -> Option<u64> {
        if self.0.len() != 6 {
            return None;
        }
        let ms_since_midnight =
            u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as u64;
        let days = u16::from_be_bytes([self.0[4], self.0[5]]) as u64;
        Some(Self::IEC61850_EPOCH_SECS * 1000 + days * 86_400_000 + ms_since_midnight)
    }
}

impl Quality {
    pub fn from_u16(value: u16) -> Self {
        Quality {
            // Validity is bits 15-14 (most significant bits)
            validity: match (value >> 14) & 0x03 {
                0 => Validity::Good,
                1 => Validity::Invalid,
                2 => Validity::Reserved,
                3 => Validity::Questionable,
                _ => Validity::Good,
            },

            // Detail quality flags
            overflow: (value & (1 << 13)) != 0,
            out_of_range: (value & (1 << 12)) != 0,
            bad_reference: (value & (1 << 11)) != 0,
            oscillatory: (value & (1 << 10)) != 0,
            failure: (value & (1 << 9)) != 0,
            old_data: (value & (1 << 8)) != 0,
            inconsistent: (value & (1 << 7)) != 0,
            inaccurate: (value & (1 << 6)) != 0,

            // Source
            source_substituted: (value & (1 << 5)) != 0,

            // Test
            test: (value & (1 << 4)) != 0,

            // Operator blocked
            operator_blocked: (value & (1 << 3)) != 0,
        }
    }

    /// Encodes quality to a 16-bit value (see `from_u16`)
    pub fn to_u16(&self) -> u16 {
        let mut value = 0u16;

        // Validity (bits 15-14)
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

    // Quality decoding acc. to IEC 61850-9-2
    pub fn from_sv(quality_u32: u32) -> Self {
        Quality {
            // Validity bits 1-0 (bit number 31-30)
            validity: match quality_u32 & 0x3 {
                0 => Validity::Good,
                1 => Validity::Invalid,
                2 => Validity::Reserved,
                3 => Validity::Questionable,
                _ => Validity::Good,
            },

            // Detail quality flags (bit number 29-22)
            overflow: (quality_u32 & (1 << 2)) != 0,
            out_of_range: (quality_u32 & (1 << 3)) != 0,
            bad_reference: (quality_u32 & (1 << 4)) != 0,
            oscillatory: (quality_u32 & (1 << 5)) != 0,
            failure: (quality_u32 & (1 << 6)) != 0,
            old_data: (quality_u32 & (1 << 7)) != 0,
            inconsistent: (quality_u32 & (1 << 8)) != 0,
            inaccurate: (quality_u32 & (1 << 9)) != 0,

            source_substituted: (quality_u32 & (1 << 10)) != 0,

            test: (quality_u32 & (1 << 11)) != 0,

            operator_blocked: (quality_u32 & (1 << 12)) != 0,
        }
    }

    pub fn to_sv(&self) -> u32 {
        let mut value = 0u32;

        // Validity bits 1-0 (bit number 31-30)
        value |= (self.validity as u32) & 0x3;

        // Detail quality flags (bit number 29-22)
        if self.overflow {
            value |= 1 << 2;
        }
        if self.out_of_range {
            value |= 1 << 3;
        }
        if self.bad_reference {
            value |= 1 << 4;
        }
        if self.oscillatory {
            value |= 1 << 5;
        }
        if self.failure {
            value |= 1 << 6;
        }
        if self.old_data {
            value |= 1 << 7;
        }
        if self.inconsistent {
            value |= 1 << 8;
        }
        if self.inaccurate {
            value |= 1 << 9;
        }

        if self.source_substituted {
            value |= 1 << 10;
        }

        if self.test {
            value |= 1 << 11;
        }

        if self.operator_blocked {
            value |= 1 << 12;
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

/// Quality flags for IEC 61850 - 13 bits total, shared by GOOSE, Reports and MMS
/// (see IEC 61850-7-2 Table 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Quality {
    // Validity (2 bits)
    pub validity: Validity,

    // Detail quality flags (8 bits)
    pub overflow: bool,
    pub out_of_range: bool,
    pub bad_reference: bool,
    pub oscillatory: bool,
    pub failure: bool,
    pub old_data: bool,
    pub inconsistent: bool,
    pub inaccurate: bool,

    pub source_substituted: bool,

    pub test: bool,

    pub operator_blocked: bool,
}

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

// ---------------- control types ----------

/// Interlocking and synchronism-check conditions (Check BIT STRING, 2 bits).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Check {
    /// Synchronism check required — bit 0
    pub synchrocheck: bool,
    /// Interlock check required — bit 1
    pub interlock_check: bool,
}

impl Check {
    pub fn to_bit_string(&self) -> String {
        format!(
            "{}{}",
            if self.synchrocheck { '1' } else { '0' },
            if self.interlock_check { '1' } else { '0' },
        )
    }
}

/// Originator of a control command (orCat + orIdent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Originator {
    /// Originator category
    pub or_cat: OriginCategory,
    /// Originator identifier (OCTET STRING, max 64 bytes)
    pub or_ident: Vec<u8>,
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
mod quality_tests {
    use super::*;

    #[test]
    fn test_quality_from_sv_good_all_zero() {
        let quality = Quality::from_sv(0x00000000);
        assert_eq!(quality.validity, Validity::Good);
        assert!(!quality.overflow);
        assert!(!quality.out_of_range);
        assert!(!quality.bad_reference);
        assert!(!quality.oscillatory);
        assert!(!quality.failure);
        assert!(!quality.old_data);
        assert!(!quality.inconsistent);
        assert!(!quality.inaccurate);
        assert!(!quality.source_substituted);
        assert!(!quality.test);
        assert!(!quality.operator_blocked);
        assert!(quality.is_good());
    }

    #[test]
    fn test_quality_from_sv_invalid() {
        let quality = Quality::from_sv(0x00000842);
        assert_eq!(quality.validity, Validity::Reserved);
        assert!(!quality.overflow);
        assert!(!quality.out_of_range);
        assert!(!quality.bad_reference);
        assert!(!quality.oscillatory);
        assert!(quality.failure);
        assert!(!quality.old_data);
        assert!(!quality.inconsistent);
        assert!(!quality.inaccurate);
        assert!(!quality.source_substituted);
        assert!(quality.test);
        assert!(!quality.operator_blocked);
    }

    #[test]
    fn test_quality_from_u16_validity_bits() {
        assert_eq!(Quality::from_sv(0x00000000).validity, Validity::Good);
        assert_eq!(Quality::from_sv(0x00000001).validity, Validity::Invalid);
        assert_eq!(Quality::from_sv(0x00000002).validity, Validity::Reserved);
        assert_eq!(
            Quality::from_sv(0x00000003).validity,
            Validity::Questionable
        );
    }

    #[test]
    fn test_quality_from_sv_detail_and_flag_bits() {
        assert!(Quality::from_sv(1 << 2).overflow);
        assert!(Quality::from_sv(1 << 3).out_of_range);
        assert!(Quality::from_sv(1 << 4).bad_reference);
        assert!(Quality::from_sv(1 << 5).oscillatory);
        assert!(Quality::from_sv(1 << 6).failure);
        assert!(Quality::from_sv(1 << 7).old_data);
        assert!(Quality::from_sv(1 << 8).inconsistent);
        assert!(Quality::from_sv(1 << 9).inaccurate);
        assert!(Quality::from_sv(1 << 10).source_substituted);
        assert!(Quality::from_sv(1 << 11).test);
        assert!(Quality::from_sv(1 << 12).operator_blocked);
    }

    #[test]
    fn test_quality_to_sv_roundtrip() {
        let quality = Quality {
            validity: Validity::Invalid,
            overflow: true,
            out_of_range: true,
            bad_reference: false,
            oscillatory: false,
            failure: false,
            old_data: false,
            inconsistent: false,
            inaccurate: false,
            source_substituted: false,
            test: true,
            operator_blocked: false,
        };

        let encoded = quality.to_sv();
        let decoded = Quality::from_sv(encoded);
        assert_eq!(quality, decoded);
    }
}
