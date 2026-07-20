use serde::{Deserialize, Serialize};

use crate::types::{EntryTime, IECData, Timestamp};

/// Maps to the BIT STRING `TrgOps` attribute. Bit 0 is reserved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TriggerOptions {
    /// Data change (dchg) — bit 0
    pub data_change: bool,
    /// Quality change (qchg) — bit 1
    pub quality_change: bool,
    /// Data update (dupd) — bit 2
    pub data_update: bool,
    /// Integrity period (period) — bit 3
    pub integrity: bool,
    /// General interrogation (gi) — bit 4
    pub general_interrogation: bool,
}

impl TriggerOptions {
    pub fn to_bit_string(&self) -> String {
        format!(
            "{}{}{}{}{}",
            if self.data_change { '1' } else { '0' },
            if self.quality_change { '1' } else { '0' },
            if self.data_update { '1' } else { '0' },
            if self.integrity { '1' } else { '0' },
            if self.general_interrogation { '1' } else { '0' },
        )
    }

    pub fn from_bit_string(bits: &str) -> Self {
        let b: Vec<char> = bits.chars().collect();
        let bit = |i: usize| b.get(i).is_some_and(|&c| c == '1');
        TriggerOptions {
            data_change: bit(0),
            quality_change: bit(1),
            data_update: bit(2),
            integrity: bit(3),
            general_interrogation: bit(4),
        }
    }
}

/// Optional fields included in each report entry (OptFlds), IEC 61850-7-2 Table 97
///
/// Maps to the BIT STRING `OptFlds` attribute. Bit 0 is reserved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReportOptFields {
    /// Sequence number — bit 1
    pub sequence_number: bool,
    /// Report timestamp — bit 2
    pub report_time_stamp: bool,
    /// Reason for inclusion — bit 3
    pub reason_for_inclusion: bool,
    /// Data-set name — bit 4
    pub data_set_name: bool,
    /// Data reference — bit 5
    pub data_reference: bool,
    /// Buffer overflow — bit 6
    pub buffer_overflow: bool,
    /// Entry ID — bit 7
    pub entry_id: bool,
    /// Configuration revision — bit 8
    pub conf_revision: bool,
    /// Segmentation — bit 9
    pub segmentation: bool,
}

impl ReportOptFields {
    /// Decodes from a binary string produced by [`to_bit_string`].
    pub fn from_bit_string(bits: &str) -> Self {
        let b: Vec<char> = bits.chars().collect();
        let bit = |i: usize| b.get(i).is_some_and(|&c| c == '1');
        ReportOptFields {
            sequence_number: bit(1),
            report_time_stamp: bit(2),
            reason_for_inclusion: bit(3),
            data_set_name: bit(4),
            data_reference: bit(5),
            buffer_overflow: bit(6),
            entry_id: bit(7),
            conf_revision: bit(8),
            segmentation: bit(9),
        }
    }

    /// Encodes as a 10-character binary string (bit 0 reserved = '0').
    pub fn to_bit_string(&self) -> String {
        format!(
            "0{}{}{}{}{}{}{}{}{}",
            if self.sequence_number { '1' } else { '0' },
            if self.report_time_stamp { '1' } else { '0' },
            if self.reason_for_inclusion { '1' } else { '0' },
            if self.data_set_name { '1' } else { '0' },
            if self.data_reference { '1' } else { '0' },
            if self.buffer_overflow { '1' } else { '0' },
            if self.entry_id { '1' } else { '0' },
            if self.conf_revision { '1' } else { '0' },
            if self.segmentation { '1' } else { '0' },
        )
    }
}

/// Optional fields for an Unbuffered Report Control Block (URCB).
///
/// Same bit layout as [`ReportOptFields`] but `buffer_overflow` (bit 6) and
/// `entry_id` (bit 7) are not applicable to unbuffered reports and are always
/// encoded as `0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct UnbufferedReportOptFields {
    /// Sequence number — bit 1
    pub sequence_number: bool,
    /// Report timestamp — bit 2
    pub report_time_stamp: bool,
    /// Reason for inclusion — bit 3
    pub reason_for_inclusion: bool,
    /// Data-set name — bit 4
    pub data_set_name: bool,
    /// Data reference — bit 5
    pub data_reference: bool,
    /// Configuration revision — bit 8
    pub conf_revision: bool,
    /// Segmentation — bit 9
    pub segmentation: bool,
}

impl UnbufferedReportOptFields {
    /// Decodes from a binary string. Bits 0 (reserved), 6 (buffer_overflow), 7 (entry_id) are ignored.
    pub fn from_bit_string(bits: &str) -> Self {
        let b: Vec<char> = bits.chars().collect();
        let bit = |i: usize| b.get(i).is_some_and(|&c| c == '1');
        UnbufferedReportOptFields {
            sequence_number: bit(1),
            report_time_stamp: bit(2),
            reason_for_inclusion: bit(3),
            data_set_name: bit(4),
            data_reference: bit(5),
            // bit 6 (buffer_overflow) and bit 7 (entry_id) not applicable to URCB
            conf_revision: bit(8),
            segmentation: bit(9),
        }
    }

    /// Encodes as a 10-character binary string.
    /// Bit 0 (reserved), bit 6 (buffer_overflow) and bit 7 (entry_id) are always `0`.
    pub fn to_bit_string(&self) -> String {
        format!(
            "0{}{}{}{}{}00{}{}",
            if self.sequence_number { '1' } else { '0' },
            if self.report_time_stamp { '1' } else { '0' },
            if self.reason_for_inclusion { '1' } else { '0' },
            if self.data_set_name { '1' } else { '0' },
            if self.data_reference { '1' } else { '0' },
            if self.conf_revision { '1' } else { '0' },
            if self.segmentation { '1' } else { '0' },
        )
    }
}

/// Settings for a Buffered Report Control Block (BRCB) write operation
/// All fields are optional — set only the attributes you want to write.
/// Read-only attributes (`SqNum`, `TimeOfEntry`, `ConfRev`, `Owner`) are excluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SetBrcbValuesSettings {
    /// Report identifier (RptID)
    pub rpt_id: Option<String>,
    /// Report enable (RptEna)
    pub rpt_ena: Option<bool>,
    /// Dataset reference (DatSet)
    pub dat_set: Option<String>,
    /// Optional fields to include in each entry (OptFlds)
    pub opt_flds: Option<ReportOptFields>,
    /// Buffer time in milliseconds (BufTm)
    pub buf_tm: Option<u32>,
    /// Trigger options (TrgOps)
    pub trg_ops: Option<TriggerOptions>,
    /// Integrity period in milliseconds (IntgPd)
    pub intg_pd: Option<u32>,
    /// General interrogation trigger (GI) — write `true` to trigger
    pub gi: Option<bool>,
    /// Purge buffer (PurgeBuf) — write `true` to purge
    pub purge_buf: Option<bool>,
    /// Entry ID to resume reporting from (EntryID), raw bytes
    pub entry_id: Option<Vec<u8>>,
    /// Reservation time in seconds (ResvTms, BRCB only)
    pub resv_tms: Option<i16>,
}

/// Full set of attributes returned by reading a Buffered Report Control Block (BRCB).
/// Includes both settable and read-only attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BufferedReportControlBlock {
    /// Report identifier (RptID)
    pub rpt_id: String,
    /// Report enable (RptEna)
    pub rpt_ena: bool,
    /// Dataset reference (DatSet)
    pub dat_set: String,
    /// Configuration revision (ConfRev) — read-only
    pub conf_rev: u32,
    /// Optional fields (OptFlds)
    pub opt_flds: ReportOptFields,
    /// Buffer time in milliseconds (BufTm)
    pub buf_tm: u32,
    /// Sequence number (SqNum) — read-only
    pub sq_num: u32,
    /// Trigger options (TrgOps)
    pub trg_ops: TriggerOptions,
    /// Integrity period in milliseconds (IntgPd)
    pub intg_pd: u32,
    /// General interrogation (GI)
    pub gi: bool,
    /// Purge buffer (PurgeBuf)
    pub purge_buf: bool,
    /// Entry ID (EntryID), raw bytes
    pub entry_id: Vec<u8>,
    /// Time of entry (TimeOfEntry) — read-only
    pub time_of_entry: EntryTime,
    /// Reservation time in seconds (ResvTms)
    pub resv_tms: i16,
    /// Owner (Owner), raw bytes — read-only; absent on some servers
    pub owner: Option<Vec<u8>>,
}

/// Settings for an Unbuffered Report Control Block (URCB) write operation.
/// All fields are optional — set only the attributes you want to write.
/// Read-only attributes (`SqNum`, `ConfRev`, `Owner`) are excluded.
/// URCB has no `PurgeBuf`, no `EntryID`, and no `ResvTms`; instead it has `Resv` (boolean reservation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SetUrcbValuesSettings {
    /// Report identifier (RptID)
    pub rpt_id: Option<String>,
    /// Report enable (RptEna)
    pub rpt_ena: Option<bool>,
    /// Reservation flag (Resv) — reserve the URCB for exclusive use by this client
    pub resv: Option<bool>,
    /// Dataset reference (DatSet)
    pub dat_set: Option<String>,
    /// Optional fields to include in each entry (OptFlds)
    pub opt_flds: Option<UnbufferedReportOptFields>,
    /// Buffer time in milliseconds (BufTm)
    pub buf_tm: Option<u32>,
    /// Trigger options (TrgOps)
    pub trg_ops: Option<TriggerOptions>,
    /// Integrity period in milliseconds (IntgPd)
    pub intg_pd: Option<u32>,
    /// General interrogation trigger (GI) — write `true` to trigger
    pub gi: Option<bool>,
}

/// Full set of attributes returned by reading an Unbuffered Report Control Block (URCB).
/// Includes both settable and read-only attributes.
/// URCB has no `PurgeBuf`, `EntryID`, `TimeOfEntry`, or `ResvTms`; instead it has `Resv`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnbufferedReportControlBlock {
    /// Report identifier (RptID)
    pub rpt_id: String,
    /// Report enable (RptEna)
    pub rpt_ena: bool,
    /// Reservation flag (Resv) — exclusive use by this client
    pub resv: bool,
    /// Dataset reference (DatSet)
    pub dat_set: String,
    /// Configuration revision (ConfRev) — read-only
    pub conf_rev: u32,
    /// Optional fields (OptFlds)
    pub opt_flds: UnbufferedReportOptFields,
    /// Buffer time in milliseconds (BufTm)
    pub buf_tm: u32,
    /// Sequence number (SqNum) — read-only
    pub sq_num: u32,
    /// Trigger options (TrgOps)
    pub trg_ops: TriggerOptions,
    /// Integrity period in milliseconds (IntgPd)
    pub intg_pd: u32,
    /// General interrogation (GI)
    pub gi: bool,
    /// Owner (Owner), raw bytes — read-only; absent on some servers
    pub owner: Option<Vec<u8>>,
}

/// Whether a report originates from a Buffered (BRCB) or Unbuffered (URCB) report control block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReportType {
    Buffered,
    Unbuffered,
}

/// Per-dataset-member reason why it was included in the report (IEC 61850-7-2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReasonForInclusion {
    /// Data value changed (bit 1)
    pub data_change: bool,
    /// Quality changed (bit 2)
    pub quality_change: bool,
    /// Data updated (bit 3)
    pub data_update: bool,
    /// Integrity period scan (bit 4)
    pub integrity: bool,
    /// General interrogation (bit 5)
    pub general_interrogation: bool,
}

impl ReasonForInclusion {
    pub fn from_byte(byte: u8) -> Self {
        ReasonForInclusion {
            data_change: (byte & 0x40) != 0,
            quality_change: (byte & 0x20) != 0,
            data_update: (byte & 0x10) != 0,
            integrity: (byte & 0x08) != 0,
            general_interrogation: (byte & 0x04) != 0,
        }
    }
}

/// Header/metadata fields present in every IEC 61850 report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Whether this came from a BRCB or URCB
    pub report_type: ReportType,
    /// MMS control block reference extracted from `variable_access_specification`,
    /// e.g. `"BCUApp/LLN0$BR$BRCB01"`
    pub control_block_ref: String,
    /// Configured RptID string (data field 0, always present)
    pub rpt_id: String,
    /// Reported optional fields bitmask (data field 1, always present)
    pub opt_flds: ReportOptFields,
    /// Sequence number — present if `opt_flds.sequence_number`
    pub seq_num: Option<u32>,
    /// Report timestamp — present if `opt_flds.report_time_stamp`
    pub time_stamp: Option<Timestamp>,
    /// Dataset name — present if `opt_flds.data_set_name`
    pub dat_set: Option<String>,
    /// Buffer overflow (BRCB only) — present if `opt_flds.buffer_overflow`
    pub buf_ovfl: Option<bool>,
    /// Entry ID (BRCB only) — present if `opt_flds.entry_id`
    pub entry_id: Option<EntryTime>,
    /// Configuration revision — present if `opt_flds.conf_revision`
    pub conf_rev: Option<u32>,
    /// Sub-sequence number (segmentation) — present if `opt_flds.segmentation`
    pub sub_seq_num: Option<u32>,
    /// More segments follow (segmentation) — present if `opt_flds.segmentation`
    pub more_segments_follow: Option<bool>,
}

/// A single dataset member value included in a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportDataPoint {
    /// MMS data reference (e.g. `"BCUApp/XCBR1$ST$Pos"`) —
    /// present if `opt_flds.data_reference`
    pub data_reference: Option<String>,
    /// The decoded value
    pub value: IECData,
    /// Reason this member was included — present if `opt_flds.reason_for_inclusion`
    pub reason: Option<ReasonForInclusion>,
}

/// A fully decoded IEC 61850 report produced by `subscribe_reports`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub metadata: ReportMetadata,
    pub data: Vec<ReportDataPoint>,
}
