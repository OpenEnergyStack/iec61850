use serde::{Deserialize, Serialize};

use crate::types::{AnalogueValue, Check, Originator, Tcmd, Timestamp};

/// Control value for a control action. The variant must match the data object's `ctlVal` type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtlVal {
    /// For SPC and DPC common data classes — BOOLEAN
    Bool(bool),
    /// For INC, ENC and ISC common data classes — direct INT32
    Int(i32),
    /// For APC common data classes — AnalogueValue structure (FLOAT32 or INT32)
    Analogue(AnalogueValue),
    /// For BSC and BAC common data classes — 2-bit coded enum bit-string
    BinaryStep(Tcmd),
}

/// Additional cause for a rejected control commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddCause {
    Unknown = 0,
    NotSupported = 1,
    BlockedBySwitchingHierarchy = 2,
    SelectFailed = 3,
    InvalidPosition = 4,
    PositionReached = 5,
    ParameterChangeInExecution = 6,
    StepLimit = 7,
    BlockedByMode = 8,
    BlockedByProcess = 9,
    BlockedByInterlocking = 10,
    BlockedBySynchrocheck = 11,
    CommandAlreadyInExecution = 12,
    BlockedByHealth = 13,
    OneOfNControl = 14,
    AbortionByCancel = 15,
    TimeLimitOver = 16,
    AbortionByTrip = 17,
    ObjectNotSelected = 18,
    ObjectAlreadySelected = 19,
    NoAccessAuthority = 20,
    EndedWithOvershoot = 21,
    AbortionDueToDeviation = 22,
    AbortionByCommunicationLoss = 23,
    BlockedByCommand = 24,
    None = 25,
    InconsistentParameters = 26,
    LockedByOtherClient = 27,
}

impl AddCause {
    pub fn from_i64(v: i64) -> Self {
        match v {
            0 => Self::Unknown,
            1 => Self::NotSupported,
            2 => Self::BlockedBySwitchingHierarchy,
            3 => Self::SelectFailed,
            4 => Self::InvalidPosition,
            5 => Self::PositionReached,
            6 => Self::ParameterChangeInExecution,
            7 => Self::StepLimit,
            8 => Self::BlockedByMode,
            9 => Self::BlockedByProcess,
            10 => Self::BlockedByInterlocking,
            11 => Self::BlockedBySynchrocheck,
            12 => Self::CommandAlreadyInExecution,
            13 => Self::BlockedByHealth,
            14 => Self::OneOfNControl,
            15 => Self::AbortionByCancel,
            16 => Self::TimeLimitOver,
            17 => Self::AbortionByTrip,
            18 => Self::ObjectNotSelected,
            19 => Self::ObjectAlreadySelected,
            20 => Self::NoAccessAuthority,
            21 => Self::EndedWithOvershoot,
            22 => Self::AbortionDueToDeviation,
            23 => Self::AbortionByCommunicationLoss,
            24 => Self::BlockedByCommand,
            25 => Self::None,
            26 => Self::InconsistentParameters,
            27 => Self::LockedByOtherClient,
            _ => Self::Unknown,
        }
    }
}

/// Response to a control service request (`operate`, `select-with-value`)
/// A positive response has `add_cause = None`.  A negative response
/// has `add_cause = Some(cause)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlResponse {
    /// IEC 61850 reference to the control object (e.g. `"IEDLD/CSWI1.Pos"`)
    pub ctrl_obj_ref: String,
    /// Echoed control value
    pub ctl_val: CtlVal,
    /// Echoed time-activated control time — `None` for immediate execution
    pub oper_tm: Option<Timestamp>,
    /// Echoed originator
    pub origin: Originator,
    /// Echoed control sequence number
    pub ctl_num: u8,
    /// Echoed timestamp
    pub t: Timestamp,
    /// Echoed test flag
    pub test: bool,
    /// Echoed check conditions
    pub check: Check,
    /// `None` for a positive response; `Some(cause)` for a negative one.
    pub add_cause: Option<AddCause>,
}

/// Response to a cancel service request. A positive response has `add_cause = None`.  
/// A negative response has `add_cause = Some(cause)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CancelResponse {
    pub ctrl_obj_ref: String,
    pub ctl_val: CtlVal,
    pub oper_tm: Option<Timestamp>,
    pub origin: Originator,
    pub ctl_num: u8,
    pub t: Timestamp,
    pub test: bool,
    /// `None` for a positive response; `Some(cause)` for a negative one.
    pub add_cause: Option<AddCause>,
}

/// Parameters for a control service request (`operate`, `select-with-value`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlObject {
    /// IEC 61850 reference to the control object, e.g. `"IEDLD/CSWI1.Pos"`
    pub ctrl_obj_ref: String,
    /// Control value — type must match the controlled data object
    pub ctl_val: CtlVal,
    /// Time-activated control time — `None` for immediate execution
    pub oper_tm: Option<Timestamp>,
    /// Originator (orCat + orIdent)
    pub origin: Originator,
    /// Control sequence number (0–255)
    pub ctl_num: u8,
    /// Timestamp of the control request (UTC)
    pub t: Timestamp,
    /// Test mode flag — set to `true` for test commands
    pub test: bool,
    /// Interlocking / synchronism-check conditions
    pub check: Check,
}

/// Parameters for a cancel service request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CancelObject {
    /// IEC 61850 reference to the control object, e.g. `"IEDLD/CSWI1.Pos"`
    pub ctrl_obj_ref: String,
    /// Control value — type must match the controlled data object
    pub ctl_val: CtlVal,
    /// Time-activated control time — `None` for immediate execution
    pub oper_tm: Option<Timestamp>,
    /// Originator (orCat + orIdent)
    pub origin: Originator,
    /// Control sequence number (0–255)
    pub ctl_num: u8,
    /// Timestamp of the control request (UTC)
    pub t: Timestamp,
    /// Test mode flag — set to `true` for test commands
    pub test: bool,
}
