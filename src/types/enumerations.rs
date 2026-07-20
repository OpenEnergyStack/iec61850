use serde::{Deserialize, Serialize};

/// Step command direction for BSC (Binary Step Control) and BAC (Binary Analog Control).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tcmd {
    Stop = 0,
    Lower = 1,
    Higher = 2,
    Reserved = 3,
}

/// Originator category (orCat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OriginCategory {
    #[default]
    NotSupported = 0,
    BayControl = 1,
    StationControl = 2,
    RemoteControl = 3,
    AutomaticBay = 4,
    AutomaticStation = 5,
    AutomaticRemote = 6,
    Maintenance = 7,
    Process = 8,
}

impl OriginCategory {
    pub fn from_i64(v: i64) -> Self {
        match v {
            1 => Self::BayControl,
            2 => Self::StationControl,
            3 => Self::RemoteControl,
            4 => Self::AutomaticBay,
            5 => Self::AutomaticStation,
            6 => Self::AutomaticRemote,
            7 => Self::Maintenance,
            8 => Self::Process,
            _ => Self::NotSupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Validity {
    #[default]
    Good = 0,
    Invalid = 1,
    Reserved = 2,
    Questionable = 3,
}
