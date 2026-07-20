use serde::{Deserialize, Serialize};

use crate::types::{IECData, Quality, Timestamp};

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

/// A single sampled value with its quality
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// The quality flags
    pub quality: Quality,
    /// voltage or current value
    pub value: f32,
    /// The scale factor for the value, e.g. 0.01 for voltage, 0.0001 for current
    pub scale_factor: f32,
}

impl Sample {
    pub fn new(value: f32, quality: Quality, scale_factor: f32) -> Self {
        Sample {
            quality,
            value,
            scale_factor,
        }
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SavDataSetConfig {
    pub config: Vec<SavValueConfig>,
}

impl SavDataSetConfig {
    pub fn new(config: Vec<SavValueConfig>) -> Self {
        SavDataSetConfig { config }
    }

    pub fn le_92() -> Self {
        SavDataSetConfig {
            config: vec![
                SavValueConfig::new(0.0001), // Phase A Current
                SavValueConfig::new(0.0001), // Phase B Current
                SavValueConfig::new(0.0001), // Phase C Current
                SavValueConfig::new(0.0001), // Neutral Current
                SavValueConfig::new(0.01),   // Phase A Voltage
                SavValueConfig::new(0.01),   // Phase B Voltage
                SavValueConfig::new(0.01),   // Phase C Voltage
                SavValueConfig::new(0.01),   // Neutral Voltage
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SavValueConfig {
    pub scale_factor: f32,
}

impl SavValueConfig {
    pub fn new(scale_factor: f32) -> Self {
        SavValueConfig { scale_factor }
    }
}
