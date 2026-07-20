pub mod client;
pub mod rt_services;
pub mod server;
pub mod types;

// Re-export codec modules at the crate root so the public API stays stable
// regardless of internal file organization.
pub use rt_services::decode_goose;
pub use rt_services::decode_smv;
pub use rt_services::encode_goose;
pub use rt_services::encode_smv;
pub use rt_services::ethernet_header;

// Flat re-exports of the most commonly used functions for shorter call sites.
pub use rt_services::decode_goose::{decode_goose_pdu, is_goose_frame};
pub use rt_services::decode_smv::{decode_smv, is_smv_frame};
pub use rt_services::encode_goose::{encode_ethernet_header, encode_goose};
pub use rt_services::encode_smv::encode_smv;
pub use rt_services::ethernet_header::decode_ethernet_header;
