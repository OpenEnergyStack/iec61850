pub mod client;
pub mod error;
mod mms;
pub mod types;

// Re-export codec modules at the crate root so the public API stays stable
// regardless of internal file organization.
pub use client::*;
pub use error::*;
pub use types::*;
