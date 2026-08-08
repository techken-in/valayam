//! Open port fingerprinting — TCP probing and service identification.
//!
//! Safe TCP probing for exposed administrative services (SSH, Telnet, DB ports).
//! Banner grabbing to identify listening service versions.
//! Cross-references discovered versions with the offline vulnerability database.

pub mod executor;
pub mod ports;
