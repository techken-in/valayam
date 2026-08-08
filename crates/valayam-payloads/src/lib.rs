//! Exploitation handlers — interactive bind and reverse shell listeners.
//!
//! For RCE verification during red-team operations. Spawns async tasks
//! to manage TCP streams transparently.

pub mod handler;
