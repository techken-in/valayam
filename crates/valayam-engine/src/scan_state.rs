//! ScanState — Tracks the pause/resume status of a scan execution.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Documentation for this item.
pub enum ScanState {
    /// Documentation for this item.
    Running,
    /// Documentation for this item.
    Paused,
}
