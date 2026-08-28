use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use valayam_models::finding::FindingOwned;

#[derive(Debug, Serialize, Deserialize)]
pub enum FindingStatus {
    New,
    Resolved,
    Recurring,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DiffReport {
    pub new: Vec<FindingOwned>,
    pub resolved: Vec<FindingOwned>,
    pub recurring: Vec<FindingOwned>,
}

impl DiffReport {
    pub fn compare(baseline: &[FindingOwned], current: &[FindingOwned]) -> Self {
        let mut report = DiffReport::default();
        
        let mut baseline_map = HashMap::new();
        for finding in baseline {
            baseline_map.insert(finding.dedup_key(), finding.clone());
        }
        
        let mut current_map = HashMap::new();
        for finding in current {
            current_map.insert(finding.dedup_key(), finding.clone());
        }
        
        let baseline_keys: HashSet<_> = baseline_map.keys().cloned().collect();
        let current_keys: HashSet<_> = current_map.keys().cloned().collect();
        
        // New findings: in current, not in baseline
        for key in current_keys.difference(&baseline_keys) {
            if let Some(f) = current_map.get(key) {
                report.new.push(f.clone());
            }
        }
        
        // Resolved findings: in baseline, not in current
        for key in baseline_keys.difference(&current_keys) {
            if let Some(f) = baseline_map.get(key) {
                report.resolved.push(f.clone());
            }
        }
        
        // Recurring findings: in both
        for key in baseline_keys.intersection(&current_keys) {
            if let Some(f) = current_map.get(key) {
                report.recurring.push(f.clone());
            }
        }
        
        report
    }
}
