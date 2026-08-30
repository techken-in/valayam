//! Scan state persistence for Valayam.
//!
//! `StateDB` stores and loads scan snapshots as bincode files with atomic writes.
//! Supports pause/resume workflows across CLI, agent, and distributed nodes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanCheckpoint {
    pub id: String,
    pub pending_tasks: Vec<(String, String)>,
    pub completed_tasks: Vec<(String, String)>,
    pub finding_count: usize,
    pub severity_counts: HashMap<String, usize>,
    pub started_at: u64,
    pub updated_at: u64,
}

pub struct StateDB {
    base_dir: PathBuf,
}

impl StateDB {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> std::io::Result<Self> {
        let path = base_dir.as_ref().to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self { base_dir: path })
    }

    pub fn save_state(
        &self,
        state_id: &str,
        pending: &[(String, String)],
        completed: &[(String, String)],
        finding_count: usize,
        severity_counts: HashMap<String, usize>,
    ) -> std::io::Result<()> {
        let snapshot = ScanCheckpoint {
            id: state_id.to_string(),
            pending_tasks: pending.to_vec(),
            completed_tasks: completed.to_vec(),
            finding_count,
            severity_counts,
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let file_path = self.base_dir.join(format!("{}.bin", state_id));
        let tmp_path = self.base_dir.join(format!("{}.bin.tmp", state_id));

        let data = bincode::serialize(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Atomic write: write to temp file first, then rename over the real file
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, &file_path)?;

        Ok(())
    }

    pub fn load_state(&self, state_id: &str) -> std::io::Result<Option<ScanCheckpoint>> {
        let file_path = self.base_dir.join(format!("{}.bin", state_id));

        if !file_path.exists() {
            return Ok(None);
        }

        let data = fs::read(file_path)?;
        let snapshot: ScanCheckpoint = bincode::deserialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some(snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_checkpoint_serde() -> anyhow::Result<()> {
        let mut severity_counts = HashMap::new();
        severity_counts.insert("high".to_string(), 1);
        let snapshot = ScanCheckpoint {
            id: "test-scan-001".into(),
            pending_tasks: vec![
                ("https://example.com".into(), "templates/x.yaml".into()),
                ("https://test.com".into(), "templates/y.yaml".into()),
            ],
            completed_tasks: vec![("https://done.com".into(), "templates/z.yaml".into())],
            finding_count: 5,
            severity_counts,
            started_at: 1700000000,
            updated_at: 1700000000,
        };
        let data = bincode::serialize(&snapshot)?;
        let back: ScanCheckpoint = bincode::deserialize(&data)?;
        assert_eq!(back.id, "test-scan-001");
        assert_eq!(back.pending_tasks.len(), 2);
        assert_eq!(back.finding_count, 5);
        assert_eq!(back.started_at, 1700000000);
        Ok(())
    }

    #[test]
    fn test_scan_checkpoint_empty_lists() -> anyhow::Result<()> {
        let snapshot = ScanCheckpoint {
            id: "empty-scan".into(),
            pending_tasks: vec![],
            completed_tasks: vec![],
            finding_count: 0,
            severity_counts: HashMap::new(),
            started_at: 1700000000,
            updated_at: 1700000000,
        };
        let data = bincode::serialize(&snapshot)?;
        assert!(!data.is_empty());
        Ok(())
    }

    #[test]
    fn test_state_db_creates_dir() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let nested = dir.path().join("sub").join("state");
        let db = StateDB::new(&nested)?;
        assert!(nested.exists());
        drop(db);
        Ok(())
    }

    #[test]
    fn test_state_save_and_load() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = StateDB::new(dir.path())?;
        db.save_state(
            "scan-1",
            &[("https://target.com".into(), "template.yaml".into())],
            &[],
            0,
            HashMap::new(),
        )?;
        let loaded = db.load_state("scan-1")?;
        assert!(loaded.is_some());
        let snapshot = loaded.unwrap();
        assert_eq!(
            snapshot.pending_tasks,
            vec![(
                "https://target.com".to_string(),
                "template.yaml".to_string()
            )]
        );
        assert!(snapshot.completed_tasks.is_empty());
        Ok(())
    }

    #[test]
    fn test_state_load_nonexistent() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = StateDB::new(dir.path())?;
        let loaded = db.load_state("nonexistent")?;
        assert!(loaded.is_none());
        Ok(())
    }

    #[test]
    fn test_state_overwrite() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = StateDB::new(dir.path())?;
        db.save_state(
            "s",
            &[("https://old.com".into(), "tmpl1".into())],
            &[],
            0,
            HashMap::new(),
        )?;
        db.save_state(
            "s",
            &[("https://new.com".into(), "tmpl2".into())],
            &[("https://old.com".into(), "tmpl1".into())],
            1,
            HashMap::new(),
        )?;
        let snapshot = db.load_state("s")?.unwrap();
        assert_eq!(
            snapshot.pending_tasks,
            vec![("https://new.com".to_string(), "tmpl2".to_string())]
        );
        assert_eq!(
            snapshot.completed_tasks,
            vec![("https://old.com".to_string(), "tmpl1".to_string())]
        );
        assert_eq!(snapshot.finding_count, 1);
        Ok(())
    }
}
