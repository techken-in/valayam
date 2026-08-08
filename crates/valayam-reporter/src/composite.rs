use valayam_engine::traits::{FindingOwned, Reporter};

/// Fans out findings to multiple reporters (e.g., Console + JSON simultaneously).
pub struct CompositeReporter {
    reporters: Vec<Box<dyn Reporter>>,
}

impl CompositeReporter {
    pub fn new(reporters: Vec<Box<dyn Reporter>>) -> Self {
        Self { reporters }
    }
}

#[async_trait::async_trait]
impl Reporter for CompositeReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error> {
        for reporter in &self.reporters {
            if let Err(e) = reporter.process_finding(finding).await {
                tracing::error!(reporter = ?std::any::type_name_of_val(reporter), error = %e, "reporter failed");
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), std::io::Error> {
        for reporter in &self.reporters {
            let _ = reporter.flush().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct MockReporter {
        called: Arc<AtomicBool>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl Reporter for MockReporter {
        async fn process_finding(&self, _: &FindingOwned) -> Result<(), std::io::Error> {
            self.called.store(true, Ordering::SeqCst);
            if self.fail {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "mock error"))
            } else {
                Ok(())
            }
        }
    }

    fn sample_finding() -> FindingOwned {
        FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "composite-001".into(),
            template_name: "Composite Test".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "match".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_composite_reporter_delegates_to_inner() {
        let called = Arc::new(AtomicBool::new(false));
        let reporter = MockReporter {
            called: called.clone(),
            fail: false,
        };
        let composite = CompositeReporter::new(vec![Box::new(reporter)]);
        let result = composite.process_finding(&sample_finding()).await;
        assert!(result.is_ok());
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_composite_reporter_multiple_reporters() {
        let called1 = Arc::new(AtomicBool::new(false));
        let called2 = Arc::new(AtomicBool::new(false));
        let r1 = MockReporter {
            called: called1.clone(),
            fail: false,
        };
        let r2 = MockReporter {
            called: called2.clone(),
            fail: false,
        };
        let composite = CompositeReporter::new(vec![Box::new(r1), Box::new(r2)]);
        let result = composite.process_finding(&sample_finding()).await;
        assert!(result.is_ok());
        assert!(called1.load(Ordering::SeqCst));
        assert!(called2.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_composite_reporter_one_fails_others_still_called() {
        let called2 = Arc::new(AtomicBool::new(false));
        let r1 = MockReporter {
            called: Arc::new(AtomicBool::new(true)),
            fail: true,
        };
        let r2 = MockReporter {
            called: called2.clone(),
            fail: false,
        };
        let composite = CompositeReporter::new(vec![Box::new(r1), Box::new(r2)]);
        let result = composite.process_finding(&sample_finding()).await;
        assert!(result.is_ok());
        assert!(called2.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_composite_reporter_flush() {
        let called = Arc::new(AtomicBool::new(false));
        let reporter = MockReporter {
            called: called.clone(),
            fail: false,
        };
        let composite = CompositeReporter::new(vec![Box::new(reporter)]);
        let result = composite.flush().await;
        assert!(result.is_ok());
    }
}
