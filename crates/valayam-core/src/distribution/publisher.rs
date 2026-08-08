use super::oci_client::{OciClient, OciDescriptor, OciManifest};
use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Documentation for this item.
pub struct PluginPublisher {
    client: OciClient,
}

impl PluginPublisher {
    /// Documentation for this item.
    pub fn new(registry: &str, username: Option<&str>, password: Option<&str>) -> Result<Self> {
        let client = OciClient::new(registry, username, password)?;
        Ok(Self { client })
    }

    /// Push a local .vpa plugin file to an OCI registry
    pub async fn push(
        &self,
        repo: &str,
        tag: &str,
        vpa_path: &Path,
        signature: Option<&str>,
    ) -> Result<()> {
        if !vpa_path.exists() {
            anyhow::bail!("Plugin archive {} does not exist", vpa_path.display());
        }

        let blob = std::fs::read(vpa_path)?;

        // Calculate SHA256 digest
        let mut hasher = Sha256::new();
        hasher.update(&blob);
        let hash = hasher.finalize();
        let digest_str = format!("sha256:{:x}", hash);
        let size = blob.len() as u64;

        tracing::info!(repo = %repo, tag = %tag, digest = %digest_str, size = %size, "Pushing plugin blob to OCI registry");

        // Push the blob
        self.client
            .push_blob(repo, &blob, &digest_str)
            .await
            .context("Failed to push plugin blob")?;

        // Prepare annotations
        let mut annotations = HashMap::new();
        annotations.insert(
            "org.valayam.plugin.version".to_string(),
            "1.0.0".to_string(),
        );

        if let Some(sig) = signature {
            annotations.insert("org.valayam.plugin.signature".to_string(), sig.to_string());
        }

        // Generate valid OCI Config blob
        let config_json = json!({
            "architecture": "wasm",
            "os": "wasi",
            "rootfs": {
                "type": "layers",
                "diff_ids": [digest_str.clone()]
            }
        });
        let config_data_str =
            serde_json::to_string(&config_json).unwrap_or_else(|_| "{}".to_string());
        let config_data = config_data_str.as_bytes();

        let mut config_hasher = Sha256::new();
        config_hasher.update(config_data);
        let config_digest_str = format!("sha256:{:x}", config_hasher.finalize());
        let config_size = config_data.len() as u64;

        // Create OCI Manifest
        let manifest = OciManifest {
            schema_version: 2,
            media_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
            config: OciDescriptor {
                media_type: "application/vnd.valayam.plugin.config.v1+json".to_string(),
                digest: config_digest_str.clone(),
                size: config_size,
                annotations: None,
            },
            layers: vec![OciDescriptor {
                media_type: "application/vnd.valayam.plugin.layer.v1+zip".to_string(),
                digest: digest_str.clone(),
                size,
                annotations: Some(annotations),
            }],
            annotations: None,
        };

        tracing::info!("Pushing plugin config blob to OCI registry");
        self.client
            .push_blob(repo, config_data, &config_digest_str)
            .await
            .context("Failed to push config blob")?;

        tracing::info!("Pushing manifest to OCI registry");
        self.client
            .push_manifest(repo, tag, &manifest)
            .await
            .context("Failed to push manifest")?;

        tracing::info!(repo = %repo, tag = %tag, "Successfully pushed Valayam plugin to OCI registry");

        Ok(())
    }
}
