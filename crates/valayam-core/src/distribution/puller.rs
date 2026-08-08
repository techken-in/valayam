use anyhow::{Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::Client;
use std::fs;
use std::path::PathBuf;

/// A puller that fetches signed Wasm plugins via HTTP and caches them locally.
pub struct PluginPuller {
    client: Client,
    cache_dir: PathBuf,
    public_key: Option<VerifyingKey>,
}

impl PluginPuller {
    /// Create a new PluginPuller.
    pub fn new(cache_dir: PathBuf, public_key_bytes: Option<&[u8; 32]>) -> Result<Self> {
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }

        let public_key = match public_key_bytes {
            Some(bytes) => Some(VerifyingKey::from_bytes(bytes)?),
            None => None,
        };

        Ok(Self {
            client: Client::builder()
                .user_agent("valayam-plugin-puller/0.1")
                .build()?,
            cache_dir,
            public_key,
        })
    }

    /// Pull a plugin from a remote URL.
    /// If the URL starts with `oci://`, it acts as an OCI client.
    /// If `public_key` is set on the puller, it verifies the Ed25519 signature.
    pub async fn pull(&self, plugin_name: &str, url: &str) -> Result<PathBuf> {
        let dest_path = self.cache_dir.join(format!("{}.wasm", plugin_name));

        let bytes = if url.starts_with("oci://") {
            tracing::info!(url = %url, plugin = %plugin_name, "Downloading plugin from OCI registry");
            let url_no_scheme = url.strip_prefix("oci://").unwrap_or(url);
            // Format: registry.com/repo/name:tag
            let parts: Vec<&str> = url_no_scheme.splitn(2, '/').collect();
            if parts.len() != 2 {
                anyhow::bail!("Invalid OCI URL format. Expected oci://registry/repo:tag");
            }
            let registry = parts[0];
            let repo_and_tag = parts[1];

            let (repo, tag) = if let Some(idx) = repo_and_tag.find(':') {
                (&repo_and_tag[..idx], &repo_and_tag[idx + 1..])
            } else {
                (repo_and_tag, "latest")
            };

            let config = crate::config::CoreConfig::from_env();
            let username = config.valayam_registry_user;
            let password = config.valayam_registry_pass;

            let oci_client = super::oci_client::OciClient::new(
                registry,
                username.as_deref(),
                password.as_deref(),
            )?;
            let manifest = oci_client.get_manifest(repo, tag).await?;

            // Assume the first layer is the plugin
            if manifest.layers.is_empty() {
                anyhow::bail!("OCI artifact has no layers");
            }
            let layer = &manifest.layers[0];

            // Extract signature from annotations if present
            let mut signature_header = None;
            if let Some(ann) = &layer.annotations {
                if let Some(sig) = ann.get("org.valayam.plugin.signature") {
                    signature_header = Some(reqwest::header::HeaderValue::from_str(sig)?);
                }
            }

            let blob = oci_client.get_blob(repo, &layer.digest).await?;
            (blob, signature_header)
        } else {
            tracing::info!(url = %url, plugin = %plugin_name, "Downloading plugin via HTTP");
            let response = self.client.get(url).send().await?.error_for_status()?;
            let signature_header = response.headers().get("x-plugin-signature").cloned();
            let bytes = response.bytes().await?;
            (bytes.to_vec(), signature_header)
        };

        // Verify signature if a public key is configured
        if let Some(pub_key) = &self.public_key {
            let sig_val = bytes.1.context("Missing signature from remote")?;
            let sig_hex = sig_val
                .to_str()
                .context("Invalid characters in signature header")?;
            let sig_bytes = hex::decode(sig_hex).context("Failed to decode hex signature")?;
            let signature =
                Signature::from_slice(&sig_bytes).context("Invalid signature format length")?;

            pub_key
                .verify_strict(&bytes.0, &signature)
                .context("Plugin signature verification failed!")?;
            tracing::info!(plugin = %plugin_name, "Signature verified successfully");
        } else {
            tracing::warn!("No public key configured. Bypassing signature verification.");
        }

        fs::write(&dest_path, &bytes.0)?;
        tracing::info!(plugin = %plugin_name, path = %dest_path.display(), "Plugin cached successfully");

        Ok(dest_path)
    }
}
