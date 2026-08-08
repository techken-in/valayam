use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Documentation for this item.
pub struct PluginManifest {
    /// Documentation for this item.
    pub name: String,
    /// Documentation for this item.
    pub version: String,
    /// Documentation for this item.
    pub author: Option<String>,
    /// Documentation for this item.
    pub runtime: String, // "grpc", "wasm"
    /// Documentation for this item.
    pub language: String,
    /// Documentation for this item.
    pub entrypoint: String,
    /// Documentation for this item.
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug)]
/// Documentation for this item.
pub enum VpaError {
    /// Documentation for this item.
    IoError(std::io::Error),
    /// Documentation for this item.
    ZipError(zip::result::ZipError),
    /// Documentation for this item.
    YamlError(serde_yaml::Error),
    /// Documentation for this item.
    InvalidManifest(String),
    /// Documentation for this item.
    ExtractionError(String),
}

impl From<std::io::Error> for VpaError {
    fn from(e: std::io::Error) -> Self {
        VpaError::IoError(e)
    }
}
impl From<zip::result::ZipError> for VpaError {
    fn from(e: zip::result::ZipError) -> Self {
        VpaError::ZipError(e)
    }
}
impl From<serde_yaml::Error> for VpaError {
    fn from(e: serde_yaml::Error) -> Self {
        VpaError::YamlError(e)
    }
}

/// Extract a VPA archive securely to the given cache directory, and return the loaded Manifest and extraction path.
/// If `pub_key` is provided, it enforces that `signature.sig` exists and is valid.
/// If `skip_extract_if_cache_hit` is true and the entrypoint WASM matching the manifest hash exists in the wasm_cache,
/// it returns the cached path without extracting.
pub fn extract_vpa(
    archive_path: &Path,
    cache_base_dir: &Path,
    pub_key: Option<&[u8; 32]>,
    skip_extract_if_cache_hit: bool,
) -> Result<(PluginManifest, PathBuf), VpaError> {
    // First, read the manifest from the VPA without fully extracting to check cache
    let file = fs::File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;

    let mut manifest_bytes: Option<Vec<u8>> = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.name() == "plugin.yaml" {
            let mut content = Vec::new();
            std::io::copy(&mut entry, &mut content)?;
            manifest_bytes = Some(content);
            break;
        }
    }

    let manifest_bytes = manifest_bytes.ok_or_else(|| {
        VpaError::InvalidManifest("plugin.yaml is missing from the VPA archive".to_string())
    })?;
    let manifest: PluginManifest = serde_yaml::from_slice(&manifest_bytes)?;

    // Check cache-hit: if offline mode and wasm entrypoint exists in cache with matching hash
    if skip_extract_if_cache_hit {
        let wasm_cache_dir = cache_base_dir.join("wasm_cache");
        let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
        let cached_entrypoint = wasm_cache_dir
            .join(&manifest_hash)
            .join(&manifest.entrypoint);

        if cached_entrypoint.exists() {
            // Return manifest and the cached extraction directory (minimal, just for compat)
            let extract_dir = wasm_cache_dir.join(&manifest_hash);
            fs::create_dir_all(&extract_dir)?;
            // Write manifest for compatibility
            fs::write(extract_dir.join("plugin.yaml"), &manifest_bytes)?;
            return Ok((manifest, extract_dir));
        }
    }

    // Full extraction
    let file = fs::File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;

    // Create a unique extraction directory for this VPA
    let file_stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin");
    let extract_dir = cache_base_dir.join(format!(
        "{}_{}",
        file_stem,
        &uuid::Uuid::new_v4().to_string().replace("-", "")[..8]
    ));

    fs::create_dir_all(&extract_dir)?;

    let mut signature_bytes: Option<Vec<u8>> = None;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue, // Skip suspicious paths
        };

        // Prevent ZipSlip (enclosed_name already does this securely in `zip` crate, but we are explicit)
        let out_full_path = extract_dir.join(&outpath);

        if (*file.name()).ends_with('/') {
            fs::create_dir_all(&out_full_path)?;
        } else {
            if let Some(p) = out_full_path.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }

            let mut outfile = fs::File::create(&out_full_path)?;
            std::io::copy(&mut file, &mut outfile)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&out_full_path, fs::Permissions::from_mode(mode))?;
                }
            }

            if outpath.to_string_lossy() == "signature.sig" {
                signature_bytes = Some(fs::read(&out_full_path)?);
            }
        }
    }

    if let Some(pk) = pub_key {
        let sig = signature_bytes.ok_or_else(|| {
            VpaError::ExtractionError("VPA requires a signature.sig but none was found".to_string())
        })?;
        if sig.len() != 64 {
            return Err(VpaError::ExtractionError(
                "Invalid signature length".to_string(),
            ));
        }

        // We verify the signature against the raw bytes of plugin.yaml
        let manifest_content = fs::read(extract_dir.join("plugin.yaml"))?;
        let sig_array: [u8; 64] = sig.try_into().map_err(|_: Vec<u8>| {
            VpaError::ExtractionError("signature length mismatch after validation".to_string())
        })?;

        let is_valid = valayam_crypto::PluginCrypto::verify(pk, &manifest_content, &sig_array)
            .map_err(|e| {
                VpaError::ExtractionError(format!("Signature verification failed: {}", e))
            })?;

        if !is_valid {
            return Err(VpaError::ExtractionError(
                "Signature validation failed: untrusted plugin".to_string(),
            ));
        }
    }

    // In offline mode, also cache the entrypoint wasm to wasm_cache for future cache hits
    if skip_extract_if_cache_hit {
        let wasm_cache_dir = cache_base_dir.join("wasm_cache");
        let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
        let cache_target_dir = wasm_cache_dir.join(&manifest_hash);
        let entrypoint_src = extract_dir.join(&manifest.entrypoint);

        if entrypoint_src.exists() {
            fs::create_dir_all(&cache_target_dir)?;
            fs::copy(&entrypoint_src, cache_target_dir.join(&manifest.entrypoint))?;
            // Also copy plugin.yaml for verification
            fs::copy(
                extract_dir.join("plugin.yaml"),
                cache_target_dir.join("plugin.yaml"),
            )?;
        }
    }

    Ok((manifest, extract_dir))
}
