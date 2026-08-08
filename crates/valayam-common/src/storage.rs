//! Storage configuration for plugins (`.vpa`) and YAML templates.
//!
//! **Mirror of `platform-config::storage`** in the `valayam-platform` workspace.
//! The standalone CLI / engine (`valayam` repo) cannot depend on the platform
//! crates, so this module reproduces the identical env contract (same variable
//! names, same defaults, same validation) so both repos honor the same settings.
//!
//! If the contract changes, update *both* copies in lock-step.
//!
//! # Env contract
//! | Env var | Default | Notes |
//! |---|---|---|
//! | `VALAYAM_STORAGE_BACKEND` | `local` | `local` · `s3` · `minio` |
//! | `VALAYAM_PLUGIN_HOME` | `./data/plugins` if it exists, else `/var/lib/valayam/plugins` | plugins dir (legacy `plugins/` watch + bundle `plugins/`) |
//! | `VALAYAM_PLUGIN_CACHE` | `./data/plugin_cache` (or `$CACHE/valayam/plugins_cache`) | extracted WASM runtime cache |
//! | `VALAYAM_TEMPLATE_HOME` | `./data/templates` | raw YAML + versioned blobs |
//! | `VALAYAM_OFFLINE_MODE` | `false` | air-gapped mode; forces `local` backend |
//! | `VALAYAM_WORKER_PLUGIN_SOURCE` | `local` | `local` · `store` |
//! | `VALAYAM_PLUGIN_ENC_KEY` | — | base64-encoded 32-byte AES-256-GCM key for per-blob encryption at rest |
//! | `VALAYAM_S3_*` | — | endpoint/bucket/region/access-key/secret-key/force-path-style |

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Error returned when configuration cannot be resolved.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid VALAYAM_STORAGE_BACKEND value '{0}' (expected local|s3|minio)")]
    InvalidBackend(String),
    #[error("invalid VALAYAM_WORKER_PLUGIN_SOURCE value '{0}' (expected local|store)")]
    InvalidWorkerSource(String),
    #[error("S3/Minio backend selected but VALAYAM_S3_BUCKET is not set")]
    MissingBucket,
}

/// Where artifacts are physically persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    /// Local filesystem (or shared volume). Default; backwards-compatible.
    Local,
    /// Amazon S3 (or any S3-compatible endpoint).
    S3,
    /// Minio (S3-compatible API with path-style addressing).
    Minio,
}

impl std::str::FromStr for StorageBackend {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "s3" => Ok(Self::S3),
            "minio" => Ok(Self::Minio),
            "" => Ok(Self::default()),
            other => Err(StorageError::InvalidBackend(other.to_string())),
        }
    }
}

impl Default for StorageBackend {
    fn default() -> Self {
        StorageBackend::Local
    }
}

/// How a worker node acquires plugins for a scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerPluginSource {
    /// Watch a local directory of `.vpa`/`.wasm` files (legacy behaviour).
    Local,
    /// Fetch each job's referenced plugin from the [`StorageBackend`] on demand.
    Store,
}

impl std::str::FromStr for WorkerPluginSource {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "store" => Ok(Self::Store),
            "" => Ok(Self::default()),
            other => Err(StorageError::InvalidWorkerSource(other.to_string())),
        }
    }
}

impl Default for WorkerPluginSource {
    fn default() -> Self {
        WorkerPluginSource::Local
    }
}

/// S3/Minio connection details. Populated only when the backend is `S3` or `Minio`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Config {
    #[serde(default)]
    pub endpoint: Option<String>,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default = "default_force_path_style")]
    pub force_path_style: bool,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_force_path_style() -> bool {
    true
}

/// Resolved storage configuration. Built via [`StorageConfig::from_env`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub plugin_home: PathBuf,
    pub plugin_cache: PathBuf,
    pub template_home: PathBuf,
    pub offline: bool,
    pub worker_plugin_source: WorkerPluginSource,
    #[serde(default)]
    pub s3: Option<S3Config>,
    /// Optional base64-encoded 32-byte AES-256-GCM key for per-blob encryption at rest.
    /// When set, all `.vpa` blobs are encrypted before storage and decrypted on retrieval.
    #[serde(default)]
    pub plugin_enc_key: Option<String>,
}

impl StorageConfig {
    /// Resolve configuration from the environment, validating cross-field rules.
    ///
    /// - `offline=true` forces [`StorageBackend::Local`] (no network egress).
    /// - `s3`/`minio` backends require `VALAYAM_S3_BUCKET`.
    pub fn from_env() -> Result<Self, StorageError> {
        let mut backend: StorageBackend = std::env::var("VALAYAM_STORAGE_BACKEND")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.parse())
            .transpose()?
            .unwrap_or_default();

        let offline = env_flag("VALAYAM_OFFLINE_MODE");
        if offline {
            if backend != StorageBackend::Local {
                tracing::warn!(
                    "VALAYAM_OFFLINE_MODE is set — forcing storage backend to 'local' \
                     (requested '{:?}')",
                    backend
                );
            }
            backend = StorageBackend::Local;
        }

        let worker_plugin_source = std::env::var("VALAYAM_WORKER_PLUGIN_SOURCE")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.parse())
            .transpose()?
            .unwrap_or_default();

        let is_s3_like = matches!(backend, StorageBackend::S3 | StorageBackend::Minio);
        let s3 = if is_s3_like {
            let bucket = std::env::var("VALAYAM_S3_BUCKET").unwrap_or_default();
            if bucket.is_empty() {
                return Err(StorageError::MissingBucket);
            }
            Some(S3Config {
                endpoint: std::env::var("VALAYAM_S3_ENDPOINT").ok(),
                bucket,
                region: std::env::var("VALAYAM_S3_REGION")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(default_region),
                access_key: std::env::var("VALAYAM_S3_ACCESS_KEY").unwrap_or_default(),
                secret_key: std::env::var("VALAYAM_S3_SECRET_KEY").unwrap_or_default(),
                force_path_style: env_flag("VALAYAM_S3_FORCE_PATH_STYLE")
                    || matches!(backend, StorageBackend::Minio),
            })
        } else {
            None
        };

        let config = StorageConfig {
            backend,
            plugin_home: env_path("VALAYAM_PLUGIN_HOME", resolve_plugin_home_default()),
            plugin_cache: env_path("VALAYAM_PLUGIN_CACHE", PathBuf::from("./data/plugin_cache")),
            template_home: env_path("VALAYAM_TEMPLATE_HOME", PathBuf::from("./data/templates")),
            offline,
            worker_plugin_source,
            s3,
            plugin_enc_key: std::env::var("VALAYAM_PLUGIN_ENC_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
        };

        config.ensure_dirs();
        Ok(config)
    }

    /// Create directories for the configured homes/cache (local backend only).
    pub fn ensure_dirs(&self) {
        if matches!(self.backend, StorageBackend::Local) {
            for dir in [&self.plugin_home, &self.plugin_cache, &self.template_home] {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    tracing::warn!(
                        dir = %dir.display(),
                        error = %e,
                        "could not create storage directory (may be a read-only mount)"
                    );
                }
            }
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            backend: StorageBackend::Local,
            plugin_home: PathBuf::from("./data/plugins"),
            plugin_cache: PathBuf::from("./data/plugin_cache"),
            template_home: PathBuf::from("./data/templates"),
            offline: false,
            worker_plugin_source: WorkerPluginSource::Local,
            s3: None,
            plugin_enc_key: None,
        }
    }
}

fn env_path(var: &str, default: PathBuf) -> PathBuf {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => default,
    }
}

fn env_flag(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Determine the default plugin home when `VALAYAM_PLUGIN_HOME` is unset.
///
/// Legacy `./data/plugins` wins if it exists; otherwise fall back to the FHS
/// production default `/var/lib/valayam/plugins`.
fn resolve_plugin_home_default() -> PathBuf {
    let legacy = Path::new("./data/plugins");
    if legacy.is_dir() {
        return legacy.to_path_buf();
    }
    PathBuf::from("/var/lib/valayam/plugins")
}

/// Simple artifact store for local filesystem operations.
/// Provides basic put/get/list/stat for templates and plugins.
#[async_trait::async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Persist `bytes` under `key`.
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ArtifactStoreError>;

    /// Read a previously stored object.
    async fn get(&self, key: &str) -> Result<Vec<u8>, ArtifactStoreError>;

    /// Remove an object. Idempotent.
    async fn delete(&self, key: &str) -> Result<(), ArtifactStoreError>;

    /// True if an object exists at `key`.
    async fn exists(&self, key: &str) -> Result<bool, ArtifactStoreError>;

    /// List object keys under `prefix`.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ArtifactStoreError>;

    /// Get metadata for an object.
    async fn stat(&self, key: &str) -> Result<ArtifactMetadata, ArtifactStoreError>;

    /// Which backend this store fronts — useful for logging & mismatch checks.
    fn backend(&self) -> StorageBackend;
}

/// Metadata returned by `stat` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

/// Error returned by [`ArtifactStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactStoreError {
    #[error("I/O error on local store: {0}")]
    Local(#[from] std::io::Error),
    #[error("S3 error: {0}")]
    S3(Box<dyn std::error::Error + Send + Sync>),
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("key is not allowed to traverse out of the store root: {0}")]
    InvalidKey(String),
}

/// Local-filesystem artifact store.
#[derive(Clone, Debug)]
pub struct LocalArtifactStore {
    root: PathBuf,
}

impl LocalArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn resolve(&self, key: &str) -> Result<PathBuf, ArtifactStoreError> {
        if key.is_empty() || key.starts_with('/') {
            return Err(ArtifactStoreError::InvalidKey(key.to_string()));
        }
        for seg in Path::new(key) {
            if seg == ".." {
                return Err(ArtifactStoreError::InvalidKey(key.to_string()));
            }
        }
        Ok(self.root.join(key))
    }
}

#[async_trait::async_trait]
impl ArtifactStore for LocalArtifactStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ArtifactStoreError> {
        let path = self.resolve(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, bytes).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, ArtifactStoreError> {
        let path = self.resolve(key)?;
        match tokio::fs::read(&path).await {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ArtifactStoreError::NotFound(key.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), ArtifactStoreError> {
        let path = self.resolve(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, ArtifactStoreError> {
        let path = self.resolve(key)?;
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, ArtifactStoreError> {
        let base = if prefix.is_empty() {
            self.root.clone()
        } else {
            self.resolve(prefix)?
        };
        let mut keys = Vec::new();
        if !tokio::fs::metadata(&self.root).await.is_ok() {
            return Ok(keys);
        }
        walk(&self.root, &base, &mut keys).await?;
        keys.sort();
        Ok(keys)
    }

    async fn stat(&self, key: &str) -> Result<ArtifactMetadata, ArtifactStoreError> {
        let path = self.resolve(key)?;
        let meta = tokio::fs::metadata(&path).await?;
        Ok(ArtifactMetadata {
            size: meta.len(),
            modified: meta.modified().ok(),
        })
    }

    fn backend(&self) -> StorageBackend {
        StorageBackend::Local
    }
}

async fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), ArtifactStoreError> {
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    while let Some(entry) = rd.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            Box::pin(walk(root, &path, out)).await?;
        } else {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

/// S3/Minio backend (compiled with `s3` feature).
#[cfg(feature = "s3")]
mod s3_backend {
    use super::*;
    use aws_sdk_s3::Client as S3Client;
    use std::sync::Arc;

    /// S3-compatible backend (Amazon S3 or Minio). Minio is selected by setting
    /// `force_path_style(true)` on the client config — the caller does this
    /// when the backend is `Minio` (see [`StorageConfig`]).
    #[derive(Clone)]
    pub struct S3ArtifactStore {
        client: Arc<S3Client>,
        bucket: String,
        backend_kind: StorageBackend,
    }

    impl S3ArtifactStore {
        pub fn new(
            client: Arc<S3Client>,
            bucket: impl Into<String>,
            backend_kind: StorageBackend,
        ) -> Self {
            Self {
                client,
                bucket: bucket.into(),
                backend_kind,
            }
        }
    }

    #[async_trait::async_trait]
    impl ArtifactStore for S3ArtifactStore {
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ArtifactStoreError> {
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(bytes.to_vec().into())
                .send()
                .await
                .map_err(|e| ArtifactStoreError::S3(Box::new(e)))?;
            Ok(())
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, ArtifactStoreError> {
            let resp = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|e| ArtifactStoreError::S3(Box::new(e)))?;
            let body = resp
                .body
                .collect()
                .await
                .map_err(|e| ArtifactStoreError::S3(Box::new(e)))?
                .into_bytes();
            Ok(body.to_vec())
        }

        async fn delete(&self, key: &str) -> Result<(), ArtifactStoreError> {
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|e| ArtifactStoreError::S3(Box::new(e)))?;
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool, ArtifactStoreError> {
            match self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
            {
                Ok(_) => Ok(true),
                Err(e) => {
                    let s = format!("{e}");
                    if s.contains("404") || s.contains("NotFound") {
                        Ok(false)
                    } else {
                        Err(ArtifactStoreError::S3(Box::new(e)))
                    }
                }
            }
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, ArtifactStoreError> {
            let mut resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .into_paginator()
                .send();
            let mut keys = Vec::new();
            while let Some(page) = resp
                .try_next()
                .await
                .map_err(|e| ArtifactStoreError::S3(Box::new(e)))?
            {
                for obj in page.contents() {
                    if let Some(k) = obj.key() {
                        keys.push(k.to_string());
                    }
                }
            }
            Ok(keys)
        }

        async fn stat(&self, key: &str) -> Result<ArtifactMetadata, ArtifactStoreError> {
            let resp = self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|e| ArtifactStoreError::S3(Box::new(e)))?;
            let size = resp.content_length().unwrap_or(0) as u64;
            let modified = resp.last_modified().and_then(|t| {
                use std::time::{Duration, UNIX_EPOCH};
                let ts = t.secs();
                let nanos = t.subsec_nanos();
                UNIX_EPOCH.checked_add(Duration::new(ts as u64, nanos))
            });
            Ok(ArtifactMetadata { size, modified })
        }

        fn backend(&self) -> StorageBackend {
            self.backend_kind.clone()
        }
    }
}

#[cfg(feature = "s3")]
pub use s3_backend::S3ArtifactStore;

/// Wrapper that adds transparent AES-256-GCM encryption to any [`ArtifactStore`].
///
/// When enabled, `put` encrypts the payload with a random nonce, stores
/// `nonce || ciphertext`, and `get` decrypts it. The key is a base64-encoded
/// 32-byte AES-256-GCM key (from `VALAYAM_PLUGIN_ENC_KEY`).
#[derive(Clone)]
pub struct EncryptedArtifactStore {
    inner: std::sync::Arc<dyn ArtifactStore>,
    key: [u8; 32],
}

impl EncryptedArtifactStore {
    /// Create a new encrypted wrapper around `inner` using the provided base64 key.
    pub fn new(
        inner: std::sync::Arc<dyn ArtifactStore>,
        key_b64: &str,
    ) -> Result<Self, ArtifactStoreError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let decoded = STANDARD.decode(key_b64).map_err(|e| {
            ArtifactStoreError::InvalidKey(format!("invalid base64 encryption key: {e}"))
        })?;
        if decoded.len() != 32 {
            return Err(ArtifactStoreError::InvalidKey(format!(
                "encryption key must be 32 bytes (got {})",
                decoded.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(Self { inner, key })
    }

    /// Encrypt plaintext using AES-256-GCM with a random 12-byte nonce.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{
            aead::{Aead, AeadCore, OsRng},
            Aes256Gcm, KeyInit,
        };
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let nonce = <Aes256Gcm as AeadCore>::generate_nonce(&mut OsRng); // 12 bytes
        let mut ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .expect("encryption failed");
        // Prepend nonce to ciphertext for storage: nonce || ciphertext
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.append(&mut ciphertext);
        out
    }

    /// Decrypt data encrypted by `encrypt` (nonce || ciphertext).
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ArtifactStoreError> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{
            aead::{Aead, Payload},
            Aes256Gcm, KeyInit,
        };
        if data.len() < 12 {
            return Err(ArtifactStoreError::InvalidKey(
                "ciphertext too short".into(),
            ));
        }
        let nonce = GenericArray::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| {
                ArtifactStoreError::InvalidKey(
                    "decryption failed (wrong key or corrupt data)".into(),
                )
            })
    }
}

#[async_trait::async_trait]
impl ArtifactStore for EncryptedArtifactStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ArtifactStoreError> {
        let encrypted = self.encrypt(bytes);
        self.inner.put(key, &encrypted).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, ArtifactStoreError> {
        let encrypted = self.inner.get(key).await?;
        self.decrypt(&encrypted)
    }

    async fn delete(&self, key: &str) -> Result<(), ArtifactStoreError> {
        self.inner.delete(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool, ArtifactStoreError> {
        self.inner.exists(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, ArtifactStoreError> {
        self.inner.list(prefix).await
    }

    async fn stat(&self, key: &str) -> Result<ArtifactMetadata, ArtifactStoreError> {
        self.inner.stat(key).await
    }

    fn backend(&self) -> StorageBackend {
        self.inner.backend()
    }
}

impl StorageConfig {
    /// Build an artifact store for plugins (and templates on S3/Minio).
    pub fn build_store(&self) -> std::sync::Arc<dyn ArtifactStore> {
        let store: std::sync::Arc<dyn ArtifactStore> = match self.backend {
            StorageBackend::Local => {
                std::sync::Arc::new(LocalArtifactStore::new(self.plugin_home.clone()))
            }
            #[cfg(feature = "s3")]
            StorageBackend::S3 | StorageBackend::Minio => {
                let s3 = self.s3.as_ref().expect(
                    "S3/Minio backend selected but S3Config is missing — from_env should have populated it",
                );
                let cfg_loader = aws_config::from_env();
                let cfg_loader = if let Some(endpoint) = &s3.endpoint {
                    cfg_loader.endpoint_url(endpoint)
                } else {
                    cfg_loader
                };
                let cfg_loader = cfg_loader.region(aws_config::Region::new(s3.region.clone()));
                let creds = aws_sdk_s3::config::Credentials::new(
                    &s3.access_key,
                    &s3.secret_key,
                    None,
                    None,
                    "valayam-static",
                );
                let cfg_loader = cfg_loader.credentials_provider(creds);
                // Load the SDK config (blocking on the async load)
                let shared = if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.block_on(cfg_loader.load())
                } else {
                    tokio::runtime::Runtime::new()
                        .unwrap()
                        .block_on(cfg_loader.load())
                };
                let mut s3_cfg = aws_sdk_s3::Config::from(&shared);
                s3_cfg = s3_cfg
                    .to_builder()
                    .force_path_style(s3.force_path_style)
                    .build();
                let client = std::sync::Arc::new(aws_sdk_s3::Client::from_conf(s3_cfg));
                std::sync::Arc::new(S3ArtifactStore::new(
                    client,
                    s3.bucket.clone(),
                    self.backend.clone(),
                ))
            }
            #[cfg(not(feature = "s3"))]
            StorageBackend::S3 | StorageBackend::Minio => {
                tracing::error!(
                    "S3/Minio backend requested but the `s3` Cargo feature is not enabled; \
                     falling back to the local artifact store"
                );
                std::sync::Arc::new(LocalArtifactStore::new(self.plugin_home.clone()))
            }
        };
        // Wrap with encryption if key is configured
        if let Some(ref key) = self.plugin_enc_key {
            std::sync::Arc::new(
                EncryptedArtifactStore::new(std::sync::Arc::clone(&store), key)
                    .expect("failed to create encrypted artifact store"),
            )
        } else {
            store
        }
    }

    /// Build a store rooted at `template_home` — used for YAML template blobs.
    pub fn build_template_store(&self) -> std::sync::Arc<dyn ArtifactStore> {
        match self.backend {
            StorageBackend::Local => {
                std::sync::Arc::new(LocalArtifactStore::new(self.template_home.clone()))
            }
            // S3/Minio backends: templates live in the *same* bucket under a
            // `templates/` prefix; reuse the plugin store (the worker distinguishes
            // by key prefix, not by a separate store). The local case is distinct
            // because the two homes are separate directories.
            #[cfg(feature = "s3")]
            _ => self.build_store(),
            #[cfg(not(feature = "s3"))]
            StorageBackend::S3 | StorageBackend::Minio => {
                tracing::error!(
                    "S3/Minio backend requested but the `s3` Cargo feature is not enabled; \
                     falling back to the local artifact store"
                );
                std::sync::Arc::new(LocalArtifactStore::new(self.template_home.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> LocalArtifactStore {
        let dir = std::env::temp_dir().join(format!(
            "valayam_store_test/{}",
            std::thread::current().name().unwrap_or("t").len()
        ));
        LocalArtifactStore::new(&dir)
    }

    #[tokio::test]
    async fn local_put_get_delete_roundtrip() {
        let store = temp_store();
        let key = "tenant-abc/00000000-0000-0000-0000-000000000000.vpa";
        store.put(key, b"hello world").await.unwrap();
        assert!(store.exists(key).await.unwrap());
        let got = store.get(key).await.unwrap();
        assert_eq!(got, b"hello world");
        store.delete(key).await.unwrap();
        assert!(!store.exists(key).await.unwrap());
        assert!(matches!(
            store.get(key).await,
            Err(ArtifactStoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn encrypted_store_roundtrip() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let key = [42u8; 32];
        let key_b64 = STANDARD.encode(&key);

        let store = temp_store();
        let enc_store = EncryptedArtifactStore::new(std::sync::Arc::new(store), &key_b64).unwrap();

        let key = "tenant-abc/encrypted.vpa";
        let plaintext = b"sensitive plugin data";
        enc_store.put(key, plaintext).await.unwrap();
        assert!(enc_store.exists(key).await.unwrap());
        let got = enc_store.get(key).await.unwrap();
        assert_eq!(got, plaintext);
        enc_store.delete(key).await.unwrap();
        assert!(!enc_store.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn encrypted_store_invalid_key_rejected() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let store = temp_store();
        let result = EncryptedArtifactStore::new(std::sync::Arc::new(store), "not-base64!");
        assert!(result.is_err());
        let key_b64 = STANDARD.encode([0u8; 16]);
        let store = temp_store();
        let result = EncryptedArtifactStore::new(std::sync::Arc::new(store), &key_b64);
        assert!(result.is_err());
    }
}
