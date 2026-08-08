use anyhow::{Context, Result};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use url::Url;

/// OCI Manifest representing an artifact
#[derive(Debug, Serialize, Deserialize)]
pub struct OciManifest {
    #[serde(rename = "schemaVersion")]
    /// Documentation for this item.
    pub schema_version: u32,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    /// Documentation for this item.
    pub media_type: Option<String>,
    /// Documentation for this item.
    pub config: OciDescriptor,
    /// Documentation for this item.
    pub layers: Vec<OciDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Documentation for this item.
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Documentation for this item.
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    /// Documentation for this item.
    pub media_type: String,
    /// Documentation for this item.
    pub digest: String,
    /// Documentation for this item.
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Documentation for this item.
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

/// A lightweight OCI v2 client
pub struct OciClient {
    client: Client,
    registry: String,
    token: Option<String>,
}

impl OciClient {
    /// Documentation for this item.
    pub fn new(registry: &str, username: Option<&str>, password: Option<&str>) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        // Set standard OCI accepts
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static(
                "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
            ),
        );

        let mut token = None;
        if let (Some(u), Some(p)) = (username, password) {
            let auth = format!("{}:{}", u, p);
            #[allow(deprecated)]
            let b64 = base64::encode(auth);
            token = Some(format!("Basic {}", b64));
        }

        let client = Client::builder()
            .default_headers(headers)
            .user_agent("valayam-oci-client/0.1")
            .build()?;

        let registry_url = if registry.starts_with("http") {
            registry.to_string()
        } else {
            format!("https://{}", registry)
        };

        Ok(Self {
            client,
            registry: registry_url,
            token,
        })
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(t) = &self.token {
            req.header(header::AUTHORIZATION, t)
        } else {
            req
        }
    }

    /// Fetch a manifest for a given repository and reference (tag or digest)
    pub async fn get_manifest(&self, repo: &str, reference: &str) -> Result<OciManifest> {
        let url = format!("{}/v2/{}/manifests/{}", self.registry, repo, reference);
        let res = self
            .apply_auth(self.client.get(&url))
            .send()
            .await?
            .error_for_status()?;

        let manifest = res.json::<OciManifest>().await?;
        Ok(manifest)
    }

    /// Push a manifest to the registry
    pub async fn push_manifest(
        &self,
        repo: &str,
        reference: &str,
        manifest: &OciManifest,
    ) -> Result<()> {
        let url = format!("{}/v2/{}/manifests/{}", self.registry, repo, reference);
        let res = self
            .apply_auth(self.client.put(&url))
            .header(
                header::CONTENT_TYPE,
                "application/vnd.oci.image.manifest.v1+json",
            )
            .json(manifest)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            anyhow::bail!("Failed to push manifest: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    /// Download a blob to a vector of bytes
    pub async fn get_blob(&self, repo: &str, digest: &str) -> Result<Vec<u8>> {
        let url = format!("{}/v2/{}/blobs/{}", self.registry, repo, digest);
        let res = self
            .apply_auth(self.client.get(&url))
            .send()
            .await?
            .error_for_status()?;

        let bytes = res.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Upload a blob (monolithic) and return its digest
    pub async fn push_blob(&self, repo: &str, data: &[u8], digest_str: &str) -> Result<()> {
        // Step 1: Initiate upload
        let init_url = format!("{}/v2/{}/blobs/uploads/", self.registry, repo);
        let res = self.apply_auth(self.client.post(&init_url)).send().await?;

        if !res.status().is_success() {
            anyhow::bail!("Failed to initiate blob upload: {}", res.status());
        }

        let location = res
            .headers()
            .get(header::LOCATION)
            .context("Missing Location header in upload initiation")?
            .to_str()?;

        // Resolve relative location if needed
        let mut upload_url = if location.starts_with("http") {
            Url::parse(location)?
        } else {
            Url::parse(&self.registry)?.join(location)?
        };

        // Step 2: Upload data
        upload_url
            .query_pairs_mut()
            .append_pair("digest", digest_str);

        let res = self
            .apply_auth(self.client.put(upload_url))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await?;

        if !res.status().is_success() {
            anyhow::bail!("Failed to upload blob: {}", res.status());
        }

        Ok(())
    }
}
