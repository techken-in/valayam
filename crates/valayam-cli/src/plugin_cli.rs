use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::write::FileOptions;

pub fn package_plugin(dir: &str, output: Option<&str>, sign: Option<&str>) -> anyhow::Result<()> {
    let dir_path = Path::new(dir);
    if !dir_path.exists() || !dir_path.is_dir() {
        anyhow::bail!("Directory '{}' does not exist or is not a directory.", dir);
    }

    let manifest_path = dir_path.join("plugin.yaml");
    if !manifest_path.exists() {
        anyhow::bail!(
            "Missing plugin.yaml in '{}'. A valid Valayam plugin requires a manifest.",
            dir
        );
    }

    // Read manifest to determine default output name
    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest: valayam_engine::vpa::PluginManifest = serde_yaml::from_str(&manifest_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse plugin.yaml: {}", e))?;

    let out_file_path = match output {
        Some(o) => std::path::PathBuf::from(o),
        None => Path::new(".").join(format!("{}.vpa", manifest.name)),
    };

    println!(
        "Packaging plugin '{}' (v{}) into {}...",
        manifest.name,
        manifest.version,
        out_file_path.display()
    );

    let file = File::create(&out_file_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.strip_prefix(dir_path)?;

        // Skip the root dir itself, the output file, and any existing signature.sig
        if name.as_os_str().is_empty()
            || path == out_file_path
            || name.to_string_lossy() == "signature.sig"
        {
            continue;
        }

        #[allow(deprecated)]
        if path.is_file() {
            zip.start_file_from_path(name, options)?;
            let mut f = File::open(path)?;
            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        } else if !name.as_os_str().is_empty() {
            zip.add_directory_from_path(name, options)?;
        }
    }

    if let Some(priv_key_path) = sign {
        println!("Signing plugin with key: {}", priv_key_path);
        let priv_key_bytes = std::fs::read(priv_key_path)?;
        if priv_key_bytes.len() != 32 {
            anyhow::bail!("Invalid private key length (expected 32 bytes)");
        }
        let mut priv_key = [0u8; 32];
        priv_key.copy_from_slice(&priv_key_bytes[0..32]);
        let manifest_bytes = std::fs::read(&manifest_path)?;
        let signature = valayam_crypto::PluginCrypto::sign(&priv_key, &manifest_bytes)?;

        zip.start_file("signature.sig", options)?;
        zip.write_all(&signature)?;
    }

    zip.finish()?;
    println!("Successfully created {}", out_file_path.display());

    Ok(())
}

pub fn init_plugin(name: &str, lang: &str, runtime: &str) -> anyhow::Result<()> {
    let dir_path = Path::new(name);
    if dir_path.exists() {
        anyhow::bail!("Directory '{}' already exists.", name);
    }

    std::fs::create_dir_all(dir_path)?;
    println!("\nCreating Valayam Plugin '{}'...", name);

    // Create plugin.yaml
    let manifest = format!(
        "name: \"{}\"\nversion: \"1.0.0\"\nauthor: \"SecurityTeam\"\nruntime: \"{}\"\nlanguage: \"{}\"\nentrypoint: \"run.bat\"\ncapabilities:\n  - \"network_scan\"\n",
        name, runtime, lang
    );
    std::fs::write(dir_path.join("plugin.yaml"), manifest)?;
    println!("- Created plugin.yaml");

    match lang {
        "python" => {
            std::fs::write(
                dir_path.join("plugin.py"),
                r#"import json
from extism_pdk import plugin_fn, Host

@plugin_fn
def run_scan():
    input_data = Host.input_string()
    ctx = json.loads(input_data)
    
    findings = [{
        "title": "Sample Finding",
        "severity": "INFO",
        "description": f"Scanned target: {ctx.get('target', 'unknown')}"
    }]
    
    Host.output_string(json.dumps(findings))
"#,
            )?;
            println!("- Created plugin.py");
            std::fs::write(dir_path.join("requirements.txt"), "extism-pdk\n")?;
            println!("- Created requirements.txt");
            std::fs::write(
                dir_path.join("build.sh"),
                "extism-py plugin.py -o plugin.wasm\n",
            )?;
            println!("- Created build.sh");
        }
        "rust" => {
            std::fs::write(
                dir_path.join("Cargo.toml"),
                format!(
                    r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
extism-pdk = "1.0.0"
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
"#,
                    name
                ),
            )?;
            println!("- Created Cargo.toml");

            std::fs::create_dir_all(dir_path.join("src"))?;
            std::fs::write(
                dir_path.join("src/lib.rs"),
                r#"use extism_pdk::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ScanContext {
    target: String,
}

#[derive(Serialize)]
struct Finding {
    title: String,
    severity: String,
    description: String,
}

#[plugin_fn]
pub fn run_scan(input: String) -> FnResult<String> {
    let ctx: ScanContext = serde_json::from_str(&input)?;
    
    let findings = vec![
        Finding {
            title: "Sample Finding".into(),
            severity: "INFO".into(),
            description: format!("Scanned target: {}", ctx.target),
        }
    ];

    let output = serde_json::to_string(&findings)?;
    Ok(output)
}
"#,
            )?;
            println!("- Created src/lib.rs");
            std::fs::write(dir_path.join("build.sh"), "cargo build --target wasm32-wasi --release\ncp target/wasm32-wasi/release/*.wasm plugin.wasm\n")?;
            println!("- Created build.sh");
        }
        "go" => {
            std::fs::write(
                dir_path.join("go.mod"),
                format!(
                    r#"module {}

go 1.21

require github.com/extism/go-pdk v1.0.0
"#,
                    name
                ),
            )?;
            println!("- Created go.mod");

            std::fs::write(
                dir_path.join("main.go"),
                r#"package main

import (
	"encoding/json"
	"github.com/extism/go-pdk"
)

type ScanContext struct {
	Target string `json:"target"`
}

type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

//export run_scan
func run_scan() int32 {
	input := pdk.Input()
	var ctx ScanContext
	json.Unmarshal(input, &ctx)

	findings := []Finding{
		{
			Title:       "Sample Finding",
			Severity:    "INFO",
			Description: "Scanned target: " + ctx.Target,
		},
	}

	output, _ := json.Marshal(findings)
	pdk.Output(output)
	return 0
}

func main() {}
"#,
            )?;
            println!("- Created main.go");
            std::fs::write(
                dir_path.join("build.sh"),
                "tinygo build -o plugin.wasm -target wasi main.go\n",
            )?;
            println!("- Created build.sh");
        }
        "ts" | "javascript" => {
            std::fs::write(
                dir_path.join("package.json"),
                format!(
                    r#"{{
  "name": "{}",
  "version": "1.0.0",
  "dependencies": {{
    "@extism/js-pdk": "^1.0.0"
  }}
}}
"#,
                    name
                ),
            )?;
            println!("- Created package.json");

            std::fs::write(
                dir_path.join("index.js"),
                r#"const { Host } = require("@extism/js-pdk");

function run_scan() {
    let input = Host.inputString();
    let ctx = JSON.parse(input);
    
    let findings = [
        {
            title: "Sample Finding",
            severity: "INFO",
            description: "Scanned target: " + ctx.target
        }
    ];
    
    Host.outputString(JSON.stringify(findings));
}

module.exports = { run_scan };
"#,
            )?;
            println!("- Created index.js");
            std::fs::write(
                dir_path.join("build.sh"),
                "npm install\nextism-js index.js -i index.d.ts -o plugin.wasm\n",
            )?;
            println!("- Created build.sh");
        }
        _ => {
            println!(
                "- Note: Boilerplate generation for language '{}' is currently minimal.",
                lang
            );
        }
    }

    println!(
        "\nRun `valayam plugin package {}` to package your plugin into {}.vpa!",
        name, name
    );
    Ok(())
}

pub trait CapitalizeExt {
    fn capitalize_first_letter(&self) -> String;
}

impl CapitalizeExt for str {
    fn capitalize_first_letter(&self) -> String {
        let mut c = self.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_init_plugin_creates_directory() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let plugin_dir = dir.path().join("test-plugin");
        let name = plugin_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 path"))?;

        let result = init_plugin(name, "python", "grpc");
        assert!(
            result.is_ok(),
            "init_plugin should succeed: {:?}",
            result.err()
        );
        assert!(plugin_dir.exists());
        assert!(plugin_dir.join("plugin.yaml").exists());
        assert!(plugin_dir.join("plugin.py").exists());

        let _ = std::fs::remove_dir_all(&plugin_dir);
        Ok(())
    }

    #[test]
    fn test_init_plugin_existing_dir_fails() -> anyhow::Result<()> {
        // Use a path that already exists on disk
        let dir = tempfile::tempdir()?;
        let path = dir
            .path()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 path"))?;
        // Temp dir already exists, so init should fail
        let result = init_plugin(path, "python", "grpc");
        assert!(result.is_err(), "init on existing dir should fail");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("already exists"),
            "Error should mention 'already exists': {}",
            err
        );
        Ok(())
    }

    #[test]
    fn test_package_nonexistent_dir_fails() {
        let result = package_plugin("/nonexistent/plugin_dir", None, None);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("does not exist") || err.contains("exist"));
    }

    #[test]
    fn test_generate_key_creates_files() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let prefix = dir.path().join("test_key");
        let prefix_str = prefix
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 path"))?;
        let result = generate_key(prefix_str);
        assert!(result.is_ok());
        assert!(Path::new(&format!("{}.pem", prefix_str)).exists());
        assert!(Path::new(&format!("{}.pub", prefix_str)).exists());
        // Cleanup
        let _ = std::fs::remove_file(format!("{}.pem", prefix_str));
        let _ = std::fs::remove_file(format!("{}.pub", prefix_str));
        Ok(())
    }

    #[test]
    fn test_capitalize_empty_string() {
        let s = String::new();
        assert_eq!(s.capitalize_first_letter(), "");
    }

    #[test]
    fn test_capitalize_lowercase() {
        let s = "hello".to_string();
        assert_eq!(s.capitalize_first_letter(), "Hello");
    }

    #[test]
    fn test_capitalize_already_capitalized() {
        let s = "Hello".to_string();
        assert_eq!(s.capitalize_first_letter(), "Hello");
    }

    #[test]
    fn test_capitalize_single_char() {
        let s = "a".to_string();
        assert_eq!(s.capitalize_first_letter(), "A");
    }

    #[test]
    fn test_capitalize_hyphenated_name() {
        // The trait capitalizes only the first letter, not after hyphens
        let s = "my-plugin".to_string();
        assert_eq!(s.capitalize_first_letter(), "My-plugin");
    }
}

pub fn generate_key(output_prefix: &str) -> anyhow::Result<()> {
    let (priv_key, pub_key) = valayam_crypto::PluginCrypto::generate_keypair();
    let priv_path = format!("{}.pem", output_prefix);
    let pub_path = format!("{}.pub", output_prefix);
    std::fs::write(&priv_path, priv_key)?;
    std::fs::write(&pub_path, pub_key)?;
    println!("Generated ED25519 keypair:\n- Private key (Keep Secret!): {}\n- Public key (Distribute!): {}", priv_path, pub_path);
    Ok(())
}

pub async fn install_plugin(name: &str, url: &str, pubkey_hex: Option<&str>) -> anyhow::Result<()> {
    use valayam_core::distribution::puller::PluginPuller;

    // Air-gapped mode guard: block network operations
    if std::env::var("VALAYAM_OFFLINE_MODE").is_ok() {
        anyhow::bail!("Cannot install plugin: VALAYAM_OFFLINE_MODE is set. Use 'valayam bundle' to create/verify offline bundles.");
    }

    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("valayam/plugins_cache");

    let pk_bytes = if let Some(hex_str) = pubkey_hex {
        let decoded =
            hex::decode(hex_str).map_err(|e| anyhow::anyhow!("Invalid hex in pubkey: {}", e))?;
        if decoded.len() != 32 {
            anyhow::bail!("Public key must be exactly 32 bytes (64 hex characters)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Some(arr)
    } else {
        println!("Warning: No public key provided. Signature verification will be bypassed.");
        None
    };

    println!("Installing plugin '{}' from {}...", name, url);
    let puller = PluginPuller::new(cache_dir, pk_bytes.as_ref())?;

    let path = puller.pull(name, url).await?;
    println!("Successfully installed plugin to {}", path.display());
    Ok(())
}

pub async fn push_plugin(
    file: &str,
    repo: &str,
    tag: &str,
    signature: Option<&str>,
) -> anyhow::Result<()> {
    use valayam_core::distribution::publisher::PluginPublisher;

    // Air-gapped mode guard: block network operations
    if std::env::var("VALAYAM_OFFLINE_MODE").is_ok() {
        anyhow::bail!("Cannot push plugin: VALAYAM_OFFLINE_MODE is set. Use 'valayam bundle' to create/verify offline bundles.");
    }

    let file_path = Path::new(file);
    if !file_path.exists() {
        anyhow::bail!("Plugin file '{}' does not exist.", file);
    }

    let registry = if let Some(idx) = repo.find('/') {
        &repo[..idx]
    } else {
        anyhow::bail!(
            "Repository format must be <registry>/<repo_name> (e.g. localhost:5000/my-plugin)"
        );
    };

    let repo_name = &repo[registry.len() + 1..];

    let config = crate::config::CliConfig::from_env();
    let username = config.valayam_registry_user;
    let password = config.valayam_registry_pass;

    println!(
        "Pushing '{}' to registry '{}', repo '{}', tag '{}'",
        file, registry, repo_name, tag
    );

    let publisher = PluginPublisher::new(registry, username.as_deref(), password.as_deref())?;
    publisher.push(repo_name, tag, file_path, signature).await?;

    println!("Successfully pushed OCI artifact to {}", repo);
    Ok(())
}

pub fn uninstall_plugin(name: &str) -> anyhow::Result<()> {
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("valayam/plugins_cache");
    let plugin_path = cache_dir.join(format!("{}.wasm", name));

    if plugin_path.exists() {
        std::fs::remove_file(&plugin_path)?;
        println!("Successfully uninstalled plugin '{}'.", name);
    } else {
        println!("Plugin '{}' is not installed.", name);
    }
    Ok(())
}

pub fn list_plugins() -> anyhow::Result<()> {
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("valayam/plugins_cache");

    if !cache_dir.exists() {
        println!("No plugins installed.");
        return Ok(());
    }

    let entries = std::fs::read_dir(cache_dir)?;
    let mut count = 0;

    println!("Installed plugins:");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "wasm") {
            if let Some(stem) = path.file_stem() {
                println!("- {}", stem.to_string_lossy());
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("No plugins installed.");
    }
    Ok(())
}
