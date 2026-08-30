use clap::Parser;

fn cli_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects, Styles};
    Styles::styled()
        .header(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Blue.on_default())
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "valayam",
    version = "0.1.0",
    about = "Modern Stealth Scanner Core\n\nA high-performance, template-driven scanner supporting HTTP requests,\nTCP port scanning, and embedded Rhai scripting for multi-step workflows.",
    styles = cli_styles(),
    after_help = "\x1b[1;36mEXAMPLES:\x1b[0m
  \x1b[1mBasic HTTP template scan:\x1b[0m
    valayam -u https://target.com -t ./demo-template.yaml

  \x1b[1mBatch template execution (runs all .yaml files in directory concurrently):\x1b[0m
    valayam -u https://target.com -t ./templates/

  \x1b[1mRun Nuclei templates:\x1b[0m
    valayam -u https://target.com --nuclei-template ./nuclei-templates/

  \x1b[1mRhai script template (multi-step chain):\x1b[0m
    valayam -u https://target.com -t ./script-demo.yaml

  \x1b[1mSave findings to JSON / SARIF:\x1b[0m
    valayam -u https://target.com -t ./demo-template.yaml -o results.json --format sarif

  \x1b[1mPre-scan web crawl & WAF detection:\x1b[0m
    valayam -u https://target.com --crawl --crawl-depth 3 --waf-detect

\x1b[1;36mTEMPLATE TYPES:\x1b[0m
  Templates are YAML files that can contain any combination of:
    \x1b[33mrequests:\x1b[0m   HTTP request rules with regex/status matchers
    \x1b[33mnetwork:\x1b[0m    TCP port scanning rules
    \x1b[33mscripts:\x1b[0m    Embedded Rhai scripts for multi-step logic

  A single template can mix all three. The engine executes them in order:
  HTTP → Network → Scripts. No separate flag is needed for scripts."
)]
pub struct Args {
    #[arg(
        short = 'u',
        long,
        default_value = "https://httpbin.org",
        value_name = "URL",
        help_heading = "TARGET CONFIGURATION",
        help = "Target base URL or hostname (e.g. https://example.com or 192.168.1.1)"
    )]
    pub target: String,

    #[arg(
        long,
        help_heading = "TARGET CONFIGURATION",
        help = "Crawl the target URL first to discover endpoints and expand attack surface"
    )]
    pub crawl: bool,

    #[arg(
        long,
        default_value = "3",
        value_name = "DEPTH",
        help_heading = "TARGET CONFIGURATION",
        help = "Maximum link traversal depth for the crawler"
    )]
    pub crawl_depth: usize,

    #[arg(
        long,
        value_name = "HEADERS",
        help_heading = "TARGET CONFIGURATION",
        help = "Custom headers for crawler requests (format: 'Key:Value,Key2:Value2')"
    )]
    pub crawl_headers: Option<String>,

    #[arg(
        long,
        help_heading = "TARGET CONFIGURATION",
        help = "Allow scanning internal/private IP ranges (RFC 1918 / loopback; disabled by default for SSRF safety)"
    )]
    pub allow_internal: bool,

    #[arg(
        short = 't',
        long,
        value_name = "TEMPLATE",
        help_heading = "SCAN & TEMPLATES",
        help = "Path to Native YAML template file or directory (HTTP/TCP/Rhai)",
        conflicts_with = "nuclei_template"
    )]
    pub template: Option<String>,

    #[arg(
        short = 'n',
        long,
        num_args = 0..=1,
        default_missing_value = "nuclei-templates",
        value_name = "TEMPLATE",
        help_heading = "SCAN & TEMPLATES",
        help = "Run with Nuclei engine using specified template file or directory (defaults to 'nuclei-templates' if omitted)",
        conflicts_with = "template"
    )]
    pub nuclei_template: Option<String>,

    #[arg(
        long,
        value_name = "CATEGORY",
        help_heading = "SCAN & TEMPLATES",
        help = "Filter templates by SDLC testing category (e.g. unit, api, security, smoke)"
    )]
    pub testing_category: Option<String>,

    #[arg(
        short = 'r',
        long,
        value_name = "RPS",
        help_heading = "PERFORMANCE & TUNING",
        help = "Maximum requests per second (global rate limit across all concurrent workers)"
    )]
    pub rate_limit: Option<u32>,

    #[arg(
        long,
        default_value = "500",
        value_name = "NUM",
        help_heading = "PERFORMANCE & TUNING",
        help = "Maximum concurrent template executions and network requests"
    )]
    pub concurrency: usize,

    #[arg(
        long,
        help_heading = "PERFORMANCE & TUNING",
        help = "Rotate User-Agent header randomly per request from a built-in pool of modern browsers"
    )]
    pub random_agent: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "proxies.txt",
        value_name = "FILE",
        help_heading = "PERFORMANCE & TUNING",
        help = "Path to proxy list file for round-robin rotation (defaults to 'proxies.txt' if omitted)"
    )]
    pub proxy_file: Option<String>,

    #[arg(
        short = 'o',
        long,
        num_args = 0..=1,
        default_missing_value = "valayam-report.json",
        value_name = "FILE",
        help_heading = "OUTPUT & REPORTING",
        help = "Destination file path to save scan report (defaults to 'valayam-report.json' if omitted)"
    )]
    pub output: Option<String>,

    #[arg(
        long,
        default_value = "json",
        value_name = "FORMAT",
        help_heading = "OUTPUT & REPORTING",
        help = "Output report format [possible values: json, sarif, pdf, html, markdown]"
    )]
    pub format: String,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        value_name = "LEVEL",
        help_heading = "OUTPUT & REPORTING",
        help = "Logging verbosity level [possible values: trace, debug, info, warn, error]"
    )]
    pub log_level: String,

    #[arg(
        short = 'f',
        long,
        num_args = 0..=1,
        default_missing_value = "valayam.log.json",
        value_name = "FILE",
        help_heading = "OUTPUT & REPORTING",
        help = "File path to export structured JSON logs (defaults to 'valayam.log.json' if omitted)"
    )]
    pub log_file: Option<String>,

    #[arg(
        long,
        help_heading = "OUTPUT & REPORTING",
        help = "Launch the interactive terminal dashboard (TUI) to monitor findings in real-time"
    )]
    pub tui: bool,

    #[arg(
        long,
        help_heading = "PLUGIN SECURITY & RUNTIME",
        help = "Enforce plugin signature verification — reject unsigned WASM/VPA plugins at load time"
    )]
    pub require_signed_plugins: bool,

    #[arg(
        long,
        default_value = "50",
        value_name = "MB",
        help_heading = "PLUGIN SECURITY & RUNTIME",
        help = "Memory limit per WASM plugin execution instance in megabytes"
    )]
    pub plugin_memory_limit: u32,

    #[arg(
        long,
        default_value = "30",
        value_name = "SECS",
        help_heading = "PLUGIN SECURITY & RUNTIME",
        help = "Plugin execution timeout in seconds"
    )]
    pub plugin_timeout: u64,

    #[arg(
        long,
        value_name = "HOST",
        help_heading = "PLUGIN SECURITY & RUNTIME",
        help = "Repeatable: allow plugin network egress to a specific host (default: deny all)"
    )]
    pub plugin_allow_host: Vec<String>,

    #[arg(
        long,
        value_name = "URI",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "URI of a remote Valayam gRPC worker node (e.g. http://127.0.0.1:50051)"
    )]
    pub worker: Option<String>,

    #[arg(
        long,
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Detect and fingerprint Web Application Firewalls (WAF) before executing scans"
    )]
    pub waf_detect: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "8080",
        value_name = "PORT",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Start a local MITM proxy on the specified port to capture traffic and generate templates (defaults to 8080)"
    )]
    pub mitm_proxy: Option<u16>,

    #[arg(
        long,
        value_name = "STATE_ID",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Resume a previously interrupted scan session using its state ID"
    )]
    pub resume: Option<String>,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "50051",
        value_name = "PORT",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Port to start the live execution control gRPC API server on (defaults to 50051)"
    )]
    pub control_port: Option<u16>,

    #[arg(
        long,
        value_name = "FILE",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Path to TLS certificate file (PEM) for gRPC control plane encryption"
    )]
    pub tls_cert: Option<String>,

    #[arg(
        long,
        value_name = "FILE",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Path to TLS private key file (PEM) for gRPC control plane encryption"
    )]
    pub tls_key: Option<String>,

    #[arg(
        long,
        value_name = "FILE",
        help_heading = "DISTRIBUTED & CONTROL PLANE",
        help = "Path to CA certificate (PEM) for mTLS client verification on the gRPC control plane"
    )]
    pub tls_ca: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate shell auto-completion scripts for Bash, Zsh, Fish, PowerShell, or Elvish
    Completions {
        /// Target shell to generate completions for [possible values: bash, zsh, fish, powershell, elvish]
        #[arg(value_enum, value_name = "SHELL")]
        shell: clap_complete::Shell,
    },
    /// Manage, package, sign, and install Valayam plugins (.vpa)
    Plugin {
        #[command(subcommand)]
        action: PluginCommands,
    },
    /// Send runtime execution control signals (pause, resume, cancel) to a worker node
    Control {
        /// Control action to execute: pause, resume, or cancel
        #[arg(value_name = "ACTION")]
        action: String,
        /// Scan state ID (required when controlling multi-tenant workers)
        #[arg(long, value_name = "STATE_ID")]
        scan_id: Option<String>,
        /// gRPC control port (defaults to 50051)
        #[arg(long, default_value = "50051", value_name = "PORT")]
        port: u16,
    },
    /// Sync local vulnerability database from the Valayam CDN for offline/air-gapped scanning
    SyncVulndb {
        /// CDN or server URL to download signed SQLite database from
        #[arg(long, default_value = "https://cdn.valayam.io", value_name = "URL")]
        cdn: String,
        /// Destination file path for downloaded database
        #[arg(long, default_value = "data/vuln-db.sqlite", value_name = "FILE")]
        output: String,
    },
    /// Create and verify self-contained air-gapped deployment bundles
    Bundle {
        #[command(subcommand)]
        action: BundleCommands,
    },
    /// Manage security templates (push/pull/list) with remote artifact storage
    Template {
        #[command(subcommand)]
        action: TemplateCommands,
    },
    /// Compare two scan result JSON files to identify new, resolved, or recurring vulnerabilities
    Diff {
        /// Baseline scan result JSON file from an earlier run
        #[arg(long, value_name = "FILE")]
        baseline: String,
        /// Current scan result JSON file from a newer run
        #[arg(long, value_name = "FILE")]
        current: String,
    },
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum PluginCommands {
    /// Package a plugin source directory into a distributable .vpa archive
    Package {
        /// Directory containing plugin source code and plugin.yaml manifest
        #[arg(value_name = "DIR")]
        dir: String,
        /// Output path for the packaged .vpa archive (e.g. dist/my-plugin.vpa)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
        /// Path to ED25519 private key to cryptographically sign the package
        #[arg(long, value_name = "KEY_FILE")]
        sign: Option<String>,
    },
    /// Scaffold a new plugin project with boilerplate code
    Init {
        /// The name of the new plugin
        name: String,
        /// Programming language to use for the plugin (python, go, rust)
        #[arg(long, default_value = "python", value_name = "LANG")]
        lang: String,
        /// Plugin execution runtime model (grpc or wasm)
        #[arg(long, default_value = "grpc", value_name = "RUNTIME")]
        runtime: String,
    },
    /// Generate a new ED25519 keypair for signing Valayam plugins
    GenerateKey {
        /// Output file path prefix for generated keypair (.pem and .pub)
        #[arg(short, long, default_value = "valayam_plugin_key", value_name = "PREFIX")]
        output: String,
    },
    /// Install a WebAssembly (WASM) plugin from a remote URL or OCI registry
    Install {
        /// Registration name for the installed plugin
        #[arg(value_name = "NAME")]
        name: String,
        /// Remote source URL to download plugin from (supports https:// and oci://)
        #[arg(value_name = "URL")]
        url: String,
        /// ED25519 public key (hex string or PEM file) to verify plugin integrity
        #[arg(long, value_name = "KEY")]
        pubkey: Option<String>,
    },
    /// Push a packaged .vpa plugin to an OCI artifact registry
    Push {
        /// Path to the packaged .vpa plugin file
        #[arg(value_name = "FILE")]
        file: String,
        /// Destination OCI repository (e.g. registry.example.com/org/plugin)
        #[arg(value_name = "REPO")]
        repo: String,
        /// OCI artifact tag (default: latest)
        #[arg(short, long, default_value = "latest", value_name = "TAG")]
        tag: String,
        /// Optional detached signature file (.sig) to attach to OCI manifest
        #[arg(long, value_name = "SIG_FILE")]
        signature: Option<String>,
    },
    /// Search for published plugins on the Valayam Marketplace
    Search {
        /// Search keyword or tag
        #[arg(value_name = "QUERY")]
        query: String,
    },
    /// Publish a packaged .vpa plugin to the Valayam Marketplace
    Publish {
        /// Path to the packaged .vpa plugin file
        #[arg(value_name = "FILE")]
        file: String,
    },
    /// Uninstall a locally cached or registered plugin
    Uninstall {
        /// Name of the plugin to uninstall
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// List all locally installed and registered plugins
    List,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum BundleCommands {
    /// Create an air-gapped bundle containing plugins, templates, and signature manifests
    Create {
        /// Directory containing plugin .vpa files
        #[arg(long, default_value = "plugins", value_name = "DIR")]
        plugins: String,
        /// Directory containing YAML security templates
        #[arg(long, default_value = "templates", value_name = "DIR")]
        templates: String,
        /// Path to ED25519 public key (PEM) for bundle manifest verification
        #[arg(long, value_name = "KEY_FILE")]
        pubkey: String,
        /// Destination directory path for the created offline bundle
        #[arg(short, long, default_value = "./bundle", value_name = "DIR")]
        output: String,
    },
    /// Verify an air-gapped bundle's manifest checksums and cryptographic signatures
    Verify {
        /// Path to bundle directory containing manifest.json
        #[arg(value_name = "DIR")]
        bundle: String,
    },
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum TemplateCommands {
    /// Push a local template file or directory to configured storage backend
    Push {
        /// Local YAML template file or directory to upload
        #[arg(value_name = "PATH")]
        path: String,
        /// Storage prefix namespace (default: templates/)
        #[arg(long, default_value = "templates/", value_name = "PREFIX")]
        prefix: String,
    },
    /// Pull templates from configured storage backend to a local directory
    Pull {
        /// Local destination directory to save downloaded templates
        #[arg(long, default_value = "templates", value_name = "DIR")]
        output: String,
        /// Storage prefix namespace to download from (default: templates/)
        #[arg(long, default_value = "templates/", value_name = "PREFIX")]
        prefix: String,
    },
    /// List templates available in the configured storage backend
    List {
        /// Storage prefix namespace to filter (default: templates/)
        #[arg(long, default_value = "templates/", value_name = "PREFIX")]
        prefix: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_target() {
        let args = Args::parse_from(&["valayam"]);
        assert_eq!(args.target, "https://httpbin.org");
        assert!(args.template.is_none());
        assert!(args.nuclei_template.is_none());
        assert!(args.output.is_none());
        assert_eq!(args.format, "json");
        assert_eq!(args.concurrency, 500);
        assert_eq!(args.log_level, "info");
        assert_eq!(args.crawl_depth, 3);
    }

    #[test]
    fn test_custom_target_and_template() {
        let args =
            Args::parse_from(&["valayam", "-u", "https://example.com", "-t", "./templates/"]);
        assert_eq!(args.target, "https://example.com");
        assert_eq!(args.template, Some("./templates/".into()));
        assert!(args.nuclei_template.is_none());
    }

    #[test]
    fn test_output_and_format() {
        let args = Args::parse_from(&[
            "valayam",
            "-u",
            "https://test.com",
            "-o",
            "results.jsonl",
            "--format",
            "sarif",
        ]);
        assert_eq!(args.output, Some("results.jsonl".into()));
        assert_eq!(args.format, "sarif");
    }

    #[test]
    fn test_rate_limit_and_concurrency() {
        let args = Args::parse_from(&["valayam", "-r", "100", "--concurrency", "10"]);
        assert_eq!(args.rate_limit, Some(100));
        assert_eq!(args.concurrency, 10);
    }

    #[test]
    fn test_nuclei_template() {
        let args = Args::parse_from(&[
            "valayam",
            "-u",
            "https://test.com",
            "-n",
            "./nuclei-templates/",
        ]);
        assert_eq!(args.nuclei_template, Some("./nuclei-templates/".into()));
        assert!(args.template.is_none());
    }

    #[test]
    fn test_plugin_subcommand_package() {
        let args = Args::parse_from(&[
            "valayam",
            "plugin",
            "package",
            "./my-plugin",
            "-o",
            "out.vpa",
        ]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::Package { dir, output, sign } => {
                    assert_eq!(dir, "./my-plugin");
                    assert_eq!(output, Some("out.vpa".into()));
                    assert!(sign.is_none());
                }
                _ => panic!("Expected Package command"),
            },
            Some(_) => panic!("Unexpected command"),
            None => panic!("Expected a subcommand"),
        }
    }

    #[test]
    fn test_plugin_subcommand_init() {
        let args = Args::parse_from(&["valayam", "plugin", "init", "my-plugin"]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::Init {
                    name,
                    lang,
                    runtime,
                } => {
                    assert_eq!(name, "my-plugin");
                    assert_eq!(lang, "python");
                    assert_eq!(runtime, "grpc");
                }
                _ => panic!("Expected Init command"),
            },
            Some(_) => panic!("Unexpected command"),
            None => panic!("Expected a subcommand"),
        }
    }

    #[test]
    fn test_plugin_subcommand_init_custom_lang() {
        let args = Args::parse_from(&["valayam", "plugin", "init", "my-go-plugin", "--lang", "go"]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::Init { name, lang, .. } => {
                    assert_eq!(name, "my-go-plugin");
                    assert_eq!(lang, "go");
                }
                _ => panic!("Expected Init command"),
            },
            Some(_) => panic!("Unexpected command"),
            None => panic!("Expected a subcommand"),
        }
    }

    #[test]
    fn test_tls_args() {
        let args = Args::parse_from(&[
            "valayam",
            "--tls-cert",
            "/etc/valayam/cert.pem",
            "--tls-key",
            "/etc/valayam/key.pem",
        ]);
        assert_eq!(args.tls_cert, Some("/etc/valayam/cert.pem".into()));
        assert_eq!(args.tls_key, Some("/etc/valayam/key.pem".into()));
        assert!(!args.require_signed_plugins);
    }

    #[test]
    fn test_require_signed_plugins() {
        let args = Args::parse_from(&["valayam", "--require-signed-plugins"]);
        assert!(args.require_signed_plugins);
    }

    #[test]
    fn test_tls_with_require_signed() {
        let args = Args::parse_from(&[
            "valayam",
            "-u",
            "https://example.com",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--require-signed-plugins",
        ]);
        assert_eq!(args.tls_cert, Some("cert.pem".into()));
        assert_eq!(args.tls_key, Some("key.pem".into()));
        assert!(args.require_signed_plugins);
    }

    #[test]
    fn test_plugin_subcommand_generate_key() {
        let args = Args::parse_from(&["valayam", "plugin", "generate-key", "-o", "custom_key"]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::GenerateKey { output } => {
                    assert_eq!(output, "custom_key");
                }
                _ => panic!("Expected GenerateKey command"),
            },
            Some(_) => panic!("Unexpected command"),
            None => panic!("Expected a subcommand"),
        }
    }
}
