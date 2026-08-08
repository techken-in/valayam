use valayam_plugin_sdk::{export_plugin, extism_pdk, Finding, WasmInput, WasmOutput, WasmScanner};
use std::fs;
use std::path::Path;

#[derive(Default)]
pub struct IacAuditScanner;

/// Configuration for IaC audit checks.
#[derive(Debug, Clone)]
pub struct IacAuditConfig {
    pub check_terraform: bool,
    pub check_dockerfile: bool,
    pub check_cloudformation: bool,
    pub check_kustomize: bool,
    pub check_helm: bool,
    pub strict_mode: bool,
    pub max_cidr_prefix: u8,
}

impl Default for IacAuditConfig {
    fn default() -> Self {
        Self {
            check_terraform: true,
            check_dockerfile: true,
            check_cloudformation: true,
            check_kustomize: true,
            check_helm: true,
            strict_mode: true,
            max_cidr_prefix: 24,
        }
    }
}

/// Known dangerous Terraform patterns (regex patterns in plain text).
const TERRAFORM_DANGEROUS_PATTERNS: &[(&str, &str, &str, f32, &str, &str)] = &[
    ("0.0.0.0/0", "overly_permissive_cidr", "Critical", 9.0, "Replace 0.0.0.0/0 with a specific IP range.", "https://owasp.org/www-community/attacks/Security_Misconfiguration"),
    ("acl.*public-read", "public_s3_acl", "High", 8.0, "Remove public-read ACL.", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"),
    ("\"*\"", "iam_full_admin", "Critical", 9.0, "Restrict IAM policy.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"),
];

const DOCKERFILE_CHECKS: &[(&str, &str, &str, f32, &str, &str)] = &[
    ("USER root", "container_as_root", "High", 7.0, "Add a non-root USER directive.", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"),
    ("ADD", "add_instead_of_copy", "Medium", 4.0, "Use COPY instead of ADD.", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"),
    ("ENV.*PASSWORD", "password_in_env", "Critical", 9.0, "Never store passwords in env vars.", "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#env"),
];

const CFN_DANGEROUS_PATTERNS: &[(&str, &str, &str, f32, &str, &str)] = &[
    ("AWS::IAM::Role.*ManagedPolicyArns.*AdministratorAccess", "cfn_admin_role", "Critical", 9.0, "Avoid AdministratorAccess.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"),
];

impl WasmScanner for IacAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();
        
        let target_path = input.template.get("target").and_then(|v| v.as_str()).unwrap_or("");
        if target_path.is_empty() {
            return Ok(WasmOutput { matched: false, count: 0, findings: vec![] });
        }

        let path = Path::new(target_path);
        
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(WasmOutput { matched: false, count: 0, findings: vec![] }),
        };

        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let template_name = input.template.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or("IaC Audit").to_string();

        for (pattern, finding_type, severity, _, solution, _) in TERRAFORM_DANGEROUS_PATTERNS {
            if let Some(line) = content.lines().position(|l| l.contains(pattern)) {
                findings.push(Finding {
                    template_id: template_id.clone(),
                    template_name: template_name.clone(),
                    severity: severity.to_string(),
                    target: target_path.to_string(),
                    matched_at: format!("Dangerous Terraform pattern '{}' at line {}", pattern, line + 1),
                    description: Some(format!("Found {}", finding_type)),
                    solution: Some(solution.to_string()),
                    extracted_data: None,
                    metadata: std::collections::HashMap::new(),
                });
            }
        }

        for (pattern, finding_type, severity, _, solution, _) in DOCKERFILE_CHECKS {
            if let Some(line) = content.lines().position(|l| l.contains(pattern)) {
                findings.push(Finding {
                    template_id: template_id.clone(),
                    template_name: template_name.clone(),
                    severity: severity.to_string(),
                    target: target_path.to_string(),
                    matched_at: format!("Dockerfile security issue '{}' at line {}", finding_type, line + 1),
                    description: Some(format!("Found {}", finding_type)),
                    solution: Some(solution.to_string()),
                    extracted_data: None,
                    metadata: std::collections::HashMap::new(),
                });
            }
        }

        for (pattern, finding_type, severity, _, solution, _) in CFN_DANGEROUS_PATTERNS {
            if content.contains(pattern) {
                findings.push(Finding {
                    template_id: template_id.clone(),
                    template_name: template_name.clone(),
                    severity: severity.to_string(),
                    target: target_path.to_string(),
                    matched_at: format!("CloudFormation security issue '{}'", finding_type),
                    description: Some(format!("Found {}", finding_type)),
                    solution: Some(solution.to_string()),
                    extracted_data: None,
                    metadata: std::collections::HashMap::new(),
                });
            }
        }

        Ok(WasmOutput {
            matched: !findings.is_empty(),
            count: findings.len(),
            findings,
        })
    }
}

export_plugin!(IacAuditScanner);
