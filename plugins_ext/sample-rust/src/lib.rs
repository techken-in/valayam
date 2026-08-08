use extism_pdk::*;
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
