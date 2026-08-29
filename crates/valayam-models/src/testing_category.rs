use serde::{Deserialize, Serialize};

/// High-level SDLC testing categories that a template can be classified under.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TestingCategory {
    UnitTesting,
    ApiTesting,
    IntegrationTesting,
    SecurityTesting,
    StaticAnalysis,
    DependencyScanning,
    SmokeTesting,
    RegressionTesting,
}

impl std::fmt::Display for TestingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnitTesting => write!(f, "unit_testing"),
            Self::ApiTesting => write!(f, "api_testing"),
            Self::IntegrationTesting => write!(f, "integration_testing"),
            Self::SecurityTesting => write!(f, "security_testing"),
            Self::StaticAnalysis => write!(f, "static_analysis"),
            Self::DependencyScanning => write!(f, "dependency_scanning"),
            Self::SmokeTesting => write!(f, "smoke_testing"),
            Self::RegressionTesting => write!(f, "regression_testing"),
        }
    }
}

impl std::str::FromStr for TestingCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unit_testing" | "unit" => Ok(Self::UnitTesting),
            "api_testing" | "api" => Ok(Self::ApiTesting),
            "integration_testing" | "integration" => Ok(Self::IntegrationTesting),
            "security_testing" | "security" => Ok(Self::SecurityTesting),
            "static_analysis" | "sast" => Ok(Self::StaticAnalysis),
            "dependency_scanning" | "dependency" | "sca" => Ok(Self::DependencyScanning),
            "smoke_testing" | "smoke" => Ok(Self::SmokeTesting),
            "regression_testing" | "regression" => Ok(Self::RegressionTesting),
            _ => Err(format!("Unknown testing category: {}", s)),
        }
    }
}
