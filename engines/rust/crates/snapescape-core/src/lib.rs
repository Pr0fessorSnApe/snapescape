//! SNAPESCAPE core types shared across all Rust engines.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: Uuid,
    pub domain: String,
    pub workspace_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    SubdomainDiscovery,
    DnsResolution,
    HttpProbing,
    PortScanning,
    ContentDiscovery,
    VulnerabilityAnalysis,
    Validation,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub phase: ScanPhase,
    pub target: String,
    pub payload: serde_json::Value,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub asset_type: AssetType,
    pub value: String,
    pub parent: Option<String>,
    pub metadata: serde_json::Value,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    Domain,
    Subdomain,
    Ip,
    Url,
    Port,
    Technology,
    Endpoint,
    Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub title: String,
    pub severity: Severity,
    pub confidence: f64,
    pub vuln_type: String,
    pub url: String,
    pub evidence: serde_json::Value,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub validated: bool,
    pub validation_stages: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub scan_id: Uuid,
    pub event_type: String,
    pub message: String,
    pub progress: f64,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapescapeError {
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    #[error("HTTP probe failed: {0}")]
    Http(String),
    #[error("Scan error: {0}")]
    Scan(String),
}

pub type Result<T> = std::result::Result<T, SnapescapeError>;
