//! Native DNS enumeration engine — crt.sh, brute-force, resolution.

use anyhow::{Context, Result};
use chrono::Utc;
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use snapescape_core::{Asset, AssetType};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

const DEFAULT_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging", "stage",
    "test", "beta", "admin", "portal", "vpn", "remote", "cdn", "static", "assets",
    "img", "images", "media", "blog", "shop", "store", "app", "mobile", "m",
    "secure", "login", "auth", "sso", "dashboard", "panel", "cpanel", "webdisk",
    "git", "gitlab", "jenkins", "ci", "build", "docs", "wiki", "help", "support",
    "status", "monitor", "grafana", "kibana", "elastic", "redis", "db", "mysql",
    "postgres", "mongo", "backup", "old", "new", "internal", "intranet", "extranet",
    "partner", "client", "customer", "pay", "payment", "billing", "invoice",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEnumConfig {
    pub domain: String,
    pub use_crtsh: bool,
    pub use_bruteforce: bool,
    pub max_concurrency: usize,
    pub wordlist: Option<Vec<String>>,
}

impl Default for DnsEnumConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            use_crtsh: true,
            use_bruteforce: true,
            max_concurrency: 100,
            wordlist: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
    pub ips: Vec<String>,
    pub cnames: Vec<String>,
}

pub struct DnsEngine {
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsEngine {
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .context("Failed to create DNS resolver")?;
        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }

    pub async fn enumerate(&self, config: &DnsEnumConfig, scan_id: Uuid) -> Result<Vec<Asset>> {
        let mut discovered = HashSet::new();
        let mut results = Vec::new();

        if config.use_crtsh {
            info!(domain = %config.domain, "Querying crt.sh certificate transparency");
            match self.query_crtsh(&config.domain).await {
                Ok(subs) => {
                    for sub in subs {
                        discovered.insert(sub.clone());
                    }
                }
                Err(e) => tracing::warn!("crt.sh query failed: {}", e),
            }
        }

        if config.use_bruteforce {
            let words: Vec<String> = config
                .wordlist
                .clone()
                .unwrap_or_else(|| DEFAULT_WORDLIST.iter().map(|s| s.to_string()).collect());

            info!(count = words.len(), "Brute-forcing subdomains");
            let candidates: Vec<String> = words
                .iter()
                .map(|w| format!("{}.{}", w, config.domain))
                .collect();

            let resolver = self.resolver.clone();
            let domain = config.domain.clone();
            let found: Vec<String> = stream::iter(candidates)
                .map(|candidate| {
                    let resolver = resolver.clone();
                    async move {
                        if resolver.lookup_ip(&candidate).await.is_ok() {
                            Some(candidate)
                        } else {
                            None
                        }
                    }
                })
                .buffer_unordered(config.max_concurrency)
                .filter_map(|x| async { x })
                .collect()
                .await;

            for sub in found {
                discovered.insert(sub);
            }
            let _ = domain;
        }

        for subdomain in discovered {
            let resolved = self.resolve(&subdomain).await.unwrap_or_default();
            debug!(subdomain = %subdomain, ips = ?resolved.ips, "Resolved subdomain");

            results.push(Asset {
                id: Uuid::new_v4(),
                scan_id,
                asset_type: AssetType::Subdomain,
                value: subdomain.clone(),
                parent: Some(config.domain.clone()),
                metadata: serde_json::json!({
                    "ips": resolved.ips,
                    "cnames": resolved.cnames,
                    "source": resolved.source,
                }),
                discovered_at: Utc::now(),
            });
        }

        info!(count = results.len(), "DNS enumeration complete");
        Ok(results)
    }

    async fn query_crtsh(&self, domain: &str) -> Result<HashSet<String>> {
        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            domain.trim_start_matches("*.")
        );
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("SNAPESCAPE/0.1")
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("crt.sh returned {}", resp.status());
        }

        let entries: Vec<serde_json::Value> = resp.json().await?;
        let mut subs = HashSet::new();

        for entry in entries {
            if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
                for name in name_value.split('\n') {
                    let name = name.trim().to_lowercase();
                    if name.ends_with(domain) && !name.contains('*') && name.contains('.') {
                        subs.insert(name);
                    }
                }
            }
        }
        Ok(subs)
    }

    pub async fn resolve(&self, hostname: &str) -> Result<SubdomainResult> {
        let mut ips = Vec::new();
        let mut cnames = Vec::new();

        if let Ok(lookup) = self.resolver.lookup_ip(hostname).await {
            for ip in lookup.iter() {
                ips.push(ip.to_string());
            }
        }

        if let Ok(cname_lookup) = self.resolver.lookup(hostname, hickory_resolver::proto::rr::RecordType::CNAME).await {
            for record in cname_lookup.record_iter() {
                if let Some(rdata) = record.data() {
                    cnames.push(rdata.to_string());
                }
            }
        }

        Ok(SubdomainResult {
            subdomain: hostname.to_string(),
            source: "resolution".to_string(),
            ips,
            cnames,
        })
    }

    pub async fn reverse_dns(&self, ip: &str) -> Result<Vec<String>> {
        use std::net::IpAddr;
        let addr: IpAddr = ip.parse().context("Invalid IP address")?;
        let lookup = self.resolver.reverse_lookup(addr).await?;
        Ok(lookup.iter().map(|n| n.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_engine_creation() {
        let engine = DnsEngine::new().await;
        assert!(engine.is_ok());
    }
}
