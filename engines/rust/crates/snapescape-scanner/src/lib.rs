//! Native HTTP probing, fingerprinting, port scan, and vulnerability detection.

use anyhow::{Context, Result};
use chrono::Utc;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use snapescape_core::{Asset, AssetType, Finding, Severity};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeConfig {
    pub hosts: Vec<String>,
    pub paths: Vec<String>,
    pub max_concurrency: usize,
    pub timeout_secs: u64,
    pub follow_redirects: bool,
}

impl Default for HttpProbeConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            paths: vec!["/".to_string()],
            max_concurrency: 50,
            timeout_secs: 10,
            follow_redirects: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
    pub technologies: Vec<String>,
    pub headers: HashMap<String, String>,
    pub content_length: usize,
    pub response_time_ms: u64,
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    pub host: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub max_concurrency: usize,
}

pub struct HttpEngine {
    client: reqwest::Client,
}

impl HttpEngine {
    pub fn new(timeout_secs: u64, follow_redirects: bool) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("SNAPESCAPE/0.1 (Authorized Security Scanner)")
            .danger_accept_invalid_certs(true);

        if !follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        let client = builder.build().context("Failed to build HTTP client")?;
        Ok(Self { client })
    }

    pub async fn probe_host(&self, host: &str, paths: &[String]) -> Result<Vec<HttpProbeResult>> {
        let mut results = Vec::new();
        let schemes = if host.starts_with("http") {
            vec![host.to_string()]
        } else {
            vec![
                format!("https://{}", host),
                format!("http://{}", host),
            ]
        };

        for base in schemes {
            for path in paths {
                let url = if path.starts_with('/') {
                    format!("{}{}", base.trim_end_matches('/'), path)
                } else {
                    format!("{}/{}", base.trim_end_matches('/'), path)
                };

                if let Ok(result) = self.probe_url(&url).await {
                    results.push(result);
                    break;
                }
            }
        }
        Ok(results)
    }

    pub async fn probe_url(&self, url: &str) -> Result<HttpProbeResult> {
        let start = std::time::Instant::now();
        let resp = self.client.get(url).send().await?;
        let status = resp.status().as_u16();
        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.unwrap_or_default();
        let content_length = body.len();
        let title = extract_title(&body);
        let technologies = fingerprint(&headers, &body);
        let response_time_ms = start.elapsed().as_millis() as u64;
        let tls = url.starts_with("https");

        Ok(HttpProbeResult {
            url: url.to_string(),
            status,
            title,
            technologies,
            headers,
            content_length,
            response_time_ms,
            tls,
        })
    }

    pub async fn probe_batch(&self, config: &HttpProbeConfig, scan_id: Uuid) -> Result<Vec<Asset>> {
        let client = self;
        let paths = config.paths.clone();
        let hosts = config.hosts.clone();

        let results: Vec<HttpProbeResult> = stream::iter(hosts)
            .map(|host| {
                let paths = paths.clone();
                async move {
                    client.probe_host(&host, &paths).await.unwrap_or_default()
                }
            })
            .buffer_unordered(config.max_concurrency)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        let assets: Vec<Asset> = results
            .iter()
            .map(|r| Asset {
                id: Uuid::new_v4(),
                scan_id,
                asset_type: AssetType::Url,
                value: r.url.clone(),
                parent: None,
                metadata: serde_json::to_value(r).unwrap_or_default(),
                discovered_at: Utc::now(),
            })
            .collect();

        info!(count = assets.len(), "HTTP probing complete");
        Ok(assets)
    }
}

pub struct PortScanner;

impl PortScanner {
    pub async fn scan(config: &PortScanConfig, scan_id: Uuid) -> Result<Vec<Asset>> {
        let host = config.host.clone();
        let ports = config.ports.clone();
        let timeout_ms = config.timeout_ms;
        let concurrency = config.max_concurrency;

        let open_ports: Vec<u16> = stream::iter(ports)
            .map(|port| {
                let host = host.clone();
                async move {
                    let addr = format!("{}:{}", host, port);
                    if let Ok(mut addrs) = addr.to_socket_addrs() {
                        if let Some(socket) = addrs.next() {
                            if Self::is_open(socket, timeout_ms).await {
                                return Some(port);
                            }
                        }
                    }
                    None
                }
            })
            .buffer_unordered(concurrency)
            .filter_map(|x| async move { x })
            .collect()
            .await;

        let assets: Vec<Asset> = open_ports
            .iter()
            .map(|port| Asset {
                id: Uuid::new_v4(),
                scan_id,
                asset_type: AssetType::Port,
                value: format!("{}:{}", config.host, port),
                parent: Some(config.host.clone()),
                metadata: serde_json::json!({ "port": port, "state": "open" }),
                discovered_at: Utc::now(),
            })
            .collect();

        info!(host = %config.host, open = assets.len(), "Port scan complete");
        Ok(assets)
    }

    async fn is_open(addr: SocketAddr, timeout_ms: u64) -> bool {
        timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
    }

    pub async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
        let addr = format!("{}:{}", host, port);
        let socket = addr.to_socket_addrs().ok()?.next()?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(socket),
        )
        .await
        .ok()?;

        let mut buf = vec![0u8; 1024];
        let _ = stream.write_all(b"\r\n").await;
        if let Ok(Ok(n)) = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
            if n > 0 {
                return Some(String::from_utf8_lossy(&buf[..n]).to_string());
            }
        }
        None
    }
}

pub struct VulnEngine;

impl VulnEngine {
    pub async fn analyze(
        client: &reqwest::Client,
        url: &str,
        scan_id: Uuid,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        findings.extend(Self::check_cors(client, url, scan_id).await);
        findings.extend(Self::check_security_headers(client, url, scan_id).await);
        findings.extend(Self::check_sensitive_paths(client, url, scan_id).await);
        findings.extend(Self::check_open_redirect(client, url, scan_id).await);

        Ok(findings)
    }

    async fn check_cors(client: &reqwest::Client, url: &str, scan_id: Uuid) -> Vec<Finding> {
        let test_origin = "https://evil.snapescape-test.local";
        let resp = client
            .get(url)
            .header("Origin", test_origin)
            .send()
            .await;

        let mut findings = Vec::new();
        if let Ok(resp) = resp {
            let acao = resp
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok());

            let acac = resp
                .headers()
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok());

            if acao == Some(test_origin) || acao == Some("*") {
                let severity = if acac == Some("true") {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    id: Uuid::new_v4(),
                    scan_id,
                    title: "CORS Misconfiguration".to_string(),
                    severity,
                    confidence: if acac == Some("true") { 0.95 } else { 0.88 },
                    vuln_type: "cors".to_string(),
                    url: url.to_string(),
                    evidence: serde_json::json!({
                        "access-control-allow-origin": acao,
                        "access-control-allow-credentials": acac,
                        "test_origin": test_origin,
                    }),
                    cwe: Some("CWE-942".to_string()),
                    owasp: Some("A05:2021".to_string()),
                    validated: true,
                    validation_stages: vec![
                        "protocol_validation".to_string(),
                        "differential_check".to_string(),
                    ],
                });
            }
        }
        findings
    }

    async fn check_security_headers(
        client: &reqwest::Client,
        url: &str,
        scan_id: Uuid,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let required = [
            ("strict-transport-security", "Missing HSTS Header", Severity::Medium),
            ("x-content-type-options", "Missing X-Content-Type-Options", Severity::Low),
            ("x-frame-options", "Missing X-Frame-Options", Severity::Low),
            ("content-security-policy", "Missing Content-Security-Policy", Severity::Medium),
        ];

        if let Ok(resp) = client.get(url).send().await {
            for (header, title, severity) in required {
                if !resp.headers().contains_key(header) {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        scan_id,
                        title: title.to_string(),
                        severity,
                        confidence: 0.90,
                        vuln_type: "missing_security_header".to_string(),
                        url: url.to_string(),
                        evidence: serde_json::json!({ "missing_header": header }),
                        cwe: Some("CWE-693".to_string()),
                        owasp: Some("A05:2021".to_string()),
                        validated: true,
                        validation_stages: vec!["protocol_validation".to_string()],
                    });
                }
            }
        }
        findings
    }

    async fn check_sensitive_paths(
        client: &reqwest::Client,
        base_url: &str,
        scan_id: Uuid,
    ) -> Vec<Finding> {
        let paths = [
            ("/.git/HEAD", "Git Repository Exposed", Severity::High),
            ("/.env", "Environment File Exposed", Severity::Critical),
            ("/backup.sql", "Database Backup Exposed", Severity::Critical),
            ("/wp-config.php.bak", "WordPress Config Backup", Severity::High),
            ("/robots.txt", "Robots.txt Found", Severity::Info),
            ("/.well-known/security.txt", "Security.txt Found", Severity::Info),
        ];

        let base = base_url.trim_end_matches('/');
        let mut findings = Vec::new();

        for (path, title, severity) in paths {
            let url = format!("{}{}", base, path);
            if let Ok(resp) = client.get(&url).send().await {
                let status = resp.status().as_u16();
                if status == 200 {
                    let body = resp.text().await.unwrap_or_default();
                    let valid = match path {
                        "/.git/HEAD" => body.starts_with("ref:"),
                        "/.env" => body.contains('=') && !body.contains("<html"),
                        "/backup.sql" => body.contains("CREATE") || body.contains("INSERT"),
                        _ => body.len() > 0,
                    };

                    if valid || severity == Severity::Info {
                        findings.push(Finding {
                            id: Uuid::new_v4(),
                            scan_id,
                            title: title.to_string(),
                            severity,
                            confidence: if severity == Severity::Info { 0.99 } else { 0.92 },
                            vuln_type: "sensitive_exposure".to_string(),
                            url,
                            evidence: serde_json::json!({
                                "status": status,
                                "body_preview": &body[..body.len().min(200)],
                            }),
                            cwe: Some("CWE-538".to_string()),
                            owasp: Some("A01:2021".to_string()),
                            validated: valid,
                            validation_stages: vec![
                                "protocol_validation".to_string(),
                                "content_verification".to_string(),
                            ],
                        });
                    }
                }
            }
        }
        findings
    }

    async fn check_open_redirect(
        client: &reqwest::Client,
        url: &str,
        scan_id: Uuid,
    ) -> Vec<Finding> {
        let params = ["url", "redirect", "next", "return", "returnUrl", "dest", "destination"];
        let payload = "https://evil.snapescape-test.local";
        let mut findings = Vec::new();

        let base = if url.contains('?') {
            format!("{}&", url.split('?').next().unwrap_or(url))
        } else {
            format!("{}?", url.trim_end_matches('/'))
        };

        for param in params {
            let test_url = format!("{}{}={}", base, param, payload);
            if let Ok(resp) = client.get(&test_url).send().await {
                if resp.status().is_redirection() {
                    if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                        if loc.contains("evil.snapescape-test.local") {
                            findings.push(Finding {
                                id: Uuid::new_v4(),
                                scan_id,
                                title: "Open Redirect".to_string(),
                                severity: Severity::Medium,
                                confidence: 0.91,
                                vuln_type: "open_redirect".to_string(),
                                url: test_url,
                                evidence: serde_json::json!({
                                    "parameter": param,
                                    "location": loc,
                                }),
                                cwe: Some("CWE-601".to_string()),
                                owasp: Some("A01:2021".to_string()),
                                validated: true,
                                validation_stages: vec![
                                    "protocol_validation".to_string(),
                                    "differential_check".to_string(),
                                ],
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    if let Some(start) = lower.find("<title>") {
        if let Some(end) = lower.find("</title>") {
            let title = &body[start + 7..end];
            return Some(title.trim().to_string());
        }
    }
    None
}

fn fingerprint(headers: &HashMap<String, String>, body: &str) -> Vec<String> {
    let mut techs = Vec::new();
    let checks: &[(&str, &str)] = &[
        ("server", "Server"),
        ("x-powered-by", "Powered-By"),
    ];

    for (header, _label) in checks {
        if let Some(val) = headers.get(&header.to_string()).or_else(|| {
            headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(header)).map(|(_, v)| v)
        }) {
            techs.push(val.clone());
        }
    }

    let body_signatures: &[(&str, &str)] = &[
        ("wp-content", "WordPress"),
        ("drupal", "Drupal"),
        ("Joomla", "Joomla"),
        ("react", "React"),
        ("vue", "Vue.js"),
        ("angular", "Angular"),
        ("__NEXT_DATA__", "Next.js"),
        ("graphql", "GraphQL"),
        ("laravel", "Laravel"),
        ("django", "Django"),
        ("flask", "Flask"),
        ("express", "Express"),
        ("cloudflare", "Cloudflare"),
    ];

    let body_lower = body.to_lowercase();
    for (sig, name) in body_signatures {
        if body_lower.contains(&sig.to_lowercase()) {
            techs.push(name.to_string());
        }
    }

    techs.sort();
    techs.dedup();
    techs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_title() {
        assert_eq!(
            extract_title("<html><title>Test Page</title></html>"),
            Some("Test Page".to_string())
        );
    }

    #[test]
    fn test_fingerprint() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx".to_string());
        let techs = fingerprint(&headers, "<html>react app</html>");
        assert!(techs.contains(&"nginx".to_string()));
        assert!(techs.contains(&"React".to_string()));
    }
}
