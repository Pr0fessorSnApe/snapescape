//! SNAPESCAPE CLI — native scanning from the command line.

use anyhow::Result;
use clap::{Parser, Subcommand};
use snapescape_dns::{DnsEngine, DnsEnumConfig};
use snapescape_scanner::{HttpEngine, HttpProbeConfig, PortScanConfig, PortScanner, VulnEngine};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "snapescape", version, about = "SNAPESCAPE — Attack Surface Intelligence")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enumerate subdomains for a domain
    Dns {
        #[arg(short, long)]
        domain: String,
        #[arg(long, default_value_t = true)]
        crtsh: bool,
        #[arg(long, default_value_t = true)]
        bruteforce: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Probe HTTP/HTTPS on hosts
    Probe {
        #[arg(short, long)]
        hosts: Vec<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Scan ports on a host
    Ports {
        #[arg(short, long)]
        host: String,
        #[arg(short, long, default_value = "80,443,8080,8443,22,21,25,3306,5432,6379,27017")]
        ports: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Full recon pipeline: DNS → HTTP → Vuln
    Scan {
        #[arg(short, long)]
        domain: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("snapescape=info".parse()?))
        .init();

    print_banner();
    let cli = Cli::parse();

    match cli.command {
        Commands::Dns { domain, crtsh, bruteforce, output } => {
            let scan_id = Uuid::new_v4();
            let engine = DnsEngine::new().await?;
            let config = DnsEnumConfig {
                domain: domain.clone(),
                use_crtsh: crtsh,
                use_bruteforce: bruteforce,
                max_concurrency: 100,
                wordlist: None,
            };
            let assets = engine.enumerate(&config, scan_id).await?;
            let json = serde_json::to_string_pretty(&assets)?;
            if let Some(path) = output {
                std::fs::write(path, &json)?;
            } else {
                println!("{}", json);
            }
            eprintln!("[+] Found {} subdomains for {}", assets.len(), domain);
        }
        Commands::Probe { hosts, output } => {
            let scan_id = Uuid::new_v4();
            let engine = HttpEngine::new(10, true)?;
            let config = HttpProbeConfig {
                hosts,
                ..Default::default()
            };
            let assets = engine.probe_batch(&config, scan_id).await?;
            let json = serde_json::to_string_pretty(&assets)?;
            if let Some(path) = output {
                std::fs::write(path, &json)?;
            } else {
                println!("{}", json);
            }
        }
        Commands::Ports { host, ports, output } => {
            let scan_id = Uuid::new_v4();
            let port_list: Vec<u16> = ports.split(',').filter_map(|p| p.trim().parse().ok()).collect();
            let config = PortScanConfig {
                host: host.clone(),
                ports: port_list,
                timeout_ms: 2000,
                max_concurrency: 200,
            };
            let assets = PortScanner::scan(&config, scan_id).await?;
            let json = serde_json::to_string_pretty(&assets)?;
            if let Some(path) = output {
                std::fs::write(path, &json)?;
            } else {
                println!("{}", json);
            }
            eprintln!("[+] Found {} open ports on {}", assets.len(), host);
        }
        Commands::Scan { domain, output } => {
            let scan_id = Uuid::new_v4();
            eprintln!("[*] SNAPESCAPE full scan: {} (scan_id: {})", domain, scan_id);

            let dns_engine = DnsEngine::new().await?;
            let dns_config = DnsEnumConfig {
                domain: domain.clone(),
                ..Default::default()
            };
            let subdomains = dns_engine.enumerate(&dns_config, scan_id).await?;
            eprintln!("[+] DNS: {} subdomains", subdomains.len());

            let hosts: Vec<String> = subdomains.iter().map(|a| a.value.clone()).collect();
            let http_engine = HttpEngine::new(10, true)?;
            let probe_config = HttpProbeConfig {
                hosts: if hosts.is_empty() { vec![domain.clone()] } else { hosts },
                paths: vec!["/".to_string()],
                ..Default::default()
            };
            let urls = http_engine.probe_batch(&probe_config, scan_id).await?;
            eprintln!("[+] HTTP: {} live hosts", urls.len());

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .user_agent("SNAPESCAPE/0.1")
                .build()?;

            let mut all_findings = Vec::new();
            for asset in &urls {
                let findings = VulnEngine::analyze(&client, &asset.value, scan_id).await?;
                all_findings.extend(findings);
            }
            eprintln!("[+] Vulns: {} findings", all_findings.len());

            let report = serde_json::json!({
                "scan_id": scan_id,
                "domain": domain,
                "subdomains": subdomains,
                "live_hosts": urls,
                "findings": all_findings,
            });
            let json = serde_json::to_string_pretty(&report)?;
            if let Some(path) = output {
                std::fs::write(&path, &json)?;
                eprintln!("[+] Report saved to {:?}", path);
            } else {
                println!("{}", json);
            }
        }
    }

    Ok(())
}

fn print_banner() {
    eprintln!(r#"
   ███████╗███╗   ██╗ █████╗ ██████╗ ███████╗███████╗ ██████╗ █████╗ ██████╗ ███████╗
   ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
   ███████╗██╔██╗ ██║███████║██████╔╝███████╗██║     ███████║██████╔╝█████╗
   ╚════██║██║╚██╗██║██╔══██║██╔═══╝ ██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
   ███████║██║ ╚████║██║  ██║██║     ╚██████╗██║  ██║██║  ██║███████╗
   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                    Created By: Pr0Fessor_SnApe | SNAPESCAPE v0.1.0
"#);
}
