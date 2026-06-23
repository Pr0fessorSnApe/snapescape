"""Master engine registry — orchestrates all native scanners."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Callable, Awaitable

from snapescape_api.engines.recon.subdomain_takeover import SubdomainTakeoverEngine
from snapescape_api.engines.recon.cloud_buckets import CloudBucketEngine
from snapescape_api.engines.recon.origin_ip import OriginIpEngine
from snapescape_api.engines.recon.waf_cdn import WafCdnEngine
from snapescape_api.engines.recon.passive_recon import PassiveReconEngine
from snapescape_api.engines.crawl.adaptive_crawler import AdaptiveCrawler
from snapescape_api.engines.crawl.content_discovery import ContentDiscoveryEngine
from snapescape_api.engines.crawl.param_miner import ParamMiner
from snapescape_api.engines.crawl.js_analyzer import JsAnalyzer
from snapescape_api.engines.crawl.secret_detector import SecretDetector
from snapescape_api.engines.vuln.sqli import SqliEngine
from snapescape_api.engines.vuln.xss import XssEngine
from snapescape_api.engines.vuln.ssrf import SsrfEngine
from snapescape_api.engines.vuln.ssti import SstiEngine
from snapescape_api.engines.vuln.xxe import XxeEngine
from snapescape_api.engines.vuln.cors import CorsEngine
from snapescape_api.engines.vuln.crlf import CrlfEngine
from snapescape_api.engines.vuln.smuggling import SmugglingEngine
from snapescape_api.engines.vuln.cache_poison import CachePoisonEngine
from snapescape_api.engines.vuln.jwt_analyzer import JwtAnalyzer
from snapescape_api.engines.vuln.graphql import GraphqlEngine
from snapescape_api.engines.vuln.cms import CmsEngine
from snapescape_api.engines.vuln.exposure import ExposureEngine
from snapescape_api.engines.vuln.redirect import RedirectEngine
from snapescape_api.engines.vuln.headers import HeadersEngine
from snapescape_api.engines.fuzz.fuzzer import FuzzEngine

logger = logging.getLogger("snapescape.engines")

PHASES = [
    "passive_recon",
    "subdomain_discovery",
    "dns_resolution",
    "http_probe",
    "port_scan",
    "waf_cdn_detection",
    "content_discovery",
    "adaptive_crawl",
    "param_mining",
    "js_analysis",
    "secret_detection",
    "cloud_bucket_discovery",
    "subdomain_takeover",
    "origin_ip_discovery",
    "vuln_analysis",
    "fuzzing",
    "validation",
    "complete",
]

SCAN_PROFILES = {
    "quick": [
        "passive_recon", "http_probe", "vuln_analysis", "complete",
    ],
    "standard": [
        "passive_recon", "subdomain_discovery", "http_probe", "port_scan",
        "content_discovery", "vuln_analysis", "complete",
    ],
    "deep": PHASES,
}


class EngineRegistry:
    def __init__(self):
        self.recon = {
            "passive": PassiveReconEngine(),
            "takeover": SubdomainTakeoverEngine(),
            "buckets": CloudBucketEngine(),
            "origin_ip": OriginIpEngine(),
            "waf_cdn": WafCdnEngine(),
        }
        self.crawl = {
            "crawler": AdaptiveCrawler(),
            "content": ContentDiscoveryEngine(),
            "params": ParamMiner(),
            "js": JsAnalyzer(),
            "secrets": SecretDetector(),
        }
        self.vuln = {
            "sqli": SqliEngine(),
            "xss": XssEngine(),
            "ssrf": SsrfEngine(),
            "ssti": SstiEngine(),
            "xxe": XxeEngine(),
            "cors": CorsEngine(),
            "crlf": CrlfEngine(),
            "smuggling": SmugglingEngine(),
            "cache_poison": CachePoisonEngine(),
            "jwt": JwtAnalyzer(),
            "graphql": GraphqlEngine(),
            "cms": CmsEngine(),
            "exposure": ExposureEngine(),
            "redirect": RedirectEngine(),
            "headers": HeadersEngine(),
        }
        self.fuzz = FuzzEngine()

    async def run_phase(
        self,
        phase: str,
        target: str,
        scan_id: str,
        context: dict[str, Any],
        on_event: Callable[[dict], Awaitable[None]] | None = None,
    ) -> dict[str, Any]:
        assets: list[dict] = context.get("assets", [])
        findings: list[dict] = context.get("findings", [])
        urls: list[str] = context.get("urls", [f"https://{target}", f"http://{target}"])

        async def emit(event: dict):
            if on_event:
                await on_event({**event, "scan_id": scan_id, "phase": phase})

        if phase == "passive_recon":
            data = await self.recon["passive"].scan(target)
            assets.extend(data.get("assets", []))
            urls.extend([a["value"] for a in data.get("assets", []) if a.get("asset_type") == "subdomain"])
            await emit({"event": "assets_found", "count": len(data.get("assets", []))})

        elif phase in ("subdomain_discovery", "dns_resolution"):
            data = await self.recon["passive"].scan(target)
            assets.extend(data.get("assets", []))
            urls.extend([a["value"] for a in data.get("assets", []) if "asset_type" in a])
            if not urls:
                urls = [f"https://{target}", f"http://{target}"]

        elif phase == "http_probe":
            import httpx
            probe_urls = urls[:20] if urls else [f"https://{target}", f"http://{target}"]
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for u in probe_urls:
                    try:
                        r = await client.get(u, follow_redirects=True)
                        assets.append({
                            "id": str(__import__("uuid").uuid4()), "scan_id": scan_id,
                            "asset_type": "url", "value": str(r.url),
                            "metadata": {"status": r.status_code, "title": r.text[:100]},
                        })
                    except Exception:
                        pass

        elif phase == "port_scan":
            import socket
            for host in [target] + [a["value"] for a in assets if a.get("asset_type") == "subdomain"][:5]:
                for port in [80, 443, 8080, 8443, 22, 3306, 5432, 6379, 27017]:
                    try:
                        s = socket.create_connection((host, port), timeout=2)
                        s.close()
                        assets.append({
                            "id": str(__import__("uuid").uuid4()), "scan_id": scan_id,
                            "asset_type": "port", "value": f"{host}:{port}",
                            "metadata": {"state": "open"},
                        })
                    except Exception:
                        pass

        elif phase == "waf_cdn_detection":
            for url in urls[:5]:
                findings.extend(await self.recon["waf_cdn"].analyze(url, scan_id))

        elif phase == "content_discovery":
            for url in urls[:3]:
                result = await self.crawl["content"].discover(url, scan_id)
                assets.extend(result.get("assets", []))
                urls.extend(result.get("urls", []))

        elif phase == "adaptive_crawl":
            result = await self.crawl["crawler"].crawl(urls[0] if urls else f"https://{target}", scan_id)
            assets.extend(result.get("assets", []))
            urls = list(set(urls + result.get("urls", [])))
            context["crawl_tree"] = result.get("tree", {})

        elif phase == "param_mining":
            for url in urls[:10]:
                assets.extend(await self.crawl["params"].mine(url, scan_id))

        elif phase == "js_analysis":
            for url in urls[:5]:
                findings.extend(await self.crawl["js"].analyze(url, scan_id))

        elif phase == "secret_detection":
            for url in urls[:5]:
                findings.extend(await self.crawl["secrets"].detect(url, scan_id))

        elif phase == "cloud_bucket_discovery":
            findings.extend(await self.recon["buckets"].discover(target, scan_id))

        elif phase == "subdomain_takeover":
            subs = [a["value"] for a in assets if a.get("asset_type") == "subdomain"]
            if not subs:
                subs = [target]
            findings.extend(await self.recon["takeover"].check(subs, scan_id))

        elif phase == "origin_ip_discovery":
            result = await self.recon["origin_ip"].discover(target, scan_id)
            assets.extend(result.get("assets", []))
            findings.extend(result.get("findings", []))

        elif phase == "vuln_analysis":
            vuln_tasks = []
            for engine in self.vuln.values():
                for url in urls[:15]:
                    vuln_tasks.append(engine.analyze(url, scan_id))
            results = await asyncio.gather(*vuln_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)

        elif phase == "fuzzing":
            for url in urls[:5]:
                findings.extend(await self.fuzz.fuzz_url(url, scan_id))

        context["assets"] = assets
        context["findings"] = findings
        context["urls"] = list(set(urls))
        return context


async def run_full_pipeline(
    target: str,
    scan_id: str,
    on_event: Callable[[dict], Awaitable[None]] | None = None,
    should_continue: Callable[[], bool] | None = None,
    profile: str = "standard",
) -> dict[str, Any]:
    registry = EngineRegistry()
    context: dict[str, Any] = {"assets": [], "findings": [], "urls": []}
    phases = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])
    total = len(phases)

    for i, phase in enumerate(phases):
        if should_continue and not should_continue():
            break
        progress = ((i + 1) / total) * 100
        if on_event:
            await on_event({"event": "phase_start", "phase": phase, "progress": progress, "scan_id": scan_id})
        context = await registry.run_phase(phase, target, scan_id, context, on_event)
        if on_event:
            await on_event({
                "event": "phase_complete",
                "phase": phase,
                "progress": progress,
                "scan_id": scan_id,
                "assets": len(context["assets"]),
                "findings": len(context["findings"]),
            })

    return context
