from snapescape_api.engines.base import BaseEngine, new_finding
import dns.resolver

TAKEOVER_FINGERPRINTS = {
    "NoSuchBucket": ("AWS S3", "high"),
    "There is no app configured at that hostname": ("Heroku", "high"),
    "GitHub Pages isn't setup": ("GitHub Pages", "high"),
    "Fastly error: unknown domain": ("Fastly", "high"),
    "The request could not be satisfied": ("CloudFront", "medium"),
    "You need to enable JavaScript": ("Shopify", "medium"),
    "Project doesnt exist": ("Readme.io", "high"),
    "This site is currently offline": ("Tumblr", "high"),
    "Do you want to register": ("WordPress", "medium"),
    "is not a registered InCloud YouTrack": ("JetBrains", "high"),
    "Sorry, this shop is currently unavailable": ("Shopify", "medium"),
    "No settings were found for this company": ("Help Scout", "high"),
    "Unrecognized domain": ("Webflow", "high"),
}


class SubdomainTakeoverEngine(BaseEngine):
    async def check(self, subdomains: list[str], scan_id: str) -> list[dict]:
        findings = []
        for sub in subdomains[:50]:
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                try:
                    resp = await self.client.get(url)
                    body = resp.text[:2000]
                    for fp, (service, severity) in TAKEOVER_FINGERPRINTS.items():
                        if fp.lower() in body.lower():
                            try:
                                answers = dns.resolver.resolve(sub, "CNAME")
                                cname = str(answers[0].target)
                            except Exception:
                                cname = "unknown"
                            findings.append(new_finding(
                                scan_id, f"Subdomain Takeover — {service}", severity,
                                "subdomain_takeover", url,
                                {"fingerprint": fp, "cname": cname, "service": service},
                                0.92, "CWE-284", "A05:2021", "T1584",
                            ))
                            break
                except Exception:
                    pass
        return findings
