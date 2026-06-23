"""Example SNAPESCAPE plugin."""

async def run(target: str, scan_id: str) -> dict:
    return {
        "findings": [{
            "title": f"Plugin scan complete for {target}",
            "severity": "info",
            "vuln_type": "plugin",
            "url": f"https://{target}",
            "confidence": 1.0,
        }],
        "assets": [],
        "metadata": {"plugin": "example_plugin"},
    }
