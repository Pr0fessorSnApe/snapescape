#!/usr/bin/env python3
"""
SNAPESCAPE Unified Launcher
Created By: Pr0Fessor_SnApe

One command to install, start, and hunt.

  python snapescape.py install     # First-time setup
  python snapescape.py start       # Start full platform
  python snapescape.py hunt target.com   # Quick scan (CLI)
  python snapescape.py dashboard   # Open browser UI
  python snapescape.py status      # Check all services
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
API_DIR = ROOT / "services" / "python-api"
DASH_DIR = ROOT / "dashboard"
ENV_FILE = ROOT / ".env"
PID_DIR = ROOT / "data" / "pids"

BANNER = r"""
   ███████╗███╗   ██╗ █████╗ ██████╗ ███████╗███████╗ ██████╗ █████╗ ██████╗ ███████╗
   ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
   ███████╗██╔██╗ ██║███████║██████╔╝███████╗██║     ███████║██████╔╝█████╗
   ╚════██║██║╚██╗██║██╔══██║██╔═══╝ ██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
   ███████║██║ ╚████║██║  ██║██║     ╚██████╗██║  ██║██║  ██║███████╗
   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
              The World's Attack Surface Intelligence Platform
                        Created By: Pr0Fessor_SnApe
"""


def run(cmd: list[str] | str, cwd: Path | None = None, check: bool = False) -> int:
    if isinstance(cmd, str):
        return subprocess.call(cmd, shell=True, cwd=cwd or ROOT)
    return subprocess.call(cmd, cwd=cwd or ROOT)


def has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def write_env():
    env_content = """# SNAPESCAPE Auto-generated config
SNAPESCAPE_VAULT_KEY=dev-vault-key-change-in-production-32b
SNAPESCAPE_JWT_SECRET=snapescape-jwt-dev-secret-change-me
REDIS_URL=redis://localhost:6379/0
MONGODB_URL=mongodb://localhost:27017
DATABASE_URL=postgresql://snapescape:snapescape_dev@localhost:5432/snapescape
VITE_API_URL=http://localhost:8000
SNAPESCAPE_URL=http://localhost:3000
"""
    ENV_FILE.write_text(env_content, encoding="utf-8")
    for line in env_content.strip().split("\n"):
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def load_env():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def cmd_install(args):
    print(BANNER)
    print("[*] SNAPESCAPE Installer — making you dangerous...\n")
    write_env()
    load_env()

    PID_DIR.mkdir(parents=True, exist_ok=True)
    (ROOT / "data" / "reports").mkdir(parents=True, exist_ok=True)
    (ROOT / "data" / "evidence").mkdir(parents=True, exist_ok=True)
    (ROOT / "bin").mkdir(parents=True, exist_ok=True)

    # Docker mode (easiest)
    if has("docker") and args.mode in ("auto", "docker"):
        print("[+] Docker detected — using one-command Docker install (recommended)")
        run(["docker", "compose", "pull"], check=False)
        run(["docker", "compose", "build"])
        print("\n[✓] Docker install complete!")
        print("    Run: python snapescape.py start\n")
        return

    # Native mode
    print("[*] Native install mode...\n")
    steps = []

    if has("python") or has("python3"):
        py = "python" if has("python") else "python3"
        print(f"  [+] Installing Python API...")
        run([py, "-m", "pip", "install", "-q", "-r", "requirements.txt"], cwd=API_DIR)
        steps.append("python-api")
    else:
        print("  [!] Python not found — install Python 3.11+")

    if has("npm"):
        print("  [+] Installing Dashboard...")
        run(["npm", "install", "--silent"], cwd=DASH_DIR)
        steps.append("dashboard")

    if has("docker"):
        print("  [+] Starting Redis + Postgres + Mongo (Docker)...")
        run(["docker", "compose", "up", "-d", "redis", "postgres", "mongo"])

    if has("cargo"):
        print("  [+] Building Rust CLI (optional, fast scans)...")
        run(["cargo", "build", "--release"], cwd=ROOT / "engines" / "rust")

    print(f"\n[✓] Install complete! Components: {', '.join(steps) or 'minimal'}")
    print("    Run: python snapescape.py start\n")


def wait_for_url(url: str, timeout: int = 60) -> bool:
    import urllib.request
    for _ in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def cmd_start(args):
    load_env()
    print(BANNER)
    print("[*] Starting SNAPESCAPE...\n")
    PID_DIR.mkdir(parents=True, exist_ok=True)

    if has("docker") and (ROOT / "docker-compose.yml").exists():
        print("[+] Launching full stack via Docker...")
        run(["docker", "compose", "up", "-d"])
        print("[*] Waiting for API...")
        if wait_for_url("http://localhost:8000/api/health"):
            print("[✓] API ready: http://localhost:8000")
        if wait_for_url("http://localhost:3000", timeout=90):
            print("[✓] Dashboard ready: http://localhost:3000")
        if args.open:
            webbrowser.open("http://localhost:3000")
        print("\n  Login: snape / snapescape")
        print("  Docs:  http://localhost:8000/docs\n")
        return

    # Native start
    py = "python" if has("python") else "python3"
    procs = []

    if has("docker"):
        run(["docker", "compose", "up", "-d", "redis", "postgres", "mongo"])

    print("[+] Starting API server...")
    api_log = open(ROOT / "data" / "api.log", "w")
    api_proc = subprocess.Popen(
        [py, "-m", "snapescape_api.main"],
        cwd=API_DIR,
        env={**os.environ},
        stdout=api_log, stderr=subprocess.STDOUT,
    )
    (PID_DIR / "api.pid").write_text(str(api_proc.pid))

    print("[+] Starting Dashboard...")
    dash_log = open(ROOT / "data" / "dashboard.log", "w")
    dash_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=DASH_DIR,
        env={**os.environ, "VITE_API_URL": "http://localhost:8000"},
        stdout=dash_log, stderr=subprocess.STDOUT,
        shell=platform.system() == "Windows",
    )
    (PID_DIR / "dashboard.pid").write_text(str(dash_proc.pid))

    print("[*] Waiting for services...")
    api_ok = wait_for_url("http://localhost:8000/api/health", 45)
    dash_ok = wait_for_url("http://localhost:3000", 60)

    if api_ok:
        print("[✓] API:       http://localhost:8000")
    if dash_ok:
        print("[✓] Dashboard: http://localhost:3000")
        if args.open:
            webbrowser.open("http://localhost:3000")

    print("\n  Login: snape / snapescape")
    print("  Stop:  python snapescape.py stop\n")


def cmd_stop(_args):
    load_env()
    if has("docker"):
        run(["docker", "compose", "down"])
    for pid_file in PID_DIR.glob("*.pid"):
        try:
            pid = int(pid_file.read_text().strip())
            if platform.system() == "Windows":
                run(f"taskkill /PID {pid} /F", check=False)
            else:
                os.kill(pid, 15)
        except Exception:
            pass
        pid_file.unlink(missing_ok=True)
    print("[✓] SNAPESCAPE stopped.")


def cmd_status(_args):
    load_env()
    import urllib.request
    services = {
        "API": "http://localhost:8000/api/health",
        "Dashboard": "http://localhost:3000",
    }
    print("\n  SNAPESCAPE Status\n  " + "─" * 30)
    for name, url in services.items():
        try:
            urllib.request.urlopen(url, timeout=3)
            print(f"  {name:12} ✓ ONLINE")
        except Exception:
            print(f"  {name:12} ✗ offline")
    print()


def cmd_hunt(args):
    """One-command scan — the easiest way to hunt bugs."""
    load_env()
    target = args.target.strip()
    profile = args.profile
    print(BANNER)
    print(f"[*] Hunting: {target}  |  Profile: {profile}\n")

    # Try API first (full pipeline)
    try:
        import urllib.request
        import urllib.parse

        # Login
        data = urllib.parse.urlencode({"username": "snape", "password": "snapescape"}).encode()
        req = urllib.request.Request(
            "http://localhost:8000/api/auth/login",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
        token = token_resp["access_token"]

        # Quick scan endpoint
        body = json.dumps({"target": target, "profile": profile}).encode()
        req = urllib.request.Request(
            "http://localhost:8000/api/quick-scan",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        result = json.loads(urllib.request.urlopen(req, timeout=300).read())
        print(f"\n[✓] Scan complete!")
        print(f"    Assets:   {result.get('assets', 0)}")
        print(f"    Confirmed findings: {result.get('findings', 0)}")
        if result.get("filtered_false_positives"):
            print(f"    Filtered (FP):      {result.get('filtered_false_positives')} unconfirmed detections removed")
        print(f"    Report:   {result.get('report_path', 'see dashboard')}")

        if result.get("top_findings"):
            print("\n  TOP FINDINGS:")
            for f in result["top_findings"][:10]:
                print(f"    [{f.get('severity','?').upper()}] {f.get('title')} — {f.get('url','')}")
        print(f"\n  Full results: http://localhost:3000\n")
        return
    except Exception as e:
        print(f"[*] API not running ({e}), using built-in engine...\n")

    # Fallback: run Python engine directly
    sys.path.insert(0, str(API_DIR))
    import asyncio
    from snapescape_api.engines.registry import run_full_pipeline

    async def _run_and_validate():
        from snapescape_api.validation_engine import ValidationEngine
        result = await run_full_pipeline(target, "cli-scan", profile=profile)
        validator = ValidationEngine()
        validated = await validator.validate_batch(result.get("findings", []))
        await validator.close()
        return result, validated

    result, validated = asyncio.run(_run_and_validate())
    findings = result.get("findings", [])

    filtered = len(findings) - len(validated)
    print(f"\n[✓] Scan complete!")
    print(f"    Assets:   {len(result.get('assets', []))}")
    print(f"    Confirmed findings: {len(validated)}")
    if filtered:
        print(f"    Filtered (FP):      {filtered} unconfirmed detections removed")
    for f in sorted(validated, key=lambda x: x.get("confidence", 0), reverse=True)[:10]:
        print(f"    [{f.get('severity','?').upper()}] {f.get('title')}")
    print()


def cmd_dashboard(args):
    load_env()
    url = "http://localhost:3000"
    print(f"[*] Opening {url}")
    webbrowser.open(url)


def main():
    parser = argparse.ArgumentParser(
        prog="snapescape",
        description="SNAPESCAPE — World's Attack Surface Intelligence Platform",
    )
    sub = parser.add_subparsers(dest="command")

    p_install = sub.add_parser("install", help="One-time setup")
    p_install.add_argument("--mode", choices=["auto", "docker", "native"], default="auto")

    p_start = sub.add_parser("start", help="Start full platform")
    p_start.add_argument("--open", action="store_true", help="Open dashboard in browser")

    sub.add_parser("stop", help="Stop all services")
    sub.add_parser("status", help="Check service health")

    p_hunt = sub.add_parser("hunt", help="Scan a target (easiest command)")
    p_hunt.add_argument("target", help="Domain to scan, e.g. example.com")
    p_hunt.add_argument("--profile", "-p", choices=["quick", "standard", "deep"], default="standard")

    p_dash = sub.add_parser("dashboard", help="Open web dashboard")
    p_dash.add_argument("--open", action="store_true", default=True)

    args = parser.parse_args()
    if not args.command:
        print(BANNER)
        parser.print_help()
        print("\n  Quick start:")
        print("    python snapescape.py install")
        print("    python snapescape.py start --open")
        print("    python snapescape.py hunt example.com\n")
        return

    cmds = {
        "install": cmd_install, "start": cmd_start, "stop": cmd_stop,
        "status": cmd_status, "hunt": cmd_hunt, "dashboard": cmd_dashboard,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
