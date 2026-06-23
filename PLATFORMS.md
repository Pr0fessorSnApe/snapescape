# SNAPESCAPE — Supported Platforms

Created By: Pr0Fessor_SnApe

## Quick answer

| OS | Support | Recommended install |
|----|---------|---------------------|
| **Windows 10/11** | Full | `INSTALL.bat` or Docker |
| **Linux** (Ubuntu, Debian, Fedora, Arch) | Full | `install.sh` or Docker |
| **macOS** (Intel & Apple Silicon) | Full | `install.sh` or Docker |
| **WSL2** (Windows) | Full | Same as Linux |
| **Docker anywhere** | Best | `docker compose up` |

---

## Tier 1 — Fully supported (recommended)

### Windows 10 / 11 (64-bit)
- **Install:** Double-click `INSTALL.bat` or `python snapescape.py install`
- **Start:** `START.bat` or `python snapescape.py start --open`
- **Hunt:** `HUNT.bat target.com`
- **Requires:** Python 3.11+ (or Docker Desktop)
- **Optional:** Rust, Go, Node.js for native builds

### Linux (Ubuntu 22.04+, Debian 12+, Fedora, Arch)
- **Install:** `chmod +x install.sh && ./install.sh`
- **Start:** `python3 snapescape.py start --open`
- **Requires:** Python 3.11+, Docker (recommended)

### macOS (12+ Monterey, Ventura, Sonoma)
- **Install:** `./install.sh`
- **Start:** `python3 snapescape.py start --open`
- **Requires:** Python 3.11+ via Homebrew, Docker Desktop (recommended)

### WSL2 (Ubuntu on Windows)
- Same as Linux — use `install.sh`
- Access dashboard at `http://localhost:3000` from Windows browser

---

## Tier 2 — Docker-only (easiest, any OS)

If Docker Desktop / Docker Engine is installed:

```bash
docker compose up --build -d
```

Works on:
- Windows 10/11 with Docker Desktop
- macOS with Docker Desktop
- Linux with Docker Engine
- Cloud VMs (AWS, GCP, Azure, DigitalOcean)

**No Python/Node/Rust install needed** — everything runs in containers.

---

## Tier 3 — Optional native components

These are **optional** — core platform runs without them.

| Component | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| Python API | Yes | Yes | Yes |
| Dashboard (Node) | Yes | Yes | Yes |
| Rust CLI scanner | Yes* | Yes | Yes |
| Go worker | Yes* | Yes | Yes |
| Playwright browser | Yes | Yes | Yes |
| Puppeteer browser | Yes | Yes | Yes |
| C/C++ packet engine | Yes* | Yes | Yes |
| Nim fuzzer | Yes* | Yes | Yes |
| Zig parser | Yes* | Yes | Yes |
| Assembly (x86_64) | Yes | Yes** | Yes** |

\* Requires toolchain installed (`rustup`, `go`, `nim`, `zig`, MSVC/GCC)  
\** x86_64 assembly; ARM Macs use C fallback checksum

---

## Minimum requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8 GB+ |
| Disk | 2 GB free | 5 GB+ |
| CPU | 2 cores | 4+ cores |
| Network | Required for scans | Stable broadband |

---

## What does NOT work

| Environment | Status | Reason |
|-------------|--------|--------|
| Windows 7/8 | Not supported | Python 3.11+ unavailable |
| 32-bit OS | Not supported | Modern toolchains are 64-bit |
| iOS / Android | Not supported | Desktop/server platform |
| Shared hosting (cPanel) | Not supported | Needs Docker or full shell |
| Air-gapped (no internet) | Partial | Scans need network; install needs packages |

---

## Architecture notes

- **Primary path:** Python 3.11+ API + React dashboard
- **Best experience:** Docker Compose (all services orchestrated)
- **CLI-only:** `python snapescape.py hunt target.com` (no dashboard needed)
- **Desktop app:** Electron wrapper — Windows, Linux, macOS

---

## Authorized use only

SNAPESCAPE is for **authorized security testing** on targets you own or have written permission to test.
