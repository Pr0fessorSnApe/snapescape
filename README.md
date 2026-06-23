<p align="center">
  <img src="branding/banner.png" alt="SnapeScape — The World's Attack Surface Intelligence Platform" width="100%"/>
</p>

<h1 align="center">SnapeScape</h1>
<p align="center"><strong>THE WORLD'S ATTACK SURFACE INTELLIGENCE PLATFORM</strong></p>
<p align="center">Created By: Pr0Fessor_SnApe</p>

<p align="center">
  <a href="#install">Install</a> •
  <a href="#hunt">Hunt</a> •
  <a href="#zero-false-positives">Zero FP</a> •
  <a href="PLATFORMS.md">Platforms</a> •
  <a href="SECURITY.md">Security</a>
</p>

---

## Zero False Positives

SnapeScape uses a **5-stage validation pipeline** before any finding is reported:

1. **Protocol validation** — URL reachable, meaningful response
2. **Baseline differential** — vuln signal absent on clean request
3. **Replay verification** — detection re-run and confirmed
4. **Content proof** — vuln-type specific evidence check
5. **Negative control** — control request must not trigger false alert

Only findings with **≥95% confidence** and **≥3 validation stages** are shown in reports and dashboard.

Unconfirmed detections are **silently filtered** — you only see real bugs.

---

## Install

### Windows (easiest)
Double-click **`INSTALL.bat`**

### Any OS
```bash
python snapescape.py install
python snapescape.py start --open
```

### Docker
```bash
docker compose up --build -d
```

---

## Hunt

```bash
python snapescape.py hunt example.com
```

| Profile | Time | Use case |
|---------|------|----------|
| `-p quick` | ~2 min | First look |
| `-p standard` | ~5 min | Bug bounty (default) |
| `-p deep` | ~15 min | Full arsenal |

---

## 3 commands

```
snapescape.bat install       → Setup once
snapescape.bat start         → Launch platform
snapescape.bat hunt X.com    → Hunt bugs
```

**Dashboard:** http://localhost:3000  
**Login:** `snape` / `snapescape` *(change before production — see SECURITY.md)*

---

## Supported OS

Windows 10/11 • Linux • macOS • WSL2 • Docker — see [PLATFORMS.md](PLATFORMS.md)

---

## What you get

- 20+ native vulnerability scanners
- **5-stage zero false positive validation**
- AI-powered triage (confirmed findings only)
- Professional HTML/PDF reports
- Real-time command center dashboard

**Authorized testing only.**
