# Security Policy — SNAPESCAPE

## Before publishing to GitHub

1. **Change default credentials** before deploying publicly:
   - Dashboard login: `snape` / `snapescape` (change in `snapescape_api/auth.py` or use env)
   - `SNAPESCAPE_JWT_SECRET` in `.env`
   - `SNAPESCAPE_VAULT_KEY` in `.env`

2. **Never commit:**
   - `.env` (gitignored)
   - `config/vault.json` (gitignored)
   - Scan reports with real target data
   - API keys (OpenAI, Shodan, etc.)

3. **Authorized testing only** — only scan targets you own or have written permission to test.

## Reporting vulnerabilities

If you find a security issue in SNAPESCAPE itself, report it privately to the repository owner.
