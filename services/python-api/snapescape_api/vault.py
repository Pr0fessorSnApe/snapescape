"""Centralized AES-256 encrypted API key vault."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger("snapescape.vault")

VAULT_PATH = Path(os.getenv("SNAPESCAPE_VAULT_PATH", "config/vault.json"))
AUDIT_LOG = Path(os.getenv("SNAPESCAPE_AUDIT_LOG", "data/audit.log"))


class VaultError(Exception):
    pass


class SecretsVault:
    """Single encrypted configuration file for all API keys."""

    def __init__(self, vault_path: Path | None = None):
        self.vault_path = vault_path or VAULT_PATH
        self._fernet: Fernet | None = None
        self._cache: dict[str, Any] | None = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _get_fernet(self) -> Fernet:
        if self._fernet:
            return self._fernet
        master_key = os.getenv("SNAPESCAPE_VAULT_KEY")
        if not master_key:
            raise VaultError("SNAPESCAPE_VAULT_KEY environment variable not set")

        if self.vault_path.exists():
            with open(self.vault_path) as f:
                meta = json.load(f)
            salt = base64.b64decode(meta["salt"])
        else:
            salt = os.urandom(16)

        key = self._derive_key(master_key, salt)
        self._fernet = Fernet(key)
        return self._fernet

    def _audit(self, action: str, key_name: str | None = None) -> None:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "key": key_name,
        }
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def load(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache

        if not self.vault_path.exists():
            self._cache = {"providers": {}, "version": 1}
            return self._cache

        with open(self.vault_path) as f:
            meta = json.load(f)

        fernet = self._get_fernet()
        try:
            decrypted = fernet.decrypt(meta["data"].encode())
            self._cache = json.loads(decrypted)
            self._audit("vault_read")
            return self._cache
        except InvalidToken:
            raise VaultError("Vault decryption failed — check SNAPESCAPE_VAULT_KEY")

    def save(self, data: dict[str, Any]) -> None:
        fernet = self._get_fernet()
        salt = os.urandom(16)
        encrypted = fernet.encrypt(json.dumps(data).encode()).decode()

        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.vault_path, "w") as f:
            json.dump({"salt": base64.b64encode(salt).decode(), "data": encrypted, "version": 1}, f, indent=2)

        self._cache = data
        self._audit("vault_write")

    def get_key(self, provider: str, key_name: str = "api_key") -> str | None:
        data = self.load()
        provider_data = data.get("providers", {}).get(provider, {})
        value = provider_data.get(key_name)
        if value:
            self._audit("key_access", f"{provider}.{key_name}")
        return value

    def set_key(self, provider: str, key_name: str, value: str) -> None:
        data = self.load()
        if "providers" not in data:
            data["providers"] = {}
        if provider not in data["providers"]:
            data["providers"][provider] = {}
        data["providers"][provider][key_name] = value
        self.save(data)
        self._audit("key_set", f"{provider}.{key_name}")

    def validate_providers(self) -> dict[str, bool]:
        """Validate configured API keys by provider."""
        data = self.load()
        results = {}
        for provider, keys in data.get("providers", {}).items():
            results[provider] = bool(keys.get("api_key"))
        return results

    def list_providers(self) -> list[str]:
        return list(self.load().get("providers", {}).keys())


_vault_instance: SecretsVault | None = None


def get_vault() -> SecretsVault:
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = SecretsVault()
    return _vault_instance
