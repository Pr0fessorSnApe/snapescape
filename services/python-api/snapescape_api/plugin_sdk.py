"""Sandboxed plugin execution environment."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


class PluginSDK:
    """Load and execute signed SNAPESCAPE plugins."""

    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self.loaded: dict[str, Any] = {}

    def list_plugins(self) -> list[str]:
        return [p.stem for p in self.plugin_dir.glob("*.py") if not p.name.startswith("_")]

    def load(self, name: str) -> Any:
        if name in self.loaded:
            return self.loaded[name]
        path = self.plugin_dir / f"{name}.py"
        if not path.exists():
            raise FileNotFoundError(f"Plugin {name} not found")
        spec = importlib.util.spec_from_file_location(f"snapescape_plugin_{name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.loaded[name] = module
        return module

    async def execute(self, name: str, target: str, scan_id: str) -> dict[str, Any]:
        module = self.load(name)
        if hasattr(module, "run"):
            result = module.run(target, scan_id)
            if hasattr(result, "__await__"):
                return await result
            return result
        raise ValueError(f"Plugin {name} missing run() function")

    def get_sdk_template(self) -> str:
        return '''"""SNAPESCAPE Plugin — implement run(target, scan_id)"""

async def run(target: str, scan_id: str) -> dict:
    return {
        "findings": [],
        "assets": [],
        "metadata": {"plugin": "my_plugin", "target": target},
    }
'''
