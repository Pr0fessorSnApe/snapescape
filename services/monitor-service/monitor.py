"""Continuous monitoring service — scheduled re-scans."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from snapescape_api.orchestrator import ScanOrchestrator

logger = logging.getLogger("snapescape.monitor")


class MonitorService:
    def __init__(self, orchestrator: ScanOrchestrator):
        self.orchestrator = orchestrator
        self.monitored: dict[str, dict] = {}

    async def add_target(self, target: str, interval_hours: int = 24) -> dict:
        scan = await self.orchestrator.create_scan(target)
        entry = {
            "target": target,
            "scan_id": scan["id"],
            "interval_hours": interval_hours,
            "last_run": None,
            "enabled": True,
        }
        self.monitored[target] = entry
        cron = f"0 */{interval_hours} * * *"
        await self.orchestrator.schedule_scan(scan["id"], cron)
        return entry

    async def run_loop(self):
        while True:
            for target, entry in self.monitored.items():
                if entry["enabled"]:
                    logger.info("Monitor tick: %s", target)
                    entry["last_run"] = datetime.now(timezone.utc).isoformat()
            await asyncio.sleep(3600)

    def list_monitored(self) -> list[dict]:
        return list(self.monitored.values())

    async def disable(self, target: str):
        if target in self.monitored:
            self.monitored[target]["enabled"] = False
