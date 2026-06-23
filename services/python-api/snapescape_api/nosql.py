"""MongoDB NoSQL document store for scan artifacts."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient


class NoSQLStore:
    def __init__(self, url: str | None = None):
        self.url = url or os.getenv("MONGODB_URL", "mongodb://localhost:27017")
        self.client: AsyncIOMotorClient | None = None
        self.db = None

    async def connect(self):
        self.client = AsyncIOMotorClient(self.url)
        self.db = self.client.snapescape

    async def disconnect(self):
        if self.client:
            self.client.close()

    async def save_scan_artifact(self, scan_id: str, artifact_type: str, data: dict[str, Any]):
        await self.db.artifacts.insert_one({
            "scan_id": scan_id,
            "type": artifact_type,
            "data": data,
            "created_at": datetime.now(timezone.utc),
        })

    async def save_evidence(self, finding_id: str, evidence: dict[str, Any]):
        await self.db.evidence.insert_one({
            "finding_id": finding_id,
            **evidence,
            "created_at": datetime.now(timezone.utc),
        })

    async def get_crawl_tree(self, scan_id: str) -> dict | None:
        doc = await self.db.artifacts.find_one({"scan_id": scan_id, "type": "crawl_tree"})
        return doc.get("data") if doc else None

    async def get_telemetry_stream(self, scan_id: str, limit: int = 100) -> list[dict]:
        cursor = self.db.telemetry.find({"scan_id": scan_id}).sort("created_at", -1).limit(limit)
        return await cursor.to_list(length=limit)
