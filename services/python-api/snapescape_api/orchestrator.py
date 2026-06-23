"""Real scan orchestration — no mocks."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Awaitable

import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from snapescape_api.engines.registry import run_full_pipeline, PHASES
from snapescape_api.graph_engine import GraphEngine
from snapescape_api.validation_engine import ValidationEngine
from snapescape_api.nosql import NoSQLStore

logger = logging.getLogger("snapescape.orchestrator")

TASK_STREAM = "snapescape:tasks"
TELEMETRY_CHANNEL = "snapescape:telemetry"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETE = "complete"
    FAILED = "failed"


class ScanOrchestrator:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None
        self._scans: dict[str, dict[str, Any]] = {}
        self._scan_tasks: dict[str, asyncio.Task] = {}
        self._telemetry_callbacks: list[Callable[[dict], Awaitable[None]]] = []
        self._scheduler = AsyncIOScheduler()
        self._graph = GraphEngine()
        self._validator = ValidationEngine()
        self._nosql = NoSQLStore()
        self._workers: dict[str, dict] = {}

    async def connect(self) -> None:
        self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        await self._redis.ping()
        try:
            await self._nosql.connect()
        except Exception as e:
            logger.warning("MongoDB unavailable: %s", e)
        self._scheduler.start()
        asyncio.create_task(self._listen_workers())
        logger.info("Orchestrator connected")

    async def disconnect(self) -> None:
        for task in self._scan_tasks.values():
            task.cancel()
        self._scheduler.shutdown(wait=False)
        if self._redis:
            await self._redis.close()
        await self._validator.close()
        await self._nosql.disconnect()

    def on_telemetry(self, callback: Callable[[dict], Awaitable[None]]) -> None:
        self._telemetry_callbacks.append(callback)

    async def _emit(self, event: dict[str, Any]) -> None:
        if self._redis:
            await self._redis.publish(TELEMETRY_CHANNEL, json.dumps(event))
        for cb in self._telemetry_callbacks:
            try:
                await cb(event)
            except Exception as e:
                logger.error("Telemetry error: %s", e)

    async def _listen_workers(self) -> None:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(TELEMETRY_CHANNEL)
        try:
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    try:
                        data = json.loads(msg["data"])
                        if data.get("worker_id"):
                            self._workers[data["worker_id"]] = data
                    except json.JSONDecodeError:
                        pass
        except asyncio.CancelledError:
            await pubsub.unsubscribe(TELEMETRY_CHANNEL)

    async def create_scan(self, target: str, workspace_id: str | None = None) -> dict[str, Any]:
        scan_id = str(uuid.uuid4())
        scan = {
            "id": scan_id,
            "target": target,
            "workspace_id": workspace_id,
            "status": ScanStatus.PENDING,
            "phase": PHASES[0],
            "progress": 0.0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "assets": [],
            "findings": [],
            "crawl_tree": {},
            "graph": {},
            "evidence": [],
            "metadata": {},
        }
        self._scans[scan_id] = scan
        await self._emit({"scan_id": scan_id, "event": "scan_created", "target": target})
        return scan

    async def start_scan(self, scan_id: str, profile: str = "standard") -> dict[str, Any]:
        scan = self._get_scan(scan_id)
        if scan["status"] == ScanStatus.RUNNING:
            return scan
        scan["status"] = ScanStatus.RUNNING
        scan["started_at"] = datetime.now(timezone.utc).isoformat()
        scan["profile"] = profile

        async def run():
            try:
                def should_continue():
                    s = self._scans.get(scan_id)
                    return s and s["status"] == ScanStatus.RUNNING

                async def on_event(event: dict):
                    s = self._scans.get(scan_id)
                    if not s:
                        return
                    if "phase" in event:
                        s["phase"] = event["phase"]
                    if "progress" in event:
                        s["progress"] = event["progress"]
                    await self._emit(event)
                    try:
                        await self._nosql.db.telemetry.insert_one({**event, "created_at": datetime.now(timezone.utc)})
                    except Exception:
                        pass

                result = await run_full_pipeline(
                    scan["target"], scan_id, on_event=on_event,
                    should_continue=should_continue, profile=profile,
                )

                validated = await self._validator.validate_batch(result.get("findings", []))
                scan["assets"] = result.get("assets", [])
                scan["findings"] = validated
                scan["crawl_tree"] = result.get("crawl_tree", {})
                scan["graph"] = self._graph.build_from_scan(scan_id, scan["assets"], scan["findings"])

                try:
                    await self._nosql.save_scan_artifact(scan_id, "crawl_tree", scan["crawl_tree"])
                    await self._nosql.save_scan_artifact(scan_id, "graph", scan["graph"])
                except Exception:
                    pass

                if scan["status"] == ScanStatus.RUNNING:
                    scan["status"] = ScanStatus.COMPLETE
                    scan["progress"] = 100.0
                    scan["phase"] = "complete"
                    scan["completed_at"] = datetime.now(timezone.utc).isoformat()
                    await self._emit({"scan_id": scan_id, "event": "scan_complete", "findings": len(validated)})
            except Exception as e:
                logger.exception("Scan failed: %s", e)
                scan["status"] = ScanStatus.FAILED
                scan["metadata"]["error"] = str(e)
                await self._emit({"scan_id": scan_id, "event": "scan_failed", "error": str(e)})

        self._scan_tasks[scan_id] = asyncio.create_task(run())
        await self._emit({"scan_id": scan_id, "event": "scan_started"})
        return scan

    async def schedule_scan(self, scan_id: str, cron: str) -> dict:
        scan = self._get_scan(scan_id)
        self._scheduler.add_job(
            self.start_scan, "cron", args=[scan_id], id=f"scan-{scan_id}", **self._parse_cron(cron),
        )
        scan["scheduled"] = cron
        return scan

    def _parse_cron(self, cron: str) -> dict:
        parts = cron.split()
        if len(parts) == 5:
            return {"minute": parts[0], "hour": parts[1], "day": parts[2], "month": parts[3], "day_of_week": parts[4]}
        return {"hour": "*/6"}

    async def pause_scan(self, scan_id: str) -> dict:
        scan = self._get_scan(scan_id)
        scan["status"] = ScanStatus.PAUSED
        await self._emit({"scan_id": scan_id, "event": "scan_paused"})
        return scan

    async def resume_scan(self, scan_id: str) -> dict:
        scan = self._get_scan(scan_id)
        if scan["status"] == ScanStatus.PAUSED:
            scan["status"] = ScanStatus.RUNNING
            if scan_id not in self._scan_tasks or self._scan_tasks[scan_id].done():
                return await self.start_scan(scan_id)
        await self._emit({"scan_id": scan_id, "event": "scan_resumed"})
        return scan

    async def stop_scan(self, scan_id: str) -> dict:
        scan = self._get_scan(scan_id)
        scan["status"] = ScanStatus.STOPPED
        task = self._scan_tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        await self._emit({"scan_id": scan_id, "event": "scan_stopped"})
        return scan

    async def get_scan(self, scan_id: str) -> dict:
        return self._get_scan(scan_id)

    async def list_scans(self) -> list[dict]:
        return list(self._scans.values())

    def list_workers(self) -> list[dict]:
        return list(self._workers.values())

    async def kill_worker(self, worker_id: str) -> dict:
        await self._redis.publish(TELEMETRY_CHANNEL, json.dumps({"command": "kill", "worker_id": worker_id}))
        self._workers.pop(worker_id, None)
        return {"status": "kill_sent", "worker_id": worker_id}

    async def restart_worker(self, worker_id: str) -> dict:
        await self._redis.publish(TELEMETRY_CHANNEL, json.dumps({"command": "restart", "worker_id": worker_id}))
        return {"status": "restart_sent", "worker_id": worker_id}

    def _get_scan(self, scan_id: str) -> dict:
        if scan_id not in self._scans:
            raise KeyError(f"Scan {scan_id} not found")
        return self._scans[scan_id]
