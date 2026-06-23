"""SNAPESCAPE performance benchmarks."""

import asyncio
import time
import pytest
from snapescape_api.engines.registry import EngineRegistry


@pytest.mark.asyncio
async def test_engine_registry_init():
    start = time.perf_counter()
    registry = EngineRegistry()
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    assert len(registry.vuln) >= 10


@pytest.mark.asyncio
async def test_concurrent_vuln_analysis():
    registry = EngineRegistry()
    urls = [f"https://example.com/page{i}" for i in range(5)]
    start = time.perf_counter()
    tasks = [registry.vuln["cors"].analyze(url, "bench-scan") for url in urls]
    await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.perf_counter() - start
    assert elapsed < 30.0
