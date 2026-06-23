"""gRPC scan service server."""

from __future__ import annotations

import json
import grpc
from concurrent import futures

# Generated stubs would live in snapescape_api.grpc_stubs after:
# python -m grpc_tools.protoc -I../../proto --python_out=. --grpc_python_out=. ../../proto/snapescape.proto

try:
    from snapescape_api.engines.registry import run_full_pipeline
except ImportError:
    run_full_pipeline = None


class ScanServicer:
    """Implements snapescape.ScanService — wire to proto after protoc generation."""

    async def RunScan(self, request, context):
        if run_full_pipeline:
            result = await run_full_pipeline(request.target, request.scan_id)
            yield type("Event", (), {
                "scan_id": request.scan_id,
                "phase": "complete",
                "event_type": "done",
                "progress": 100.0,
                "payload_json": json.dumps(result),
            })()


def serve(port: int = 50051):
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
    server.add_insecure_port(f"[::]:{port}")
    print(f"SNAPESCAPE gRPC on :{port}")
    return server


if __name__ == "__main__":
    import asyncio
    srv = serve()
    asyncio.get_event_loop().run_until_complete(srv.start())
    asyncio.get_event_loop().run_until_complete(srv.wait_for_termination())
