"""Agent outage/recovery scenario using a synthetic local HTTP backend."""

import json
import socket
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from random import Random
from threading import Thread

import pytest

from woland_guard_agent.config import SecretToken
from woland_guard_agent.delivery import BackoffPolicy, DeliveryAction, DeliveryManager
from woland_guard_agent.spool import SQLiteSpool
from woland_guard_agent.transport import IngestionTransport
from woland_guard_contracts import NormalizedEventV1

pytestmark = pytest.mark.integration
SYNTHETIC_TOKEN = "wgak_outage.synthetic-secret"  # noqa: S105


def test_backend_outage_preserves_event_then_recovery_delivers_it(tmp_path: Path) -> None:
    port = reserve_unused_port()
    spool = SQLiteSpool(tmp_path / "outage.sqlite3", max_events=10)
    spool.initialize()
    event = NormalizedEventV1(
        occurred_at=datetime.now(UTC),
        collected_at=datetime.now(UTC),
        event_type="linux.journald",
        summary="synthetic outage recovery",
    )
    spool.enqueue_with_cursor(source_name="journald", cursor="s=outage;i=1", event=event)
    transport = IngestionTransport(
        base_url=f"http://127.0.0.1:{port}",
        token=SecretToken(SYNTHETIC_TOKEN),
        connect_timeout_seconds=0.2,
        read_timeout_seconds=1,
        allow_insecure_http_for_tests=True,
    )
    manager = DeliveryManager(
        spool=spool,
        transport=transport,
        configured_batch_size=10,
        backoff=BackoffPolicy(
            base_seconds=0,
            maximum_seconds=0,
            random_source=Random(1),  # noqa: S311 - immediate deterministic integration retry
        ),
        authentication_retry_seconds=300,
    )

    unavailable = manager.deliver_once()

    assert unavailable.action is DeliveryAction.DEFERRED
    assert spool.statistics().pending == 1
    assert spool.contains(event.event_id)

    received: list[dict[str, object]] = []
    server = make_backend(port, received)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        recovered = manager.deliver_once()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        transport.close()

    assert recovered.action is DeliveryAction.DELIVERED
    assert recovered.accepted == 1
    assert recovered.existing == 0
    assert spool.statistics().total == 0
    assert len(received) == 1
    assert len(received[0]["events"]) == 1  # type: ignore[arg-type]
    assert received[0]["request_id"]


def reserve_unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def make_backend(
    port: int,
    received: list[dict[str, object]],
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            length = int(self.headers["Content-Length"])
            body = json.loads(self.rfile.read(length))
            events = body["events"]
            received.append(
                {
                    "events": events,
                    "request_id": self.headers["X-Request-ID"],
                }
            )
            response = json.dumps({"accepted": len(events), "existing": 0}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *args: object) -> None:
            del args

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
