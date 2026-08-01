from __future__ import annotations

import os
import socket
from pathlib import Path
from urllib.parse import urlsplit

import httpx2 as httpx
import pytest
from scripts.demo_e2e.contracts import DemoRunIdentity
from scripts.demo_e2e.ownership import ComposeDemoEnvironment
from scripts.demo_e2e.recovery import RecoveryLedgerStore

pytestmark = [pytest.mark.e2e, pytest.mark.docker]


@pytest.mark.skipif(
    os.environ.get("WG_RUN_DEMO_E2E") != "1",
    reason="set WG_RUN_DEMO_E2E=1 for the isolated 8B Compose runtime gate",
)
def test_random_ports_are_exact_loopback_and_released_after_cleanup(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    identity = DemoRunIdentity.create()
    ledger_directory = tmp_path / "ledger"
    ledger_directory.mkdir(mode=0o700)
    ledger = RecoveryLedgerStore.create(ledger_directory / "recovery.json", identity)
    environment = ComposeDemoEnvironment(
        project_root=project_root,
        identity=identity,
        ledger=ledger,
    )
    postgres_port = 0
    control_plane_port = 0
    try:
        environment.start_foundation()
        postgres_port = environment.database_configuration().port
        with socket.create_connection(("127.0.0.1", postgres_port), timeout=2):
            pass
        origin = environment.start_control_plane()
        parsed = urlsplit(origin)
        assert parsed.scheme == "http"
        assert parsed.hostname == "127.0.0.1"
        assert parsed.port is not None
        control_plane_port = parsed.port
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client:
            response = client.get(f"{origin}/health/ready")
        assert response.status_code == 200
        non_loopback = _non_loopback_ipv4_addresses()
        assert non_loopback, "no non-loopback local IPv4 address was available for this gate"
        for address in non_loopback:
            assert _connection_refused(address, postgres_port)
            assert _connection_refused(address, control_plane_port)
    finally:
        environment.stop()

    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", postgres_port), timeout=1)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", control_plane_port), timeout=1)
    ledger.finish()


def _non_loopback_ipv4_addresses() -> tuple[str, ...]:
    values: set[str] = set()
    for record in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        address = record[4][0]
        assert isinstance(address, str)
        if address != "127.0.0.1" and not address.startswith("127."):
            values.add(address)
    return tuple(sorted(values))


def _connection_refused(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=1):
            return False
    except OSError:
        return True
