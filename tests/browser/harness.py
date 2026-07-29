from __future__ import annotations

import http.client
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from multiprocessing import get_context
from multiprocessing.connection import Connection
from pathlib import Path
from types import TracebackType
from typing import Protocol, cast

import trustme
import uvicorn
from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from starlette.types import ASGIApp

from tests.browser.server_process import (
    ApplicationServerConfiguration,
    run_application_server,
)

_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_NAME = re.compile(r"^wg-browser-postgres-[0-9a-f]{16}$")
_OWNERSHIP_LABEL = re.compile(r"^browser-[0-9a-f]{16}$")
_OWNERSHIP_LABEL_KEY = "woland-guard.test-scope"
_RECOVERY_LOOKUP_ATTEMPTS = 5
_RECOVERY_POLL_SECONDS = 0.05
_PUBLISHED_PORT = re.compile(r"^127\.0\.0\.1:(?P<port>[1-9][0-9]{0,4})$")


class BrowserHarnessError(RuntimeError):
    """A safe browser-harness error without wrapped sensitive context."""


class _ManagedProcess(Protocol):
    def join(self, timeout: float | None = None) -> None: ...

    def is_alive(self) -> bool: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class EphemeralDatabaseConfiguration:
    host: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)

    def url(self) -> URL:
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.username,
            password=self.password,
            host=self.host,
            port=self.port,
            database=self.database,
        )

    def environment(self) -> dict[str, str]:
        return {
            "WG_APP_ENV": "test",
            "WG_POSTGRES_HOST": self.host,
            "WG_POSTGRES_PORT": str(self.port),
            "WG_POSTGRES_DB": self.database,
            "WG_POSTGRES_USER": self.username,
            "WG_POSTGRES_PASSWORD": self.password,
            "WG_RUN_INTEGRATION_TESTS": "1",
        }


class EphemeralPostgres:
    def __init__(self, *, startup_timeout_seconds: float = 30.0) -> None:
        self._startup_timeout_seconds = startup_timeout_seconds
        self._container_id: str | None = None
        self._container_name: str | None = None
        self._ownership_label: str | None = None
        self._configuration: EphemeralDatabaseConfiguration | None = None
        self._engine: Engine | None = None

    def __repr__(self) -> str:
        return "EphemeralPostgres(container=<redacted>)"

    @property
    def configuration(self) -> EphemeralDatabaseConfiguration:
        if self._configuration is None:
            raise BrowserHarnessError("browser PostgreSQL is not running")
        return self._configuration

    @property
    def session_factory(self) -> sessionmaker[Session]:
        if self._engine is None:
            raise BrowserHarnessError("browser PostgreSQL is not running")
        return sessionmaker(bind=self._engine, expire_on_commit=False)

    def start(self) -> EphemeralPostgres:
        if any(
            value is not None
            for value in (
                self._container_id,
                self._container_name,
                self._ownership_label,
            )
        ):
            raise BrowserHarnessError("browser PostgreSQL is already running")
        run_id = secrets.token_hex(8)
        container_name = f"wg-browser-postgres-{run_id}"
        ownership_label = f"browser-{run_id}"
        if (
            _CONTAINER_NAME.fullmatch(container_name) is None
            or _OWNERSHIP_LABEL.fullmatch(ownership_label) is None
        ):
            raise BrowserHarnessError("browser PostgreSQL identity generation failed")
        self._container_name = container_name
        self._ownership_label = ownership_label

        password = secrets.token_urlsafe(32)
        database = f"wg_browser_{run_id}_test"
        username = "wg_browser"
        try:
            env_path = _write_private_environment_file(
                {
                    "POSTGRES_DB": database,
                    "POSTGRES_USER": username,
                    "POSTGRES_PASSWORD": password,
                }
            )
        except Exception:
            self._clear_container_identity()
            raise BrowserHarnessError("browser PostgreSQL failed to start") from None

        try:
            try:
                output = _run_command(
                    [
                        "docker",
                        "run",
                        "--detach",
                        "--rm",
                        "--name",
                        container_name,
                        "--label",
                        f"{_OWNERSHIP_LABEL_KEY}={ownership_label}",
                        "--publish",
                        "127.0.0.1::5432",
                        "--env-file",
                        str(env_path),
                        "--tmpfs",
                        "/var/lib/postgresql/data:rw",
                        "postgres:17-bookworm",
                    ],
                    timeout_seconds=60,
                ).strip()
            finally:
                env_path.unlink(missing_ok=True)
            if _CONTAINER_ID.fullmatch(output) is None:
                raise BrowserHarnessError("Docker returned an invalid browser database identifier")
            _confirm_container_ownership(
                output,
                expected_name=container_name,
                expected_label=ownership_label,
            )
        except Exception:
            try:
                self._recover_failed_run()
            except BrowserHarnessError:
                raise BrowserHarnessError("browser PostgreSQL recovery cleanup failed") from None
            raise BrowserHarnessError("browser PostgreSQL failed to start") from None

        self._container_id = output
        try:
            published = _run_command(
                ["docker", "port", output, "5432/tcp"],
                timeout_seconds=10,
            ).strip()
            match = _PUBLISHED_PORT.fullmatch(published)
            if match is None:
                raise BrowserHarnessError("Docker returned an invalid browser database port")
            port = int(match.group("port"))
            configuration = EphemeralDatabaseConfiguration(
                host="127.0.0.1",
                port=port,
                database=database,
                username=username,
                password=password,
            )
            engine = create_engine(
                configuration.url(),
                pool_pre_ping=True,
                connect_args={"connect_timeout": 1},
            )
            self._configuration = configuration
            self._engine = engine
            self._wait_until_ready()
            return self
        except Exception:
            self.stop()
            raise BrowserHarnessError("browser PostgreSQL failed to start") from None

    def migrate(self, project_root: Path) -> None:
        environment = os.environ.copy()
        environment.update(self.configuration.environment())
        _run_command(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
            timeout_seconds=60,
            cwd=project_root,
            environment=environment,
        )

    def stop(self) -> None:
        engine = self._engine
        cleanup_failed = False
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                cleanup_failed = True
        self._engine = None
        self._configuration = None

        container_id = self._container_id
        if container_id is None and any(
            value is not None for value in (self._container_name, self._ownership_label)
        ):
            try:
                container_id = self._poll_for_owned_container()
            except BrowserHarnessError:
                cleanup_failed = True
            else:
                if container_id is None:
                    self._clear_container_identity()
                else:
                    self._container_id = container_id

        if container_id is not None:
            try:
                _run_command(
                    ["docker", "stop", "--time", "10", container_id],
                    timeout_seconds=20,
                )
            except BrowserHarnessError:
                pass

            try:
                container_exists = _docker_container_exists(container_id)
            except BrowserHarnessError:
                container_exists = True

            if container_exists:
                try:
                    _run_command(
                        ["docker", "rm", "--force", container_id],
                        timeout_seconds=20,
                    )
                except BrowserHarnessError:
                    pass

            try:
                container_exists = _docker_container_exists(container_id)
            except BrowserHarnessError:
                cleanup_failed = True
                container_exists = True

            if container_exists:
                cleanup_failed = True
            else:
                self._clear_container_identity()

        if cleanup_failed:
            raise BrowserHarnessError("browser PostgreSQL cleanup failed")

    def _recover_failed_run(self) -> None:
        container_id = self._poll_for_owned_container()
        if container_id is None:
            self._clear_container_identity()
            return
        self._container_id = container_id
        try:
            self.stop()
        except BrowserHarnessError:
            raise BrowserHarnessError("browser PostgreSQL recovery cleanup failed") from None

    def _poll_for_owned_container(self) -> str | None:
        container_name = self._container_name
        ownership_label = self._ownership_label
        if (
            container_name is None
            or ownership_label is None
            or _CONTAINER_NAME.fullmatch(container_name) is None
            or _OWNERSHIP_LABEL.fullmatch(ownership_label) is None
        ):
            raise BrowserHarnessError("browser PostgreSQL ownership identity is invalid")

        for attempt in range(_RECOVERY_LOOKUP_ATTEMPTS):
            container_id = _lookup_owned_container(
                expected_name=container_name,
                expected_label=ownership_label,
            )
            if container_id is not None:
                return container_id
            if attempt + 1 < _RECOVERY_LOOKUP_ATTEMPTS:
                time.sleep(_RECOVERY_POLL_SECONDS)
        return None

    def _clear_container_identity(self) -> None:
        self._container_id = None
        self._container_name = None
        self._ownership_label = None

    def _wait_until_ready(self) -> None:
        engine = self._engine
        if engine is None:
            raise BrowserHarnessError("browser PostgreSQL engine is unavailable")
        deadline = time.monotonic() + self._startup_timeout_seconds
        while time.monotonic() < deadline:
            try:
                with engine.connect() as connection:
                    if connection.execute(text("SELECT 1")).scalar_one() == 1:
                        return
            except Exception:
                time.sleep(0.05)
        raise BrowserHarnessError("browser PostgreSQL readiness deadline expired")


class TemporaryTlsMaterial:
    def __init__(self) -> None:
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self.ca_path: Path | None = None
        self.certificate_path: Path | None = None
        self.private_key_path: Path | None = None

    def __repr__(self) -> str:
        return "TemporaryTlsMaterial(paths=<redacted>)"

    def start(self) -> TemporaryTlsMaterial:
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="wg-browser-tls-")
        temporary_path = Path(self._temporary_directory.name)
        self.ca_path = temporary_path / "ca.pem"
        self.certificate_path = temporary_path / "certificate.pem"
        self.private_key_path = temporary_path / "private-key.pem"
        ca = trustme.CA()
        certificate = ca.issue_cert("127.0.0.1")
        ca.cert_pem.write_to_path(self.ca_path)
        certificate.cert_chain_pems[0].write_to_path(self.certificate_path)
        certificate.private_key_pem.write_to_path(self.private_key_path)
        return self

    def stop(self) -> None:
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
        self._temporary_directory = None
        self.ca_path = None
        self.certificate_path = None
        self.private_key_path = None


class ApplicationProcess:
    def __init__(
        self,
        *,
        database: EphemeralDatabaseConfiguration,
        tls: TemporaryTlsMaterial,
        startup_timeout_seconds: float = 15.0,
        shutdown_timeout_seconds: float = 10.0,
    ) -> None:
        self._database = database
        self._tls = tls
        self._startup_timeout_seconds = startup_timeout_seconds
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._connection: Connection | None = None
        self._process: _ManagedProcess | None = None
        self._origin: str | None = None
        self._port: int | None = None
        self._logs: list[str] = []

    def __repr__(self) -> str:
        return "ApplicationProcess(origin=<redacted>)"

    @property
    def origin(self) -> str:
        if self._origin is None:
            raise BrowserHarnessError("browser application is not running")
        return self._origin

    @property
    def logs(self) -> tuple[str, ...]:
        self._drain_messages()
        return tuple(self._logs)

    def start(self) -> ApplicationProcess:
        certificate_path = self._tls.certificate_path
        private_key_path = self._tls.private_key_path
        ca_path = self._tls.ca_path
        if certificate_path is None or private_key_path is None or ca_path is None:
            raise BrowserHarnessError("temporary TLS material is unavailable")
        context = get_context("spawn")
        parent_connection, child_connection = context.Pipe(duplex=True)
        configuration = ApplicationServerConfiguration(
            postgres_host=self._database.host,
            postgres_port=self._database.port,
            postgres_db=self._database.database,
            postgres_user=self._database.username,
            postgres_password=self._database.password,
            certificate_path=certificate_path,
            private_key_path=private_key_path,
        )
        process = context.Process(
            target=run_application_server,
            args=(child_connection, configuration),
            name="wg-browser-application",
            daemon=True,
        )
        process.start()
        child_connection.close()
        self._connection = cast(Connection, parent_connection)
        self._process = cast(_ManagedProcess, process)
        try:
            port = self._wait_for_bound_port()
            self._port = port
            self._origin = f"https://127.0.0.1:{port}"
            _wait_for_strict_https(
                host="127.0.0.1",
                port=port,
                path="/health/ready",
                ca_path=ca_path,
                timeout_seconds=self._startup_timeout_seconds,
            )
            return self
        except Exception:
            self.stop()
            raise BrowserHarnessError("browser application failed to start") from None

    def stop(self) -> None:
        connection = self._connection
        process = self._process
        port = self._port
        cleanup_failed = False
        process_stopped = process is None
        process_closed = process is None
        port_released = port is None
        connection_closed = connection is None

        if connection is not None:
            with suppress(Exception):
                connection.send("stop")

        if process is not None:
            try:
                process.join(timeout=self._shutdown_timeout_seconds)
            except Exception:
                cleanup_failed = True

            process_alive = _process_is_alive(process)
            if process_alive:
                try:
                    process.terminate()
                except Exception:
                    cleanup_failed = True
                try:
                    process.join(timeout=5.0)
                except Exception:
                    cleanup_failed = True
                process_alive = _process_is_alive(process)

            if process_alive:
                try:
                    process.kill()
                except Exception:
                    cleanup_failed = True
                try:
                    process.join(timeout=5.0)
                except Exception:
                    cleanup_failed = True
                process_alive = _process_is_alive(process)

            process_stopped = not process_alive
            if not process_stopped:
                cleanup_failed = True
            else:
                try:
                    process.close()
                    process_closed = True
                except Exception:
                    cleanup_failed = True

        try:
            self._drain_messages()
        finally:
            if connection is not None:
                try:
                    connection.close()
                    connection_closed = True
                except Exception:
                    cleanup_failed = True

        if process_stopped and port is not None:
            try:
                LocalHttpsServer._assert_port_released(port)
                port_released = True
            except BrowserHarnessError:
                cleanup_failed = True

        if connection_closed:
            self._connection = None

        if process_closed:
            self._process = None

        if process_stopped:
            self._origin = None

        if port_released:
            self._port = None

        if cleanup_failed:
            raise BrowserHarnessError("browser application cleanup failed")

    def _wait_for_bound_port(self) -> int:
        connection = self._connection
        if connection is None:
            raise BrowserHarnessError("application control channel is unavailable")
        deadline = time.monotonic() + self._startup_timeout_seconds
        while time.monotonic() < deadline:
            if connection.poll(0.05):
                message = connection.recv()
                if not isinstance(message, tuple) or not message:
                    raise BrowserHarnessError("application sent an invalid control message")
                if message[0] == "log" and len(message) == 4:
                    self._logs.append("|".join(str(value) for value in message[1:]))
                    continue
                if message[0] == "bound" and len(message) == 2 and type(message[1]) is int:
                    return int(message[1])
                raise BrowserHarnessError("application failed before binding HTTPS")
        raise BrowserHarnessError("application did not bind HTTPS within its deadline")

    def _drain_messages(self) -> None:
        connection = self._connection
        if connection is None:
            return
        try:
            while connection.poll():
                message = connection.recv()
                if isinstance(message, tuple) and len(message) == 4 and message[0] == "log":
                    self._logs.append("|".join(str(value) for value in message[1:]))
        except Exception:
            return


class BrowserEnvironment:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.postgres = EphemeralPostgres()
        self.tls = TemporaryTlsMaterial()
        self.application: ApplicationProcess | None = None

    @property
    def origin(self) -> str:
        if self.application is None:
            raise BrowserHarnessError("browser environment is not running")
        return self.application.origin

    def start(self) -> BrowserEnvironment:
        try:
            self.postgres.start()
            self.postgres.migrate(self.project_root)
            self.tls.start()
            self.application = ApplicationProcess(
                database=self.postgres.configuration,
                tls=self.tls,
            ).start()
            return self
        except Exception:
            try:
                self.stop()
            except BrowserHarnessError:
                pass
            raise BrowserHarnessError("browser environment failed to start") from None

    def stop(self) -> None:
        cleanup_failed = False
        application = self.application
        if application is not None:
            try:
                application.stop()
            except Exception:
                cleanup_failed = True
            else:
                self.application = None

        for resource in (self.tls, self.postgres):
            try:
                resource.stop()
            except Exception:
                cleanup_failed = True

        if cleanup_failed:
            raise BrowserHarnessError("browser environment cleanup failed")

    def __enter__(self) -> BrowserEnvironment:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()


def _wait_for_strict_https(
    *,
    host: str,
    port: int,
    path: str,
    ca_path: Path,
    timeout_seconds: float,
) -> None:
    context = ssl.create_default_context(cafile=str(ca_path))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=0.5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            if response.status == 200:
                return
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException):
            time.sleep(0.02)
        finally:
            connection.close()
    raise BrowserHarnessError("strict HTTPS readiness deadline expired")


def _write_private_environment_file(values: dict[str, str]) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix="wg-browser-postgres-", suffix=".env")
    path = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            for key, value in values.items():
                if not key.isidentifier() or "\n" in value or "\r" in value:
                    raise BrowserHarnessError("invalid temporary database environment")
                stream.write(f"{key}={value}\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            path.chmod(0o600)
        return path
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise BrowserHarnessError("temporary database environment could not be created") from None


def _run_command(
    arguments: list[str],
    *,
    timeout_seconds: float,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> str:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(  # noqa: S603 - closed harness command arguments only
            arguments,
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
            creationflags=creation_flags,
        )
    except (OSError, subprocess.SubprocessError):
        raise BrowserHarnessError("browser harness command failed") from None
    if completed.returncode != 0:
        raise BrowserHarnessError("browser harness command failed")
    return completed.stdout


def _lookup_owned_container(*, expected_name: str, expected_label: str) -> str | None:
    output = _run_command(
        [
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"name=^/{expected_name}$",
            "--filter",
            f"label={_OWNERSHIP_LABEL_KEY}={expected_label}",
        ],
        timeout_seconds=10,
    )
    identifiers = [line.strip() for line in output.splitlines() if line.strip()]
    if len(identifiers) > 1 or any(
        _CONTAINER_ID.fullmatch(identifier) is None for identifier in identifiers
    ):
        raise BrowserHarnessError("Docker returned an ambiguous ownership lookup")
    if not identifiers:
        return None
    container_id = identifiers[0]
    _confirm_container_ownership(
        container_id,
        expected_name=expected_name,
        expected_label=expected_label,
    )
    return container_id


def _confirm_container_ownership(
    container_id: str,
    *,
    expected_name: str,
    expected_label: str,
) -> None:
    if (
        _CONTAINER_ID.fullmatch(container_id) is None
        or _CONTAINER_NAME.fullmatch(expected_name) is None
        or _OWNERSHIP_LABEL.fullmatch(expected_label) is None
    ):
        raise BrowserHarnessError("browser PostgreSQL ownership identity is invalid")
    output = _run_command(
        [
            "docker",
            "inspect",
            "--type",
            "container",
            "--format",
            (f'{{{{.Id}}}}|{{{{.Name}}}}|{{{{index .Config.Labels "{_OWNERSHIP_LABEL_KEY}"}}}}'),
            container_id,
        ],
        timeout_seconds=10,
    ).strip()
    parts = output.split("|")
    if parts != [container_id, f"/{expected_name}", expected_label]:
        raise BrowserHarnessError("Docker container ownership could not be confirmed")


def _docker_container_exists(container_id: str) -> bool:
    output = _run_command(
        [
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"id={container_id}",
        ],
        timeout_seconds=10,
    )
    identifiers = [line.strip() for line in output.splitlines() if line.strip()]
    if len(identifiers) > 1 or any(
        _CONTAINER_ID.fullmatch(identifier) is None for identifier in identifiers
    ):
        raise BrowserHarnessError("Docker returned an invalid container cleanup status")
    return container_id in identifiers


def _process_is_alive(process: _ManagedProcess) -> bool:
    try:
        return process.is_alive()
    except Exception:
        return True


class LocalHttpsServer:
    """Run an ASGI app on a pre-bound loopback TLS socket using public Uvicorn APIs."""

    def __init__(
        self,
        application: ASGIApp,
        *,
        readiness_path: str,
        startup_timeout_seconds: float = 10.0,
        shutdown_timeout_seconds: float = 10.0,
    ) -> None:
        self._application = application
        self._readiness_path = readiness_path
        self._startup_timeout_seconds = startup_timeout_seconds
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._socket: socket.socket | None = None
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._ca_path: Path | None = None
        self._origin: str | None = None
        self._port: int | None = None

    def __repr__(self) -> str:
        return "LocalHttpsServer(origin=<redacted>)"

    @property
    def origin(self) -> str:
        if self._origin is None:
            raise BrowserHarnessError("HTTPS harness is not running")
        return self._origin

    @property
    def ca_path(self) -> Path:
        if self._ca_path is None:
            raise BrowserHarnessError("HTTPS harness is not running")
        return self._ca_path

    @property
    def port(self) -> int:
        if self._port is None:
            raise BrowserHarnessError("HTTPS harness is not running")
        return self._port

    def start(self) -> LocalHttpsServer:
        if self._thread is not None:
            raise BrowserHarnessError("HTTPS harness is already running")
        try:
            self._temporary_directory = tempfile.TemporaryDirectory(prefix="wg-browser-tls-")
            temporary_path = Path(self._temporary_directory.name)
            ca_path = temporary_path / "ca.pem"
            certificate_path = temporary_path / "certificate.pem"
            private_key_path = temporary_path / "private-key.pem"
            ca = trustme.CA()
            certificate = ca.issue_cert("127.0.0.1")
            ca.cert_pem.write_to_path(ca_path)
            certificate.cert_chain_pems[0].write_to_path(certificate_path)
            certificate.private_key_pem.write_to_path(private_key_path)

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("127.0.0.1", 0))
            server_socket.listen(2048)
            port = int(server_socket.getsockname()[1])
            self._assert_port_reserved(port)

            config = uvicorn.Config(
                self._application,
                host="127.0.0.1",
                port=port,
                access_log=False,
                log_config=None,
                log_level="critical",
                lifespan="on",
                ssl_certfile=certificate_path,
                ssl_keyfile=private_key_path,
            )
            server = uvicorn.Server(config)
            thread = threading.Thread(
                target=server.run,
                kwargs={"sockets": [server_socket]},
                name="wg-browser-https",
                daemon=True,
            )
            self._socket = server_socket
            self._server = server
            self._thread = thread
            self._ca_path = ca_path
            self._port = port
            self._origin = f"https://127.0.0.1:{port}"
            thread.start()
            self._wait_until_ready()
            return self
        except Exception:
            self._force_cleanup()
            raise BrowserHarnessError("HTTPS harness failed to start") from None

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        server_socket = self._socket
        port = int(server_socket.getsockname()[1]) if server_socket is not None else None
        try:
            if server is not None:
                server.should_exit = True
            if thread is not None:
                thread.join(timeout=self._shutdown_timeout_seconds)
                if thread.is_alive():
                    raise BrowserHarnessError("HTTPS harness did not stop within its deadline")
            if port is not None:
                self._assert_port_released(port)
        finally:
            self._force_cleanup()

    def __enter__(self) -> LocalHttpsServer:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()

    def _wait_until_ready(self) -> None:
        context = ssl.create_default_context(cafile=str(self.ca_path))
        deadline = time.monotonic() + self._startup_timeout_seconds
        while time.monotonic() < deadline:
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                self.port,
                context=context,
                timeout=0.5,
            )
            try:
                connection.request("GET", self._readiness_path)
                response = connection.getresponse()
                if response.status == 200:
                    return
            except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(0.02)
        raise BrowserHarnessError("HTTPS readiness deadline expired")

    @staticmethod
    def _assert_port_reserved(port: int) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                return
            raise BrowserHarnessError("reserved HTTPS port was unexpectedly available")
        finally:
            probe.close()

    @staticmethod
    def _assert_port_released(port: int) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            raise BrowserHarnessError("HTTPS socket remained reserved after shutdown") from None
        finally:
            probe.close()

    def _force_cleanup(self) -> None:
        server_socket = self._socket
        if server_socket is not None:
            try:
                server_socket.close()
            except OSError:
                pass
        temporary_directory = self._temporary_directory
        if temporary_directory is not None:
            temporary_directory.cleanup()
        self._temporary_directory = None
        self._socket = None
        self._server = None
        self._thread = None
        self._ca_path = None
        self._origin = None
        self._port = None
