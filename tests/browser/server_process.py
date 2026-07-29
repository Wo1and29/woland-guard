from __future__ import annotations

import logging
import os
import socket
import threading
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from pathlib import Path

import uvicorn


@dataclass(frozen=True, slots=True)
class ApplicationServerConfiguration:
    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    certificate_path: Path = field(repr=False)
    private_key_path: Path = field(repr=False)
    postgres_password: str = field(repr=False)


class _PipeLogHandler(logging.Handler):
    def __init__(self, connection: Connection) -> None:
        super().__init__()
        self._connection = connection

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._connection.send(
                (
                    "log",
                    record.levelname,
                    record.name,
                    record.getMessage(),
                )
            )
        except (OSError, EOFError, BrokenPipeError):
            return


def run_application_server(
    connection: Connection,
    configuration: ApplicationServerConfiguration,
) -> None:
    """Run the real application on one pre-bound TLS socket in an isolated process."""

    server_socket: socket.socket | None = None
    try:
        root_logger = logging.getLogger()
        root_logger.handlers = [_PipeLogHandler(connection)]
        root_logger.setLevel(logging.INFO)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("127.0.0.1", 0))
        server_socket.listen(2048)
        port = int(server_socket.getsockname()[1])

        _configure_environment(configuration, port=port)
        from woland_guard_control_plane.config import get_settings
        from woland_guard_control_plane.database import get_engine, get_session_factory
        from woland_guard_control_plane.main import create_app

        get_settings.cache_clear()
        get_session_factory.cache_clear()
        get_engine.cache_clear()
        settings = get_settings()
        application = create_app(settings)
        config = uvicorn.Config(
            application,
            host="127.0.0.1",
            port=port,
            access_log=False,
            log_config=None,
            log_level="critical",
            lifespan="on",
            ssl_certfile=configuration.certificate_path,
            ssl_keyfile=configuration.private_key_path,
        )
        server = uvicorn.Server(config)
        stop_thread = threading.Thread(
            target=_wait_for_stop,
            args=(connection, server),
            name="wg-browser-stop",
            daemon=True,
        )
        stop_thread.start()
        connection.send(("bound", port))
        server.run(sockets=[server_socket])
        connection.send(("stopped",))
    except Exception:
        try:
            connection.send(("failed", "application_server_failed"))
        except (OSError, EOFError, BrokenPipeError):
            pass
    finally:
        if server_socket is not None:
            try:
                server_socket.close()
            except OSError:
                pass
        connection.close()


def _configure_environment(configuration: ApplicationServerConfiguration, *, port: int) -> None:
    values = {
        "WG_APP_ENV": "test",
        "WG_POSTGRES_HOST": configuration.postgres_host,
        "WG_POSTGRES_PORT": str(configuration.postgres_port),
        "WG_POSTGRES_DB": configuration.postgres_db,
        "WG_POSTGRES_USER": configuration.postgres_user,
        "WG_POSTGRES_PASSWORD": configuration.postgres_password,
        "WG_POSTGRES_CONNECT_TIMEOUT_SECONDS": "3",
        "WG_WEB_PUBLIC_ORIGIN": f"https://127.0.0.1:{port}",
        "WG_WEB_LOGIN_GLOBAL_LIMIT": "1000",
        "WG_WEB_LOGIN_SUBJECT_LIMIT": "1000",
    }
    os.environ.update(values)


def _wait_for_stop(connection: Connection, server: uvicorn.Server) -> None:
    try:
        while True:
            message = connection.recv()
            if message == "stop":
                server.should_exit = True
                return
    except (EOFError, OSError):
        server.should_exit = True
