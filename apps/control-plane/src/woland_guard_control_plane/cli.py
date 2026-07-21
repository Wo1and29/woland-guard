"""Local-only administrative CLI; no network admin API is exposed."""

import argparse
import sys

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from woland_guard_control_plane.application.provisioning import provision_test_server
from woland_guard_control_plane.database import get_session_factory


def build_parser() -> argparse.ArgumentParser:
    """Build the local provisioning command parser."""

    parser = argparse.ArgumentParser(prog="woland-guard-admin")
    subcommands = parser.add_subparsers(dest="command", required=True)
    create_agent = subcommands.add_parser(
        "create-test-agent",
        help="create a local test server and print its agent token once",
    )
    create_agent.add_argument("--name", required=True)
    create_agent.add_argument("--hostname", required=True)
    create_agent.add_argument("--label")
    return parser


def main() -> None:
    """Provision a local test server and reveal its generated token exactly once."""

    arguments = build_parser().parse_args()
    try:
        with get_session_factory().begin() as session:
            provisioned = provision_test_server(
                session,
                name=arguments.name,
                hostname=arguments.hostname,
                label=arguments.label,
            )
    except (IntegrityError, ValueError):
        print(
            "Не удалось создать тестовый сервер: проверьте уникальность и аргументы.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    except SQLAlchemyError:
        print("Не удалось создать тестовый сервер из-за ошибки базы данных.", file=sys.stderr)
        raise SystemExit(1) from None

    print(f"server_id={provisioned.server_id}")
    print(f"key_id={provisioned.key_id}")
    print(f"public_id={provisioned.public_id}")
    print("Сохраните токен сейчас: повторно получить его из базы данных невозможно.")
    print(f"token={provisioned.token}")
