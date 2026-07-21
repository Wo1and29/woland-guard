"""Local-only administrative CLI; no network admin API is exposed."""

import argparse
import sys
from pathlib import Path

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from woland_guard_control_plane.application.detection.rules import (
    RuleValidationError,
    load_rules_directory,
)
from woland_guard_control_plane.application.detection.sync import RuleSyncError, sync_rules
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
    validate_rules = subcommands.add_parser(
        "validate-rules",
        help="validate every YAML rule without changing PostgreSQL",
    )
    validate_rules.add_argument("--rules-dir", type=Path, required=True)
    sync_rule_set = subcommands.add_parser(
        "sync-rules",
        help="atomically append and activate a fully valid rule set",
    )
    sync_rule_set.add_argument("--rules-dir", type=Path, required=True)
    return parser


def main() -> None:
    """Provision a local test server and reveal its generated token exactly once."""

    arguments = build_parser().parse_args()
    if arguments.command in {"validate-rules", "sync-rules"}:
        try:
            rules = load_rules_directory(arguments.rules_dir)
            if arguments.command == "validate-rules":
                print(f"Правила корректны: {len(rules)}")
                return
            with get_session_factory().begin() as session:
                synchronized = sync_rules(session, rules)
        except RuleValidationError:
            print("Набор правил не прошёл строгую проверку.", file=sys.stderr)
            raise SystemExit(2) from None
        except (RuleSyncError, SQLAlchemyError):
            print("Не удалось атомарно синхронизировать правила.", file=sys.stderr)
            raise SystemExit(1) from None
        print(f"Активировано правил: {synchronized}")
        return

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
