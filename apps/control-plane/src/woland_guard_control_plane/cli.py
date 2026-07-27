"""Local-only administrative CLI; no network admin API is exposed."""

import argparse
import getpass
import sys
from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from woland_guard_control_plane.application.detection.rules import (
    RuleValidationError,
    load_rules_directory,
)
from woland_guard_control_plane.application.detection.sync import RuleSyncError, sync_rules
from woland_guard_control_plane.application.notification_destinations import (
    DestinationSummary,
    NotificationDestinationManagementError,
    create_telegram_destination,
    get_notification_destination,
    list_notification_destinations,
    set_notification_destination_enabled,
    update_telegram_destination,
)
from woland_guard_control_plane.application.operators import (
    IssuedOperatorApiKey,
    OperatorManagementError,
    create_operator,
    issue_operator_api_key,
    revoke_operator_api_key,
    rotate_operator_api_key,
)
from woland_guard_control_plane.application.provisioning import provision_test_server
from woland_guard_control_plane.database import get_session_factory
from woland_guard_control_plane.infrastructure.database.models import (
    NotificationSeverity,
    OperatorRole,
)
from woland_guard_control_plane.infrastructure.telegram.token_file import (
    TelegramTokenSynchronizer,
)

_OPERATOR_COMMANDS = {
    "create-operator",
    "issue-operator-key",
    "rotate-operator-key",
    "revoke-operator-key",
}
_DESTINATION_COMMANDS = {
    "create-telegram-destination",
    "list-notification-destinations",
    "show-notification-destination",
    "enable-notification-destination",
    "disable-notification-destination",
    "update-telegram-destination",
}


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

    create_local_operator = subcommands.add_parser(
        "create-operator",
        help="create a local operator identity without issuing credentials",
    )
    create_local_operator.add_argument("--username", required=True)
    create_local_operator.add_argument(
        "--role",
        required=True,
        choices=tuple(role.value for role in OperatorRole),
    )
    issue_operator_key = subcommands.add_parser(
        "issue-operator-key",
        help="issue and print a new operator API key exactly once",
    )
    issue_operator_key.add_argument("--operator-id", type=UUID, required=True)
    issue_operator_key.add_argument("--label")
    issue_operator_key.add_argument("--expires-at", type=_parse_timestamp)
    rotate_operator_key = subcommands.add_parser(
        "rotate-operator-key",
        help="atomically revoke an operator key and print its replacement once",
    )
    rotate_operator_key.add_argument("--key-id", type=UUID, required=True)
    rotate_operator_key.add_argument("--label")
    rotate_operator_key.add_argument("--expires-at", type=_parse_timestamp)
    revoke_operator_key = subcommands.add_parser(
        "revoke-operator-key",
        help="revoke an operator API key without deleting its history",
    )
    revoke_operator_key.add_argument("--key-id", type=UUID, required=True)

    create_destination = subcommands.add_parser(
        "create-telegram-destination",
        help="create a disabled Telegram destination without storing credentials",
    )
    create_destination.add_argument("--token-file-name", required=True)
    create_destination.add_argument(
        "--minimum-severity",
        choices=tuple(severity.value for severity in NotificationSeverity),
        default=NotificationSeverity.LOW.value,
    )
    subcommands.add_parser(
        "list-notification-destinations",
        help="show redacted destination readiness",
    )
    show_destination = subcommands.add_parser(
        "show-notification-destination",
        help="show one redacted destination",
    )
    show_destination.add_argument("--destination-id", type=UUID, required=True)
    enable_destination = subcommands.add_parser("enable-notification-destination")
    enable_destination.add_argument("--destination-id", type=UUID, required=True)
    disable_destination = subcommands.add_parser("disable-notification-destination")
    disable_destination.add_argument("--destination-id", type=UUID, required=True)
    update_destination = subcommands.add_parser("update-telegram-destination")
    update_destination.add_argument("--destination-id", type=UUID, required=True)
    update_destination.add_argument("--token-file-name")
    update_destination.add_argument(
        "--minimum-severity",
        choices=tuple(severity.value for severity in NotificationSeverity),
    )
    update_destination.add_argument("--change-chat-id", action="store_true")
    return parser


def main() -> None:
    """Dispatch one explicit local administrative operation."""

    arguments = build_parser().parse_args()
    if arguments.command in {"validate-rules", "sync-rules"}:
        _run_rules_command(arguments)
        return
    if arguments.command in _OPERATOR_COMMANDS:
        _run_operator_command(arguments)
        return
    if arguments.command in _DESTINATION_COMMANDS:
        _run_destination_command(arguments)
        return
    _run_create_test_agent(arguments)


def _run_rules_command(arguments: argparse.Namespace) -> None:
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


def _run_create_test_agent(arguments: argparse.Namespace) -> None:
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


def _run_operator_command(arguments: argparse.Namespace) -> None:
    try:
        with get_session_factory().begin() as session:
            if arguments.command == "create-operator":
                operator = create_operator(
                    session,
                    username=arguments.username,
                    role=OperatorRole(arguments.role),
                )
                issued = None
                revoked = None
            elif arguments.command == "issue-operator-key":
                issued = issue_operator_api_key(
                    session,
                    operator_id=arguments.operator_id,
                    label=arguments.label,
                    expires_at=arguments.expires_at,
                )
                operator = None
                revoked = None
            elif arguments.command == "rotate-operator-key":
                issued = rotate_operator_api_key(
                    session,
                    key_id=arguments.key_id,
                    label=arguments.label,
                    expires_at=arguments.expires_at,
                )
                operator = None
                revoked = None
            else:
                revoked = revoke_operator_api_key(session, key_id=arguments.key_id)
                operator = None
                issued = None
    except (IntegrityError, OperatorManagementError):
        print(
            "Не удалось изменить оператора или ключ: проверьте идентификаторы и аргументы.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    except SQLAlchemyError:
        print("Не удалось изменить оператора или ключ из-за ошибки базы данных.", file=sys.stderr)
        raise SystemExit(1) from None

    if operator is not None:
        print(f"operator_id={operator.id}")
        print(f"username={operator.username}")
        print(f"role={operator.role.value}")
    elif issued is not None:
        _print_issued_operator_key(issued)
    else:
        print(f"key_id={arguments.key_id}")
        print(f"revoked={'true' if revoked else 'already'}")


def _print_issued_operator_key(issued: IssuedOperatorApiKey) -> None:
    print(f"operator_id={issued.operator_id}")
    print(f"key_id={issued.key_id}")
    print(f"public_id={issued.public_id}")
    print(f"expires_at={issued.expires_at.isoformat() if issued.expires_at else 'none'}")
    if issued.rotated_from_id is not None:
        print(f"rotated_from_id={issued.rotated_from_id}")
    print("Сохраните токен сейчас: повторно получить его из базы данных невозможно.")
    print(f"token={issued.token}")


def _run_destination_command(arguments: argparse.Namespace) -> None:
    synchronizer = TelegramTokenSynchronizer()
    readiness = synchronizer.staging_file_ready
    try:
        if arguments.command == "list-notification-destinations":
            with get_session_factory()() as session:
                destinations = list_notification_destinations(
                    session,
                    staging_readiness=readiness,
                )
            for destination in destinations:
                _print_destination(destination)
            return
        with get_session_factory().begin() as session:
            if arguments.command == "create-telegram-destination":
                destination = create_telegram_destination(
                    session,
                    chat_id=_read_chat_id(),
                    token_file_name=arguments.token_file_name,
                    minimum_severity=NotificationSeverity(arguments.minimum_severity),
                    staging_readiness=readiness,
                )
            elif arguments.command == "show-notification-destination":
                destination = get_notification_destination(
                    session,
                    destination_id=arguments.destination_id,
                    staging_readiness=readiness,
                )
            elif arguments.command in {
                "enable-notification-destination",
                "disable-notification-destination",
            }:
                destination = set_notification_destination_enabled(
                    session,
                    destination_id=arguments.destination_id,
                    enabled=arguments.command == "enable-notification-destination",
                    staging_readiness=readiness,
                )
            else:
                destination = update_telegram_destination(
                    session,
                    destination_id=arguments.destination_id,
                    chat_id=_read_chat_id() if arguments.change_chat_id else None,
                    token_file_name=arguments.token_file_name,
                    minimum_severity=(
                        None
                        if arguments.minimum_severity is None
                        else NotificationSeverity(arguments.minimum_severity)
                    ),
                    staging_readiness=readiness,
                )
    except (IntegrityError, NotificationDestinationManagementError, ValueError):
        print("Не удалось безопасно изменить destination.", file=sys.stderr)
        raise SystemExit(2) from None
    except SQLAlchemyError:
        print("Не удалось изменить destination из-за ошибки базы данных.", file=sys.stderr)
        raise SystemExit(1) from None
    _print_destination(destination)


def _read_chat_id() -> int:
    value = getpass.getpass("Telegram chat ID: ")
    try:
        return int(value)
    except ValueError:
        raise NotificationDestinationManagementError(
            "Telegram chat identifier is invalid."
        ) from None


def _print_destination(destination: DestinationSummary) -> None:
    print(
        " ".join(
            (
                f"destination_id={destination.destination_id}",
                f"adapter_kind={destination.adapter_kind}",
                f"enabled={str(destination.enabled).lower()}",
                f"minimum_severity={destination.minimum_severity}",
                f"configured={str(destination.configured).lower()}",
                f"staging_file_ready={str(destination.staging_file_ready).lower()}",
            )
        )
    )


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timestamp must be ISO 8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return parsed
