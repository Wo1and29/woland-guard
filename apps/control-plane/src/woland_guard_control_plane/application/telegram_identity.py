"""Telegram account links used as a third operator authentication method."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from woland_guard_control_plane.application.audit import record_local_cli_action
from woland_guard_control_plane.application.operator_principal import OperatorPrincipal
from woland_guard_control_plane.infrastructure.database.models import (
    Operator,
    OperatorAuthMethodType,
    OperatorRole,
    OperatorTelegramLink,
)
from woland_guard_control_plane.language import Language, normalize_language

TELEGRAM_USER_ID_MAX = 2**53 - 1


class TelegramIdentityError(ValueError):
    """A safe validation or lifecycle conflict for Telegram operator links."""


@dataclass(frozen=True, slots=True)
class LinkedTelegramAccount:
    """One active link returned to the administrative CLI."""

    link_id: UUID
    operator_id: UUID
    username: str
    telegram_user_id: int


def validate_telegram_user_id(value: object) -> int:
    """Return one positive Telegram user id inside the safe integer range."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TelegramIdentityError("telegram user id must be a positive integer")
    if not 1 <= value <= TELEGRAM_USER_ID_MAX:
        raise TelegramIdentityError("telegram user id must be a positive integer")
    return value


def link_telegram_user(
    session: Session,
    *,
    operator_id: UUID,
    telegram_user_id: int,
    now: datetime | None = None,
) -> LinkedTelegramAccount:
    """Bind one Telegram account to one active operator through the local CLI."""

    current_time = _as_utc(now or datetime.now(UTC))
    identifier = validate_telegram_user_id(telegram_user_id)
    operator = session.get(Operator, operator_id, with_for_update=True)
    if operator is None:
        raise TelegramIdentityError("operator does not exist")
    if not operator.is_active:
        raise TelegramIdentityError("operator is inactive")
    if _active_link_for_operator(session, operator_id=operator.id) is not None:
        raise TelegramIdentityError("operator already has an active telegram link")
    if _active_link_for_telegram_user(session, telegram_user_id=identifier) is not None:
        raise TelegramIdentityError("telegram account is already linked")

    link = OperatorTelegramLink(
        operator_id=operator.id,
        telegram_user_id=identifier,
        created_at=current_time,
    )
    session.add(link)
    session.flush()
    record_local_cli_action(
        session,
        action="operator_telegram_link.created",
        target_type="operator_telegram_link",
        target_id=link.id,
        details={"operator_id": str(operator.id)},
    )
    return LinkedTelegramAccount(
        link_id=link.id,
        operator_id=operator.id,
        username=operator.username,
        telegram_user_id=identifier,
    )


def revoke_telegram_link(
    session: Session,
    *,
    link_id: UUID,
    now: datetime | None = None,
) -> LinkedTelegramAccount:
    """Revoke one active link without deleting its provenance."""

    current_time = _as_utc(now or datetime.now(UTC))
    link = session.get(OperatorTelegramLink, link_id, with_for_update=True)
    if link is None:
        raise TelegramIdentityError("telegram link does not exist")
    if link.revoked_at is not None:
        raise TelegramIdentityError("telegram link is already revoked")
    operator = session.get(Operator, link.operator_id)
    if operator is None:
        raise TelegramIdentityError("operator does not exist")
    link.revoked_at = max(current_time, _as_utc(link.created_at))
    session.flush()
    record_local_cli_action(
        session,
        action="operator_telegram_link.revoked",
        target_type="operator_telegram_link",
        target_id=link.id,
        details={"operator_id": str(link.operator_id)},
    )
    return LinkedTelegramAccount(
        link_id=link.id,
        operator_id=link.operator_id,
        username=operator.username,
        telegram_user_id=link.telegram_user_id,
    )


def list_telegram_links(session: Session) -> tuple[LinkedTelegramAccount, ...]:
    """Return every active link for safe local inspection."""

    rows = session.execute(
        select(OperatorTelegramLink, Operator)
        .join(Operator, Operator.id == OperatorTelegramLink.operator_id)
        .where(OperatorTelegramLink.revoked_at.is_(None))
        .order_by(Operator.username)
    ).all()
    return tuple(
        LinkedTelegramAccount(
            link_id=link.id,
            operator_id=link.operator_id,
            username=operator.username,
            telegram_user_id=link.telegram_user_id,
        )
        for link, operator in rows
    )


def authenticate_telegram_user(
    session: Session,
    *,
    telegram_user_id: int,
    now: datetime | None = None,
) -> OperatorPrincipal | None:
    """Return the principal for one linked Telegram account, or None when denied.

    Every denial returns None so the caller cannot distinguish an unknown account
    from a revoked link or a deactivated operator.
    """

    current_time = _as_utc(now or datetime.now(UTC))
    try:
        identifier = validate_telegram_user_id(telegram_user_id)
    except TelegramIdentityError:
        return None
    link = _active_link_for_telegram_user(session, telegram_user_id=identifier)
    if link is None:
        return None
    operator = session.get(Operator, link.operator_id)
    if operator is None or not operator.is_active:
        return None
    link.last_used_at = current_time
    return OperatorPrincipal(
        operator_id=operator.id,
        username=operator.username,
        role=OperatorRole(operator.role),
        auth_method_type=OperatorAuthMethodType.TELEGRAM,
        auth_method_id=link.id,
    )


def stored_telegram_language(
    session: Session,
    *,
    telegram_user_id: int,
) -> Language | None:
    """Return the operator's saved reply language, or None when they never set one.

    None is not "Russian": it tells the caller to fall through to the language tag
    reported by the Telegram client instead of assuming a preference.
    """

    try:
        identifier = validate_telegram_user_id(telegram_user_id)
    except TelegramIdentityError:
        return None
    link = _active_link_for_telegram_user(session, telegram_user_id=identifier)
    if link is None or link.language is None:
        return None
    return normalize_language(link.language)


def set_telegram_language(
    session: Session,
    *,
    telegram_user_id: int,
    language: Language,
) -> bool:
    """Persist one reply-language preference; returns False for an unlinked account.

    Deliberately not audited: this changes how text is rendered for one operator,
    not what they may access, so it is not a security-relevant event the way
    `operator_telegram_link.created` and `.revoked` are.
    """

    try:
        identifier = validate_telegram_user_id(telegram_user_id)
    except TelegramIdentityError:
        return False
    link = _active_link_for_telegram_user(session, telegram_user_id=identifier)
    if link is None:
        return False
    link.language = normalize_language(language)
    return True


def _active_link_for_operator(
    session: Session,
    *,
    operator_id: UUID,
) -> OperatorTelegramLink | None:
    return session.scalars(
        select(OperatorTelegramLink).where(
            OperatorTelegramLink.operator_id == operator_id,
            OperatorTelegramLink.revoked_at.is_(None),
        )
    ).one_or_none()


def _active_link_for_telegram_user(
    session: Session,
    *,
    telegram_user_id: int,
) -> OperatorTelegramLink | None:
    return session.scalars(
        select(OperatorTelegramLink).where(
            OperatorTelegramLink.telegram_user_id == telegram_user_id,
            OperatorTelegramLink.revoked_at.is_(None),
        )
    ).one_or_none()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise TelegramIdentityError("timestamps must be timezone aware")
    return value.astimezone(UTC)
