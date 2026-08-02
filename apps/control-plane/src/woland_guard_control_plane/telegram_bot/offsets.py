"""Durable confirmed-offset storage for the single allowed inbound poller."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from woland_guard_control_plane.infrastructure.database.models import TelegramBotOffset

OFFSET_ROW_ID = 1


def load_next_update_id(session: Session) -> int:
    """Return the confirmed offset, or zero before the first successful batch."""

    stored = session.scalars(
        select(TelegramBotOffset).where(TelegramBotOffset.id == OFFSET_ROW_ID)
    ).one_or_none()
    return 0 if stored is None else stored.next_update_id


def confirm_next_update_id(session: Session, *, next_update_id: int) -> None:
    """Advance the confirmed offset, never moving it backwards.

    The offset is written only after a batch has been fully handled, so a crash in
    the middle of a batch replays that batch instead of silently dropping it.
    """

    if isinstance(next_update_id, bool) or not isinstance(next_update_id, int):
        raise ValueError("telegram offset must be an integer")
    if next_update_id < 0:
        raise ValueError("telegram offset must not be negative")
    statement = (
        insert(TelegramBotOffset)
        .values(id=OFFSET_ROW_ID, next_update_id=next_update_id)
        .on_conflict_do_update(
            index_elements=[TelegramBotOffset.id],
            set_={"next_update_id": next_update_id},
            where=TelegramBotOffset.next_update_id < next_update_id,
        )
    )
    session.execute(statement)
