"""Telegram operator links and the single confirmed inbound update offset."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class OperatorTelegramLink(Base):
    """One revocable binding between a Telegram account and an operator identity."""

    __tablename__ = "operator_telegram_links"
    __table_args__ = (
        CheckConstraint(
            "telegram_user_id > 0",
            name="telegram_user_id_positive",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="revocation_not_before_creation",
        ),
        CheckConstraint(
            "language IS NULL OR language IN ('ru', 'en')",
            name="language_allowed",
        ),
        Index(
            "uq_operator_telegram_links_active_telegram_user",
            "telegram_user_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index(
            "uq_operator_telegram_links_active_operator",
            "operator_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operator_id: Mapped[UUID] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"),
        index=True,
    )
    telegram_user_id: Mapped[int] = mapped_column(BigInteger)
    # Null until the operator runs /lang: the bot then falls back to the language
    # tag the Telegram client itself reports, so a reply is never left untranslated
    # just because nobody has set a preference yet.
    language: Mapped[str | None] = mapped_column(String(2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TelegramBotOffset(Base):
    """The single confirmed inbound update offset for the one allowed poller."""

    __tablename__ = "telegram_bot_offsets"
    __table_args__ = (
        CheckConstraint("id = 1", name="single_row"),
        CheckConstraint("next_update_id >= 0", name="next_update_id_not_negative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    next_update_id: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )
