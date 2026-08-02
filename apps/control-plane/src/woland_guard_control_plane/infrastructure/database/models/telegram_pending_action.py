"""One pending terminal-status transition awaiting a reason from the bot user."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class TelegramPendingAction(Base):
    """At most one pending action per Telegram account, replaced on re-request.

    The primary key is ``telegram_user_id`` itself, so a second button press
    naturally replaces (rather than accumulates alongside) any earlier pending
    action for the same account -- there is nothing to garbage-collect beyond
    the lazy expiry check performed wherever this row is read.
    """

    __tablename__ = "telegram_pending_actions"
    __table_args__ = (
        CheckConstraint("telegram_user_id > 0", name="telegram_user_id_positive"),
        CheckConstraint(
            "target_status IN ('resolved', 'false_positive')",
            name="target_status_allowed",
        ),
        CheckConstraint("expected_version > 0", name="expected_version_positive"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
    )

    telegram_user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    target_status: Mapped[str] = mapped_column(String(32))
    expected_version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
