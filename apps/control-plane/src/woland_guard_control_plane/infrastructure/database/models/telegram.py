"""Telegram-specific configuration linked one-to-one to a neutral destination."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from woland_guard_control_plane.infrastructure.database.base import Base, utc_now


class TelegramDestinationConfig(Base):
    """Provider configuration without bot credentials."""

    __tablename__ = "telegram_destination_configs"
    __table_args__ = (
        CheckConstraint(
            "chat_id <> 0 AND chat_id BETWEEN -4503599627370495 AND 4503599627370495",
            name="chat_id_safe_range",
        ),
        CheckConstraint(
            "token_file_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'",
            name="token_file_name_safe",
        ),
        CheckConstraint("updated_at >= created_at", name="timestamps_ordered"),
        UniqueConstraint(
            "chat_id",
            "token_file_name",
            name="uq_telegram_destination_configs_chat_token_file",
        ),
    )

    destination_id: Mapped[UUID] = mapped_column(
        ForeignKey("notification_destinations.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    chat_id: Mapped[int] = mapped_column(BigInteger)
    token_file_name: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )
