"""Version 1 of the normalized security event contract."""

from collections.abc import Mapping
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    field_validator,
    model_validator,
)


class EventSource(StrEnum):
    """Supported event sources for the current contract version."""

    JOURNALD = "journald"
    # A file-read event is never relabelled as journald: the two differ in what
    # they can guarantee about ordering and rotation loss (ADR-0019).
    SYSLOG_FILE = "syslog_file"
    NGINX_ACCESS = "nginx_access"


class NormalizedEventV1(BaseModel):
    """A single source-independent event produced by a Woland Guard agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: AwareDatetime
    collected_at: AwareDatetime
    source: EventSource = EventSource.JOURNALD
    event_type: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    actor: str | None = Field(default=None, max_length=255)
    source_ip: IPvAnyAddress | None = None
    summary: str | None = Field(default=None, max_length=1_000)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("actor", "summary")
    @classmethod
    def text_fields_do_not_contain_nul(cls, value: str | None) -> str | None:
        """Reject text PostgreSQL JSONB cannot represent without altering it."""

        if value is not None:
            _reject_nul(value)
        return value

    @field_validator("attributes", mode="before")
    @classmethod
    def attributes_do_not_contain_nul(cls, value: object) -> object:
        """Reject U+0000 recursively in JSON object keys and string values."""

        _reject_nul(value)
        return value

    @model_validator(mode="after")
    def collected_at_is_not_earlier_than_occurrence(self) -> Self:
        """Reject internally inconsistent timestamps."""

        if self.collected_at < self.occurred_at:
            raise ValueError("collected_at must not be earlier than occurred_at")
        return self


def _reject_nul(value: object) -> None:
    """Validate a JSON-like tree without mutating or normalizing its contents."""

    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("U+0000 is not allowed in event text")
        return

    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if isinstance(key, str):
                _reject_nul(key)
            _reject_nul(nested_value)
        return

    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_nul(item)


class EventBatchV1(BaseModel):
    """A bounded, idempotency-friendly delivery unit for normalized events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    batch_id: UUID = Field(default_factory=uuid4)
    sent_at: AwareDatetime
    events: tuple[NormalizedEventV1, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def event_ids_are_unique(self) -> Self:
        """Reject accidental duplicates inside one delivery unit."""

        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event_id values must be unique within a batch")
        return self
