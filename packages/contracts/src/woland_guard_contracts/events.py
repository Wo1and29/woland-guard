"""Version 1 of the normalized security event contract."""

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
    model_validator,
)


class EventSource(StrEnum):
    """Supported event sources for the current contract version."""

    JOURNALD = "journald"


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

    @model_validator(mode="after")
    def collected_at_is_not_earlier_than_occurrence(self) -> Self:
        """Reject internally inconsistent timestamps."""

        if self.collected_at < self.occurred_at:
            raise ValueError("collected_at must not be earlier than occurred_at")
        return self


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
