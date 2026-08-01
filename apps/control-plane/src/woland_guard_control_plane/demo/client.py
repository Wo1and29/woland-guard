"""Narrow loopback-only ingestion client for synthetic demo manifests."""

from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from time import sleep
from typing import Any, Final, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from woland_guard_contracts import EventBatchV1
from woland_guard_control_plane.application.agent_keys import parse_agent_api_key_public_id
from woland_guard_control_plane.demo.contracts import (
    DemoManifest,
    demo_batch_id,
)
from woland_guard_control_plane.demo.scenarios import validate_catalog_manifest

INGESTION_PATH: Final = "/api/v1/events"
MAX_API_KEY_BYTES: Final = 4_096
MAX_RESPONSE_BYTES: Final = 65_536
MAX_REQUEST_BYTES: Final = 1_048_576
MAX_RETRY_AFTER_SECONDS: Final = 60.0
MAX_ATTEMPTS: Final = 3

_TOKEN_PATTERN = re.compile(r"^wgak_[A-Za-z0-9_-]{1,128}[.][A-Za-z0-9_-]{1,256}$")


class DemoClientError(RuntimeError):
    """Base class for safe, non-reflective demo client failures."""


class UnsafeDemoOriginError(DemoClientError):
    pass


class DemoAuthenticationError(DemoClientError):
    pass


class DemoRejectedEventsError(DemoClientError):
    pass


class DemoTemporaryTransportError(DemoClientError):
    pass


class DemoProtocolError(DemoClientError):
    pass


class DemoClockSkewError(DemoClientError):
    pass


class DemoCredentialError(ValueError):
    """Safe credential error without token or path reflection."""


class DemoApiCredential:
    """Plaintext agent token available only at the Authorization boundary."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if (
            type(value) is not str
            or not value.isascii()
            or any(character.isspace() or ord(character) < 0x20 for character in value)
            or _TOKEN_PATTERN.fullmatch(value) is None
            or parse_agent_api_key_public_id(value) is None
        ):
            raise DemoCredentialError("demo API credential is invalid")
        self._value = value

    def authorization_header(self) -> str:
        return f"Bearer {self._value}"

    def __repr__(self) -> str:
        return "DemoApiCredential(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class DemoOrigin:
    value: str

    @classmethod
    def parse(cls, value: object) -> DemoOrigin:
        if type(value) is not str:
            raise UnsafeDemoOriginError("demo origin is unsafe")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise UnsafeDemoOriginError("demo origin is unsafe") from None
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username is not None
            or parsed.password is not None
            or port is None
            or not 1 <= port <= 65_535
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.netloc != f"{parsed.hostname}:{port}"
            or value != f"{parsed.scheme}://{parsed.hostname}:{port}"
        ):
            raise UnsafeDemoOriginError("demo origin is unsafe")
        return cls(value)

    @property
    def endpoint(self) -> str:
        return f"{self.value}{INGESTION_PATH}"


@dataclass(frozen=True, slots=True)
class DemoHttpTimeouts:
    connect: float = 3.0
    read: float = 10.0
    write: float = 10.0
    pool: float = 3.0

    def validate(self) -> None:
        values = (self.connect, self.read, self.write, self.pool)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
            or value > 60
            for value in values
        ):
            raise ValueError("demo HTTP timeout configuration is invalid")


@dataclass(frozen=True, slots=True)
class PreparedBatch:
    batch_id: UUID
    event_count: int
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class DemoSendSummary:
    scenario_id: str
    batches: int
    accepted: int
    duplicates: int
    rejected: int = 0


class _IngestionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=64)
    batch_id: UUID
    accepted: int = Field(ge=0, le=100)
    existing: int = Field(ge=0, le=100)

    @classmethod
    def validate_wire_types(cls, document: object) -> None:
        if not isinstance(document, dict):
            raise ValueError("response must be an object")
        if type(document.get("request_id")) is not str:
            raise ValueError("request id has an invalid type")
        if type(document.get("batch_id")) is not str:
            raise ValueError("batch id has an invalid type")
        if type(document.get("accepted")) is not int or type(document.get("existing")) is not int:
            raise ValueError("response counts have invalid types")


class _StreamingResponse(Protocol):
    status_code: int
    headers: Any

    def iter_bytes(self) -> Iterator[bytes]: ...


class _HttpClient(Protocol):
    def stream(
        self, method: str, url: str, **kwargs: Any
    ) -> AbstractContextManager[_StreamingResponse]: ...

    def close(self) -> None: ...


class DemoIngestionClient:
    """Send immutable batches with bounded retries and no response-body reflection."""

    def __init__(
        self,
        *,
        origin: DemoOrigin,
        credential: DemoApiCredential,
        timeouts: DemoHttpTimeouts | None = None,
        max_attempts: int = MAX_ATTEMPTS,
        sleep_function: Callable[[float], None] = sleep,
        now_function: Callable[[], datetime] = lambda: datetime.now(UTC),
        _test_client: _HttpClient | None = None,
    ) -> None:
        effective_timeouts = timeouts or DemoHttpTimeouts()
        effective_timeouts.validate()
        if type(max_attempts) is not int or not 1 <= max_attempts <= MAX_ATTEMPTS:
            raise ValueError("demo retry count is invalid")
        self._origin = origin
        self._credential = credential
        self._max_attempts = max_attempts
        self._sleep = sleep_function
        self._now = now_function
        if _test_client is None:
            timeout = httpx2.Timeout(
                connect=effective_timeouts.connect,
                read=effective_timeouts.read,
                write=effective_timeouts.write,
                pool=effective_timeouts.pool,
            )
            self._client: _HttpClient = cast(
                _HttpClient,
                httpx2.Client(
                    timeout=timeout,
                    trust_env=False,
                    verify=True,
                    follow_redirects=False,
                    transport=httpx2.HTTPTransport(retries=0, verify=True),
                ),
            )
            self._owns_client = True
        else:
            self._client = _test_client
            self._owns_client = False

    def send(self, manifest: DemoManifest, *, max_clock_skew_seconds: int = 300) -> DemoSendSummary:
        manifest = validate_catalog_manifest(manifest)
        if type(max_clock_skew_seconds) is not int or not 0 <= max_clock_skew_seconds <= 86_400:
            raise ValueError("demo clock-skew limit is invalid")
        now = self._now()
        if (
            now.tzinfo is None
            or abs((now.astimezone(UTC) - manifest.anchor_utc).total_seconds())
            > max_clock_skew_seconds
        ):
            raise DemoClockSkewError("demo manifest anchor is outside the allowed clock skew")
        batches = prepare_batches(manifest)
        accepted = 0
        duplicates = 0
        for batch in batches:
            result = self._send_batch(batch)
            accepted += result.accepted
            duplicates += result.existing
        return DemoSendSummary(
            scenario_id=manifest.scenario_id,
            batches=len(batches),
            accepted=accepted,
            duplicates=duplicates,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> DemoIngestionClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _send_batch(self, batch: PreparedBatch) -> _IngestionResponse:
        request_id = f"demo-{batch.batch_id.hex}"
        for attempt in range(1, self._max_attempts + 1):
            try:
                with self._client.stream(
                    "POST",
                    self._origin.endpoint,
                    headers={
                        "Authorization": self._credential.authorization_header(),
                        "Content-Type": "application/json",
                        "X-Request-ID": request_id,
                    },
                    content=batch.body,
                    follow_redirects=False,
                ) as response:
                    status_code = response.status_code
                    if status_code == 200:
                        return _parse_success(response, batch=batch)
                    if status_code == 401:
                        raise DemoAuthenticationError("demo API authentication failed")
                    if status_code == 429:
                        _bounded_retry_after(response.headers.get("Retry-After"))
                        raise DemoTemporaryTransportError("demo API rate limit was reached")
                    if 500 <= status_code <= 599:
                        if attempt < self._max_attempts:
                            self._sleep(_retry_delay(attempt))
                            continue
                        raise DemoTemporaryTransportError("demo API is temporarily unavailable")
                    if 400 <= status_code <= 499:
                        raise DemoRejectedEventsError("demo API rejected the event batch")
                    raise DemoProtocolError("demo API returned an unsupported status")
            except DemoClientError:
                raise
            except httpx2.HTTPError:
                if attempt < self._max_attempts:
                    self._sleep(_retry_delay(attempt))
                    continue
                raise DemoTemporaryTransportError("demo transport failed safely") from None
        raise DemoTemporaryTransportError("demo transport failed safely")


def prepare_batches(manifest: DemoManifest) -> tuple[PreparedBatch, ...]:
    prepared: list[PreparedBatch] = []
    for batch_ordinal, start in enumerate(range(0, len(manifest.events), 100)):
        events = manifest.events[start : start + 100]
        batch_id = demo_batch_id(manifest.run_id, manifest.scenario_id, batch_ordinal)
        batch = EventBatchV1(
            batch_id=batch_id,
            sent_at=manifest.anchor_utc,
            events=events,
        )
        try:
            body = json.dumps(
                batch.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise DemoProtocolError("demo request could not be serialized safely") from None
        if len(body) > MAX_REQUEST_BYTES:
            raise DemoRejectedEventsError("demo request exceeds the ingestion body limit")
        prepared.append(PreparedBatch(batch_id=batch_id, event_count=len(events), body=body))
    return tuple(prepared)


def load_api_credential(path: Path) -> DemoApiCredential:
    try:
        metadata = path.lstat()
    except OSError:
        raise DemoCredentialError("demo API credential file is unavailable") from None
    if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise DemoCredentialError("demo API credential file is unsafe")
    if os.name == "posix":
        if metadata.st_uid != _current_uid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise DemoCredentialError("demo API credential file permissions are unsafe")
    if metadata.st_size <= 0 or metadata.st_size > MAX_API_KEY_BYTES:
        raise DemoCredentialError("demo API credential file has an invalid size")
    descriptor = -1
    flags = os.O_RDONLY | cast(int, getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise DemoCredentialError("demo API credential file changed during secure open")
        if os.name == "posix" and (
            opened.st_uid != _current_uid() or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            raise DemoCredentialError("demo API credential file permissions changed")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_API_KEY_BYTES + 1)
    except DemoCredentialError:
        raise
    except OSError:
        raise DemoCredentialError("demo API credential file cannot be read safely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_API_KEY_BYTES or b"\x00" in raw or b"\r" in raw or b"\n" in raw:
        raise DemoCredentialError("demo API credential file content is invalid")
    try:
        token = raw.decode("ascii", errors="strict")
    except UnicodeError:
        raise DemoCredentialError("demo API credential file content is invalid") from None
    return DemoApiCredential(token)


def _parse_success(response: _StreamingResponse, *, batch: PreparedBatch) -> _IngestionResponse:
    buffer = bytearray()
    try:
        for chunk in response.iter_bytes():
            if len(buffer) + len(chunk) > MAX_RESPONSE_BYTES:
                raise DemoProtocolError("demo API response exceeded the safe size limit")
            buffer.extend(chunk)
        document = json.loads(bytes(buffer), object_pairs_hook=_reject_duplicate_response_keys)
        _IngestionResponse.validate_wire_types(document)
        result = _IngestionResponse.model_validate(document)
    except DemoClientError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValidationError, ValueError, TypeError):
        raise DemoProtocolError("demo API response failed strict validation") from None
    if result.batch_id != batch.batch_id or result.accepted + result.existing != batch.event_count:
        raise DemoProtocolError("demo API response is inconsistent")
    return result


def _reject_duplicate_response_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response key")
        result[key] = value
    return result


def _retry_delay(attempt: int) -> float:
    return float(min(0.25 * (2 ** (attempt - 1)), 1.0))


def _bounded_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            target = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if target.tzinfo is None:
            target = target.replace(tzinfo=UTC)
        seconds = (target - datetime.now(UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return max(0.0, min(seconds, MAX_RETRY_AFTER_SECONDS))


def _is_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    flag = cast(int, getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    attributes = cast(int, getattr(metadata, "st_file_attributes", 0))
    return bool(flag and attributes & flag)


def _current_uid() -> int:
    getter = cast(Callable[[], int] | None, getattr(os, "geteuid", None))
    if getter is None:
        raise DemoCredentialError("POSIX credential ownership cannot be verified")
    return getter()
