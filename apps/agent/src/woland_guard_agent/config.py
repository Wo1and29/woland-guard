"""Strict YAML configuration and protected token loading for the Linux agent."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Literal, Self, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError, model_validator

_TOKEN_PATTERN = re.compile(r"^wgak_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_MAX_TOKEN_BYTES = 4_096


class AgentConfigurationError(ValueError):
    """A safe configuration failure that never includes credential contents."""


class SecretToken:
    """Credential wrapper whose string representations are always redacted."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def authorization_header(self) -> str:
        """Return the credential only at the HTTP authorization boundary."""

        return f"Bearer {self._value}"

    def __repr__(self) -> str:
        return "SecretToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


class HttpSettings(BaseModel):
    """HTTPS delivery settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: HttpUrl
    token_file: Path
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    read_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    batch_size: int = Field(default=100, ge=1, le=100)

    @model_validator(mode="after")
    def https_is_required(self) -> Self:
        """Prevent plaintext credential transport in production configuration."""

        if self.base_url.scheme != "https":
            raise ValueError("http.base_url must use HTTPS")
        if self.base_url.username is not None or self.base_url.password is not None:
            raise ValueError("http.base_url must not contain credentials")
        if self.base_url.query is not None or self.base_url.fragment is not None:
            raise ValueError("http.base_url must not contain query or fragment")
        if not self.token_file.is_absolute():
            raise ValueError("http.token_file must be an absolute path")
        return self


class SpoolSettings(BaseModel):
    """Durable local queue limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    max_events: int = Field(default=10_000, ge=1, le=1_000_000)

    @model_validator(mode="after")
    def path_is_absolute(self) -> Self:
        if not self.path.is_absolute():
            raise ValueError("spool.path must be an absolute path")
        return self


class RetrySettings(BaseModel):
    """Bounded retry delays used by the delivery loop."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    base_seconds: float = Field(default=1.0, gt=0, le=60)
    maximum_seconds: float = Field(default=300.0, gt=0, le=3_600)
    authentication_seconds: float = Field(default=300.0, gt=0, le=3_600)

    @model_validator(mode="after")
    def maximum_is_not_below_base(self) -> Self:
        if self.maximum_seconds < self.base_seconds:
            raise ValueError("retry.maximum_seconds must be >= retry.base_seconds")
        return self


class SyslogFileSettings(BaseModel):
    """Location of the plain-text syslog file to follow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path

    @model_validator(mode="after")
    def path_is_absolute(self) -> Self:
        if not self.path.is_absolute():
            raise ValueError("syslog_file.path must be an absolute path")
        return self


class NginxAccessSettings(BaseModel):
    """Location of the nginx access log to follow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path

    @model_validator(mode="after")
    def path_is_absolute(self) -> Self:
        if not self.path.is_absolute():
            raise ValueError("nginx_access.path must be an absolute path")
        return self


class AgentSettings(BaseModel):
    """Complete versioned agent configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    # The system journal, read one way or the other. journald and syslog_file
    # carry the same sshd lines, so enabling both would double-count every
    # attempt and halve each detection threshold (ADR-0019 §1).
    source: Literal["journald", "syslog_file"] = "journald"
    http: HttpSettings
    spool: SpoolSettings
    syslog_file: SyslogFileSettings | None = None
    # Independent of the journal source: an access log shares no record with it,
    # and a web host almost always needs SSH monitoring too (ADR-0020 §5).
    nginx_access: NginxAccessSettings | None = None
    retry: RetrySettings = Field(default_factory=RetrySettings)
    delivery_poll_seconds: float = Field(default=1.0, gt=0, le=60)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @model_validator(mode="after")
    def source_settings_match_the_selected_source(self) -> Self:
        """Require the journal source to be configured completely, and only once."""

        if self.source == "syslog_file" and self.syslog_file is None:
            raise ValueError("syslog_file settings are required when source is syslog_file")
        if self.source != "syslog_file" and self.syslog_file is not None:
            raise ValueError("syslog_file settings require source: syslog_file")
        return self


def load_agent_settings(path: Path) -> AgentSettings:
    """Parse a YAML document without interpolating environment variables or secrets."""

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise AgentConfigurationError(f"cannot read agent configuration: {path}") from error

    if not isinstance(raw, dict):
        raise AgentConfigurationError("agent configuration must be a YAML mapping")

    try:
        return AgentSettings.model_validate(raw)
    except ValidationError as error:
        raise AgentConfigurationError(_safe_validation_message(error)) from error


def load_secret_token(path: Path) -> SecretToken:
    """Read a one-line credential from an owned, non-symlink, private file."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise AgentConfigurationError(f"token_file is unavailable: {path}") from error

    if stat.S_ISLNK(metadata.st_mode):
        raise AgentConfigurationError("token_file must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise AgentConfigurationError("token_file must be a regular file")

    if os.name == "posix":
        if metadata.st_uid != Path("/proc/self").stat().st_uid:
            raise AgentConfigurationError("token_file must be owned by the agent user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AgentConfigurationError("token_file permissions must be 0600 or stricter")

    if metadata.st_size <= 0 or metadata.st_size > _MAX_TOKEN_BYTES:
        raise AgentConfigurationError("token_file has an invalid size")

    flags = os.O_RDONLY | cast(int, getattr(os, "O_NOFOLLOW", 0))
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_metadata = os.fstat(descriptor)
        if opened_metadata.st_dev != metadata.st_dev or opened_metadata.st_ino != metadata.st_ino:
            raise AgentConfigurationError("token_file changed during secure open")
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise AgentConfigurationError("token_file must remain a regular file")
        if os.name == "posix":
            if opened_metadata.st_uid != Path("/proc/self").stat().st_uid:
                raise AgentConfigurationError("token_file ownership changed during secure open")
            if stat.S_IMODE(opened_metadata.st_mode) & 0o077:
                raise AgentConfigurationError("token_file permissions changed during secure open")
        with os.fdopen(descriptor, "rb") as token_stream:
            descriptor = -1
            token_bytes = token_stream.read(_MAX_TOKEN_BYTES + 1)
        token = token_bytes.decode("utf-8").strip()
    except AgentConfigurationError:
        raise
    except (OSError, UnicodeError) as error:
        raise AgentConfigurationError("token_file cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(token_bytes) > _MAX_TOKEN_BYTES or not _TOKEN_PATTERN.fullmatch(token):
        raise AgentConfigurationError("token_file does not contain a valid agent token")
    return SecretToken(token)


def _safe_validation_message(error: ValidationError) -> str:
    locations = sorted({".".join(str(part) for part in item["loc"]) for item in error.errors()})
    joined = ", ".join(location for location in locations if location)
    return f"invalid agent configuration fields: {joined or 'root'}"
