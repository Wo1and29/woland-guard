"""Bounded process-local rate limiting for operator web login attempts."""

from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from hmac import new as hmac_new
from math import ceil
from secrets import token_bytes
from threading import Lock
from time import monotonic

from woland_guard_control_plane.application.operator_keys import (
    parse_operator_api_key_public_id,
)


@dataclass(frozen=True, slots=True)
class LoginRateLimitDecision:
    """A safe limiter outcome containing no credential-derived identifier."""

    retry_after_seconds: int
    scope: str


class LoginRateLimiter:
    """Global plus bounded subject/malformed fixed-window counters."""

    def __init__(
        self,
        *,
        global_limit: int,
        global_window_seconds: int,
        subject_limit: int,
        subject_window_seconds: int,
        malformed_limit: int,
        malformed_window_seconds: int,
        max_subject_buckets: int,
        clock: Callable[[], float] = monotonic,
        process_key: bytes | None = None,
    ) -> None:
        values = (
            global_limit,
            global_window_seconds,
            subject_limit,
            subject_window_seconds,
            malformed_limit,
            malformed_window_seconds,
            max_subject_buckets,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("login limiter values must be positive integers")
        key = process_key if process_key is not None else token_bytes(32)
        if len(key) < 32:
            raise ValueError("login limiter process key is too short")
        self._global_limit = global_limit
        self._global_window_seconds = global_window_seconds
        self._subject_limit = subject_limit
        self._subject_window_seconds = subject_window_seconds
        self._malformed_limit = malformed_limit
        self._malformed_window_seconds = malformed_window_seconds
        self._max_subject_buckets = max_subject_buckets
        self._clock = clock
        self._process_key = key
        self._global_requests: deque[float] = deque()
        self._malformed_requests: deque[float] = deque()
        self._subject_requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = Lock()

    def consume(self, credential: str) -> LoginRateLimitDecision | None:
        """Consume all applicable buckets without retaining the credential/public ID."""

        now = self._clock()
        with self._lock:
            global_retry = _consume_window(
                self._global_requests,
                now=now,
                limit=self._global_limit,
                window_seconds=self._global_window_seconds,
            )
            if global_retry is not None:
                return LoginRateLimitDecision(global_retry, "global")

            public_id = parse_operator_api_key_public_id(credential)
            if public_id is None:
                retry = _consume_window(
                    self._malformed_requests,
                    now=now,
                    limit=self._malformed_limit,
                    window_seconds=self._malformed_window_seconds,
                )
                return None if retry is None else LoginRateLimitDecision(retry, "malformed")

            self._cleanup_subjects(now)
            subject_key = hmac_new(
                self._process_key,
                public_id.encode("ascii"),
                sha256,
            ).hexdigest()
            requests = self._subject_requests.get(subject_key)
            if requests is None:
                if len(self._subject_requests) >= self._max_subject_buckets:
                    return LoginRateLimitDecision(self._subject_window_seconds, "capacity")
                requests = deque()
                self._subject_requests[subject_key] = requests
            else:
                self._subject_requests.move_to_end(subject_key)
            retry = _consume_window(
                requests,
                now=now,
                limit=self._subject_limit,
                window_seconds=self._subject_window_seconds,
            )
            return None if retry is None else LoginRateLimitDecision(retry, "subject")

    @property
    def subject_bucket_count(self) -> int:
        with self._lock:
            return len(self._subject_requests)

    def reset(self) -> None:
        with self._lock:
            self._global_requests.clear()
            self._malformed_requests.clear()
            self._subject_requests.clear()

    def _cleanup_subjects(self, now: float) -> None:
        cutoff = now - self._subject_window_seconds
        expired: list[str] = []
        for key, requests in self._subject_requests.items():
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if not requests:
                expired.append(key)
        for key in expired:
            del self._subject_requests[key]


def _consume_window(
    requests: deque[float],
    *,
    now: float,
    limit: int,
    window_seconds: int,
) -> int | None:
    cutoff = now - window_seconds
    while requests and requests[0] <= cutoff:
        requests.popleft()
    if len(requests) >= limit:
        return max(1, ceil(requests[0] + window_seconds - now))
    requests.append(now)
    return None
