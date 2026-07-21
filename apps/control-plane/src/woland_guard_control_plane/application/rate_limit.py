"""Small process-local fixed-window limiters for bounded MVP use cases."""

from collections import defaultdict, deque
from collections.abc import Callable
from math import ceil
from threading import Lock
from time import monotonic


class FixedWindowRateLimiter:
    """Thread-safe fixed-window counter keyed by a caller-provided safe identifier."""

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: int,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._clock = clock
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def consume(self, key: str) -> int | None:
        """Record one request or return the required retry delay in seconds."""

        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            requests = self._requests[key]
            while requests and requests[0] <= cutoff:
                requests.popleft()

            if len(requests) >= self._max_requests:
                return max(1, ceil(requests[0] + self._window_seconds - now))

            requests.append(now)
            return None

    def reset(self) -> None:
        """Clear process-local state, primarily for isolated tests."""

        with self._lock:
            self._requests.clear()


class AgentRateLimiter(FixedWindowRateLimiter):
    """Named compatibility type for the authenticated agent request limiter."""
