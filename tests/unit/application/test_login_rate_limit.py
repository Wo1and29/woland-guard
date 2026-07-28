"""Unit tests for bounded, non-identifying Dashboard login limiting."""

from woland_guard_control_plane.application.login_rate_limit import LoginRateLimiter
from woland_guard_control_plane.application.operator_keys import generate_operator_api_key


def _limiter(clock: list[float], *, max_subjects: int = 2) -> LoginRateLimiter:
    return LoginRateLimiter(
        global_limit=20,
        global_window_seconds=60,
        subject_limit=1,
        subject_window_seconds=10,
        malformed_limit=1,
        malformed_window_seconds=10,
        max_subject_buckets=max_subjects,
        clock=lambda: clock[0],
        process_key=b"p" * 32,
    )


def test_subject_and_malformed_buckets_have_indistinguishable_safe_decisions() -> None:
    clock = [0.0]
    limiter = _limiter(clock)
    credential = generate_operator_api_key().token

    assert limiter.consume(credential) is None
    subject_decision = limiter.consume(credential)
    assert subject_decision is not None and subject_decision.scope == "subject"
    assert limiter.consume("malformed") is None
    decision = limiter.consume("another malformed credential")
    assert decision is not None
    assert decision.scope == "malformed"
    assert credential not in repr(limiter)


def test_subject_memory_is_bounded_and_expired_buckets_are_cleaned() -> None:
    clock = [0.0]
    limiter = _limiter(clock, max_subjects=1)
    first = generate_operator_api_key().token
    second = generate_operator_api_key().token

    assert limiter.consume(first) is None
    capacity = limiter.consume(second)
    assert capacity is not None and capacity.scope == "capacity"
    assert limiter.subject_bucket_count == 1

    clock[0] = 11.0
    assert limiter.consume(second) is None
    assert limiter.subject_bucket_count == 1
