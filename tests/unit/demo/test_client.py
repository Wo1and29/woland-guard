"""Loopback client, retry, response, and credential security tests."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import httpx2
import pytest

from woland_guard_contracts import NormalizedEventV1
from woland_guard_control_plane.demo.client import (
    DemoApiCredential,
    DemoAuthenticationError,
    DemoClockSkewError,
    DemoCredentialError,
    DemoHttpTimeouts,
    DemoIngestionClient,
    DemoOrigin,
    DemoProtocolError,
    DemoRejectedEventsError,
    DemoTemporaryTransportError,
    UnsafeDemoOriginError,
    _bounded_retry_after,
    load_api_credential,
    prepare_batches,
)
from woland_guard_control_plane.demo.contracts import (
    DemoManifest,
    DemoManifestError,
    canonical_manifest_bytes,
    demo_event_id,
    load_manifest_bytes,
)
from woland_guard_control_plane.demo.scenarios import build_manifest, list_scenarios

RUN_ID = UUID("33333333-3333-4333-8333-333333333333")
ANCHOR = datetime(2026, 7, 29, 12, tzinfo=UTC)
TOKEN = "wgak_demo-public.demo-secret-material"  # noqa: S105 - synthetic canary


def _manifest() -> DemoManifest:
    return build_manifest(list_scenarios()[0].scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR)


def _client(
    handler: Callable[[httpx2.Request], httpx2.Response],
    *,
    sleeps: list[float] | None = None,
    max_attempts: int = 3,
) -> DemoIngestionClient:
    transport = httpx2.MockTransport(handler)
    http_client = httpx2.Client(transport=transport, follow_redirects=False, trust_env=False)
    return DemoIngestionClient(
        origin=DemoOrigin.parse("http://127.0.0.1:8000"),
        credential=DemoApiCredential(TOKEN),
        max_attempts=max_attempts,
        sleep_function=sleeps.append if sleeps is not None else lambda _seconds: None,
        now_function=lambda: ANCHOR,
        _test_client=cast(Any, http_client),
    )


def _success(request: httpx2.Request) -> httpx2.Response:
    body = json.loads(request.content)
    return httpx2.Response(
        200,
        json={
            "request_id": request.headers["X-Request-ID"],
            "batch_id": body["batch_id"],
            "accepted": len(body["events"]),
            "existing": 0,
        },
    )


def _canonical_document_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _manifest_document(scenario_id: str = "ssh_bruteforce_by_ip.positive.v1") -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(
            canonical_manifest_bytes(build_manifest(scenario_id, run_id=RUN_ID, anchor_utc=ANCHOR))
        ),
    )


def _replace_identity(
    document: dict[str, Any],
    *,
    scenario_id: str,
    rule_key: str,
    case_type: str,
) -> None:
    document["scenario_id"] = scenario_id
    document["rule_key"] = rule_key
    document["case_type"] = case_type
    for ordinal, event in enumerate(document["events"]):
        event["event_id"] = str(demo_event_id(RUN_ID, scenario_id, ordinal))
        event["attributes"]["demo_scenario_id"] = scenario_id


def _add_cross_incident(document: dict[str, Any], *, include_allowlist: bool) -> None:
    cross = _manifest_document("user_account_created.positive.v1")["expected_outcomes"][
        "incidents"
    ][0]
    outcomes = document["expected_outcomes"]
    outcomes["incidents"] = sorted(
        [*outcomes["incidents"], cross],
        key=lambda item: item["rule_key"],
    )
    outcomes["new_incident_count"] = 2
    outcomes["evidence_link_count"] = 9
    outcomes["outbox_count_delta"] = 2
    outcomes["allowed_cross_rule_outcomes"] = ["user_account_created"] if include_allowlist else []


def _mutated_manifest_bytes(mutation: str) -> bytes:
    document = _manifest_document()
    outcomes = document["expected_outcomes"]
    incident = outcomes["incidents"][0]
    if mutation == "case_type_mismatch":
        document["case_type"] = "negative"
    elif mutation == "version_v2":
        _replace_identity(
            document,
            scenario_id="ssh_bruteforce_by_ip.positive.v2",
            rule_key="ssh_bruteforce_by_ip",
            case_type="positive",
        )
    elif mutation == "extra_identity_component":
        _replace_identity(
            document,
            scenario_id="ssh_bruteforce_by_ip.positive.v1.extra",
            rule_key="ssh_bruteforce_by_ip",
            case_type="positive",
        )
    elif mutation == "unknown_case":
        _replace_identity(
            document,
            scenario_id="ssh_bruteforce_by_ip.unknown.v1",
            rule_key="ssh_bruteforce_by_ip",
            case_type="positive",
        )
    elif mutation == "unknown_scenario":
        _replace_identity(
            document,
            scenario_id="unknown_valid_rule.positive.v1",
            rule_key="unknown_valid_rule",
            case_type="positive",
        )
        incident["rule_key"] = "unknown_valid_rule"
    elif mutation == "positive_without_target":
        outcomes.update(
            incidents=[],
            new_incident_count=0,
            evidence_link_count=0,
            outbox_count_delta=0,
        )
    elif mutation == "positive_other_incident":
        incident["rule_key"] = "user_account_created"
        outcomes["allowed_cross_rule_outcomes"] = ["user_account_created"]
    elif mutation == "negative_with_target":
        document = _manifest_document("ssh_bruteforce_by_ip.negative.v1")
        target = _manifest_document()["expected_outcomes"]["incidents"][0]
        document["expected_outcomes"].update(
            incidents=[target],
            new_incident_count=1,
            evidence_link_count=8,
            outbox_count_delta=1,
        )
    elif mutation == "severity":
        incident["severity"] = "critical"
    elif mutation == "title":
        incident["title"] = "Synthetic mutated catalog title"
    elif mutation == "evidence":
        incident["evidence_links"] = 9
        outcomes["evidence_link_count"] = 9
    elif mutation == "outbox":
        _add_cross_incident(document, include_allowlist=True)
    elif mutation == "cross_without_allowlist":
        _add_cross_incident(document, include_allowlist=False)
    elif mutation == "extra_cross_allowlist":
        outcomes["allowed_cross_rule_outcomes"] = ["user_account_created"]
    elif mutation == "event_type":
        document["events"][0]["event_type"] = "linux.sudo.authentication_failed"
    elif mutation == "actor":
        document["events"][0]["actor"] = "synthetic_mutated_actor"
    elif mutation == "source_ip":
        document["events"][0]["source_ip"] = "203.0.113.254"
    elif mutation == "timestamp":
        original = datetime.fromisoformat(
            document["events"][0]["occurred_at"].replace("Z", "+00:00")
        )
        changed = (original + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
        document["events"][0]["occurred_at"] = changed
        document["events"][0]["collected_at"] = changed
    elif mutation == "attribute":
        document["events"][0]["attributes"]["demo_source_id"] = "synthetic-mutated-source"
    elif mutation == "summary":
        document["events"][0]["summary"] = "Synthetic mutated summary"
    elif mutation == "event_order":
        document = _manifest_document("ssh_success_after_failures.positive.v1")
        first_type = document["events"][0]["event_type"]
        document["events"][0]["event_type"] = document["events"][-1]["event_type"]
        document["events"][-1]["event_type"] = first_type
        for ordinal, event in enumerate(document["events"]):
            event["event_id"] = str(demo_event_id(RUN_ID, document["scenario_id"], ordinal))
    else:  # pragma: no cover - closed test mutation registry
        raise AssertionError("unknown test mutation")
    return _canonical_document_bytes(document)


CATALOG_MUTATIONS = (
    "case_type_mismatch",
    "version_v2",
    "extra_identity_component",
    "unknown_case",
    "unknown_scenario",
    "positive_without_target",
    "positive_other_incident",
    "negative_with_target",
    "severity",
    "title",
    "evidence",
    "outbox",
    "cross_without_allowlist",
    "extra_cross_allowlist",
    "event_type",
    "actor",
    "source_ip",
    "timestamp",
    "attribute",
    "summary",
    "event_order",
)


@pytest.mark.parametrize("mutation", CATALOG_MUTATIONS)
def test_untrusted_manifest_mutations_never_reach_http(mutation: str) -> None:
    raw = _mutated_manifest_bytes(mutation)
    assert isinstance(json.loads(raw), dict)
    requests = 0

    def handler(_request: httpx2.Request) -> httpx2.Response:
        nonlocal requests
        requests += 1
        return httpx2.Response(500)

    rendered_error = ""
    try:
        manifest = load_manifest_bytes(raw)
    except DemoManifestError as error:
        rendered_error = str(error)
    else:
        with pytest.raises(DemoManifestError) as captured:
            _client(handler).send(manifest)
        rendered_error = str(captured.value)

    assert requests == 0
    assert rendered_error in {
        "manifest failed strict validation",
        "demo manifest failed catalog validation",
    }
    assert "mutated" not in rendered_error
    assert "203.0.113.254" not in rendered_error


@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1:8443",
        "http://127.0.0.1:8000",
        "https://localhost:9443",
        "http://localhost:8000",
    ],
)
def test_exact_loopback_origins_are_accepted(origin: str) -> None:
    assert DemoOrigin.parse(origin).value == origin


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.com:443",
        "http://127.0.0.1",
        "http://127.0.0.1:8000/",
        "http://LOCALHOST:8000",
        "http://localhost:8000/path",
        "http://localhost:8000?query=1",
        "http://localhost:8000#fragment",
        "http://user:pass@localhost:8000",
        "file://localhost:8000",
        "http://[::1]:8000",
    ],
)
def test_unsafe_or_noncanonical_origins_are_rejected(origin: str) -> None:
    with pytest.raises(UnsafeDemoOriginError, match="unsafe"):
        DemoOrigin.parse(origin)


@pytest.mark.parametrize("value", [True, False, 0, -1, float("nan"), float("inf"), -float("inf")])
def test_http_timeouts_reject_nonpositive_bool_and_nonfinite_values(value: object) -> None:
    with pytest.raises(ValueError, match="timeout"):
        DemoHttpTimeouts(connect=cast(Any, value)).validate()


def test_retry_after_is_bounded_without_controlling_automatic_retries() -> None:
    assert _bounded_retry_after("999999") == 60.0
    assert _bounded_retry_after("-10") == 0.0
    assert _bounded_retry_after("nan") is None
    assert _bounded_retry_after("invalid") is None


def test_success_uses_only_exact_post_endpoint_and_bounded_body() -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return _success(request)

    summary = _client(handler).send(_manifest())

    assert summary.accepted == len(_manifest().events)
    assert summary.duplicates == 0
    assert summary.rejected == 0
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert str(requests[0].url) == "http://127.0.0.1:8000/api/v1/events"
    assert requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert len(requests[0].content) <= 1_048_576


def test_transport_uncertainty_retries_identical_request_body() -> None:
    requests: list[bytes] = []
    sleeps: list[float] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request.content)
        if len(requests) == 1:
            raise httpx2.ReadError("sensitive transport detail", request=request)
        return _success(request)

    summary = _client(handler, sleeps=sleeps).send(_manifest())

    assert summary.accepted == len(_manifest().events)
    assert requests[0] == requests[1]
    assert sleeps == [0.25]


def test_5xx_retries_are_bounded_and_exact() -> None:
    requests: list[bytes] = []
    sleeps: list[float] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request.content)
        return httpx2.Response(503, content=b"sensitive provider body")

    with pytest.raises(DemoTemporaryTransportError, match="temporarily"):
        _client(handler, sleeps=sleeps).send(_manifest())

    assert len(requests) == 3
    assert len(set(requests)) == 1
    assert sleeps == [0.25, 0.5]


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [
        (401, DemoAuthenticationError),
        (403, DemoRejectedEventsError),
        (413, DemoRejectedEventsError),
        (422, DemoRejectedEventsError),
        (429, DemoTemporaryTransportError),
        (302, DemoProtocolError),
    ],
)
def test_4xx_and_redirects_are_never_retried(status_code: int, error_type: type[Exception]) -> None:
    calls = 0

    def handler(_request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        return httpx2.Response(status_code, headers={"Retry-After": "999999"})

    with pytest.raises(error_type):
        _client(handler).send(_manifest())

    assert calls == 1


@pytest.mark.parametrize(
    "response_body",
    [
        b"not-json",
        b'{"request_id":"x","request_id":"y"}',
        b'{"request_id":"x","batch_id":"33333333-3333-4333-8333-333333333333",'
        b'"accepted":true,"existing":0}',
    ],
)
def test_malformed_success_response_is_rejected_without_reflection(response_body: bytes) -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=response_body)

    with pytest.raises(DemoProtocolError, match="strict|inconsistent") as captured:
        _client(handler).send(_manifest())

    assert "not-json" not in str(captured.value)


def test_oversized_success_response_is_rejected() -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=b"x" * 65_537)

    with pytest.raises(DemoProtocolError, match="size"):
        _client(handler).send(_manifest())


def test_clock_skew_is_checked_before_request() -> None:
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        return _success(request)

    client = _client(handler)
    stale = build_manifest(
        list_scenarios()[0].scenario_id,
        run_id=RUN_ID,
        anchor_utc=ANCHOR - timedelta(seconds=1),
    )

    with pytest.raises(DemoClockSkewError, match="clock skew"):
        client.send(stale, max_clock_skew_seconds=0)
    assert calls == 0


def test_batch_splitting_uses_stable_ids_and_one_hundred_event_limit() -> None:
    base = _manifest()
    events = tuple(
        NormalizedEventV1(
            event_id=demo_event_id(RUN_ID, base.scenario_id, index),
            occurred_at=ANCHOR,
            collected_at=ANCHOR,
            event_type="linux.account.user_created",
            actor=f"synthetic_{index}",
            summary="Synthetic Woland Guard demo event",
            attributes={"demo_scenario_id": base.scenario_id},
        )
        for index in range(101)
    )
    expanded = DemoManifest.model_construct(**{**base.__dict__, "events": events})

    first = prepare_batches(expanded)
    second = prepare_batches(expanded)

    assert [item.event_count for item in first] == [100, 1]
    assert [item.batch_id for item in first] == [item.batch_id for item in second]
    assert [item.body for item in first] == [item.body for item in second]


def test_credential_repr_str_and_nested_containers_are_redacted() -> None:
    credential = DemoApiCredential(TOKEN)

    rendered = " ".join(
        (repr(credential), str(credential), repr([credential]), repr({"k": credential}))
    )

    assert TOKEN not in rendered
    assert "demo-secret-material" not in rendered
    assert "redacted" in rendered


@pytest.mark.parametrize(
    "content",
    [
        TOKEN + "\n",
        TOKEN + "\r\n",
        TOKEN + " extra",
        "not-a-token",
        "",
        "wgak_public.секрет",
    ],
)
def test_key_file_rejects_newline_extra_non_ascii_and_malformed_content(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "agent.key"
    path.write_bytes(content.encode("utf-8"))
    if os.name == "posix":
        path.chmod(0o600)

    with pytest.raises(DemoCredentialError, match="content|invalid"):
        load_api_credential(path)


def test_key_file_loads_one_bounded_token_without_exposing_path(tmp_path: Path) -> None:
    path = tmp_path / "agent.key"
    path.write_text(TOKEN, encoding="ascii")
    if os.name == "posix":
        path.chmod(0o600)

    credential = load_api_credential(path)

    assert str(credential) == "<redacted>"
    assert str(path) not in repr(credential)


def test_key_file_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.key"
    target.write_text(TOKEN, encoding="ascii")
    if os.name == "posix":
        target.chmod(0o600)
    link = tmp_path / "agent.key"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is not available")

    with pytest.raises(DemoCredentialError, match="unsafe"):
        load_api_credential(link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_key_file_rejects_group_or_other_permissions(tmp_path: Path) -> None:
    path = tmp_path / "agent.key"
    path.write_text(TOKEN, encoding="ascii")
    path.chmod(0o644)

    with pytest.raises(DemoCredentialError, match="permissions"):
        load_api_credential(path)
