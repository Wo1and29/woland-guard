"""Adversarial probe: direct-URL access, privilege escalation, and garbage input.

Written as an audit of the running application rather than of the code: every
assertion here is about what an unauthenticated or under-privileged HTTP client
actually receives, including whether any internal detail leaks into the body.
"""

from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.integration.conftest import OperatorFactory
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.infrastructure.database.models import OperatorRole
from woland_guard_control_plane.main import create_app

pytestmark = pytest.mark.integration

ORIGIN = "https://localhost:8000"

# Anything in a response body that would mean an internal detail escaped.
LEAK_MARKERS = (
    "Traceback",
    "traceback",
    "sqlalchemy",
    "SQLAlchemy",
    "psycopg",
    'File "',
    "site-packages",
    "woland_guard_control_plane",
    "D:\\kwork",
    "/workspace/",
    "SELECT ",
    "INSERT ",
    'relation "',
    "psql",
)

PROTECTED_GET = [
    "/dashboard/",
    "/dashboard/servers",
    f"/dashboard/servers/{uuid4()}",
    "/dashboard/incidents",
    f"/dashboard/incidents/{uuid4()}",
    "/dashboard/rules",
    "/dashboard/audit",
]

PROTECTED_POST = [
    f"/dashboard/incidents/{uuid4()}/transitions",
    f"/dashboard/incidents/{uuid4()}/comments",
]


def _client(api_app: FastAPI) -> TestClient:
    return TestClient(api_app, base_url=ORIGIN, raise_server_exceptions=False)


def _assert_no_leak(body: str, where: str) -> None:
    for marker in LEAK_MARKERS:
        assert marker not in body, f"{where}: response body leaked {marker!r}"


def _login(client: TestClient, token: str) -> None:
    client.get("/dashboard/login")
    csrf = client.cookies.get("__Host-wg_csrf")
    assert csrf is not None
    response = client.post(
        "/dashboard/login",
        data={"credential": token, "_csrf": csrf},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert response.status_code == 303, f"login failed: {response.status_code}"


# --------------------------------------------------------------- direct URL


def test_protected_pages_are_not_reachable_without_a_session(api_app: FastAPI) -> None:
    """No closed screen may render for an anonymous client."""

    with _client(api_app) as client:
        for path in PROTECTED_GET:
            response = client.get(path, follow_redirects=False)
            assert response.status_code in {302, 303, 401, 403}, (
                f"{path} returned {response.status_code} to an anonymous client"
            )
            if response.status_code in {302, 303}:
                assert "/dashboard/login" in response.headers.get("location", "")
            _assert_no_leak(response.text, path)

        # A well-formed body with the correct content type, so the request is
        # rejected on identity rather than bounced earlier on content type.
        for path in PROTECTED_POST:
            response = client.post(
                path,
                data={"_csrf": "x", "comment": "probe", "idempotency_key": "k"},
                headers={"Origin": ORIGIN},
                follow_redirects=False,
            )
            assert response.status_code in {302, 303, 401, 403, 422}, (
                f"{path} returned {response.status_code} to an anonymous client"
            )
            assert response.status_code != 200, f"{path} accepted an anonymous mutation"
            _assert_no_leak(response.text, path)


def test_forged_session_cookie_is_rejected(api_app: FastAPI) -> None:
    """A guessed or tampered session identifier must not authenticate anyone."""

    with _client(api_app) as client:
        for forged in ("", "x", "a" * 64, str(uuid4()), "../../etc/passwd", "null", "0"):
            client.cookies.set("__Host-wg_session", forged, domain="localhost", path="/")
            response = client.get("/dashboard/", follow_redirects=False)
            assert response.status_code in {302, 303, 401, 403}, (
                f"forged session {forged!r} reached the dashboard"
            )
            _assert_no_leak(response.text, f"forged-session {forged!r}")
            client.cookies.clear()


# ------------------------------------------------------- privilege boundary


def test_viewer_cannot_obtain_a_dashboard_session_at_all(
    api_app: FastAPI, register_operator: OperatorFactory
) -> None:
    """VIEWER lacks ACCESS_DASHBOARD, so login itself must refuse the exchange.

    The role is API-only by design; the check that matters is that a refused
    login hands back no session cookie a later request could replay.
    """

    operator = register_operator(role=OperatorRole.VIEWER)
    with _client(api_app) as client:
        client.get("/dashboard/login")
        csrf = client.cookies.get("__Host-wg_csrf")
        assert csrf is not None
        response = client.post(
            "/dashboard/login",
            data={"credential": operator.token, "_csrf": csrf},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        assert response.status_code == 403
        assert client.cookies.get("__Host-wg_session") is None, (
            "a refused login still issued a session cookie"
        )
        _assert_no_leak(response.text, "viewer login")

        response = client.get("/dashboard/", follow_redirects=False)
        assert response.status_code in {302, 303, 401, 403}


def test_analyst_cannot_read_the_audit_log(
    api_app: FastAPI, register_operator: OperatorFactory
) -> None:
    """VIEW_AUDIT_LOG is admin-only."""

    operator = register_operator(role=OperatorRole.ANALYST)
    with _client(api_app) as client:
        _login(client, operator.token)
        response = client.get("/dashboard/audit", follow_redirects=False)
        assert response.status_code == 403
        _assert_no_leak(response.text, "analyst /dashboard/audit")


# ------------------------------------------------------------ garbage input


GARBAGE = [
    "'; DROP TABLE incidents; --",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "%00%00%00",
    "\x00nul",
    "A" * 5000,
    "-1",
    "999999999999999999999999",
    "NaN",
    "{{7*7}}",
    "${jndi:ldap://x}",
    "\u202e\u0000",
]


def test_garbage_query_parameters_never_crash_or_leak(
    api_app: FastAPI, register_operator: OperatorFactory
) -> None:
    """Filters and pagination must reject nonsense with a clean status."""

    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        _login(client, operator.token)

        for value in GARBAGE:
            for path, param in [
                ("/dashboard/incidents", "q"),
                ("/dashboard/incidents", "cursor"),
                ("/dashboard/incidents", "page_size"),
                ("/dashboard/incidents", "status"),
                ("/dashboard/incidents", "server_id"),
                ("/dashboard/servers", "q"),
                ("/dashboard/servers", "sort"),
                ("/dashboard/rules", "condition"),
                ("/dashboard/audit", "target_id"),
                ("/dashboard/audit", "created_from"),
            ]:
                response = client.get(path, params={param: value}, follow_redirects=False)
                assert response.status_code < 500, (
                    f"{path}?{param}={value[:40]!r} produced {response.status_code}"
                )
                _assert_no_leak(response.text, f"{path}?{param}")


def test_malformed_uuid_paths_are_rejected_cleanly(
    api_app: FastAPI, register_operator: OperatorFactory
) -> None:
    """A hand-typed identifier must not reach the database layer raw."""

    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        _login(client, operator.token)

        for bad in ["not-a-uuid", "1", "../../admin", "%2e%2e", "A" * 500, "'; --"]:
            for template in ("/dashboard/incidents/{}", "/dashboard/servers/{}"):
                path = template.format(bad)
                response = client.get(path, follow_redirects=False)
                assert response.status_code < 500, f"{path} produced {response.status_code}"
                _assert_no_leak(response.text, path)


def test_login_form_survives_hostile_input(api_app: FastAPI) -> None:
    """The unauthenticated form is the most exposed surface on the service."""

    with _client(api_app) as client:
        client.get("/dashboard/login")
        csrf = client.cookies.get("__Host-wg_csrf")
        assert csrf is not None

        for value in GARBAGE + ["wgok_" + "A" * 400, "\n\r\n", " " * 100]:
            response = client.post(
                "/dashboard/login",
                data={"credential": value, "_csrf": csrf},
                headers={"Origin": ORIGIN},
                follow_redirects=False,
            )
            assert response.status_code < 500, (
                f"login with {value[:40]!r} produced {response.status_code}"
            )
            _assert_no_leak(response.text, f"login {value[:40]!r}")


def test_mutation_forms_reject_unknown_and_oversized_fields(
    api_app: FastAPI, register_operator: OperatorFactory
) -> None:
    """Mutation bodies are allowlisted; extra or huge fields must not crash."""

    operator = register_operator(role=OperatorRole.ANALYST)
    incident_id = uuid4()
    with _client(api_app) as client:
        _login(client, operator.token)
        csrf = client.cookies.get("__Host-wg_csrf")
        assert csrf is not None

        bodies = [
            {"_csrf": csrf, "unexpected_field": "x"},
            {"_csrf": csrf, "comment": "A" * 100_000, "idempotency_key": "k"},
            {"_csrf": csrf, "comment": "ok", "idempotency_key": "A" * 10_000},
            {"_csrf": csrf},
            {},
        ]
        for body in bodies:
            for path in (
                f"/dashboard/incidents/{incident_id}/comments",
                f"/dashboard/incidents/{incident_id}/transitions",
            ):
                response = client.post(
                    path, data=body, headers={"Origin": ORIGIN}, follow_redirects=False
                )
                assert response.status_code < 500, (
                    f"{path} with {list(body)} produced {response.status_code}"
                )
                _assert_no_leak(response.text, path)


# -------------------------------------------------------------- JSON API


API_PROTECTED = [
    ("GET", "/api/v1/incidents"),
    ("GET", f"/api/v1/incidents/{uuid4()}"),
    ("GET", "/api/v1/audit-log"),
    ("POST", f"/api/v1/incidents/{uuid4()}/transitions"),
]


def test_json_api_refuses_anonymous_and_malformed_credentials(api_app: FastAPI) -> None:
    """The API must fail closed on a missing, malformed, or invented bearer token."""

    with _client(api_app) as client:
        for method, path in API_PROTECTED:
            for headers in (
                {},
                {"Authorization": ""},
                {"Authorization": "Bearer"},
                {"Authorization": "Bearer " + "A" * 500},
                {"Authorization": "Bearer wgok_fake.fake"},
                {"Authorization": "Basic YWRtaW46YWRtaW4="},
                {"Authorization": "Bearer ../../etc/passwd"},
            ):
                response = client.request(method, path, headers=headers)
                assert response.status_code in {401, 403}, (
                    f"{path} with {headers} returned {response.status_code}"
                )
                _assert_no_leak(response.text, f"{path} {headers}")


def test_page_size_is_an_allowlist_not_a_free_integer(
    api_app: FastAPI, register_operator: OperatorFactory
) -> None:
    """An unbounded page size would let one click ask for the whole table.

    The dashboard route signature types page_size as a plain int (unlike the
    JSON API, which constrains it with Query(ge=1, le=100)), so the bound has
    to come from DASHBOARD_PAGE_SIZES downstream -- this asserts it actually does.
    """

    operator = register_operator(role=OperatorRole.ADMIN)
    with _client(api_app) as client:
        _login(client, operator.token)

        for rejected in (0, 1, 24, 26, 101, 10_000, 999_999_999, -1, 2**63):
            for path in ("/dashboard/incidents", "/dashboard/servers", "/dashboard/rules"):
                response = client.get(path, params={"page_size": rejected}, follow_redirects=False)
                assert response.status_code != 200, f"{path}?page_size={rejected} was accepted"
                assert response.status_code < 500, (
                    f"{path}?page_size={rejected} produced {response.status_code}"
                )
                _assert_no_leak(response.text, f"{path} page_size={rejected}")

        for allowed in (25, 50, 100):
            response = client.get(
                "/dashboard/incidents", params={"page_size": allowed}, follow_redirects=False
            )
            assert response.status_code == 200, (
                f"page_size={allowed} should be allowed, got {response.status_code}"
            )


def test_openapi_surface_is_withheld_in_production(integration_settings: Settings) -> None:
    """The schema names every endpoint, parameter and error shape in one fetch.

    It stays available outside production because the README points operators at
    /docs; the assertion is that a production build does not hand an anonymous
    caller that map together with the exact version string.
    """

    production = create_app(integration_settings.model_copy(update={"app_env": "production"}))
    with TestClient(production, base_url=ORIGIN, raise_server_exceptions=False) as client:
        for path in ("/openapi.json", "/docs", "/redoc"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 404, (
                f"{path} is anonymously readable in production ({response.status_code})"
            )

    development = create_app(integration_settings.model_copy(update={"app_env": "development"}))
    with TestClient(development, base_url=ORIGIN, raise_server_exceptions=False) as client:
        assert client.get("/openapi.json").status_code == 200, (
            "the documented local /docs workflow was broken"
        )


def test_ingestion_endpoint_rejects_hostile_bodies(api_app: FastAPI) -> None:
    """Ingestion is the only endpoint an unattended agent posts to."""

    with _client(api_app) as client:
        headers = {"Authorization": "Bearer wgak_fake.fake"}
        for body in (
            b"",
            b"not json at all",
            b"{",
            b'{"events": null}',
            b'{"events": []}',
            b'{"events": [' + b'{"a":1},' * 5000 + b"{}]}",
            b'{"schema_version": 999, "events": []}',
            b"\x00\x01\x02",
        ):
            response = client.post(
                "/api/v1/events",
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )
            assert response.status_code < 500, (
                f"ingestion produced {response.status_code} for {body[:40]!r}"
            )
            _assert_no_leak(response.text, f"ingest {body[:40]!r}")
