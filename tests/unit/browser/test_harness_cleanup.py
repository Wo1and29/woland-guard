from __future__ import annotations

import secrets
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any, cast

import pytest
import tests.browser.conftest as browser_fixtures
import tests.browser.harness as harness_module
from tests.browser.harness import (
    ApplicationProcess,
    BrowserEnvironment,
    BrowserHarnessError,
    EphemeralDatabaseConfiguration,
    EphemeralPostgres,
    TemporaryTlsMaterial,
)

_CONTAINER_ID = "a" * 64
_SECOND_CONTAINER_ID = "b" * 64
_RUN_ID = "0123456789abcdef"
_CONTAINER_NAME = f"wg-browser-postgres-{_RUN_ID}"
_OWNERSHIP_LABEL = f"browser-{_RUN_ID}"
_OWNERSHIP_LABEL_KEY = "woland-guard.test-scope"


class _FakeDockerRunner:
    def __init__(
        self,
        *,
        run_output: str = _CONTAINER_ID,
        run_error: bool = False,
        create_on_run: bool = False,
        appear_on_lookup: int | None = None,
        recovery_output: str | None = None,
        removal_fails: bool = False,
    ) -> None:
        self.run_output = run_output
        self.run_error = run_error
        self.create_on_run = create_on_run
        self.appear_on_lookup = appear_on_lookup
        self.recovery_output = recovery_output
        self.removal_fails = removal_fails
        self.containers: dict[str, tuple[str, str]] = {}
        self.calls: list[tuple[str, ...]] = []
        self.deleted_ids: list[str] = []
        self.ownership_lookup_count = 0

    def add_container(self, container_id: str, *, name: str, label: str) -> None:
        self.containers[container_id] = (name, label)

    def __call__(
        self,
        arguments: list[str],
        *,
        timeout_seconds: float,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> str:
        del timeout_seconds, cwd, environment
        self.calls.append(tuple(arguments))
        command = arguments[1]
        if command == "run":
            name = arguments[arguments.index("--name") + 1]
            label_argument = arguments[arguments.index("--label") + 1]
            label_key, label = label_argument.split("=", maxsplit=1)
            assert name == _CONTAINER_NAME
            assert label_key == _OWNERSHIP_LABEL_KEY
            assert label == _OWNERSHIP_LABEL
            if self.create_on_run:
                self.add_container(_CONTAINER_ID, name=name, label=label)
            if self.run_error:
                raise BrowserHarnessError("canary command failure")
            return self.run_output
        if command == "ps":
            filters = [
                arguments[index + 1] for index, value in enumerate(arguments) if value == "--filter"
            ]
            id_filter = next((value[3:] for value in filters if value.startswith("id=")), None)
            if id_filter is not None:
                return f"{id_filter}\n" if id_filter in self.containers else ""

            self.ownership_lookup_count += 1
            if self.appear_on_lookup == self.ownership_lookup_count:
                self.add_container(
                    _CONTAINER_ID,
                    name=_CONTAINER_NAME,
                    label=_OWNERSHIP_LABEL,
                )
            if self.recovery_output is not None:
                return self.recovery_output
            expected_name = f"name=^/{_CONTAINER_NAME}$"
            expected_label = f"label={_OWNERSHIP_LABEL_KEY}={_OWNERSHIP_LABEL}"
            assert filters == [expected_name, expected_label]
            matches = [
                container_id
                for container_id, (name, label) in self.containers.items()
                if name == _CONTAINER_NAME and label == _OWNERSHIP_LABEL
            ]
            return "".join(f"{container_id}\n" for container_id in matches)
        if command == "inspect":
            container_id = arguments[-1]
            name, label = self.containers[container_id]
            return f"{container_id}|/{name}|{label}\n"
        if command in {"stop", "rm"}:
            container_id = arguments[-1]
            self.deleted_ids.append(container_id)
            if self.removal_fails:
                raise BrowserHarnessError("canary removal failure")
            self.containers.pop(container_id, None)
            return ""
        raise AssertionError("unexpected fake Docker command")


def _start_postgres_with_runner(
    monkeypatch: pytest.MonkeyPatch,
    runner: _FakeDockerRunner,
) -> tuple[EphemeralPostgres, BrowserHarnessError]:
    monkeypatch.setattr(harness_module, "_run_command", runner)
    monkeypatch.setattr(
        "tests.browser.harness.secrets.token_hex",
        lambda _: _RUN_ID,
    )
    monkeypatch.setattr(
        "tests.browser.harness.secrets.token_urlsafe",
        lambda _: "browser-credential-canary",
    )
    monkeypatch.setattr("tests.browser.harness.time.sleep", lambda _: None)
    postgres = EphemeralPostgres()
    with pytest.raises(BrowserHarnessError) as captured:
        postgres.start()
    return postgres, captured.value


def _assert_only_exact_ownership_lookups(runner: _FakeDockerRunner) -> None:
    ownership_lookups = [
        call
        for call in runner.calls
        if call[1] == "ps" and not any(value.startswith("id=") for value in call)
    ]
    assert ownership_lookups
    for call in ownership_lookups:
        filters = [call[index + 1] for index, value in enumerate(call) if value == "--filter"]
        assert filters == [
            f"name=^/{_CONTAINER_NAME}$",
            f"label={_OWNERSHIP_LABEL_KEY}={_OWNERSHIP_LABEL}",
        ]


def test_failed_docker_run_recovers_and_removes_exact_owned_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(run_error=True, create_on_run=True)

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL failed to start"
    assert "canary" not in str(error)
    assert _CONTAINER_ID in runner.deleted_ids
    assert runner.containers == {}
    assert cast(Any, postgres)._container_id is None
    assert cast(Any, postgres)._container_name is None
    assert cast(Any, postgres)._ownership_label is None
    _assert_only_exact_ownership_lookups(runner)


def test_malformed_docker_run_output_recovers_owned_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(run_output="malformed-output", create_on_run=True)

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL failed to start"
    assert _CONTAINER_ID in runner.deleted_ids
    assert runner.containers == {}
    assert cast(Any, postgres)._container_id is None
    _assert_only_exact_ownership_lookups(runner)


def test_recovery_does_not_remove_same_name_with_different_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(run_error=True)
    runner.add_container(
        _SECOND_CONTAINER_ID,
        name=_CONTAINER_NAME,
        label="foreign-owner",
    )

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL failed to start"
    assert runner.deleted_ids == []
    assert _SECOND_CONTAINER_ID in runner.containers
    assert cast(Any, postgres)._container_name is None
    _assert_only_exact_ownership_lookups(runner)


def test_recovery_does_not_remove_same_label_with_different_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(run_error=True)
    runner.add_container(
        _SECOND_CONTAINER_ID,
        name=f"{_CONTAINER_NAME}-foreign",
        label=_OWNERSHIP_LABEL,
    )

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL failed to start"
    assert runner.deleted_ids == []
    assert _SECOND_CONTAINER_ID in runner.containers
    assert cast(Any, postgres)._ownership_label is None
    _assert_only_exact_ownership_lookups(runner)


@pytest.mark.parametrize(
    "recovery_output",
    [
        f"{_CONTAINER_ID}\n{_SECOND_CONTAINER_ID}\n",
        "not-a-container-id\n",
    ],
    ids=["multiple", "invalid"],
)
def test_ambiguous_or_invalid_recovery_result_never_deletes(
    monkeypatch: pytest.MonkeyPatch,
    recovery_output: str,
) -> None:
    runner = _FakeDockerRunner(run_error=True, recovery_output=recovery_output)

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL recovery cleanup failed"
    assert runner.deleted_ids == []
    assert cast(Any, postgres)._container_name == _CONTAINER_NAME
    assert cast(Any, postgres)._ownership_label == _OWNERSHIP_LABEL
    _assert_only_exact_ownership_lookups(runner)


def test_recovery_finds_container_on_later_bounded_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(run_error=True, appear_on_lookup=3)

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL failed to start"
    assert runner.ownership_lookup_count == 3
    assert _CONTAINER_ID in runner.deleted_ids
    assert runner.containers == {}
    assert cast(Any, postgres)._container_id is None
    _assert_only_exact_ownership_lookups(runner)


def test_recovery_deadline_without_container_clears_identity_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(run_error=True)

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL failed to start"
    assert "credential" not in str(error)
    assert runner.ownership_lookup_count > 1
    assert runner.deleted_ids == []
    assert cast(Any, postgres)._container_name is None
    assert cast(Any, postgres)._ownership_label is None
    assert "credential" not in repr(postgres)
    _assert_only_exact_ownership_lookups(runner)


def test_failed_recovered_container_removal_retains_exact_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _FakeDockerRunner(
        run_error=True,
        create_on_run=True,
        removal_fails=True,
    )

    postgres, error = _start_postgres_with_runner(monkeypatch, runner)

    assert str(error) == "browser PostgreSQL recovery cleanup failed"
    assert "canary" not in str(error)
    assert runner.containers == {
        _CONTAINER_ID: (_CONTAINER_NAME, _OWNERSHIP_LABEL),
    }
    assert cast(Any, postgres)._container_id == _CONTAINER_ID
    assert cast(Any, postgres)._container_name == _CONTAINER_NAME
    assert cast(Any, postgres)._ownership_label == _OWNERSHIP_LABEL
    _assert_only_exact_ownership_lookups(runner)


class _StubbornProcess:
    def __init__(self, *, survives_kill: bool = False) -> None:
        self.alive = True
        self.survives_kill = survives_kill
        self.calls: list[str] = []

    def join(self, timeout: float | None = None) -> None:
        self.calls.append(f"join:{timeout}")

    def is_alive(self) -> bool:
        self.calls.append("is_alive")
        return self.alive

    def terminate(self) -> None:
        self.calls.append("terminate")

    def kill(self) -> None:
        self.calls.append("kill")
        if not self.survives_kill:
            self.alive = False

    def close(self) -> None:
        self.calls.append("close")


class _FailingResource:
    def __init__(self, name: str, calls: list[str]) -> None:
        self.name = name
        self.calls = calls

    def stop(self) -> None:
        self.calls.append(self.name)
        raise BrowserHarnessError("canary cleanup detail")


def _application_process() -> ApplicationProcess:
    return ApplicationProcess(
        database=EphemeralDatabaseConfiguration(
            host="127.0.0.1",
            port=5432,
            database="synthetic",
            username="synthetic",
            password=secrets.token_urlsafe(32),
        ),
        tls=TemporaryTlsMaterial(),
        shutdown_timeout_seconds=0.01,
    )


def test_postgres_cleanup_refuses_to_forget_unverified_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    postgres = EphemeralPostgres()
    cast(Any, postgres)._container_id = _CONTAINER_ID

    def fail_commands(
        arguments: list[str],
        *,
        timeout_seconds: float,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> str:
        del timeout_seconds, cwd, environment
        if arguments[1] == "ps":
            return f"{_CONTAINER_ID}\n"
        raise BrowserHarnessError("canary docker detail")

    monkeypatch.setattr(harness_module, "_run_command", fail_commands)

    with pytest.raises(BrowserHarnessError, match="browser PostgreSQL cleanup failed") as captured:
        postgres.stop()

    assert "canary" not in str(captured.value)
    assert cast(Any, postgres)._container_id == _CONTAINER_ID


def test_postgres_cleanup_force_removes_and_verifies_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    postgres = EphemeralPostgres()
    cast(Any, postgres)._container_id = _CONTAINER_ID
    verification_count = 0
    calls: list[tuple[str, ...]] = []

    def simulate_commands(
        arguments: list[str],
        *,
        timeout_seconds: float,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> str:
        nonlocal verification_count
        del timeout_seconds, cwd, environment
        calls.append(tuple(arguments))
        if arguments[1] == "stop":
            raise BrowserHarnessError("synthetic stop failure")
        if arguments[1] == "ps":
            verification_count += 1
            return f"{_CONTAINER_ID}\n" if verification_count == 1 else ""
        if arguments[1] == "rm":
            return ""
        raise AssertionError("unexpected harness command")

    monkeypatch.setattr(harness_module, "_run_command", simulate_commands)

    postgres.stop()

    assert cast(Any, postgres)._container_id is None
    assert any(command[1:3] == ("rm", "--force") for command in calls)
    assert verification_count == 2


def test_application_process_escalates_from_terminate_to_kill() -> None:
    application = _application_process()
    process = _StubbornProcess()
    cast(Any, application)._process = process

    application.stop()

    assert "terminate" in process.calls
    assert "kill" in process.calls
    assert "close" in process.calls
    assert process.calls.index("terminate") < process.calls.index("kill")


def test_application_process_refuses_to_forget_process_that_survives_kill() -> None:
    application = _application_process()
    process = _StubbornProcess(survives_kill=True)
    cast(Any, application)._process = process

    with pytest.raises(BrowserHarnessError, match="browser application cleanup failed"):
        application.stop()

    assert "terminate" in process.calls
    assert "kill" in process.calls
    assert cast(Any, application)._process is process


def test_browser_environment_attempts_every_cleanup_after_failures(tmp_path: Path) -> None:
    calls: list[str] = []
    environment = BrowserEnvironment(tmp_path)
    cast(Any, environment).application = _FailingResource("application", calls)
    cast(Any, environment).tls = _FailingResource("tls", calls)
    cast(Any, environment).postgres = _FailingResource("postgres", calls)

    with pytest.raises(BrowserHarnessError, match="browser environment cleanup failed") as captured:
        environment.stop()

    assert calls == ["application", "tls", "postgres"]
    assert "canary" not in str(captured.value)


def test_browser_environment_fixture_stops_when_test_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class FakeEnvironment:
        def start(self) -> FakeEnvironment:
            calls.append("start")
            return self

        def stop(self) -> None:
            calls.append("stop")

    fake = FakeEnvironment()
    monkeypatch.setattr(browser_fixtures, "BrowserEnvironment", lambda _: fake)
    fixture = cast(
        Callable[[Path], Generator[Any, None, None]],
        cast(Any, browser_fixtures.browser_environment).__wrapped__,
    )
    generator = fixture(tmp_path)
    assert next(generator) is fake

    with pytest.raises(RuntimeError, match="synthetic test failure"):
        generator.throw(RuntimeError("synthetic test failure"))

    assert calls == ["start", "stop"]


def test_browser_environment_fixture_stops_when_start_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class FakeEnvironment:
        def start(self) -> FakeEnvironment:
            calls.append("start")
            raise BrowserHarnessError("synthetic start failure")

        def stop(self) -> None:
            calls.append("stop")

    monkeypatch.setattr(browser_fixtures, "BrowserEnvironment", lambda _: FakeEnvironment())
    fixture = cast(
        Callable[[Path], Generator[Any, None, None]],
        cast(Any, browser_fixtures.browser_environment).__wrapped__,
    )

    with pytest.raises(BrowserHarnessError, match="synthetic start failure"):
        next(fixture(tmp_path))

    assert calls == ["start", "stop"]


def test_browser_artifact_fixture_removes_empty_directory_when_test_raises(
    tmp_path: Path,
) -> None:
    fixture = cast(
        Callable[[Path], Generator[Path, None, None]],
        cast(Any, browser_fixtures.browser_artifact_root).__wrapped__,
    )
    generator = fixture(tmp_path)
    artifact_root = next(generator)
    assert artifact_root.is_dir()

    with pytest.raises(RuntimeError, match="synthetic test failure"):
        generator.throw(RuntimeError("synthetic test failure"))

    assert not artifact_root.exists()


def test_chromium_fixture_closes_browser_and_playwright_when_test_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeBrowser:
        def close(self) -> None:
            calls.append("browser.close")

    class FakeChromium:
        def launch(self, *, channel: str, headless: bool) -> FakeBrowser:
            assert channel == "chromium"
            assert headless is True
            calls.append("chromium.launch")
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

        def stop(self) -> None:
            calls.append("playwright.stop")

    class FakeManager:
        def start(self) -> FakePlaywright:
            calls.append("playwright.start")
            return FakePlaywright()

    monkeypatch.setattr(browser_fixtures, "sync_playwright", FakeManager)
    fixture = cast(
        Callable[[], Generator[Any, None, None]],
        cast(Any, browser_fixtures.chromium_browser).__wrapped__,
    )
    generator = fixture()
    next(generator)

    with pytest.raises(RuntimeError, match="synthetic test failure"):
        generator.throw(RuntimeError("synthetic test failure"))

    assert calls == [
        "playwright.start",
        "chromium.launch",
        "browser.close",
        "playwright.stop",
    ]


def test_browser_page_fixture_checks_guard_and_closes_context_when_test_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeContext:
        def set_default_timeout(self, value: int) -> None:
            assert value == 5_000

        def set_default_navigation_timeout(self, value: int) -> None:
            assert value == 10_000

        def new_page(self) -> object:
            calls.append("new_page")
            return object()

        def close(self) -> None:
            calls.append("context.close")

    context = FakeContext()

    class FakeBrowser:
        def new_context(self, **kwargs: object) -> FakeContext:
            assert kwargs["service_workers"] == "block"
            return context

    class FakeEnvironment:
        origin = "https://127.0.0.1:4443"

    class FakeGuard:
        def __init__(self, origin: str) -> None:
            assert origin == FakeEnvironment.origin

        def install(self, supplied_context: object) -> None:
            assert supplied_context is context

        def attach_page(self, page: object) -> None:
            assert page is not None

        def assert_clean(self) -> None:
            calls.append("guard.assert_clean")

    monkeypatch.setattr(browser_fixtures, "PageRequestGuard", FakeGuard)
    fixture = cast(
        Callable[[Any, Any, None], Generator[Any, None, None]],
        cast(Any, browser_fixtures.browser_page).__wrapped__,
    )
    generator = fixture(FakeBrowser(), FakeEnvironment(), None)
    next(generator)

    with pytest.raises(RuntimeError, match="synthetic test failure"):
        generator.throw(RuntimeError("synthetic test failure"))

    assert calls == ["new_page", "guard.assert_clean", "context.close"]


def test_browser_security_audit_runs_when_test_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class FakeSeed:
        secrets: tuple[object, ...] = ()

    def fake_audit(root: Path, secrets: object) -> None:
        assert root == tmp_path
        assert secrets == ()
        calls.append("audit")

    monkeypatch.setattr(browser_fixtures, "audit_browser_artifacts", fake_audit)
    fixture = cast(
        Callable[[Path, Any], Generator[None, None, None]],
        cast(Any, browser_fixtures.browser_security_audit).__wrapped__,
    )
    generator = fixture(tmp_path, FakeSeed())
    next(generator)

    with pytest.raises(RuntimeError, match="synthetic test failure"):
        generator.throw(RuntimeError("synthetic test failure"))

    assert calls == ["audit"]
