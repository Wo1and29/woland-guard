"""Strict validation tests for declarative Detection Engine rules."""

import sys
from pathlib import Path

import pytest

from woland_guard_control_plane import cli
from woland_guard_control_plane.application.detection.rules import (
    DistinctCountCondition,
    FirstSeenCondition,
    RuleKeyValidationError,
    RuleValidationError,
    SequenceCondition,
    SingleCondition,
    ThresholdCondition,
    canonical_rule,
    load_rules_directory,
    rule_checksum,
    validate_rule_key,
)

RULES_DIR = Path(__file__).parents[3] / "detection-rules"


def test_public_rule_key_validator_is_the_rule_definition_contract() -> None:
    assert validate_rule_key("canonical_rule_1") == "canonical_rule_1"
    with pytest.raises(RuleKeyValidationError, match="invalid rule key"):
        validate_rule_key("Non_Canonical")


def test_thirteen_default_rules_are_strict_and_cover_exactly_five_condition_types() -> None:
    """The shipped set has the agreed identities and no executable condition language."""

    rules = load_rules_directory(RULES_DIR)

    assert {rule.rule_key for rule in rules} == {
        "critical_systemd_unit_stopped",
        "cron_job_changed",
        "nginx_error_spike",
        "nginx_failed_requests_by_ip",
        "privileged_group_membership_changed",
        "ssh_bruteforce_by_ip",
        "ssh_login_from_new_ip",
        "ssh_password_spray_by_ip",
        "ssh_root_login_success",
        "ssh_success_after_failures",
        "sudo_auth_failures",
        "system_file_changed",
        "user_account_created",
    }
    assert {type(rule.condition) for rule in rules} == {
        SingleCondition,
        ThresholdCondition,
        DistinctCountCondition,
        SequenceCondition,
        FirstSeenCondition,
    }
    assert all(rule.schema_version == 1 for rule in rules)
    assert all(rule.version > 0 for rule in rules)
    assert all(
        rule.title_en and rule.description_en and rule.explanation_en and rule.recommendation_en
        for rule in rules
    )


def test_rule_checksum_is_stable_sha256_of_canonical_json() -> None:
    """Equivalent validated input produces an immutable 64-character checksum."""

    rule = load_rules_directory(RULES_DIR)[0]
    reconstructed = type(rule).model_validate(canonical_rule(rule))

    assert rule_checksum(rule) == rule_checksum(reconstructed)
    assert len(rule_checksum(rule)) == 64


@pytest.mark.parametrize(
    "invalid_document",
    [
        "schema_version: 1\ncondition:\n  type: arbitrary_expression\n",
        "schema_version: 1\nunexpected_stage5_field: true\n",
        "!!python/object/apply:os.system ['synthetic-command']\n",
        "condition: [not: valid\n",
    ],
    ids=["unknown-condition", "extra-field", "unsafe-yaml-tag", "malformed-yaml"],
)
def test_unknown_extra_unsafe_and_malformed_yaml_are_rejected(
    tmp_path: Path,
    invalid_document: str,
) -> None:
    """Only safe-loadable documents matching the closed Pydantic schema are accepted."""

    (tmp_path / "invalid.yaml").write_text(invalid_document, encoding="utf-8")

    with pytest.raises(RuleValidationError, match="invalid rule file: invalid.yaml"):
        load_rules_directory(tmp_path)


def test_all_files_are_validated_before_callers_can_sync_any_rule(tmp_path: Path) -> None:
    """One malformed member prevents returning a partially valid rule set."""

    valid = (RULES_DIR / "ssh_root_login_success.yaml").read_text(encoding="utf-8")
    (tmp_path / "01-valid.yaml").write_text(valid, encoding="utf-8")
    (tmp_path / "02-invalid.yaml").write_text("condition: {type: unknown}\n", encoding="utf-8")

    with pytest.raises(RuleValidationError, match="02-invalid.yaml"):
        load_rules_directory(tmp_path)


def test_two_versions_of_same_rule_key_in_one_directory_are_rejected(tmp_path: Path) -> None:
    """A deployment set contains at most one requested version for each stable rule key."""

    shipped = (RULES_DIR / "ssh_root_login_success.yaml").read_text(encoding="utf-8")
    current = next(line for line in shipped.splitlines() if line.startswith("version: "))
    successor = f"version: {int(current.removeprefix('version: ')) + 1}"
    (tmp_path / "root-current.yaml").write_text(shipped, encoding="utf-8")
    (tmp_path / "root-next.yaml").write_text(
        shipped.replace(f"\n{current}\n", f"\n{successor}\n", 1), encoding="utf-8"
    )

    with pytest.raises(RuleValidationError, match="duplicate rule keys"):
        load_rules_directory(tmp_path)


@pytest.mark.parametrize(
    "field",
    ["title_en", "description_en", "explanation_en", "recommendation_en"],
)
def test_rule_file_without_english_prose_is_rejected(tmp_path: Path, field: str) -> None:
    """A rule may not ship untranslated: the Dashboard renders it in both languages."""

    shipped = (RULES_DIR / "ssh_root_login_success.yaml").read_text(encoding="utf-8")
    without_translation = "\n".join(
        line for line in shipped.splitlines() if not line.startswith(f"{field}: ")
    )
    (tmp_path / "untranslated.yaml").write_text(without_translation + "\n", encoding="utf-8")

    with pytest.raises(RuleValidationError, match="missing English prose"):
        load_rules_directory(tmp_path)


def test_missing_or_empty_rules_directory_is_rejected(tmp_path: Path) -> None:
    """An absent configuration is not silently treated as zero active rules."""

    with pytest.raises(RuleValidationError, match="contains no YAML"):
        load_rules_directory(tmp_path)
    with pytest.raises(RuleValidationError, match="unavailable"):
        load_rules_directory(tmp_path / "missing")


def test_validate_rules_cli_checks_files_without_opening_database(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The validation command succeeds without constructing a PostgreSQL session."""

    monkeypatch.setattr(
        sys, "argv", ["woland-guard-admin", "validate-rules", "--rules-dir", str(RULES_DIR)]
    )
    monkeypatch.setattr(
        cli,
        "get_session_factory",
        lambda: (_ for _ in ()).throw(AssertionError("database must not be opened")),
    )

    cli.main()

    assert capsys.readouterr().out == "Правила корректны: 13\n"


def test_validate_rules_cli_returns_safe_error_for_invalid_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI error output contains no YAML body or arbitrary source content."""

    marker = "synthetic-sensitive-marker"
    (tmp_path / "bad.yaml").write_text(f"condition: [{marker}\n", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["woland-guard-admin", "validate-rules", "--rules-dir", str(tmp_path)]
    )

    with pytest.raises(SystemExit) as raised:
        cli.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert "Набор правил не прошёл строгую проверку." in captured.err
    assert marker not in captured.err
