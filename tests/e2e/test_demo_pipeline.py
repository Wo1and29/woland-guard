from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import SecretStr
from scripts.demo_e2e.backup_restore import (
    DemoBackupError,
    TemporaryBackup,
    create_backup,
    restore_and_verify,
)
from scripts.demo_e2e.contracts import DemoRunIdentity
from scripts.demo_e2e.ownership import ComposeDemoEnvironment
from scripts.demo_e2e.pipeline import (
    DemoProvisioning,
    PipelineExpectations,
    PipelineSnapshot,
    SchemaFingerprint,
    build_all_manifests,
    create_session_factory,
    database_schema_fingerprint,
    database_snapshot,
    deliver_outbox,
    provision_demo,
    send_manifests,
    verify_exact_rules,
    verify_ingestion,
    verify_replay,
)
from scripts.demo_e2e.recovery import RecoveryLedgerStore
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from woland_guard_control_plane.config import Settings

pytestmark = [pytest.mark.e2e, pytest.mark.docker]


@pytest.mark.skipif(
    os.environ.get("WG_RUN_DEMO_E2E") != "1",
    reason="set WG_RUN_DEMO_E2E=1 for the isolated 8B pipeline",
)
def test_all_32_manifests_real_worker_and_replay(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    identity = DemoRunIdentity.create()
    ledger_directory = tmp_path / "ledger"
    ledger_directory.mkdir(mode=0o700)
    ledger = RecoveryLedgerStore.create(ledger_directory / "recovery.json", identity)
    environment = ComposeDemoEnvironment(
        project_root=project_root, identity=identity, ledger=ledger
    )
    engine = None
    backup = None
    try:
        environment.start_foundation()
        environment.verify_schema()
        database = environment.database_configuration()
        session_factory, engine = create_session_factory(database)
        verify_exact_rules(session_factory, project_root)
        provisioning = provision_demo(session_factory, identity)
        origin = environment.start_control_plane()
        manifests = build_all_manifests()
        expectations = PipelineExpectations.from_manifests(manifests)

        first = send_manifests(
            origin=origin,
            credential=provisioning.agent_token,
            manifests=manifests,
        )
        assert sum(summary.accepted for summary in first) == expectations.event_count
        assert sum(summary.duplicates for summary in first) == 0
        verify_ingestion(
            session_factory,
            provisioning=provisioning,
            expectations=expectations,
        )

        delivery = deliver_outbox(
            session_factory,
            settings=Settings(
                app_env="test",
                postgres_host=database.host,
                postgres_port=database.port,
                postgres_db=database.database,
                postgres_user=database.username,
                postgres_password=SecretStr(database.password.reveal()),
                web_public_origin="https://127.0.0.1:8443",
            ),
            provisioning=provisioning,
            expectations=expectations,
        )
        assert delivery.request_count == expectations.outbox_count
        before_replay = database_snapshot(session_factory, provisioning)

        replay = send_manifests(
            origin=origin,
            credential=provisioning.agent_token,
            manifests=manifests,
        )
        assert sum(summary.accepted for summary in replay) == 0
        assert sum(summary.duplicates for summary in replay) == expectations.event_count
        assert (
            verify_replay(
                session_factory,
                provisioning=provisioning,
                expectations=expectations,
                before=before_replay,
            )
            == before_replay
        )
        _create_schema_probe(session_factory)
        schema_fingerprint = database_schema_fingerprint(session_factory)
        environment.stop_control_plane()
        engine.dispose()
        engine = None
        backup = create_backup(environment, forbidden_plaintext=provisioning.secrets)
        restore_and_verify(
            project_root=project_root,
            identity=identity,
            ledger=ledger,
            backup=backup,
            expected_snapshot=before_replay,
            expected_schema=schema_fingerprint,
            provisioning=provisioning,
        )
        _verify_semantic_schema_mutations_are_rejected(
            project_root=project_root,
            identity=identity,
            ledger=ledger,
            backup=backup,
            expected_snapshot=before_replay,
            expected_schema=schema_fingerprint,
            provisioning=provisioning,
        )
    finally:
        if engine is not None:
            engine.dispose()
        if backup is not None:
            backup.cleanup()
        environment.stop()
        if not ledger.ledger.resources and not ledger.ledger.artifacts and ledger.path.exists():
            ledger.finish()


def _verify_semantic_schema_mutations_are_rejected(
    *,
    project_root: Path,
    identity: DemoRunIdentity,
    ledger: RecoveryLedgerStore,
    backup: TemporaryBackup,
    expected_snapshot: PipelineSnapshot,
    expected_schema: SchemaFingerprint,
    provisioning: DemoProvisioning,
) -> None:
    mutations = (
        (_mutate_check_expression, "restore_constraint_semantics"),
        (_mutate_trigger_function, "restore_triggers"),
        (_mutate_partial_index_predicate, "restore_index_predicate"),
    )
    for mutator, expected_phase in mutations:
        with pytest.raises(DemoBackupError) as captured:
            restore_and_verify(
                project_root=project_root,
                identity=identity,
                ledger=ledger,
                backup=backup,
                expected_snapshot=expected_snapshot,
                expected_schema=expected_schema,
                provisioning=provisioning,
                _test_schema_mutator=mutator,
            )
        assert captured.value.phase == expected_phase


def _mutate_check_expression(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as session:
        session.execute(
            text(
                "ALTER TABLE wg8b_schema_probe DROP CONSTRAINT wg8b_schema_probe_check, "
                "ADD CONSTRAINT wg8b_schema_probe_check CHECK (value >= 0)"
            )
        )


def _mutate_trigger_function(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as session:
        session.execute(
            text(
                "CREATE OR REPLACE FUNCTION wg8b_schema_probe_fn() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN NEW.value := NEW.value + 0; RETURN NEW; END $$"
            )
        )


def _mutate_partial_index_predicate(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as session:
        session.execute(text("DROP INDEX wg8b_schema_probe_active_idx"))
        session.execute(
            text(
                "CREATE INDEX wg8b_schema_probe_active_idx ON wg8b_schema_probe (value) "
                "WHERE NOT active"
            )
        )


def _create_schema_probe(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as session:
        session.execute(
            text(
                "CREATE TABLE wg8b_schema_probe ("
                "id integer PRIMARY KEY, value integer NOT NULL, active boolean NOT NULL, "
                "CONSTRAINT wg8b_schema_probe_check CHECK (value > 0))"
            )
        )
        session.execute(
            text(
                "CREATE FUNCTION wg8b_schema_probe_fn() RETURNS trigger LANGUAGE plpgsql "
                "AS $$ BEGIN NEW.value := NEW.value; RETURN NEW; END $$"
            )
        )
        session.execute(
            text(
                "CREATE TRIGGER wg8b_schema_probe_trigger BEFORE INSERT ON wg8b_schema_probe "
                "FOR EACH ROW EXECUTE FUNCTION wg8b_schema_probe_fn()"
            )
        )
        session.execute(
            text(
                "CREATE INDEX wg8b_schema_probe_active_idx ON wg8b_schema_probe (value) "
                "WHERE active"
            )
        )
