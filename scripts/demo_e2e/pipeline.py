"""Application-service provisioning, canonical ingestion and exact DB verification."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import SecretStr
from sqlalchemy import URL, Engine, create_engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from scripts.demo_e2e.contracts import (
    DemoDatabaseConfiguration,
    DemoE2EError,
    DemoRunIdentity,
    SecretValue,
)
from scripts.demo_e2e.fake_delivery import (
    DEMO_TOKEN_FILE_NAME,
    DemoDeliveryEvidence,
    assert_production_origin_unchanged,
    build_demo_worker,
)
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.notification_destinations import (
    create_telegram_destination,
    set_notification_destination_enabled,
)
from woland_guard_control_plane.application.operators import (
    create_operator,
    issue_operator_api_key,
)
from woland_guard_control_plane.application.provisioning import provision_test_server
from woland_guard_control_plane.config import Settings
from woland_guard_control_plane.demo.client import (
    DemoApiCredential,
    DemoIngestionClient,
    DemoOrigin,
    DemoSendSummary,
)
from woland_guard_control_plane.demo.contracts import DemoManifest
from woland_guard_control_plane.demo.scenarios import (
    EXPECTED_RULE_KEYS,
    build_manifest,
    list_scenarios,
    validate_catalog_manifest,
)
from woland_guard_control_plane.infrastructure.database.models import (
    AuditLogEntry,
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentComment,
    IncidentEvent,
    IncidentHistoryEntry,
    NotificationSeverity,
    Operator,
    OperatorRole,
    OperatorWebSession,
    OutboxMessage,
    OutboxStatus,
    Server,
)


class DemoPipelineError(DemoE2EError):
    """A full-stack persistence invariant did not match the canonical catalog."""


HUMAN_DEMO_SCENARIO_IDS = ("ssh_success_after_failures.positive.v1",)


@dataclass(frozen=True, slots=True)
class DemoOperatorCredential:
    operator_id: UUID
    username: str
    role: OperatorRole
    token: SecretValue = field(repr=False)


@dataclass(frozen=True, slots=True)
class DemoProvisioning:
    server_id: UUID
    agent_token: SecretValue = field(repr=False)
    analyst: DemoOperatorCredential = field(repr=False)
    admin: DemoOperatorCredential = field(repr=False)
    viewer: DemoOperatorCredential = field(repr=False)
    destination_id: UUID
    telegram_token: SecretValue = field(repr=False)

    @property
    def secrets(self) -> tuple[str, ...]:
        return (
            self.agent_token.reveal(),
            self.analyst.token.reveal(),
            self.admin.token.reveal(),
            self.viewer.token.reveal(),
            self.telegram_token.reveal(),
        )


@dataclass(frozen=True, slots=True)
class PipelineExpectations:
    event_count: int
    incidents: tuple[tuple[str, str, str, int], ...]
    evidence_count: int
    initial_history_count: int
    outbox_count: int

    @classmethod
    def from_manifests(cls, manifests: tuple[DemoManifest, ...]) -> PipelineExpectations:
        validated = tuple(validate_catalog_manifest(manifest) for manifest in manifests)
        incidents = tuple(
            (
                incident.rule_key,
                incident.severity.value,
                incident.title,
                incident.evidence_links,
            )
            for manifest in validated
            for incident in manifest.expected_outcomes.incidents
        )
        return cls(
            event_count=sum(len(manifest.events) for manifest in validated),
            incidents=incidents,
            evidence_count=sum(
                manifest.expected_outcomes.evidence_link_count for manifest in validated
            ),
            initial_history_count=sum(
                manifest.expected_outcomes.new_incident_count for manifest in validated
            ),
            outbox_count=sum(
                manifest.expected_outcomes.outbox_count_delta for manifest in validated
            ),
        )


@dataclass(frozen=True, slots=True)
class PipelineSnapshot:
    events: int
    incidents: int
    evidence: int
    history: int
    comments: int
    outbox: int
    delivered: int
    failed: int
    pending: int
    processing: int
    audit: int
    active_sessions: int


@dataclass(frozen=True, slots=True)
class SchemaFingerprint:
    constraints: tuple[tuple[str, ...], ...]
    triggers: tuple[tuple[str, ...], ...]
    indexes: tuple[tuple[str, ...], ...]


def create_session_factory(
    configuration: DemoDatabaseConfiguration,
) -> tuple[sessionmaker[Session], Engine]:
    engine = create_engine(
        URL.create(
            drivername="postgresql+psycopg",
            username=configuration.username,
            password=configuration.password.reveal(),
            host=configuration.host,
            port=configuration.port,
            database=configuration.database,
        ),
        pool_pre_ping=True,
        connect_args={"connect_timeout": 3},
    )
    return sessionmaker(bind=engine, expire_on_commit=False), engine


def build_worker_settings(configuration: DemoDatabaseConfiguration) -> Settings:
    return Settings(
        app_env="test",
        postgres_host=configuration.host,
        postgres_port=configuration.port,
        postgres_db=configuration.database,
        postgres_user=configuration.username,
        postgres_password=SecretStr(configuration.password.reveal()),
        web_public_origin="https://127.0.0.1:8443",
    )


def verify_exact_rules(session_factory: sessionmaker[Session], project_root: Path) -> None:
    shipped = load_rules_directory(project_root / "detection-rules")
    # Versions are derived from the files, never pinned to a literal: a prose-only
    # rule bump must not silently break the demo stand.
    expected = {rule.rule_key: rule.version for rule in shipped if rule.enabled}
    if len(shipped) != 8 or frozenset(expected) != EXPECTED_RULE_KEYS:
        raise DemoPipelineError("shipped demo rule catalog is not the expected enabled set")
    with session_factory() as session:
        rows = session.execute(
            select(
                DetectionRuleVersion.rule_key,
                DetectionRuleVersion.version,
                DetectionRuleVersion.enabled,
            ).where(DetectionRuleVersion.is_active.is_(True))
        ).all()
    actual = {rule_key: version for rule_key, version, enabled in rows if enabled}
    if len(rows) != 8 or actual != expected:
        raise DemoPipelineError("database active rule catalog does not match the shipped files")


def provision_demo(
    session_factory: sessionmaker[Session], identity: DemoRunIdentity
) -> DemoProvisioning:
    suffix = identity.run_id[:8]
    telegram_token = SecretValue(f"synthetic-demo-{uuid4().hex}")
    with session_factory.begin() as session:
        agent = provision_test_server(
            session,
            name=f"Synthetic demo {suffix}",
            hostname=f"demo-{suffix}.invalid",
            label="synthetic-8b",
        )
        analyst = _create_demo_operator(session, role=OperatorRole.ANALYST, suffix=suffix)
        admin = _create_demo_operator(session, role=OperatorRole.ADMIN, suffix=suffix)
        viewer = _create_demo_operator(session, role=OperatorRole.VIEWER, suffix=suffix)
        destination = create_telegram_destination(
            session,
            chat_id=-1_001_234_567_890,
            token_file_name=DEMO_TOKEN_FILE_NAME,
            minimum_severity=NotificationSeverity.LOW,
            staging_readiness=lambda name: name == DEMO_TOKEN_FILE_NAME,
        )
        enabled = set_notification_destination_enabled(
            session,
            destination_id=destination.destination_id,
            enabled=True,
            staging_readiness=lambda name: name == DEMO_TOKEN_FILE_NAME,
        )
        if not enabled.enabled:
            raise DemoPipelineError("synthetic notification destination was not enabled")
    return DemoProvisioning(
        server_id=agent.server_id,
        agent_token=SecretValue(agent.token),
        analyst=analyst,
        admin=admin,
        viewer=viewer,
        destination_id=destination.destination_id,
        telegram_token=telegram_token,
    )


def build_all_manifests(*, anchor_utc: datetime | None = None) -> tuple[DemoManifest, ...]:
    anchor = (anchor_utc or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    run_id = uuid4()
    definitions = list_scenarios()
    if len(definitions) != 52:
        raise DemoPipelineError("demo catalog does not contain exactly 52 scenarios")
    return tuple(
        validate_catalog_manifest(
            build_manifest(definition.scenario_id, run_id=run_id, anchor_utc=anchor)
        )
        for definition in definitions
    )


def build_human_manifests(*, anchor_utc: datetime | None = None) -> tuple[DemoManifest, ...]:
    anchor = (anchor_utc or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    run_id = uuid4()
    return tuple(
        validate_catalog_manifest(build_manifest(scenario_id, run_id=run_id, anchor_utc=anchor))
        for scenario_id in HUMAN_DEMO_SCENARIO_IDS
    )


def send_manifests(
    *,
    origin: str,
    credential: SecretValue,
    manifests: tuple[DemoManifest, ...],
) -> tuple[DemoSendSummary, ...]:
    with DemoIngestionClient(
        origin=DemoOrigin(origin),
        credential=DemoApiCredential(credential.reveal()),
    ) as client:
        return tuple(client.send(validate_catalog_manifest(manifest)) for manifest in manifests)


def verify_ingestion(
    session_factory: sessionmaker[Session],
    *,
    provisioning: DemoProvisioning,
    expectations: PipelineExpectations,
) -> PipelineSnapshot:
    _verify_incident_set(
        session_factory,
        provisioning=provisioning,
        expectations=expectations,
    )
    with session_factory() as session:
        incident_ids = tuple(
            session.scalars(select(Incident.id).where(Incident.server_id == provisioning.server_id))
        )
        snapshot = _snapshot(session, provisioning.server_id, incident_ids)
    if (
        snapshot.events != expectations.event_count
        or snapshot.incidents != len(expectations.incidents)
        or snapshot.evidence != expectations.evidence_count
        or snapshot.history != expectations.initial_history_count
        or snapshot.outbox != expectations.outbox_count
        or snapshot.delivered != 0
        or snapshot.failed != 0
        or snapshot.pending != expectations.outbox_count
        or snapshot.processing != 0
    ):
        raise DemoPipelineError("ingestion persistence totals did not match expectations")
    return snapshot


def deliver_outbox(
    session_factory: sessionmaker[Session],
    *,
    settings: Settings,
    provisioning: DemoProvisioning,
    expectations: PipelineExpectations,
) -> DemoDeliveryEvidence:
    assert_production_origin_unchanged()
    worker, transport = build_demo_worker(
        session_factory=session_factory,
        settings=settings,
        token=provisioning.telegram_token,
    )
    result = worker.run_once(limit=100)
    if (
        result.processed != expectations.outbox_count
        or result.delivered != expectations.outbox_count
        or result.deferred
        or result.failed
        or result.lease_lost
    ):
        raise DemoPipelineError("outbox worker did not deliver the exact expected set")
    evidence = transport.evidence
    if evidence.request_count != expectations.outbox_count:
        raise DemoPipelineError("fake delivery evidence did not match expected outbox rows")
    with session_factory() as session:
        rows = tuple(session.scalars(select(OutboxMessage).order_by(OutboxMessage.id)))
        if len(rows) != expectations.outbox_count or any(
            row.status != OutboxStatus.DELIVERED.value
            or row.attempt_count != 1
            or row.delivered_at is None
            or row.failed_at is not None
            or row.claim_token is not None
            or row.claimed_at is not None
            or row.lease_expires_at is not None
            or row.last_error_code is not None
            or row.last_error is not None
            for row in rows
        ):
            raise DemoPipelineError("delivered outbox lifecycle is invalid")
    return evidence


def verify_replay(
    session_factory: sessionmaker[Session],
    *,
    provisioning: DemoProvisioning,
    expectations: PipelineExpectations,
    before: PipelineSnapshot,
) -> PipelineSnapshot:
    _verify_incident_set(
        session_factory,
        provisioning=provisioning,
        expectations=expectations,
    )
    after = database_snapshot(session_factory, provisioning)
    if after != before:
        raise DemoPipelineError("manifest replay changed persisted business rows")
    return after


def database_snapshot(
    session_factory: sessionmaker[Session], provisioning: DemoProvisioning
) -> PipelineSnapshot:
    with session_factory() as session:
        incident_ids = tuple(
            session.scalars(select(Incident.id).where(Incident.server_id == provisioning.server_id))
        )
        return _snapshot(session, provisioning.server_id, incident_ids)


_CAST_PATTERN = re.compile(r"::\s*[A-Za-z_][A-Za-z0-9_ ]*(\[\])?")
_LITERAL_PARENS_PATTERN = re.compile(r"\('([^']*)'\)")
_REDUNDANT_DOUBLE_PARENS_PATTERN = re.compile(r"\(\(([^()]*)\)\)")


def _normalize_pg_expression_text(expression: str) -> str:
    """Collapse PostgreSQL's non-deterministic cast placement for array literals.

    ``pg_get_constraintdef``/``pg_get_expr`` print an ``= ANY (ARRAY[...])`` comparison
    against a live catalog as one array-wide cast, but print the identical expression
    re-parsed from a ``pg_dump`` custom-format backup with a per-element cast instead.
    Both forms are the same CHECK/predicate; only the cast placement differs.
    """

    normalized = _CAST_PATTERN.sub("", expression)
    previous = None
    while previous != normalized:
        previous = normalized
        normalized = _LITERAL_PARENS_PATTERN.sub(r"'\1'", normalized)
        normalized = _REDUNDANT_DOUBLE_PARENS_PATTERN.sub(r"(\1)", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def database_schema_fingerprint(
    session_factory: sessionmaker[Session],
) -> SchemaFingerprint:
    with session_factory() as session:
        constraints = session.execute(
            text(
                """
                SELECT c.relname, con.conname, con.contype::text,
                       con.condeferrable::text, con.condeferred::text,
                       con.convalidated::text, con.connoinherit::text,
                       COALESCE(
                           ARRAY(
                               SELECT attribute.attname
                               FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum, ordinal)
                               JOIN pg_attribute AS attribute
                                 ON attribute.attrelid = con.conrelid
                                AND attribute.attnum = key.attnum
                               ORDER BY key.ordinal
                           )::text,
                           ''
                       ),
                       COALESCE(referenced.relname, ''),
                       COALESCE(
                           ARRAY(
                               SELECT attribute.attname
                               FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum, ordinal)
                               JOIN pg_attribute AS attribute
                                 ON attribute.attrelid = con.confrelid
                                AND attribute.attnum = key.attnum
                               ORDER BY key.ordinal
                           )::text,
                           ''
                       ),
                       con.confupdtype::text, con.confdeltype::text,
                       con.confmatchtype::text,
                       regexp_replace(
                           pg_get_constraintdef(con.oid, true), '\\s+', ' ', 'g'
                       )
                FROM pg_constraint AS con
                JOIN pg_class AS c ON c.oid = con.conrelid
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                LEFT JOIN pg_class AS referenced ON referenced.oid = con.confrelid
                WHERE n.nspname = 'public'
                ORDER BY c.relname, con.conname
                """
            )
        ).all()
        triggers = session.execute(
            text(
                """
                SELECT c.relname, t.tgname, t.tgtype::text, t.tgenabled::text,
                       function_namespace.nspname, function_data.proname,
                       language.lanname, function_data.provolatile::text,
                       function_data.proparallel::text, function_data.prosecdef::text,
                       function_data.proleakproof::text, function_data.proisstrict::text,
                       regexp_replace(function_data.prosrc, '\\s+', ' ', 'g'),
                       regexp_replace(pg_get_triggerdef(t.oid, true), '\\s+', ' ', 'g')
                FROM pg_trigger AS t
                JOIN pg_class AS c ON c.oid = t.tgrelid
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_proc AS function_data ON function_data.oid = t.tgfoid
                JOIN pg_namespace AS function_namespace
                  ON function_namespace.oid = function_data.pronamespace
                JOIN pg_language AS language ON language.oid = function_data.prolang
                WHERE n.nspname = 'public' AND NOT t.tgisinternal
                ORDER BY c.relname, t.tgname
                """
            )
        ).all()
        indexes = session.execute(
            text(
                """
                SELECT table_class.relname, index_class.relname,
                       index_data.indisunique::text,
                       index_data.indisprimary::text,
                       index_data.indisexclusion::text,
                       index_data.indimmediate::text,
                       index_data.indisclustered::text,
                       index_data.indisreplident::text,
                       index_data.indisvalid::text,
                       index_data.indisready::text,
                       index_data.indislive::text,
                       index_data.indnkeyatts::text,
                       index_data.indnatts::text,
                       ARRAY(
                           SELECT pg_get_indexdef(
                               index_data.indexrelid, ordinal, false
                           )
                           FROM generate_series(
                               1, index_data.indnatts
                           ) AS ordinal
                           ORDER BY ordinal
                       )::text,
                       COALESCE(
                           regexp_replace(
                               pg_get_expr(index_data.indpred, index_data.indrelid, true),
                               '\\s+', ' ', 'g'
                           ),
                           ''
                       ),
                       access_method.amname,
                       ARRAY(
                           SELECT operator_class.opcname
                           FROM unnest(index_data.indclass) WITH ORDINALITY
                                AS configured(opclass_oid, ordinal)
                           JOIN pg_opclass AS operator_class
                             ON operator_class.oid = configured.opclass_oid
                           ORDER BY configured.ordinal
                       )::text,
                       index_data.indoption::text
                FROM pg_index AS index_data
                JOIN pg_class AS table_class ON table_class.oid = index_data.indrelid
                JOIN pg_class AS index_class ON index_class.oid = index_data.indexrelid
                JOIN pg_namespace AS n ON n.oid = table_class.relnamespace
                JOIN pg_am AS access_method ON access_method.oid = index_class.relam
                WHERE n.nspname = 'public'
                ORDER BY table_class.relname, index_class.relname
                """
            )
        ).all()
    fingerprint = SchemaFingerprint(
        constraints=tuple(
            tuple(
                _normalize_pg_expression_text(str(value)) if position == 13 else str(value)
                for position, value in enumerate(row)
            )
            for row in constraints
        ),
        triggers=tuple(tuple(str(value) for value in row) for row in triggers),
        indexes=tuple(
            tuple(
                _normalize_pg_expression_text(str(value)) if position == 14 else str(value)
                for position, value in enumerate(row)
            )
            for row in indexes
        ),
    )
    if not fingerprint.constraints or not fingerprint.triggers or not fingerprint.indexes:
        raise DemoPipelineError("database schema fingerprint is incomplete")
    return fingerprint


def assert_restore_metadata(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        if session.scalar(select(func.count()).select_from(Server)) != 1:
            raise DemoPipelineError("restored server count is invalid")
        if session.scalar(select(func.count()).select_from(Operator)) != 3:
            raise DemoPipelineError("restored operator count is invalid")
        active_sessions = int(
            session.scalar(
                select(func.count())
                .select_from(OperatorWebSession)
                .where(OperatorWebSession.revoked_at.is_(None))
            )
            or 0
        )
        if active_sessions:
            raise DemoPipelineError("restored database contains an active web session")


def _create_demo_operator(
    session: Session, *, role: OperatorRole, suffix: str
) -> DemoOperatorCredential:
    provisioned = create_operator(
        session,
        username=f"demo-{role.value}-{suffix}",
        role=role,
    )
    issued = issue_operator_api_key(
        session,
        operator_id=provisioned.id,
        label="synthetic-8b",
    )
    return DemoOperatorCredential(
        operator_id=provisioned.id,
        username=provisioned.username,
        role=role,
        token=SecretValue(issued.token),
    )


def _verify_incident_set(
    session_factory: sessionmaker[Session],
    *,
    provisioning: DemoProvisioning,
    expectations: PipelineExpectations,
) -> None:
    with session_factory() as session:
        incidents = tuple(
            session.scalars(
                select(Incident)
                .where(Incident.server_id == provisioning.server_id)
                .order_by(Incident.created_at, Incident.id)
            )
        )
        actual = Counter(
            (
                incident.rule_key,
                incident.severity,
                incident.title,
                int(
                    session.scalar(
                        select(func.count())
                        .select_from(IncidentEvent)
                        .where(IncidentEvent.incident_id == incident.id)
                    )
                    or 0
                ),
            )
            for incident in incidents
        )
    if actual != Counter(expectations.incidents):
        raise DemoPipelineError("incident set did not match catalog-derived expectations")


def _snapshot(
    session: Session, server_id: UUID, incident_ids: tuple[UUID, ...]
) -> PipelineSnapshot:
    def count(model: Any, *criteria: Any) -> int:
        statement = select(func.count()).select_from(model)
        for criterion in criteria:
            statement = statement.where(criterion)
        return int(session.scalar(statement) or 0)

    no_ids = not incident_ids
    history = (
        0
        if no_ids
        else count(IncidentHistoryEntry, IncidentHistoryEntry.incident_id.in_(incident_ids))
    )
    comments = (
        0 if no_ids else count(IncidentComment, IncidentComment.incident_id.in_(incident_ids))
    )
    evidence = 0 if no_ids else count(IncidentEvent, IncidentEvent.incident_id.in_(incident_ids))
    outbox = 0 if no_ids else count(OutboxMessage, OutboxMessage.incident_id.in_(incident_ids))
    delivered = (
        0
        if no_ids
        else count(
            OutboxMessage,
            OutboxMessage.incident_id.in_(incident_ids),
            OutboxMessage.status == OutboxStatus.DELIVERED.value,
        )
    )
    failed = (
        0
        if no_ids
        else count(
            OutboxMessage,
            OutboxMessage.incident_id.in_(incident_ids),
            OutboxMessage.status == OutboxStatus.FAILED.value,
        )
    )
    pending = (
        0
        if no_ids
        else count(
            OutboxMessage,
            OutboxMessage.incident_id.in_(incident_ids),
            OutboxMessage.status == OutboxStatus.PENDING.value,
        )
    )
    processing = (
        0
        if no_ids
        else count(
            OutboxMessage,
            OutboxMessage.incident_id.in_(incident_ids),
            OutboxMessage.status == OutboxStatus.PROCESSING.value,
        )
    )
    return PipelineSnapshot(
        events=count(Event, Event.server_id == server_id),
        incidents=len(incident_ids),
        evidence=evidence,
        history=history,
        comments=comments,
        outbox=outbox,
        delivered=delivered,
        failed=failed,
        pending=pending,
        processing=processing,
        audit=count(AuditLogEntry),
        active_sessions=count(
            OperatorWebSession,
            OperatorWebSession.revoked_at.is_(None),
        ),
    )
