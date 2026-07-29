from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from tests.browser.guards import SecretValue
from woland_guard_control_plane.application.detection.rules import load_rules_directory
from woland_guard_control_plane.application.detection.sync import sync_rules
from woland_guard_control_plane.application.operators import (
    create_operator,
    issue_operator_api_key,
)
from woland_guard_control_plane.infrastructure.database.models import (
    DetectionRuleVersion,
    Event,
    Incident,
    IncidentEvent,
    IncidentHistoryEntry,
    OperatorRole,
    Server,
)

XSS_CANARY = '<img src="https://browser-canary.invalid/x" onerror="window.wgCanary=1">'


@dataclass(frozen=True, slots=True)
class BrowserOperator:
    username: str
    token: SecretValue = field(repr=False)


@dataclass(frozen=True, slots=True)
class BrowserSeed:
    analyst: BrowserOperator
    admin: BrowserOperator
    viewer: BrowserOperator
    primary_server_id: UUID
    primary_server_name: str
    primary_incident_id: UUID
    secondary_incident_id: UUID
    rule_key: str
    xss_canary: str = field(repr=False)

    @property
    def secrets(self) -> tuple[SecretValue, ...]:
        return (self.analyst.token, self.admin.token, self.viewer.token)


def seed_browser_database(
    session_factory: sessionmaker[Session],
    *,
    project_root: Path,
) -> BrowserSeed:
    now = datetime.now(UTC)
    rules = load_rules_directory(project_root / "detection-rules")
    if not rules:
        raise RuntimeError("browser seed requires at least one detection rule")
    selected_rule = rules[0]
    with session_factory.begin() as session:
        sync_rules(session, rules, activated_at=now)
        stored_rule = session.scalar(
            select(DetectionRuleVersion).where(
                DetectionRuleVersion.rule_key == selected_rule.rule_key,
                DetectionRuleVersion.is_active.is_(True),
            )
        )
        if stored_rule is None:
            raise RuntimeError("browser seed could not load the active detection rule")

        analyst = _create_browser_operator(session, role=OperatorRole.ANALYST, suffix="analyst")
        admin = _create_browser_operator(session, role=OperatorRole.ADMIN, suffix="admin")
        viewer = _create_browser_operator(session, role=OperatorRole.VIEWER, suffix="viewer")

        primary_server_id: UUID | None = None
        primary_server_name = "browser-server-00"
        primary_incident_id: UUID | None = None
        secondary_incident_id: UUID | None = None
        for index in range(30):
            timestamp = now - timedelta(minutes=index)
            server = Server(
                name=f"browser-server-{index:02d}",
                hostname=f"browser-{index:02d}.invalid",
                description="Synthetic browser verification server",
                is_active=index != 29,
                created_at=timestamp,
                updated_at=timestamp,
            )
            session.add(server)
            session.flush()
            event = Event(
                server_id=server.id,
                agent_event_id=uuid4(),
                schema_version=1,
                source="journald",
                event_type="linux.ssh.authentication_failed",
                occurred_at=timestamp,
                collected_at=timestamp + timedelta(seconds=1),
                persisted_at=timestamp + timedelta(seconds=2),
                payload={},
            )
            correlation_hash = sha256(f"browser-{index}".encode()).hexdigest()
            incident = Incident(
                server_id=server.id,
                rule_version_id=stored_rule.id,
                rule_key=selected_rule.rule_key,
                rule_version=selected_rule.version,
                severity=selected_rule.severity.value,
                status="new",
                title=f"Browser synthetic incident {index:02d}",
                explanation="Synthetic browser verification incident.",
                recommendation="Review the synthetic browser verification event.",
                correlation={},
                correlation_hash=correlation_hash,
                rule_snapshot=selected_rule.model_dump(mode="json"),
                first_seen_at=timestamp,
                last_seen_at=timestamp,
                event_count=1,
                lock_version=1,
                created_at=timestamp,
                updated_at=timestamp,
            )
            session.add_all((event, incident))
            session.flush()
            session.add_all(
                (
                    IncidentHistoryEntry(
                        incident_id=incident.id,
                        version=1,
                        entry_type="baseline",
                        from_status=None,
                        to_status="new",
                        reason=None,
                        changed_by_operator_id=None,
                        actor_username_snapshot=None,
                        auth_method_type=None,
                        auth_method_id=None,
                    ),
                    IncidentEvent(
                        incident_id=incident.id,
                        event_id=event.id,
                        linked_at=timestamp + timedelta(seconds=3),
                    ),
                )
            )
            if index == 0:
                primary_server_id = server.id
                primary_incident_id = incident.id
            elif index == 1:
                secondary_incident_id = incident.id

    if primary_server_id is None or primary_incident_id is None or secondary_incident_id is None:
        raise RuntimeError("browser seed did not create its primary entities")
    return BrowserSeed(
        analyst=analyst,
        admin=admin,
        viewer=viewer,
        primary_server_id=primary_server_id,
        primary_server_name=primary_server_name,
        primary_incident_id=primary_incident_id,
        secondary_incident_id=secondary_incident_id,
        rule_key=selected_rule.rule_key,
        xss_canary=XSS_CANARY,
    )


def _create_browser_operator(
    session: Session,
    *,
    role: OperatorRole,
    suffix: str,
) -> BrowserOperator:
    provisioned = create_operator(
        session,
        username=f"browser-{suffix}-{uuid4().hex[:8]}",
        role=role,
    )
    issued = issue_operator_api_key(
        session,
        operator_id=provisioned.id,
        label="browser-test",
    )
    return BrowserOperator(username=provisioned.username, token=SecretValue(issued.token))
