"""Exact tests for the centralized fixed-role permission matrix."""

import pytest

from woland_guard_control_plane.application.rbac import (
    ROLE_PERMISSIONS,
    Permission,
    role_has_permission,
)
from woland_guard_control_plane.infrastructure.database.models import OperatorRole


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (OperatorRole.VIEWER, {Permission.VIEW_INCIDENTS}),
        (
            OperatorRole.ANALYST,
            {
                Permission.ACCESS_DASHBOARD,
                Permission.VIEW_INCIDENTS,
                Permission.TRANSITION_INCIDENTS,
                Permission.COMMENT_INCIDENTS,
                Permission.PROPOSE_IP_BLOCK,
            },
        ),
        (OperatorRole.ADMIN, set(Permission)),
    ],
)
def test_role_permission_sets_are_explicit_and_complete(
    role: OperatorRole,
    expected: set[Permission],
) -> None:
    assert ROLE_PERMISSIONS[role] == frozenset(expected)
    assert {
        permission for permission in Permission if role_has_permission(role, permission)
    } == expected


def test_every_operator_role_has_exactly_one_matrix_entry() -> None:
    assert set(ROLE_PERMISSIONS) == set(OperatorRole)
