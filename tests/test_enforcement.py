# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Tests for runtime RBAC enforcement via :class:`Guard`."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from pl.afya.actionguard import Guard, PermissionDenied, actionguard_permission


class _User:
    """Minimal principal mirroring an app user with a permission set."""

    def __init__(self, name: str, perms: set[str]) -> None:
        self.name = name
        self.perms = perms

    def has_permission(self, perm: str) -> bool:
        return perm in self.perms


# Swapped per-test via dependency_overrides to simulate different callers.
def _current_user() -> _User:  # pragma: no cover - overridden in tests
    raise NotImplementedError


def _checker(user: _User, perm: str) -> bool:
    return user.has_permission(perm)


def _build_app(checker=_checker) -> tuple[FastAPI, Guard]:
    guard = Guard(principal_dependency=_current_user, permission_checker=checker)
    app = FastAPI()

    @app.post("/users")
    @actionguard_permission("user.create", label="Create users")
    async def create_user(actor: _User = Depends(guard.requires("user.create"))):
        return {"created_by": actor.name}

    @app.delete(
        "/users/{user_id}",
        dependencies=[Depends(guard.requires("user.delete"))],
    )
    @actionguard_permission("user.delete", label="Delete users")
    async def delete_user(user_id: int):
        return {"deleted": user_id}

    return app, guard


def test_allows_and_injects_principal_when_permitted() -> None:
    app, _ = _build_app()
    app.dependency_overrides[_current_user] = lambda: _User("alice", {"user.create"})
    client = TestClient(app)

    response = client.post("/users")
    assert response.status_code == 200
    assert response.json() == {"created_by": "alice"}


def test_denies_with_403_when_permission_missing() -> None:
    app, _ = _build_app()
    app.dependency_overrides[_current_user] = lambda: _User("bob", set())
    client = TestClient(app)

    response = client.post("/users")
    assert response.status_code == 403
    assert response.json()["detail"] == "Missing required permission: user.create"


def test_route_level_dependency_enforced() -> None:
    app, _ = _build_app()
    app.dependency_overrides[_current_user] = lambda: _User("carol", {"user.create"})
    client = TestClient(app)

    # carol may create but not delete.
    assert client.delete("/users/7").status_code == 403

    app.dependency_overrides[_current_user] = lambda: _User("dan", {"user.delete"})
    assert client.delete("/users/7").json() == {"deleted": 7}


def test_async_permission_checker_supported() -> None:
    async def async_checker(user: _User, perm: str) -> bool:
        return user.has_permission(perm)

    app, _ = _build_app(checker=async_checker)
    app.dependency_overrides[_current_user] = lambda: _User("eve", {"user.create"})
    client = TestClient(app)

    assert client.post("/users").status_code == 200


def test_custom_status_and_detail() -> None:
    guard = Guard(
        principal_dependency=_current_user,
        permission_checker=_checker,
        status_code=401,
    )
    app = FastAPI()

    @app.get("/secret")
    async def secret(_: _User = Depends(guard.requires("x", detail="nope"))):
        return {"ok": True}

    app.dependency_overrides[_current_user] = lambda: _User("frank", set())
    response = TestClient(app).get("/secret")
    assert response.status_code == 401
    assert response.json()["detail"] == "nope"


def test_permission_denied_carries_identifier() -> None:
    err = PermissionDenied("user.create")
    assert err.permission == "user.create"
    assert err.status_code == 403
