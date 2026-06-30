# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Tests for audit logging of permission checks."""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from pl.afya.actionguard import (
    AuditEvent,
    Guard,
    PermissionRegistry,
    PermissionSpec,
    discover_permissions,
    logging_audit_sink,
    actionguard_permission,
)


def _user_factory(name: str, perms: set[str]):
    def _current_user():  # pragma: no cover - replaced by override
        raise NotImplementedError

    return _current_user, {"name": name, "perms": perms}


def _checker(user: dict, perm: str) -> bool:
    return perm in user["perms"]


def test_audits_allow_and_deny_without_registry() -> None:
    events: list[AuditEvent] = []
    dep, principal = _user_factory("alice", {"user.create"})
    guard = Guard(
        principal_dependency=dep,
        permission_checker=_checker,
        audit=events.append,
    )
    app = FastAPI()

    @app.post("/users")
    @actionguard_permission("user.create", label="Create", log=True)
    async def create(actor=Depends(guard.requires("user.create"))):
        return {"ok": actor["name"]}

    app.dependency_overrides[dep] = lambda: principal
    client = TestClient(app)

    assert client.post("/users").status_code == 200
    assert len(events) == 1
    assert events[0].permission == "user.create"
    assert events[0].allowed is True
    assert events[0].detail is None
    assert events[0].timestamp.tzinfo is not None

    principal["perms"] = set()
    assert client.post("/users").status_code == 403
    assert len(events) == 2
    assert events[1].allowed is False
    assert "user.create" in events[1].detail


def test_registry_log_flag_filters_audit() -> None:
    events: list[AuditEvent] = []
    registry = PermissionRegistry()
    registry.register(PermissionSpec(permission="audited", label="A", log=True))
    registry.register(PermissionSpec(permission="silent", label="S", log=False))

    dep, principal = _user_factory("bob", {"audited", "silent"})
    guard = Guard(
        principal_dependency=dep,
        permission_checker=_checker,
        audit=events.append,
        registry=registry,
    )
    app = FastAPI()

    @app.get("/a")
    async def a(actor=Depends(guard.requires("audited"))):
        return {}

    @app.get("/s")
    async def s(actor=Depends(guard.requires("silent"))):
        return {}

    app.dependency_overrides[dep] = lambda: principal
    client = TestClient(app)

    client.get("/a")
    client.get("/s")

    assert [e.permission for e in events] == ["audited"]


def test_requires_audit_override_forces_logging() -> None:
    events: list[AuditEvent] = []
    registry = PermissionRegistry()
    registry.register(PermissionSpec(permission="silent", label="S", log=False))

    dep, principal = _user_factory("carol", {"silent"})
    guard = Guard(
        principal_dependency=dep,
        permission_checker=_checker,
        audit=events.append,
        registry=registry,
    )
    app = FastAPI()

    @app.get("/s")
    async def s(actor=Depends(guard.requires("silent", audit=True))):
        return {}

    app.dependency_overrides[dep] = lambda: principal
    TestClient(app).get("/s")

    assert len(events) == 1 and events[0].permission == "silent"


def test_no_audit_when_sink_absent() -> None:
    dep, principal = _user_factory("dan", {"user.create"})
    guard = Guard(principal_dependency=dep, permission_checker=_checker)
    app = FastAPI()

    @app.post("/users")
    async def create(actor=Depends(guard.requires("user.create"))):
        return {}

    app.dependency_overrides[dep] = lambda: principal
    # Simply must not raise despite no sink configured.
    assert TestClient(app).post("/users").status_code == 200


def test_async_sink_awaited() -> None:
    events: list[AuditEvent] = []

    async def async_sink(event: AuditEvent) -> None:
        events.append(event)

    dep, principal = _user_factory("eve", {"user.create"})
    guard = Guard(
        principal_dependency=dep,
        permission_checker=_checker,
        audit=async_sink,
    )
    app = FastAPI()

    @app.post("/users")
    async def create(actor=Depends(guard.requires("user.create"))):
        return {}

    app.dependency_overrides[dep] = lambda: principal
    TestClient(app).post("/users")

    assert len(events) == 1


def test_logging_audit_sink_writes(caplog) -> None:
    sink = logging_audit_sink()
    dep, principal = _user_factory("frank", {"user.create"})
    guard = Guard(principal_dependency=dep, permission_checker=_checker, audit=sink)
    app = FastAPI()

    @app.post("/users")
    async def create(actor=Depends(guard.requires("user.create"))):
        return {}

    app.dependency_overrides[dep] = lambda: principal

    with caplog.at_level(logging.INFO, logger="pl.afya.actionguard.audit"):
        TestClient(app).post("/users")

    assert any("permission=user.create" in r.message for r in caplog.records)


def test_audit_uses_registry_populated_by_discovery() -> None:
    """The flag is read at request time, so discovery may run after guard setup."""
    events: list[AuditEvent] = []
    registry = PermissionRegistry()
    dep, principal = _user_factory("gina", {"user.create"})
    guard = Guard(
        principal_dependency=dep,
        permission_checker=_checker,
        audit=events.append,
        registry=registry,
    )
    app = FastAPI()

    @app.post("/users")
    @actionguard_permission("user.create", label="Create", log=True)
    async def create(actor=Depends(guard.requires("user.create"))):
        return {}

    # Registry filled AFTER guard construction — same object, ready by request time.
    discover_permissions(app, registry)

    app.dependency_overrides[dep] = lambda: principal
    TestClient(app).post("/users")

    assert len(events) == 1 and events[0].allowed is True
