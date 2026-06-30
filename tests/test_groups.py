# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Tests for dynamic, group-based RBAC (:class:`GroupRBAC`)."""

from __future__ import annotations

import asyncio

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from pl.afya.actionguard import Guard, GroupRBAC, actionguard_permission


def test_unions_permissions_across_groups() -> None:
    db = {"editors": {"place.edit"}, "uploaders": {"place.photo.add"}}
    rbac = GroupRBAC(
        group_loader=lambda u: u["groups"],
        permission_loader=lambda gid: db[gid],
    )
    user = {"groups": ["editors", "uploaders"]}

    perms = asyncio.run(rbac.permissions_for(user))
    assert perms == frozenset({"place.edit", "place.photo.add"})


def test_exact_permission_match() -> None:
    rbac = GroupRBAC(
        group_loader=lambda u: ["g"],
        permission_loader=lambda gid: {"user.create"},
        wildcard=False,
    )
    assert asyncio.run(rbac.has_permission(object(), "user.create")) is True
    assert asyncio.run(rbac.has_permission(object(), "user.delete")) is False


def test_wildcard_grants_prefix() -> None:
    rbac = GroupRBAC(
        group_loader=lambda u: ["admins"],
        permission_loader=lambda gid: {"place.*"},
    )
    assert asyncio.run(rbac.has_permission(object(), "place.create")) is True
    assert asyncio.run(rbac.has_permission(object(), "place.photo.delete")) is True
    assert asyncio.run(rbac.has_permission(object(), "user.create")) is False


def test_global_wildcard_grants_everything() -> None:
    rbac = GroupRBAC(
        group_loader=lambda u: ["root"],
        permission_loader=lambda gid: {"*"},
    )
    assert asyncio.run(rbac.has_permission(object(), "anything.at.all")) is True


def test_wildcard_disabled_is_literal() -> None:
    rbac = GroupRBAC(
        group_loader=lambda u: ["admins"],
        permission_loader=lambda gid: {"place.*"},
        wildcard=False,
    )
    assert asyncio.run(rbac.has_permission(object(), "place.create")) is False
    assert asyncio.run(rbac.has_permission(object(), "place.*")) is True


def test_cache_calls_loader_once_per_group() -> None:
    calls: list[str] = []

    def loader(gid: str) -> set[str]:
        calls.append(gid)
        return {"place.edit"}

    rbac = GroupRBAC(group_loader=lambda u: ["editors"], permission_loader=loader)

    asyncio.run(rbac.has_permission(object(), "place.edit"))
    asyncio.run(rbac.has_permission(object(), "place.edit"))
    assert calls == ["editors"]  # second call served from cache


def test_invalidate_reloads_group() -> None:
    state = {"editors": {"place.edit"}}

    def loader(gid: str) -> set[str]:
        return set(state[gid])

    rbac = GroupRBAC(group_loader=lambda u: ["editors"], permission_loader=loader)
    user = object()

    assert asyncio.run(rbac.has_permission(user, "place.delete")) is False

    # Admin grants a new permission to the group in the database...
    state["editors"].add("place.delete")
    # ...still cached as the old set until invalidated:
    assert asyncio.run(rbac.has_permission(user, "place.delete")) is False

    rbac.invalidate("editors")
    assert asyncio.run(rbac.has_permission(user, "place.delete")) is True


def test_async_loaders_supported() -> None:
    async def group_loader(user: dict) -> list[str]:
        return user["groups"]

    async def permission_loader(gid: str) -> set[str]:
        return {"place.edit"}

    rbac = GroupRBAC(group_loader=group_loader, permission_loader=permission_loader)
    assert asyncio.run(rbac.has_permission({"groups": ["editors"]}, "place.edit")) is True


def test_integration_with_guard_and_dynamic_change() -> None:
    # Mutable "database" of group -> permissions.
    db: dict[str, set[str]] = {"viewers": set()}

    async def load_group_permissions(group_id: str) -> set[str]:
        return set(db[group_id])

    rbac = GroupRBAC(
        group_loader=lambda user: user["groups"],
        permission_loader=load_group_permissions,
    )

    def current_user() -> dict:  # overridden below
        raise NotImplementedError

    guard = Guard(principal_dependency=current_user, permission_checker=rbac.checker)
    app = FastAPI()

    @app.post("/places")
    @actionguard_permission("place.create", label="Create places")
    async def create_place(actor=Depends(guard.requires("place.create"))):
        return {"by": actor["name"]}

    app.dependency_overrides[current_user] = lambda: {"name": "ann", "groups": ["viewers"]}
    client = TestClient(app)

    # No permission yet -> denied.
    assert client.post("/places").status_code == 403

    # Admin grants place.create to the "viewers" group and invalidates cache.
    db["viewers"].add("place.create")
    rbac.invalidate("viewers")

    assert client.post("/places").status_code == 200
