# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Tests for the ActionGuard core: decorator, registry and discovery."""

from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI

from pl.afya.actionguard import (
    DuplicatePermissionError,
    PermissionRegistry,
    PermissionSpec,
    discover_permissions,
    get_permission_spec,
    actionguard_permission,
)


def test_decorator_attaches_spec_without_changing_behaviour() -> None:
    @actionguard_permission("user.create", label="Create users", group="Users", log=True)
    async def create_user() -> str:
        return "ok"

    spec = get_permission_spec(create_user)
    assert spec is not None
    assert spec.permission == "user.create"
    assert spec.label == "Create users"
    assert spec.group == "Users"
    assert spec.log is True


def test_undecorated_endpoint_is_public() -> None:
    async def public_endpoint() -> None: ...

    assert get_permission_spec(public_endpoint) is None


def test_double_declaration_raises() -> None:
    with pytest.raises(ValueError):

        @actionguard_permission("a", label="A")
        @actionguard_permission("b", label="B")
        async def endpoint() -> None: ...


def test_registry_basic_operations() -> None:
    registry = PermissionRegistry()
    spec = PermissionSpec(permission="user.create", label="Create")
    registry.register(spec)

    assert "user.create" in registry
    assert len(registry) == 1
    assert registry.get("user.create") == spec
    assert registry.get("missing") is None
    assert registry.all() == (spec,)


def test_registry_rejects_conflicting_duplicate() -> None:
    registry = PermissionRegistry()
    registry.register(PermissionSpec(permission="x", label="X", path="/x"))
    with pytest.raises(DuplicatePermissionError):
        registry.register(PermissionSpec(permission="x", label="X", path="/y"))


def test_registry_allows_identical_reregistration() -> None:
    registry = PermissionRegistry()
    spec = PermissionSpec(permission="x", label="X")
    registry.register(spec)
    registry.register(spec)
    assert len(registry) == 1


def _build_app() -> FastAPI:
    app = FastAPI()
    router = APIRouter()

    @router.post("/users")
    @actionguard_permission("user.create", label="Create users", group="Users", log=True)
    async def create_user() -> None: ...

    @router.get("/users/{user_id}")
    @actionguard_permission("user.read", label="Read users", group="Users")
    async def read_user(user_id: int) -> None: ...

    @router.get("/health")
    async def health() -> None: ...

    app.include_router(router)
    return app


def test_discovery_collects_decorated_routes() -> None:
    registry = discover_permissions(_build_app())

    assert len(registry) == 2
    assert "user.create" in registry
    assert "user.read" in registry

    create = registry.get("user.create")
    assert create is not None
    assert create.path == "/users"
    assert create.methods == ("POST",)
    assert create.log is True

    read = registry.get("user.read")
    assert read is not None
    assert read.path == "/users/{user_id}"
    assert read.methods == ("GET",)


def test_discovery_skips_public_routes() -> None:
    registry = discover_permissions(_build_app())
    ids = {spec.permission for spec in registry}
    assert "health" not in ids


def test_discovery_resolves_router_prefix() -> None:
    app = FastAPI()
    router = APIRouter()

    @router.delete("/items/{item_id}")
    @actionguard_permission("item.delete", label="Delete items")
    async def delete_item(item_id: int) -> None: ...

    app.include_router(router, prefix="/api/v1")

    registry = discover_permissions(app)
    spec = registry.get("item.delete")
    assert spec is not None
    assert spec.path == "/api/v1/items/{item_id}"
    assert spec.methods == ("DELETE",)


def test_to_list_serialisation() -> None:
    registry = discover_permissions(_build_app())
    rows = registry.to_list()
    create = next(r for r in rows if r["permission"] == "user.create")
    assert create["label"] == "Create users"
    assert create["path"] == "/users"
    assert create["methods"] == ("POST",)
