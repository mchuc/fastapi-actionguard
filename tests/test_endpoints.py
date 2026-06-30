# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Tests for the endpoint coverage view (:func:`discover_endpoints`)."""

from __future__ import annotations

from fastapi import APIRouter, FastAPI

from pl.afya.actionguard import discover_endpoints, actionguard_permission


def _build_app() -> FastAPI:
    app = FastAPI()
    router = APIRouter()

    @router.post("/users")
    @actionguard_permission("user.create", label="Create users", group="Users", log=True)
    async def create_user() -> None: ...

    @router.get("/health")
    async def health() -> None: ...

    app.include_router(router, prefix="/api/v1")
    return app


def test_lists_protected_and_public_endpoints() -> None:
    coverage = {e.path: e for e in discover_endpoints(_build_app())}

    assert coverage["/api/v1/users"].protected is True
    assert coverage["/api/v1/users"].permission.permission == "user.create"
    assert coverage["/api/v1/users"].methods == ("POST",)

    assert coverage["/api/v1/health"].protected is False
    assert coverage["/api/v1/health"].permission is None


def test_internal_routes_excluded_by_default() -> None:
    paths = {e.path for e in discover_endpoints(_build_app())}
    assert "/openapi.json" not in paths
    assert "/docs" not in paths


def test_internal_routes_included_when_requested() -> None:
    paths = {e.path for e in discover_endpoints(_build_app(), include_internal=True)}
    assert "/openapi.json" in paths


def test_protected_permission_carries_resolved_path() -> None:
    coverage = {e.path: e for e in discover_endpoints(_build_app())}
    spec = coverage["/api/v1/users"].permission
    assert spec.path == "/api/v1/users"
    assert spec.log is True


def test_coverage_counts() -> None:
    endpoints = discover_endpoints(_build_app())
    protected = [e for e in endpoints if e.protected]
    public = [e for e in endpoints if not e.protected]
    assert len(protected) == 1
    assert len(public) == 1
