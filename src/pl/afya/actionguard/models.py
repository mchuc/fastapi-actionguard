# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Data models for the permission registry."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PermissionSpec(BaseModel):
    """A single declarative permission attached to an endpoint.

    The decorator-supplied fields (``permission``, ``label``, ``description``,
    ``group`` and ``log``) are known at import time. The routing fields
    (``path`` and ``methods``) are filled in later, during discovery, once the
    endpoint has been mounted on a FastAPI application.

    Attributes:
        permission: Stable, unique permission identifier, e.g. ``"user.create"``.
        label: Short human-readable label, e.g. ``"Create users"``.
        description: Optional longer explanation of what the permission allows.
        group: Optional grouping label used to organise permissions in a UI.
        log: Whether access to the endpoint should be audit-logged.
        methods: HTTP methods the endpoint answers to. Filled during discovery.
        path: Router path of the endpoint. Filled during discovery.

    Example:
        >>> spec = PermissionSpec(permission="user.create", label="Create users")
        >>> spec.permission
        'user.create'
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    permission: str = Field(min_length=1)
    label: str = Field(min_length=1)
    description: str | None = None
    group: str | None = None
    log: bool = False
    methods: tuple[str, ...] = ()
    path: str | None = None


class EndpointInfo(BaseModel):
    """A discovered endpoint and whether ActionGuard protects it.

    Produced by :func:`pl.afya.actionguard.discovery.discover_endpoints` to give
    a coverage view of an application: every route, with the ones carrying a
    ``@permission`` declaration marked as protected and the rest as public.

    Attributes:
        path: The fully resolved route path (including router/mount prefixes).
        methods: HTTP methods the endpoint answers to.
        name: The route name (usually the endpoint function name).
        protected: ``True`` when the endpoint declares a permission.
        permission: The endpoint's :class:`PermissionSpec` when protected,
            otherwise ``None`` (the endpoint is public).

    Example:
        >>> info = EndpointInfo(path="/health", methods=("GET",), name="health")
        >>> info.protected
        False
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str | None = None
    methods: tuple[str, ...] = ()
    name: str | None = None
    protected: bool = False
    permission: PermissionSpec | None = None
