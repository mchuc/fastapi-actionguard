# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""FastAPI ActionGuard — a lightweight, declarative permission framework.

Declare permissions on endpoints with :func:`permission`, then build a
:class:`PermissionRegistry` at startup with :func:`discover_permissions`.

Example:
    >>> from fastapi import FastAPI
    >>> from pl.afya.actionguard import actionguard_permission, discover_permissions
    >>> app = FastAPI()
    >>> @app.post("/users")
    ... @actionguard_permission("user.create", label="Create users", group="Users", log=True)
    ... async def create_user() -> None: ...
    >>> registry = discover_permissions(app)
    >>> len(registry)
    1
"""

from __future__ import annotations

from .audit import AuditEvent, AuditSink, logging_audit_sink
from .decorator import actionguard_permission, get_permission_spec
from .discovery import discover_endpoints, discover_permissions
from .enforcement import Guard, PermissionChecker, PermissionDenied
from .groups import GroupLoader, GroupRBAC, PermissionLoader
from .models import EndpointInfo, PermissionSpec
from .policy import (
    AccessRequest,
    AttributePolicy,
    CombiningAlgorithm,
    Decision,
    FunctionPolicy,
    Policy,
    PolicySet,
    RoleBasedPolicy,
    deny_overrides,
    first_applicable,
    permit_overrides,
)
from .registry import DuplicatePermissionError, PermissionRegistry

__version__ = "0.1.0"

__all__ = [
    "AccessRequest",
    "AttributePolicy",
    "AuditEvent",
    "AuditSink",
    "CombiningAlgorithm",
    "Decision",
    "DuplicatePermissionError",
    "EndpointInfo",
    "FunctionPolicy",
    "Guard",
    "GroupLoader",
    "GroupRBAC",
    "Policy",
    "PermissionChecker",
    "PermissionDenied",
    "PermissionLoader",
    "PermissionRegistry",
    "PermissionSpec",
    "PolicySet",
    "RoleBasedPolicy",
    "__version__",
    "deny_overrides",
    "discover_endpoints",
    "discover_permissions",
    "first_applicable",
    "get_permission_spec",
    "logging_audit_sink",
    "actionguard_permission",
    "permit_overrides",
]
