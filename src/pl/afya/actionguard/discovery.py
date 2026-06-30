# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Automatic discovery of declared permissions from a FastAPI application."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import NamedTuple

from .decorator import get_permission_spec
from .models import EndpointInfo, PermissionSpec
from .registry import PermissionRegistry

# HTTP methods that Starlette adds implicitly and that carry no permission value.
_IMPLICIT_METHODS = frozenset({"HEAD", "OPTIONS"})


class _RouteRecord(NamedTuple):
    """An endpoint found while walking the route tree.

    Attributes:
        path: Fully resolved route path (including prefixes).
        methods: Explicit HTTP methods.
        name: Route name (usually the endpoint function name).
        in_schema: Whether the route is included in the OpenAPI schema.
        spec: The attached :class:`PermissionSpec`, or ``None`` if public.
    """

    path: str
    methods: tuple[str, ...]
    name: str | None
    in_schema: bool
    spec: PermissionSpec | None


def discover_permissions(
    app: object,
    registry: PermissionRegistry | None = None,
) -> PermissionRegistry:
    """Scan a FastAPI/Starlette application and collect declared permissions.

    The application's route tree is walked recursively. Every endpoint carrying
    a ``@permission`` declaration is added to the registry with its fully
    resolved path (including any router or mount prefixes) and explicit HTTP
    methods. Undecorated routes are skipped and remain public.

    The walker handles lazily included routers (FastAPI 0.138+), eagerly
    flattened routers (older FastAPI), nested includes with prefixes, and
    mounted sub-applications.

    Args:
        app: A FastAPI (or Starlette) application exposing a ``routes`` iterable.
        registry: An existing registry to populate. A new one is created when
            omitted.

    Returns:
        The populated :class:`~pl.afya.actionguard.registry.PermissionRegistry`.

    Raises:
        DuplicatePermissionError: If two endpoints declare the same identifier
            with conflicting metadata.

    Example:
        >>> from fastapi import FastAPI
        >>> from pl.afya.actionguard import actionguard_permission
        >>> app = FastAPI()
        >>> @app.post("/users")
        ... @actionguard_permission("user.create", label="Create users", group="Users")
        ... async def create_user() -> None: ...
        >>> registry = discover_permissions(app)
        >>> registry.get("user.create").path
        '/users'
    """
    registry = registry if registry is not None else PermissionRegistry()
    for record in _walk(getattr(app, "routes", ()), prefix=""):
        if record.spec is None:
            continue
        registry.register(
            record.spec.model_copy(
                update={"path": record.path, "methods": record.methods}
            )
        )
    return registry


def discover_endpoints(
    app: object,
    *,
    include_internal: bool = False,
) -> tuple[EndpointInfo, ...]:
    """List every endpoint and whether ActionGuard protects it.

    A coverage view complementing :func:`discover_permissions`: it returns *all*
    routes — both the ones declaring a ``@permission`` (``protected=True``) and
    the public ones (``protected=False``) — so you can audit which parts of an
    application are guarded.

    Args:
        app: A FastAPI (or Starlette) application exposing a ``routes`` iterable.
        include_internal: When ``False`` (default), routes excluded from the
            OpenAPI schema (e.g. FastAPI's ``/docs``, ``/openapi.json``) are
            omitted. Set ``True`` to include them.

    Returns:
        A tuple of :class:`~pl.afya.actionguard.models.EndpointInfo`, in route
        declaration order.

    Example:
        >>> from fastapi import FastAPI
        >>> from pl.afya.actionguard import actionguard_permission
        >>> app = FastAPI()
        >>> @app.post("/users")
        ... @actionguard_permission("user.create", label="Create users")
        ... async def create_user() -> None: ...
        >>> @app.get("/health")
        ... async def health() -> None: ...
        >>> coverage = discover_endpoints(app)
        >>> {e.path: e.protected for e in coverage}
        {'/users': True, '/health': False}
    """
    endpoints: list[EndpointInfo] = []
    for record in _walk(getattr(app, "routes", ()), prefix=""):
        if not include_internal and not record.in_schema:
            continue
        spec = record.spec
        if spec is not None:
            spec = spec.model_copy(
                update={"path": record.path, "methods": record.methods}
            )
        endpoints.append(
            EndpointInfo(
                path=record.path,
                methods=record.methods,
                name=record.name,
                protected=spec is not None,
                permission=spec,
            )
        )
    return tuple(endpoints)


def _walk(routes: Iterable[object], prefix: str) -> Iterator[_RouteRecord]:
    """Yield a :class:`_RouteRecord` for every endpoint in a route tree.

    Args:
        routes: An iterable of Starlette/FastAPI route objects.
        prefix: Path prefix accumulated from enclosing routers and mounts.

    Yields:
        One :class:`_RouteRecord` per endpoint (decorated or not), with paths
        and prefixes fully resolved.
    """
    for route in routes:
        # Lazily included router (FastAPI 0.138+): no endpoint and no `routes`,
        # the real router and its prefix live on the include context.
        context = getattr(route, "include_context", None)
        if context is not None:
            included = getattr(context, "included_router", None)
            sub_prefix = getattr(context, "prefix", "") or ""
            if included is not None:
                yield from _walk(getattr(included, "routes", ()), prefix + sub_prefix)
            continue

        endpoint = getattr(route, "endpoint", None)
        if endpoint is not None:
            yield _RouteRecord(
                path=prefix + (getattr(route, "path", "") or ""),
                methods=_resolve_methods(route),
                name=getattr(route, "name", None),
                in_schema=bool(getattr(route, "include_in_schema", True)),
                spec=get_permission_spec(endpoint),
            )
            continue

        # Mounted sub-application or nested router exposing its own `routes`.
        sub_routes = getattr(route, "routes", None)
        if sub_routes is not None:
            yield from _walk(sub_routes, prefix + (getattr(route, "path", "") or ""))


def _resolve_methods(route: object) -> tuple[str, ...]:
    """Return the explicit HTTP methods for a route, sorted and deduplicated.

    Args:
        route: A route object optionally exposing a ``methods`` set.

    Returns:
        A sorted tuple of HTTP method names, excluding implicit ``HEAD`` and
        ``OPTIONS`` entries.
    """
    methods = getattr(route, "methods", None)
    if not methods:
        return ()
    return tuple(sorted(m for m in methods if m not in _IMPLICIT_METHODS))


__all__ = ["discover_endpoints", "discover_permissions"]
