# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""The ``@permission`` decorator used to declare endpoint permissions."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from .models import PermissionSpec

#: Attribute under which the :class:`PermissionSpec` is stored on an endpoint.
PERMISSION_ATTR = "__actionguard_permission__"

F = TypeVar("F", bound=Callable[..., object])


def actionguard_permission(
    permission: str,
    *,
    label: str,
    description: str | None = None,
    group: str | None = None,
    log: bool = False,
) -> Callable[[F], F]:
    """Declare the permission required to access an endpoint.

    The decorator does not wrap or alter the endpoint's behaviour. It only
    attaches a :class:`~pl.afya.actionguard.models.PermissionSpec` to the
    function, which is later collected during discovery. Endpoints without this
    decorator are treated as public.

    Apply it directly below the FastAPI route decorator so that the spec is
    attached to the function FastAPI registers as the route endpoint::

        @router.post("/users")
        @actionguard_permission("user.create", label="Create users", group="Users", log=True)
        async def create_user() -> None:
            ...

    Args:
        permission: Stable, unique permission identifier (e.g. ``"user.create"``).
        label: Short human-readable label (e.g. ``"Create users"``).
        description: Optional longer explanation of what the permission allows.
        group: Optional grouping label used to organise permissions in a UI.
        log: Whether access to the endpoint should be audit-logged.

    Returns:
        A decorator that tags the endpoint and returns it unchanged.

    Raises:
        ValueError: If the endpoint already carries a permission declaration.

    Example:
        >>> @actionguard_permission("user.create", label="Create users")
        ... async def create_user() -> None:
        ...     ...
        >>> get_permission_spec(create_user).permission
        'user.create'
    """

    def decorator(func: F) -> F:
        if getattr(func, PERMISSION_ATTR, None) is not None:
            raise ValueError(
                f"{func.__qualname__!r} already declares a permission; "
                "apply @permission only once per endpoint."
            )
        spec = PermissionSpec(
            permission=permission,
            label=label,
            description=description,
            group=group,
            log=log,
        )
        setattr(func, PERMISSION_ATTR, spec)
        return func

    return decorator


def get_permission_spec(endpoint: Callable[..., object]) -> PermissionSpec | None:
    """Return the permission spec attached to an endpoint, if any.

    Args:
        endpoint: The endpoint callable to inspect.

    Returns:
        The attached :class:`~pl.afya.actionguard.models.PermissionSpec`, or
        ``None`` if the endpoint is public (undecorated).

    Example:
        >>> async def public() -> None: ...
        >>> get_permission_spec(public) is None
        True
    """
    spec = getattr(endpoint, PERMISSION_ATTR, None)
    return spec if isinstance(spec, PermissionSpec) else None
