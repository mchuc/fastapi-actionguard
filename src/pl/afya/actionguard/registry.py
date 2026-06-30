# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""In-memory registry of declared permissions."""

from __future__ import annotations

from collections.abc import Iterator

from .models import PermissionSpec


class DuplicatePermissionError(ValueError):
    """Raised when two endpoints declare the same permission identifier."""


class PermissionRegistry:
    """Ordered, keyed collection of discovered permissions.

    The registry is the single source of truth for every permission declared in
    an application. It is typically built once at startup by
    :func:`~pl.afya.actionguard.discovery.discover_permissions`.

    Example:
        >>> registry = PermissionRegistry()
        >>> registry.register(PermissionSpec(permission="user.create", label="Create"))
        >>> "user.create" in registry
        True
        >>> len(registry)
        1
    """

    def __init__(self) -> None:
        """Initialise an empty registry."""
        self._by_id: dict[str, PermissionSpec] = {}

    def register(self, spec: PermissionSpec) -> None:
        """Add a permission to the registry.

        Args:
            spec: The permission specification to store.

        Raises:
            DuplicatePermissionError: If a different permission with the same
                identifier is already registered. Re-registering an identical
                spec is a no-op.

        Example:
            >>> registry = PermissionRegistry()
            >>> registry.register(PermissionSpec(permission="a", label="A"))
        """
        existing = self._by_id.get(spec.permission)
        if existing is not None and existing != spec:
            raise DuplicatePermissionError(
                f"Permission {spec.permission!r} is already registered "
                f"for path {existing.path!r}; conflicting declaration "
                f"for path {spec.path!r}."
            )
        self._by_id[spec.permission] = spec

    def get(self, permission: str) -> PermissionSpec | None:
        """Return the spec for an identifier, or ``None`` if it is not present.

        Args:
            permission: The permission identifier to look up.

        Returns:
            The matching :class:`PermissionSpec`, or ``None``.

        Example:
            >>> registry = PermissionRegistry()
            >>> registry.get("missing") is None
            True
        """
        return self._by_id.get(permission)

    def all(self) -> tuple[PermissionSpec, ...]:
        """Return all registered permissions in registration order.

        Returns:
            A tuple of every registered :class:`PermissionSpec`.

        Example:
            >>> PermissionRegistry().all()
            ()
        """
        return tuple(self._by_id.values())

    def to_list(self) -> list[dict[str, object]]:
        """Serialise the registry to a list of plain dictionaries.

        Useful for exposing the permission catalogue over an API or for
        synchronising permissions with an external store.

        Returns:
            One dictionary per permission, in registration order.

        Example:
            >>> registry = PermissionRegistry()
            >>> registry.register(PermissionSpec(permission="a", label="A"))
            >>> registry.to_list()[0]["permission"]
            'a'
        """
        return [spec.model_dump() for spec in self._by_id.values()]

    def __contains__(self, permission: object) -> bool:
        """Return whether a permission identifier is registered."""
        return permission in self._by_id

    def __iter__(self) -> Iterator[PermissionSpec]:
        """Iterate over registered permissions in registration order."""
        return iter(self._by_id.values())

    def __len__(self) -> int:
        """Return the number of registered permissions."""
        return len(self._by_id)
