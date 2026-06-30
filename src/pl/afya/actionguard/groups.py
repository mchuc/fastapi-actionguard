# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Dynamic, group-based RBAC backed by application-supplied loaders.

Instead of hard-coding a role-to-permission table, permissions are resolved at
request time through two callables the application provides:

* a *group loader* — given the current principal, return the identifiers of the
  groups it belongs to (typically read straight off the user object), and
* a *permission loader* — given a group identifier, return that group's
  permissions (typically read from a database).

:class:`GroupRBAC` unions the permissions of all the principal's groups,
optionally supports wildcard grants (``"place.*"``), and caches per-group
results with an explicit invalidation hook so an admin editing a group in the
database takes effect immediately, without a restart.

It exposes a :attr:`GroupRBAC.checker` compatible with
:class:`pl.afya.actionguard.enforcement.Guard`.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable

#: Returns the group identifiers a principal belongs to. May be sync or async.
GroupLoader = Callable[[object], "Iterable[str] | Awaitable[Iterable[str]]"]

#: Returns the permissions granted by a single group. May be sync or async.
PermissionLoader = Callable[[str], "Iterable[str] | Awaitable[Iterable[str]]"]


class GroupRBAC:
    """Resolve a principal's effective permissions via dynamic groups.

    Args:
        group_loader: Callable mapping a principal to its group identifiers
            (e.g. ``lambda user: user.group_ids``). May be sync or async.
        permission_loader: Callable mapping a group identifier to its
            permissions (e.g. a database lookup). May be sync or async.
        cache: When ``True`` (default), per-group permission sets are cached in
            memory until explicitly invalidated. Group membership itself is read
            fresh on every call (it comes from the principal).
        wildcard: When ``True`` (default), a granted ``"prefix.*"`` permission
            satisfies any required permission under that prefix (e.g.
            ``"place.*"`` grants ``"place.create"``), and a granted ``"*"``
            grants everything.

    Example:
        >>> groups = {"editors": {"place.*"}, "users": {"place.create"}}
        >>> rbac = GroupRBAC(
        ...     group_loader=lambda user: user["groups"],
        ...     permission_loader=lambda gid: groups[gid],
        ... )
        >>> import asyncio
        >>> asyncio.run(rbac.has_permission({"groups": ["users"]}, "place.create"))
        True
    """

    def __init__(
        self,
        *,
        group_loader: GroupLoader,
        permission_loader: PermissionLoader,
        cache: bool = True,
        wildcard: bool = True,
    ) -> None:
        """Store the loaders and behaviour flags."""
        self._group_loader = group_loader
        self._permission_loader = permission_loader
        self._cache_enabled = cache
        self._wildcard = wildcard
        self._cache: dict[str, frozenset[str]] = {}

    async def permissions_for(self, principal: object) -> frozenset[str]:
        """Return the union of permissions across the principal's groups.

        Args:
            principal: The current principal (whatever ``group_loader`` accepts).

        Returns:
            The complete set of permission identifiers granted to the principal.

        Example:
            >>> rbac = GroupRBAC(
            ...     group_loader=lambda u: ["a", "b"],
            ...     permission_loader=lambda g: {"a": {"x"}, "b": {"y"}}[g],
            ... )
            >>> import asyncio
            >>> sorted(asyncio.run(rbac.permissions_for(object())))
            ['x', 'y']
        """
        group_ids = await _maybe_await(self._group_loader(principal))
        effective: set[str] = set()
        for group_id in group_ids:
            effective |= await self._permissions_of_group(group_id)
        return frozenset(effective)

    async def has_permission(self, principal: object, permission: str) -> bool:
        """Return whether the principal holds ``permission``.

        Compatible with the ``permission_checker`` signature expected by
        :class:`~pl.afya.actionguard.enforcement.Guard`.

        Args:
            principal: The current principal.
            permission: The required permission identifier.

        Returns:
            ``True`` if any of the principal's groups grant the permission
            (directly or via a wildcard when enabled), otherwise ``False``.
        """
        granted = await self.permissions_for(principal)
        return self._is_granted(granted, permission)

    @property
    def checker(self) -> Callable[[object, str], Awaitable[bool]]:
        """Return the bound :meth:`has_permission`, ready to hand to ``Guard``.

        Example:
            >>> from pl.afya.actionguard import Guard
            >>> rbac = GroupRBAC(
            ...     group_loader=lambda u: [],
            ...     permission_loader=lambda g: [],
            ... )
            >>> guard = Guard(  # doctest: +SKIP
            ...     principal_dependency=get_current_user,
            ...     permission_checker=rbac.checker,
            ... )
        """
        return self.has_permission

    def invalidate(self, group_id: str) -> None:
        """Drop the cached permissions of a single group.

        Call this right after a group's permissions change in your database so
        the next request re-reads them. Mirrors the cache-invalidation
        discipline used for other cached objects.

        Args:
            group_id: The identifier of the group whose cache entry to clear.
        """
        self._cache.pop(group_id, None)

    def invalidate_all(self) -> None:
        """Drop every cached group, forcing a full reload on next access."""
        self._cache.clear()

    async def _permissions_of_group(self, group_id: str) -> frozenset[str]:
        """Return a group's permissions, using and populating the cache.

        Args:
            group_id: The group identifier to resolve.

        Returns:
            The frozen set of permissions granted by the group.
        """
        if self._cache_enabled and group_id in self._cache:
            return self._cache[group_id]
        loaded = await _maybe_await(self._permission_loader(group_id))
        perms = frozenset(loaded)
        if self._cache_enabled:
            self._cache[group_id] = perms
        return perms

    def _is_granted(self, granted: frozenset[str], required: str) -> bool:
        """Decide whether ``required`` is covered by the ``granted`` set.

        Args:
            granted: The principal's effective permissions.
            required: The permission being checked.

        Returns:
            ``True`` on an exact match, or — when wildcards are enabled — when a
            covering ``"*"`` or ``"prefix.*"`` grant is present.
        """
        if required in granted:
            return True
        if not self._wildcard:
            return False
        if "*" in granted:
            return True
        prefix = required
        while "." in prefix:
            prefix = prefix.rsplit(".", 1)[0]
            if f"{prefix}.*" in granted:
                return True
        return False


async def _maybe_await(value: Iterable[str] | Awaitable[Iterable[str]]) -> Iterable[str]:
    """Await ``value`` if it is awaitable, otherwise return it unchanged.

    Args:
        value: A result that may be a plain iterable or an awaitable yielding
            one (supports both sync and async loaders).

    Returns:
        The resolved iterable.
    """
    if inspect.isawaitable(value):
        return await value
    return value


__all__ = ["GroupLoader", "GroupRBAC", "PermissionLoader"]
