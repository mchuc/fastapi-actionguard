# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Runtime enforcement of declared permissions (RBAC) as FastAPI dependencies.

ActionGuard deliberately knows nothing about your user model, authentication
scheme or database. Enforcement is wired through two application-supplied
callables:

* a *principal dependency* — your existing FastAPI dependency that resolves the
  current user (e.g. from a JWT), and
* a *permission checker* — a function answering "does this principal hold this
  permission?". This is where your role-to-permission mapping (RBAC) lives.

:class:`Guard` combines them into reusable ``requires(...)`` dependencies that
return the principal when access is granted and raise :class:`PermissionDenied`
(HTTP 403) otherwise.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, HTTPException
from starlette.status import HTTP_403_FORBIDDEN

from .audit import AuditEvent, AuditSink
from .policy import AccessRequest, Decision, Policy
from .policy import evaluate as evaluate_policy
from .registry import PermissionRegistry

#: A callable deciding whether ``principal`` holds ``permission``. May be sync or
#: async and receives the resolved principal and the permission identifier.
PermissionChecker = Callable[[Any, str], bool | Awaitable[bool]]


class PermissionDenied(HTTPException):
    """Raised when an authenticated principal lacks a required permission.

    A thin :class:`fastapi.HTTPException` subclass defaulting to HTTP 403 so it
    can be caught or customised distinctly from other HTTP errors.

    Attributes:
        permission: The permission identifier that was required.

    Example:
        >>> raise PermissionDenied("user.create")  # doctest: +SKIP
    """

    def __init__(
        self,
        permission: str,
        *,
        status_code: int = HTTP_403_FORBIDDEN,
        detail: str | None = None,
    ) -> None:
        """Initialise the error.

        Args:
            permission: The permission identifier that was required.
            status_code: HTTP status code to return. Defaults to ``403``.
            detail: Human-readable detail. A default mentioning the permission
                is used when omitted.
        """
        self.permission = permission
        super().__init__(
            status_code=status_code,
            detail=detail or f"Missing required permission: {permission}",
        )


class Guard:
    """Builds FastAPI dependencies that enforce declared permissions.

    The guard is configured once with how to obtain the current principal and
    how to check its permissions, then used throughout the application to
    protect endpoints.

    Args:
        principal_dependency: A FastAPI dependency callable returning the
            current principal (e.g. your ``get_current_user``). Whatever it
            returns is passed to ``permission_checker`` and to the endpoint.
        permission_checker: A callable ``(principal, permission) -> bool``
            deciding whether access is allowed. May be synchronous or
            asynchronous. This is where role-based logic belongs.
        status_code: HTTP status code raised on denial. Defaults to ``403``.
        audit: Optional sink receiving an :class:`~pl.afya.actionguard.audit.AuditEvent`
            for every audited check (both allowed and denied). May be sync or
            async.
        registry: Optional populated :class:`~pl.afya.actionguard.registry.PermissionRegistry`.
            When given, only permissions whose declaration sets ``log=True`` are
            audited. When omitted, every check is audited (the presence of a
            sink is the opt-in).

    Example:
        >>> from fastapi import FastAPI
        >>> from pl.afya.actionguard import Guard, actionguard_permission
        >>>
        >>> async def current_user() -> dict:
        ...     return {"roles": ["admin"], "perms": {"user.create"}}
        >>>
        >>> def has_permission(user: dict, perm: str) -> bool:
        ...     return perm in user["perms"]
        >>>
        >>> guard = Guard(
        ...     principal_dependency=current_user,
        ...     permission_checker=has_permission,
        ... )
        >>>
        >>> app = FastAPI()
        >>> @app.post("/users")
        ... @actionguard_permission("user.create", label="Create users")
        ... async def create_user(user=Depends(guard.requires("user.create"))):
        ...     return {"created_by": user}
    """

    def __init__(
        self,
        *,
        principal_dependency: Callable[..., Any],
        permission_checker: PermissionChecker | None = None,
        policy: Policy | None = None,
        status_code: int = HTTP_403_FORBIDDEN,
        audit: AuditSink | None = None,
        registry: PermissionRegistry | None = None,
    ) -> None:
        """Store the principal provider, decision logic and audit config.

        Provide ``permission_checker`` for the simple RBAC path (:meth:`requires`)
        and/or ``policy`` for the policy engine (:meth:`authorize`/:meth:`enforce`,
        covering RBAC + ABAC + custom rules). At least one is required for the
        corresponding methods to work.
        """
        self._principal_dependency = principal_dependency
        self._permission_checker = permission_checker
        self._policy = policy
        self._status_code = status_code
        self._audit = audit
        self._registry = registry

    def requires(
        self,
        permission: str,
        *,
        detail: str | None = None,
        audit: bool | None = None,
    ) -> Callable[..., Awaitable[Any]]:
        """Return a dependency enforcing ``permission`` for an endpoint.

        The returned dependency resolves the current principal via the
        configured ``principal_dependency``, runs the ``permission_checker`` and
        either returns the principal (so the endpoint can reuse it) or raises
        :class:`PermissionDenied`.

        Args:
            permission: The permission identifier required to proceed (should
                match a declared ``@permission`` identifier).
            detail: Optional human-readable message used when access is denied.
            audit: Override the audit decision for this dependency. ``True``
                always audits, ``False`` never does; ``None`` (default) defers
                to the guard's configuration (the ``log`` flag via the registry,
                or "audit all" when no registry was supplied).

        Returns:
            An ``async`` FastAPI dependency. Use it via ``Depends(...)`` either
            as an endpoint parameter (to receive the principal) or in the
            route's ``dependencies=[...]`` list.

        Example:
            >>> guard = Guard(  # doctest: +SKIP
            ...     principal_dependency=get_current_user,
            ...     permission_checker=has_permission,
            ... )
            >>> @app.delete(  # doctest: +SKIP
            ...     "/users/{user_id}",
            ...     dependencies=[Depends(guard.requires("user.delete"))],
            ... )
            ... @actionguard_permission("user.delete", label="Delete users")
            ... async def delete_user(user_id: int) -> None: ...
        """
        if self._permission_checker is None:
            raise RuntimeError(
                "Guard.requires needs a permission_checker; construct the guard "
                "with permission_checker=... (or use enforce()/authorize() with "
                "a policy)."
            )
        principal_dependency = self._principal_dependency
        permission_checker = self._permission_checker
        status_code = self._status_code

        async def dependency(
            principal: Any = Depends(principal_dependency),
        ) -> Any:
            allowed = permission_checker(principal, permission)
            if inspect.isawaitable(allowed):
                allowed = await allowed
            if allowed:
                await self._emit_audit(
                    permission=permission,
                    principal=principal,
                    allowed=True,
                    detail=None,
                    override=audit,
                )
                return principal
            error = PermissionDenied(
                permission, status_code=status_code, detail=detail
            )
            await self._emit_audit(
                permission=permission,
                principal=principal,
                allowed=False,
                detail=error.detail,
                override=audit,
            )
            raise error

        return dependency

    async def authorize(
        self,
        principal: Any,
        *,
        permission: str | None = None,
        resource: Any = None,
        attributes: Mapping[str, Any] | None = None,
        detail: str | None = None,
        audit: bool | None = None,
    ) -> Any:
        """Evaluate the configured policy and enforce its decision.

        The imperative counterpart to :meth:`requires`/:meth:`enforce`, intended
        to be called *inside* an endpoint once you have loaded everything the
        policy needs — most importantly the ``resource`` for attribute-based
        (ABAC) rules such as "may edit only their own object".

        Args:
            principal: The current principal (e.g. from your auth dependency).
            permission: The action/permission being requested, if any.
            resource: The object being accessed, for resource-based policies.
            attributes: Environment/subject attributes (region, IP, time, …).
            detail: Optional denial message.
            audit: Per-call audit override (``True``/``False``/``None``).

        Returns:
            The ``principal``, so the call can be inlined.

        Raises:
            RuntimeError: If the guard was created without a ``policy``.
            PermissionDenied: If the policy does not return ``PERMIT``.

        Example:
            >>> @app.patch("/places/{place_id}")  # doctest: +SKIP
            ... @actionguard_permission("place.edit", label="Edit places")
            ... async def edit_place(place_id: int, user=Depends(get_current_user)):
            ...     place = await load_place(place_id)
            ...     await guard.authorize(user, permission="place.edit", resource=place)
            ...     ...
        """
        if self._policy is None:
            raise RuntimeError(
                "Guard.authorize requires a policy; construct the guard with "
                "policy=... (see pl.afya.actionguard.policy)."
            )
        request = AccessRequest(
            principal=principal,
            permission=permission,
            resource=resource,
            attributes=attributes or {},
        )
        decision = await evaluate_policy(self._policy, request)
        allowed = decision is Decision.PERMIT
        if allowed:
            await self._emit_audit(
                permission=permission,
                principal=principal,
                allowed=True,
                detail=None,
                override=audit,
            )
            return principal
        error = PermissionDenied(
            permission or "policy", status_code=self._status_code, detail=detail
        )
        await self._emit_audit(
            permission=permission,
            principal=principal,
            allowed=False,
            detail=error.detail,
            override=audit,
        )
        raise error

    def enforce(
        self,
        permission: str | None = None,
        *,
        attributes: Mapping[str, Any]
        | Callable[[], Mapping[str, Any] | Awaitable[Mapping[str, Any]]]
        | None = None,
        detail: str | None = None,
        audit: bool | None = None,
    ) -> Callable[..., Awaitable[Any]]:
        """Return a dependency enforcing the configured policy for an endpoint.

        The declarative counterpart to :meth:`authorize`, for policies that need
        only the subject and environment (no per-request resource to load).

        Args:
            permission: The action/permission to evaluate, if any.
            attributes: Static environment attributes, or a zero-argument
                callable (sync or async) producing them at request time.
            detail: Optional denial message.
            audit: Per-call audit override (``True``/``False``/``None``).

        Returns:
            An ``async`` FastAPI dependency returning the principal on permit and
            raising :class:`PermissionDenied` otherwise.

        Example:
            >>> @app.get(  # doctest: +SKIP
            ...     "/reports",
            ...     dependencies=[Depends(guard.enforce("report.read"))],
            ... )
            ... async def reports() -> list: ...
        """
        principal_dependency = self._principal_dependency

        async def dependency(principal: Any = Depends(principal_dependency)) -> Any:
            attrs: Mapping[str, Any] | None
            if callable(attributes):
                produced = attributes()
                if inspect.isawaitable(produced):
                    produced = await produced
                attrs = produced
            else:
                attrs = attributes
            return await self.authorize(
                principal,
                permission=permission,
                attributes=attrs,
                detail=detail,
                audit=audit,
            )

        return dependency

    async def _emit_audit(
        self,
        *,
        permission: str | None,
        principal: Any,
        allowed: bool,
        detail: str | None,
        override: bool | None,
    ) -> None:
        """Send an :class:`AuditEvent` to the sink when the check is audited.

        Args:
            permission: The checked permission identifier, or ``None`` for a
                policy decision not tied to a single permission.
            principal: The principal the check ran against.
            allowed: Whether access was granted.
            detail: Optional message (denial detail on deny, ``None`` on allow).
            override: Per-call audit decision: ``True``/``False`` force the
                behaviour; ``None`` defers to the guard's configuration.
        """
        if self._audit is None:
            return
        if override is None:
            if self._registry is not None and permission is not None:
                spec = self._registry.get(permission)
                should_audit = bool(spec and spec.log)
            else:
                should_audit = True
        else:
            should_audit = override
        if not should_audit:
            return
        event = AuditEvent(
            permission=permission,
            allowed=allowed,
            principal=principal,
            timestamp=datetime.now(timezone.utc),
            detail=detail,
        )
        result = self._audit(event)
        if inspect.isawaitable(result):
            await result


__all__ = ["Guard", "PermissionChecker", "PermissionDenied"]
