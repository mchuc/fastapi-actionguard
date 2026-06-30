# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""A small, composable authorization policy engine.

Three access-control styles are expressed through a single abstraction — a
*policy* that, given an :class:`AccessRequest`, returns a :class:`Decision`:

* **RBAC** — :class:`RoleBasedPolicy` wraps a role/permission check.
* **ABAC** — :class:`AttributePolicy` evaluates a predicate over the subject,
  resource and environment attributes.
* **Custom / local policies** — :class:`FunctionPolicy` adapts any function, so
  you can encode locally tuned rules (e.g. by region/localization).

Policies are combined with :class:`PolicySet` and a combining algorithm
(``deny_overrides`` by default), producing a single decision point you hand to
:class:`pl.afya.actionguard.enforcement.Guard`.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

#: What a policy may return: a :class:`Decision`, or a ``bool`` (``True`` →
#: ``PERMIT``, ``False`` → ``NOT_APPLICABLE``).
PolicyResult = "Decision | bool"

#: A policy is any callable mapping an :class:`AccessRequest` to a
#: :data:`PolicyResult`. May be synchronous or asynchronous.
Policy = Callable[["AccessRequest"], "PolicyResult | Awaitable[PolicyResult]"]


class Decision(Enum):
    """The outcome of evaluating a policy.

    Attributes:
        PERMIT: Access is explicitly allowed.
        DENY: Access is explicitly forbidden.
        NOT_APPLICABLE: The policy abstains (it has nothing to say).
    """

    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """The context a policy decides upon.

    Attributes:
        principal: The subject requesting access (your user object).
        permission: The action/permission identifier being requested, if any.
        resource: The object being accessed, if known (enables resource ABAC,
            e.g. "may edit only their own POI").
        attributes: Free-form environment/subject attributes (e.g. region, IP,
            time, brand) used by attribute-based policies.

    Example:
        >>> req = AccessRequest(principal={"id": 1}, permission="place.edit")
        >>> req.permission
        'place.edit'
    """

    principal: Any
    permission: str | None = None
    resource: Any | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)


async def evaluate(policy: Policy, request: AccessRequest) -> Decision:
    """Evaluate a policy against a request, normalising the result.

    Awaits asynchronous policies and coerces a ``bool`` result to a
    :class:`Decision` (``True`` → ``PERMIT``, ``False`` → ``NOT_APPLICABLE``).

    Args:
        policy: The policy callable to evaluate.
        request: The access request to decide upon.

    Returns:
        The resulting :class:`Decision`.

    Example:
        >>> import asyncio
        >>> asyncio.run(evaluate(lambda r: True, AccessRequest(principal=None)))
        <Decision.PERMIT: 'permit'>
    """
    result = policy(request)
    if inspect.isawaitable(result):
        result = await result
    if isinstance(result, Decision):
        return result
    return Decision.PERMIT if result else Decision.NOT_APPLICABLE


class RoleBasedPolicy:
    """RBAC policy: permit when the principal holds the requested permission.

    Wraps a ``checker(principal, permission) -> bool`` (the same shape used by
    :class:`pl.afya.actionguard.enforcement.Guard` and produced by
    :class:`pl.afya.actionguard.groups.GroupRBAC`). Permits on a positive check
    and otherwise abstains (``NOT_APPLICABLE``), so it composes with other
    policies; a final lack of permits denies via the combining algorithm.

    Args:
        checker: A callable deciding whether the principal holds the permission.
            May be sync or async.

    Example:
        >>> policy = RoleBasedPolicy(lambda user, perm: perm in user["perms"])
        >>> import asyncio
        >>> req = AccessRequest(principal={"perms": {"a"}}, permission="a")
        >>> asyncio.run(evaluate(policy, req))
        <Decision.PERMIT: 'permit'>
    """

    def __init__(
        self,
        checker: Callable[[Any, str], bool | Awaitable[bool]],
    ) -> None:
        """Store the permission checker."""
        self._checker = checker

    async def __call__(self, request: AccessRequest) -> Decision:
        """Evaluate the RBAC check for ``request``."""
        if request.permission is None:
            return Decision.NOT_APPLICABLE
        allowed = self._checker(request.principal, request.permission)
        if inspect.isawaitable(allowed):
            allowed = await allowed
        return Decision.PERMIT if allowed else Decision.NOT_APPLICABLE


class AttributePolicy:
    """ABAC policy: decide from a predicate over the request's attributes.

    The predicate receives the whole :class:`AccessRequest`, so it can read the
    subject (``request.principal``), the resource (``request.resource``) and the
    environment (``request.attributes``).

    Args:
        predicate: ``(request) -> bool``. May be sync or async.
        on_match: Decision returned when the predicate is true. Defaults to
            ``PERMIT``. Set to ``DENY`` to express a prohibition.
        on_miss: Decision returned when the predicate is false. Defaults to
            ``NOT_APPLICABLE`` (abstain).
        name: Optional human-readable name (useful in audit/debugging).

    Example:
        >>> # Allow only callers in the EU region.
        >>> eu_only = AttributePolicy(lambda r: r.attributes.get("region") == "EU")
        >>> import asyncio
        >>> asyncio.run(evaluate(eu_only, AccessRequest(principal=None,
        ...     attributes={"region": "EU"})))
        <Decision.PERMIT: 'permit'>
    """

    def __init__(
        self,
        predicate: Callable[[AccessRequest], bool | Awaitable[bool]],
        *,
        on_match: Decision = Decision.PERMIT,
        on_miss: Decision = Decision.NOT_APPLICABLE,
        name: str | None = None,
    ) -> None:
        """Store the predicate and the decisions to emit."""
        self._predicate = predicate
        self._on_match = on_match
        self._on_miss = on_miss
        self.name = name

    async def __call__(self, request: AccessRequest) -> Decision:
        """Evaluate the attribute predicate for ``request``."""
        matched = self._predicate(request)
        if inspect.isawaitable(matched):
            matched = await matched
        return self._on_match if matched else self._on_miss


class FunctionPolicy:
    """Adapt any function into a named policy.

    The escape hatch for locally tuned rules that do not fit RBAC or a single
    attribute predicate — the function may return a :class:`Decision` (full
    control) or a ``bool``.

    Args:
        func: ``(request) -> Decision | bool``. May be sync or async.
        name: Optional human-readable name.

    Example:
        >>> def local_rule(req: AccessRequest) -> Decision:
        ...     if req.attributes.get("region") in {"PL", "DE"}:
        ...         return Decision.PERMIT
        ...     return Decision.NOT_APPLICABLE
        >>> policy = FunctionPolicy(local_rule, name="regional")
        >>> policy.name
        'regional'
    """

    def __init__(
        self,
        func: Policy,
        *,
        name: str | None = None,
    ) -> None:
        """Store the wrapped function."""
        self._func = func
        self.name = name

    async def __call__(self, request: AccessRequest) -> Decision:
        """Evaluate the wrapped function for ``request``."""
        return await evaluate(self._func, request)


def deny_overrides(decisions: Iterable[Decision]) -> Decision:
    """Combine decisions so any ``DENY`` wins (default, safest).

    Args:
        decisions: The child decisions to combine.

    Returns:
        ``DENY`` if any decision denies; else ``PERMIT`` if any permits; else
        ``NOT_APPLICABLE``.
    """
    seen_permit = False
    for decision in decisions:
        if decision is Decision.DENY:
            return Decision.DENY
        if decision is Decision.PERMIT:
            seen_permit = True
    return Decision.PERMIT if seen_permit else Decision.NOT_APPLICABLE


def permit_overrides(decisions: Iterable[Decision]) -> Decision:
    """Combine decisions so any ``PERMIT`` wins.

    Args:
        decisions: The child decisions to combine.

    Returns:
        ``PERMIT`` if any decision permits; else ``DENY`` if any denies; else
        ``NOT_APPLICABLE``.
    """
    seen_deny = False
    for decision in decisions:
        if decision is Decision.PERMIT:
            return Decision.PERMIT
        if decision is Decision.DENY:
            seen_deny = True
    return Decision.DENY if seen_deny else Decision.NOT_APPLICABLE


def first_applicable(decisions: Iterable[Decision]) -> Decision:
    """Return the first decision that is not ``NOT_APPLICABLE``.

    Args:
        decisions: The child decisions to combine, in order.

    Returns:
        The first applicable decision, or ``NOT_APPLICABLE`` if all abstain.
    """
    for decision in decisions:
        if decision is not Decision.NOT_APPLICABLE:
            return decision
    return Decision.NOT_APPLICABLE


#: A combining algorithm reduces child decisions to one.
CombiningAlgorithm = Callable[[Iterable[Decision]], Decision]


class PolicySet:
    """Combine several policies into one using a combining algorithm.

    Child policies are evaluated in order and their decisions reduced by the
    chosen algorithm. A ``PolicySet`` is itself a policy, so sets may nest
    (e.g. an RBAC set permit-combined, AND-ed with an ABAC guard rail).

    Args:
        policies: The child policies to combine.
        algorithm: How to reduce child decisions. Defaults to
            :func:`deny_overrides`.
        name: Optional human-readable name.

    Example:
        >>> rbac = RoleBasedPolicy(lambda u, p: p in u["perms"])
        >>> region = AttributePolicy(
        ...     lambda r: r.attributes.get("region") != "BLOCKED",
        ...     on_miss=Decision.DENY,
        ... )
        >>> policy = PolicySet([rbac, region])
        >>> import asyncio
        >>> req = AccessRequest(principal={"perms": {"a"}}, permission="a",
        ...     attributes={"region": "EU"})
        >>> asyncio.run(evaluate(policy, req))
        <Decision.PERMIT: 'permit'>
    """

    def __init__(
        self,
        policies: Iterable[Policy],
        *,
        algorithm: CombiningAlgorithm = deny_overrides,
        name: str | None = None,
    ) -> None:
        """Store the child policies and combining algorithm."""
        self._policies = tuple(policies)
        self._algorithm = algorithm
        self.name = name

    async def __call__(self, request: AccessRequest) -> Decision:
        """Evaluate every child policy and combine the decisions."""
        decisions = [await evaluate(policy, request) for policy in self._policies]
        return self._algorithm(decisions)


__all__ = [
    "AccessRequest",
    "AttributePolicy",
    "CombiningAlgorithm",
    "Decision",
    "FunctionPolicy",
    "Policy",
    "PolicyResult",
    "PolicySet",
    "RoleBasedPolicy",
    "deny_overrides",
    "evaluate",
    "first_applicable",
    "permit_overrides",
]
