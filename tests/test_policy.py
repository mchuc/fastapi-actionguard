# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Tests for the policy engine (RBAC + ABAC + custom) and Guard integration."""

from __future__ import annotations

import asyncio

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from pl.afya.actionguard import (
    AccessRequest,
    AttributePolicy,
    Decision,
    FunctionPolicy,
    Guard,
    PolicySet,
    RoleBasedPolicy,
    deny_overrides,
    first_applicable,
    permit_overrides,
)


def _run(coro):
    return asyncio.run(coro)


# --- Building blocks -------------------------------------------------------

def test_role_based_policy_permits_then_abstains() -> None:
    policy = RoleBasedPolicy(lambda user, perm: perm in user["perms"])
    permit = _run(policy(AccessRequest(principal={"perms": {"a"}}, permission="a")))
    abstain = _run(policy(AccessRequest(principal={"perms": set()}, permission="a")))
    assert permit is Decision.PERMIT
    assert abstain is Decision.NOT_APPLICABLE


def test_attribute_policy_abac() -> None:
    eu_only = AttributePolicy(lambda r: r.attributes.get("region") == "EU")
    assert _run(eu_only(AccessRequest(principal=None, attributes={"region": "EU"}))) is Decision.PERMIT
    assert _run(eu_only(AccessRequest(principal=None, attributes={"region": "US"}))) is Decision.NOT_APPLICABLE


def test_attribute_policy_as_prohibition() -> None:
    deny_blocked = AttributePolicy(
        lambda r: r.attributes.get("region") == "BLOCKED",
        on_match=Decision.DENY,
    )
    assert _run(deny_blocked(AccessRequest(principal=None, attributes={"region": "BLOCKED"}))) is Decision.DENY


def test_resource_based_abac_owns_object() -> None:
    own_only = AttributePolicy(lambda r: r.resource["owner_id"] == r.principal["id"])
    req_ok = AccessRequest(principal={"id": 1}, resource={"owner_id": 1})
    req_no = AccessRequest(principal={"id": 1}, resource={"owner_id": 2})
    assert _run(own_only(req_ok)) is Decision.PERMIT
    assert _run(own_only(req_no)) is Decision.NOT_APPLICABLE


def test_function_policy_localization() -> None:
    def regional(req: AccessRequest) -> Decision:
        return Decision.PERMIT if req.attributes.get("region") in {"PL", "DE"} else Decision.NOT_APPLICABLE

    policy = FunctionPolicy(regional, name="regional")
    assert _run(policy(AccessRequest(principal=None, attributes={"region": "PL"}))) is Decision.PERMIT
    assert _run(policy(AccessRequest(principal=None, attributes={"region": "FR"}))) is Decision.NOT_APPLICABLE


# --- Combining algorithms --------------------------------------------------

def test_deny_overrides() -> None:
    assert deny_overrides([Decision.PERMIT, Decision.DENY]) is Decision.DENY
    assert deny_overrides([Decision.PERMIT, Decision.NOT_APPLICABLE]) is Decision.PERMIT
    assert deny_overrides([Decision.NOT_APPLICABLE]) is Decision.NOT_APPLICABLE


def test_permit_overrides() -> None:
    assert permit_overrides([Decision.DENY, Decision.PERMIT]) is Decision.PERMIT
    assert permit_overrides([Decision.DENY, Decision.NOT_APPLICABLE]) is Decision.DENY


def test_first_applicable() -> None:
    assert first_applicable([Decision.NOT_APPLICABLE, Decision.DENY, Decision.PERMIT]) is Decision.DENY


def test_policy_set_rbac_and_abac() -> None:
    # RBAC must grant AND region must not be blocked (deny rail).
    rbac = RoleBasedPolicy(lambda u, p: p in u["perms"])
    region_rail = AttributePolicy(
        lambda r: r.attributes.get("region") == "BLOCKED",
        on_match=Decision.DENY,
    )
    policy = PolicySet([rbac, region_rail], algorithm=deny_overrides)

    allowed = _run(policy(AccessRequest(
        principal={"perms": {"a"}}, permission="a", attributes={"region": "EU"})))
    blocked = _run(policy(AccessRequest(
        principal={"perms": {"a"}}, permission="a", attributes={"region": "BLOCKED"})))
    no_role = _run(policy(AccessRequest(
        principal={"perms": set()}, permission="a", attributes={"region": "EU"})))

    assert allowed is Decision.PERMIT
    assert blocked is Decision.DENY          # deny rail overrides the RBAC permit
    assert no_role is Decision.NOT_APPLICABLE  # -> Guard treats as denied


def test_nested_policy_sets() -> None:
    editors = PolicySet(
        [AttributePolicy(lambda r: "editor" in r.principal["roles"])],
        algorithm=permit_overrides,
    )
    owners = PolicySet(
        [AttributePolicy(lambda r: r.resource["owner_id"] == r.principal["id"])],
        algorithm=permit_overrides,
    )
    # Either an editor OR the owner may proceed.
    policy = PolicySet([editors, owners], algorithm=permit_overrides)

    owner_req = AccessRequest(principal={"id": 1, "roles": []}, resource={"owner_id": 1})
    editor_req = AccessRequest(principal={"id": 9, "roles": ["editor"]}, resource={"owner_id": 1})
    stranger = AccessRequest(principal={"id": 9, "roles": []}, resource={"owner_id": 1})

    assert _run(policy(owner_req)) is Decision.PERMIT
    assert _run(policy(editor_req)) is Decision.PERMIT
    assert _run(policy(stranger)) is Decision.NOT_APPLICABLE


# --- Guard integration -----------------------------------------------------

def _user_dep():  # pragma: no cover - overridden
    raise NotImplementedError


def test_enforce_dependency_subject_and_environment() -> None:
    policy = PolicySet(
        [
            RoleBasedPolicy(lambda u, p: p in u["perms"]),
            AttributePolicy(
                lambda r: r.attributes.get("region") == "BLOCKED",
                on_match=Decision.DENY,
            ),
        ]
    )
    guard = Guard(principal_dependency=_user_dep, policy=policy)
    app = FastAPI()

    @app.get("/reports", dependencies=[Depends(guard.enforce("report.read", attributes={"region": "EU"}))])
    async def reports():
        return {"ok": True}

    app.dependency_overrides[_user_dep] = lambda: {"perms": {"report.read"}}
    assert TestClient(app).get("/reports").status_code == 200

    app.dependency_overrides[_user_dep] = lambda: {"perms": set()}
    assert TestClient(app).get("/reports").status_code == 403


def test_authorize_imperative_with_resource() -> None:
    policy = AttributePolicy(lambda r: r.resource["owner_id"] == r.principal["id"])
    guard = Guard(principal_dependency=_user_dep, policy=policy)
    app = FastAPI()

    PLACES = {1: {"owner_id": 1}, 2: {"owner_id": 99}}

    @app.patch("/places/{place_id}")
    async def edit_place(place_id: int, user=Depends(_user_dep)):
        place = PLACES[place_id]
        await guard.authorize(user, permission="place.edit", resource=place)
        return {"edited": place_id}

    app.dependency_overrides[_user_dep] = lambda: {"id": 1}
    client = TestClient(app)

    assert client.patch("/places/1").status_code == 200   # owns it
    assert client.patch("/places/2").status_code == 403   # someone else's


def test_authorize_without_policy_raises() -> None:
    guard = Guard(principal_dependency=_user_dep, permission_checker=lambda u, p: True)
    try:
        _run(guard.authorize({"id": 1}, permission="x"))
    except RuntimeError as exc:
        assert "policy" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_policy_decision_is_audited() -> None:
    events = []
    policy = RoleBasedPolicy(lambda u, p: p in u["perms"])
    guard = Guard(principal_dependency=_user_dep, policy=policy, audit=events.append)
    app = FastAPI()

    @app.get("/x", dependencies=[Depends(guard.enforce("x.read"))])
    async def x():
        return {}

    app.dependency_overrides[_user_dep] = lambda: {"perms": set()}
    TestClient(app).get("/x")

    assert len(events) == 1
    assert events[0].allowed is False
    assert events[0].permission == "x.read"
