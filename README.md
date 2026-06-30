<!--
SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
SPDX-License-Identifier: AGPL-3.0-only
-->

# FastAPI ActionGuard

**English** | [Polski](https://github.com/mchuc/fastapi-actionguard/blob/HEAD/README.pl.md)

A lightweight, declarative permission framework for [FastAPI](https://fastapi.tiangolo.com/).

Declare permissions where your endpoints live, and ActionGuard builds a
human-readable permission registry automatically at startup. Endpoints without a
`@actionguard_permission` decorator are public by default — zero configuration required.

## Features

- Declarative `@actionguard_permission` decorator that never alters endpoint behaviour.
- Automatic endpoint discovery from a FastAPI/Starlette app.
- A typed, in-memory permission registry as the single source of truth.
- Human-readable labels, descriptions and groups for building UIs.
- Optional per-permission audit-logging flag.
- Fully typed (`py.typed`), Pydantic v2, Python 3.12+.

## Installation

The package is named `pl-afya-actionguard` and imported as `pl.afya.actionguard`.

This project is developed with [uv](https://docs.astral.sh/uv/):

```bash
uv add pl-afya-actionguard      # add to a uv project
# or, working on this repo:
uv sync                         # create the env and install dev deps
uv run pytest                   # run the tests
```

It is a standard PEP 621 project, so plain `pip` works too:

```bash
pip install pl-afya-actionguard
# from source, editable, with test extras:
pip install -e ".[test]"
```

### Exporting for pip / requirements.txt

To produce a pip-installable artifact or a `requirements.txt` from the uv
project:

```bash
# build a wheel + sdist (installable with `pip install dist/*.whl`)
uv build                        # or: python -m build

# export the locked dependencies to a pip requirements file
uv export --format requirements-txt --no-dev > requirements.txt
pip install -r requirements.txt
```

## Quick start

```python
from fastapi import FastAPI
from pl.afya.actionguard import actionguard_permission, discover_permissions

app = FastAPI()


@app.post("/users")
@actionguard_permission(
    "user.create",
    label="Create users",
    group="Users",
    description="Allows creating new users",
    log=True,
)
async def create_user() -> None:
    ...


@app.get("/health")  # no decorator -> public
async def health() -> dict[str, str]:
    return {"status": "ok"}


registry = discover_permissions(app)

for spec in registry:
    print(spec.permission, spec.methods, spec.path)
# user.create ('POST',) /users
```

Expose the catalogue, e.g. for an admin UI or to synchronise an external store:

```python
@app.get("/_permissions")
async def list_permissions() -> list[dict]:
    return discover_permissions(app).to_list()
```

A registry entry serialises to:

```json
{
    "permission": "user.create",
    "label": "Create users",
    "description": "Allows creating new users",
    "group": "Users",
    "log": true,
    "methods": ["POST"],
    "path": "/users"
}
```

## Step by step (for beginners)

A complete, runnable example from zero. Copy it, run it, poke it.

**1. Install the package (plus a server to run it):**

```bash
pip install pl-afya-actionguard uvicorn
```

**2. Create `app.py`:**

```python
from fastapi import Depends, FastAPI, Header
from pl.afya.actionguard import Guard, actionguard_permission, discover_permissions

app = FastAPI()

# --- 2a. Your authentication: turn a request into a "current user". ---
# In a real app this reads a JWT / session and loads the user from a database.
# Here we fake it: send header "X-User: admin" to act as the admin.
FAKE_USERS = {
    "admin": {"name": "admin", "permissions": {"user.create", "user.delete"}},
    "guest": {"name": "guest", "permissions": set()},
}

def get_current_user(x_user: str = Header(default="guest")) -> dict:
    return FAKE_USERS.get(x_user, FAKE_USERS["guest"])

# --- 2b. Tell ActionGuard how to get the user and how to check a permission. ---
guard = Guard(
    principal_dependency=get_current_user,
    permission_checker=lambda user, perm: perm in user["permissions"],
)

# --- 2c. Declare permissions on endpoints and enforce them. ---
@app.post("/users")
@actionguard_permission("user.create", label="Create users", group="Users")
async def create_user(actor=Depends(guard.requires("user.create"))):
    return {"created_by": actor["name"]}

@app.get("/health")           # no @actionguard_permission -> public, anyone can call it
async def health():
    return {"status": "ok"}

# --- 2d. (Optional) See every permission your app declares, at startup. ---
@app.on_event("startup")
async def show_permissions():
    for spec in discover_permissions(app):
        print(spec.permission, spec.methods, spec.path)
```

**3. Run it:**

```bash
uvicorn app:app --reload
```

**4. Try it** (in another terminal):

```bash
curl -s localhost:8000/health
# {"status":"ok"}                      <- public, always works

curl -s -X POST localhost:8000/users -H "X-User: guest"
# {"detail":"Missing required permission: user.create"}   <- 403, no permission

curl -s -X POST localhost:8000/users -H "X-User: admin"
# {"created_by":"admin"}               <- allowed
```

That's the whole idea: **declare** a permission on the endpoint, **enforce** it
with `guard.requires(...)`, and anything without `@actionguard_permission` stays public.

From here:

- permissions per group, managed in a database → [Dynamic groups](#dynamic-groups-database-backed),
- recording who accessed what → [Audit logging](#audit-logging),
- the full list of objects → [Public API](#public-api).

## RBAC enforcement

ActionGuard never talks to your database or user model. You plug in two things
and ActionGuard turns them into reusable `403`-raising dependencies:

1. a **principal dependency** — your existing dependency that returns the
   current user, and
2. a **permission checker** — `(user, permission) -> bool`. Your role-to-permission
   mapping (RBAC) lives here.

```python
from fastapi import Depends, FastAPI
from pl.afya.actionguard import Guard, actionguard_permission

guard = Guard(
    principal_dependency=get_current_user,           # your auth dependency
    permission_checker=lambda user, perm: user.has_permission(perm),
)

app = FastAPI()


@app.post("/users")
@actionguard_permission("user.create", label="Create users", group="Users")
async def create_user(actor=Depends(guard.requires("user.create"))):
    # `actor` is the resolved principal; reaching here means access was granted.
    return {"created_by": actor.id}
```

`guard.requires(...)` returns the principal, so you can use it as an endpoint
parameter, or put it in the route's `dependencies=[...]` when the endpoint does
not need the user object:

```python
@app.delete("/users/{user_id}", dependencies=[Depends(guard.requires("user.delete"))])
@actionguard_permission("user.delete", label="Delete users")
async def delete_user(user_id: int) -> None:
    ...
```

The checker may be synchronous or asynchronous, and the denial status code
(default `403`) and message are configurable.

### Example: wiring an existing role-based app

If your app already resolves the user through a typed dependency and exposes a
role-driven permission check — e.g. a `VERIFIED_USER = Annotated[UserModel,
Depends(get_verified_user)]` alias and a `user.has_permissions(...)` method
backed by a role→permission table — wiring is a one-liner. Map ActionGuard's
string identifiers to your own permission enum in the checker:

```python
PERMS = {"user.create": TypUprawnien.dodaj_uzytkownika}

guard = Guard(
    principal_dependency=get_verified_user,
    permission_checker=lambda user, perm: user.has_permissions(PERMS[perm]),
)
```

### Dynamic groups (database-backed)

When groups are managed at runtime — an admin creates a group, assigns it
permissions and adds users, all stored in a database — use `GroupRBAC`. You
supply two loaders and it produces a ready-made checker for the `Guard`:

* `group_loader(principal)` → the group identifiers the user belongs to
  (usually read straight off the user object),
* `permission_loader(group_id)` → that group's permissions (a database read).

`GroupRBAC` unions the permissions across all the user's groups. Per-group
results are cached; call `invalidate(group_id)` right after a group changes in
the database so the change takes effect immediately, without a restart. Either
loader may be synchronous or asynchronous.

```python
from pl.afya.actionguard import Guard, GroupRBAC

async def load_group_permissions(group_id: str) -> set[str]:
    doc = await db.groups.find_one({"_id": group_id})
    return set(doc["permissions"])  # e.g. {"place.*", "user.create"}

rbac = GroupRBAC(
    group_loader=lambda user: user.group_ids,     # from the user object
    permission_loader=load_group_permissions,     # from the database
)

guard = Guard(
    principal_dependency=get_current_user,
    permission_checker=rbac.checker,
)

# After an admin edits a group in your admin panel:
rbac.invalidate(changed_group_id)
```

A group may grant wildcard permissions: `"place.*"` satisfies `place.create`,
`place.photo.delete`, etc., and `"*"` grants everything. Pass `wildcard=False`
to require exact identifiers only.

## Policies: RBAC, ABAC and custom rules

For anything beyond a single permission check, ActionGuard ships a small policy
engine. A **policy** is any callable that, given an `AccessRequest`, returns a
`Decision` (`PERMIT`, `DENY` or `NOT_APPLICABLE`). RBAC, ABAC and your own local
rules are all just policies, combined into one decision point.

```python
from pl.afya.actionguard import (
    AccessRequest, Decision, RoleBasedPolicy, AttributePolicy,
    FunctionPolicy, PolicySet, deny_overrides, permit_overrides,
)
```

An `AccessRequest` carries everything a policy may look at: the `principal`
(subject), the `permission` (action), the `resource` (object being accessed)
and free-form `attributes` (environment: region, IP, time, brand, …).

### Ready-made policies

```python
# RBAC — permit when the user holds the requested permission.
rbac = RoleBasedPolicy(lambda user, perm: perm in user.permissions)

# ABAC — decide from attributes of subject / resource / environment.
owns_resource = AttributePolicy(lambda r: r.resource.owner_id == r.principal.id)

# A prohibition (deny rail): block a region outright.
region_block = AttributePolicy(
    lambda r: r.attributes.get("region") == "BLOCKED",
    on_match=Decision.DENY,
)
```

### Custom policies (e.g. localization)

`FunctionPolicy` adapts any function — the escape hatch for locally tuned rules.
A policy returning `NOT_APPLICABLE` abstains, letting other policies decide.

```python
def regional_rule(req: AccessRequest) -> Decision:
    """Locally tuned: editors may act only within their own region."""
    if "editor" not in req.principal.roles:
        return Decision.NOT_APPLICABLE
    if req.attributes.get("region") == req.principal.region:
        return Decision.PERMIT
    return Decision.DENY

localization = FunctionPolicy(regional_rule, name="regional")
```

### Combining policies

`PolicySet` reduces child decisions with a combining algorithm —
`deny_overrides` (default, safest), `permit_overrides`, or `first_applicable`.
Sets nest, so you can express "RBAC must grant **and** no deny rail fires":

```python
policy = PolicySet(
    [rbac, owns_resource, region_block, localization],
    algorithm=deny_overrides,
)
```

### Enforcing a policy

Hand the policy to the `Guard`. Two ways to enforce it:

```python
guard = Guard(principal_dependency=get_current_user, policy=policy)

# Declarative — subject + environment, no per-request object to load:
@app.get("/reports", dependencies=[Depends(guard.enforce("report.read",
                                                          attributes={"region": "EU"}))])
async def reports(): ...

# Imperative — load the resource first, then authorize (resource ABAC):
@app.patch("/places/{place_id}")
@actionguard_permission("place.edit", label="Edit places")
async def edit_place(place_id: int, user=Depends(get_current_user)):
    place = await load_place(place_id)
    await guard.authorize(user, permission="place.edit", resource=place)
    ...  # reaching here means the policy permitted
```

### Loading & assigning policies to users

Policies themselves are static code; what is *dynamic* is the data they read —
which you fetch from your database and attach to the principal or the request.

```python
# 1) Assign by storing role/group/attributes on the user (read in your auth dep).
async def get_current_user(token: str = ...) -> User:
    user = await db.users.find_one_by_token(token)
    return User(id=user["_id"], roles=user["roles"],
                region=user["region"], group_ids=user["groups"])

# 2) Fetch group permissions from the DB and let GroupRBAC be the RBAC policy:
from pl.afya.actionguard import GroupRBAC
rbac_dynamic = GroupRBAC(
    group_loader=lambda u: u.group_ids,
    permission_loader=lambda gid: db.groups.permissions(gid),  # DB read, cached
)
policy = PolicySet([RoleBasedPolicy(rbac_dynamic.checker), region_block])

# 3) Or load a whole per-user policy set from a stored definition:
async def policy_for(user: User) -> PolicySet:
    rules = await db.policies.for_user(user.id)        # your own table
    return PolicySet([build_policy(r) for r in rules])
```

After an admin changes a group/policy in the database, call
`rbac_dynamic.invalidate(group_id)` so the change applies immediately.

### Passing data between requests (POST → GET)

HTTP is stateless: each request re-resolves the principal through your auth
dependency, so identity and roles flow automatically — you never thread the user
manually. What varies per request is the **resource** and the **environment
attributes**, which you assemble inside the endpoint:

```python
# Environment attributes derived from the request (shared across GET/POST):
def request_attributes(request: Request) -> dict:
    return {"ip": request.client.host,
            "region": request.headers.get("X-Region", "EU"),
            "brand": request.headers.get("X-Brand")}

@app.post("/places")
async def create_place(body: PlaceIn, user=Depends(get_current_user),
                       attrs: dict = Depends(request_attributes)):
    await guard.authorize(user, permission="place.create", attributes=attrs)
    place = await db.places.insert(body, owner_id=user.id)
    return {"id": place.id}            # the POST returns the new id

@app.get("/places/{place_id}")
async def read_place(place_id: int, user=Depends(get_current_user),
                     attrs: dict = Depends(request_attributes)):
    place = await db.places.get(place_id)          # client passes the id back
    await guard.authorize(user, permission="place.read",
                          resource=place, attributes=attrs)
    return place
```

The pattern: the **principal** comes from auth on every request, **resource**
is loaded by id (the id is what travels between a POST response and a later GET),
and **attributes** are rebuilt per request via a shared dependency. ActionGuard
keeps no hidden cross-request state.

## Audit logging

Each permission can opt into auditing with `log=True` on its declaration.
ActionGuard records the event but never decides where it goes — you supply an
*audit sink* (any callable receiving an `AuditEvent`) and the `Guard` hands it
every audited check, both allowed and denied:

```python
from pl.afya.actionguard import Guard, discover_permissions

registry = PermissionRegistry()

def audit_sink(event):  # persist however you like
    db.audit.insert_one({
        "permission": event.permission,
        "allowed": event.allowed,
        "user_id": event.principal.id,        # extract your own identifier
        "detail": event.detail,
        "at": event.timestamp,                # tz-aware UTC
    })

guard = Guard(
    principal_dependency=get_current_user,
    permission_checker=rbac.checker,
    audit=audit_sink,
    registry=registry,        # only permissions declared with log=True are audited
)

discover_permissions(app, registry)   # fills the registry; may run after guard setup
```

When a `registry` is supplied, only permissions whose declaration sets
`log=True` are audited. Without a registry, every check is audited (providing a
sink is the opt-in). You can also force a single dependency with
`guard.requires("user.delete", audit=True)`. The sink may be sync or async.

An `AuditEvent` carries `permission`, `allowed`, `principal`, `timestamp`
(tz-aware UTC) and `detail` (the denial message on deny, `None` on allow). For a
quick start, `logging_audit_sink()` writes events through the standard library
logger `pl.afya.actionguard.audit`.

## Endpoint coverage

`discover_permissions` only collects the protected endpoints. To audit *which*
parts of your app are guarded, `discover_endpoints` lists every route and marks
each as protected or public:

```python
from pl.afya.actionguard import discover_endpoints

for e in discover_endpoints(app):
    flag = e.permission.permission if e.protected else "PUBLIC"
    print(f"{flag:15} {','.join(e.methods):10} {e.path}")
# user.create     POST       /api/v1/users
# PUBLIC          GET        /api/v1/health
```

FastAPI's internal routes (`/docs`, `/openapi.json`, …) are omitted by default;
pass `include_internal=True` to include them. Each entry is an `EndpointInfo`
with `path`, `methods`, `name`, `protected` and (when protected) the full
`permission` spec.

## Public API

All objects are imported from `pl.afya.actionguard`.

| Object | Purpose |
| --- | --- |
| `actionguard_permission(...)` | Decorator declaring an endpoint's permission. |
| `discover_permissions(app)` | Build a `PermissionRegistry` from an app. |
| `discover_endpoints(app)` | Coverage view: every route, protected or public. |
| `PermissionRegistry` | Keyed collection of discovered permissions. |
| `PermissionSpec` / `EndpointInfo` | Immutable models for a permission / endpoint. |
| `get_permission_spec(endpoint)` | Read the spec attached to an endpoint. |
| `Guard` | Builds `requires(...)`/`enforce(...)` deps and `authorize(...)`. |
| `PermissionDenied` | `HTTPException` (403) raised when access is denied. |
| `GroupRBAC` | Dynamic, database-backed group → permission resolution. |
| `RoleBasedPolicy` / `AttributePolicy` / `FunctionPolicy` | RBAC / ABAC / custom policies. |
| `PolicySet`, `deny_overrides`, `permit_overrides`, `first_applicable` | Combine policies. |
| `AccessRequest` / `Decision` | The context a policy decides upon / its outcome. |
| `AuditEvent` | One audited permission check (who, what, when, allowed). |
| `logging_audit_sink(...)` | Ready-made audit sink writing via stdlib logging. |

> **Tip:** apply `@actionguard_permission` directly **below** the route decorator so the spec
> attaches to the function FastAPI registers as the endpoint.

## Development

```bash
uv sync            # create the environment with dev dependencies
uv run pytest      # run the test suite
# plain pip alternative:
pip install -e ".[test]" && pytest
```

## License

GNU Affero General Public License v3.0 (AGPL-3.0-only). See
[LICENSE](https://github.com/mchuc/fastapi-actionguard/blob/HEAD/LICENSE).

Commercial licensing, professional support and consulting are available
directly from the copyright holder — see
[NOTICE](https://github.com/mchuc/fastapi-actionguard/blob/HEAD/NOTICE) for
contact details.
