<!--
SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
SPDX-License-Identifier: AGPL-3.0-only
-->

# FastAPI ActionGuard

[English](https://github.com/mchuc/fastapi-actionguard/blob/HEAD/README.md) | **Polski**

Lekki, deklaratywny framework uprawnień dla [FastAPI](https://fastapi.tiangolo.com/).

Deklarujesz uprawnienia tam, gdzie żyją Twoje endpointy, a ActionGuard sam
buduje czytelny rejestr uprawnień przy starcie aplikacji. Endpointy bez
dekoratora `@actionguard_permission` są domyślnie publiczne — zero konfiguracji.

## Funkcje

- Deklaratywny dekorator `@actionguard_permission`, który nigdy nie zmienia działania endpointu.
- Automatyczne wykrywanie endpointów z aplikacji FastAPI/Starlette.
- Typowany, trzymany w pamięci rejestr uprawnień jako jedyne źródło prawdy.
- Czytelne etykiety, opisy i grupy do budowy interfejsów.
- Opcjonalna flaga audytu per-uprawnienie.
- W pełni typowany (`py.typed`), Pydantic v2, Python 3.12+.

## Instalacja

Pakiet nazywa się `pl-afya-actionguard`, a import to `pl.afya.actionguard`.

Projekt rozwijamy w [uv](https://docs.astral.sh/uv/):

```bash
uv add pl-afya-actionguard      # dodaj do projektu uv
# albo, pracując na tym repo:
uv sync                         # utwórz środowisko i zainstaluj zależności dev
uv run pytest                   # uruchom testy
```

To standardowy projekt PEP 621, więc zwykły `pip` też działa:

```bash
pip install pl-afya-actionguard
# ze źródeł, edytowalnie, z zależnościami testowymi:
pip install -e ".[test]"
```

### Eksport do pip / requirements.txt

Aby uzyskać artefakt instalowalny pipem lub `requirements.txt` z projektu uv:

```bash
# zbuduj wheel + sdist (instalacja: `pip install dist/*.whl`)
uv build                        # lub: python -m build

# wyeksportuj zablokowane zależności do pliku requirements pip
uv export --format requirements-txt --no-dev > requirements.txt
pip install -r requirements.txt
```

## Szybki start

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


@app.get("/health")  # brak dekoratora -> publiczny
async def health() -> dict[str, str]:
    return {"status": "ok"}


registry = discover_permissions(app)

for spec in registry:
    print(spec.permission, spec.methods, spec.path)
# user.create ('POST',) /users
```

Wystaw katalog uprawnień, np. dla panelu admina lub do synchronizacji
z zewnętrznym magazynem:

```python
@app.get("/_permissions")
async def list_permissions() -> list[dict]:
    return discover_permissions(app).to_list()
```

Wpis rejestru serializuje się do:

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

## Krok po kroku (dla początkujących)

Kompletny, działający przykład od zera. Skopiuj, uruchom, poklikaj.

**1. Zainstaluj pakiet (plus serwer do uruchomienia):**

```bash
pip install pl-afya-actionguard uvicorn
```

**2. Utwórz `app.py`:**

```python
from fastapi import Depends, FastAPI, Header
from pl.afya.actionguard import Guard, actionguard_permission, discover_permissions

app = FastAPI()

# --- 2a. Twoje uwierzytelnianie: zamień request na "bieżącego użytkownika". ---
# W realnej aplikacji czyta to JWT / sesję i ładuje usera z bazy.
# Tutaj udajemy: wyślij nagłówek "X-User: admin", żeby działać jako admin.
FAKE_USERS = {
    "admin": {"name": "admin", "permissions": {"user.create", "user.delete"}},
    "guest": {"name": "guest", "permissions": set()},
}

def get_current_user(x_user: str = Header(default="guest")) -> dict:
    return FAKE_USERS.get(x_user, FAKE_USERS["guest"])

# --- 2b. Powiedz ActionGuardowi, jak pobrać usera i jak sprawdzić uprawnienie. ---
guard = Guard(
    principal_dependency=get_current_user,
    permission_checker=lambda user, perm: perm in user["permissions"],
)

# --- 2c. Zadeklaruj uprawnienia na endpointach i egzekwuj je. ---
@app.post("/users")
@actionguard_permission("user.create", label="Create users", group="Users")
async def create_user(actor=Depends(guard.requires("user.create"))):
    return {"created_by": actor["name"]}

@app.get("/health")           # brak @actionguard_permission -> publiczny, każdy może wywołać
async def health():
    return {"status": "ok"}

# --- 2d. (Opcjonalnie) Zobacz wszystkie uprawnienia aplikacji przy starcie. ---
@app.on_event("startup")
async def show_permissions():
    for spec in discover_permissions(app):
        print(spec.permission, spec.methods, spec.path)
```

**3. Uruchom:**

```bash
uvicorn app:app --reload
```

**4. Przetestuj** (w drugim terminalu):

```bash
curl -s localhost:8000/health
# {"status":"ok"}                      <- publiczny, zawsze działa

curl -s -X POST localhost:8000/users -H "X-User: guest"
# {"detail":"Missing required permission: user.create"}   <- 403, brak uprawnienia

curl -s -X POST localhost:8000/users -H "X-User: admin"
# {"created_by":"admin"}               <- dozwolone
```

Cała idea: **zadeklaruj** uprawnienie na endpoincie, **egzekwuj** je przez
`guard.requires(...)`, a wszystko bez `@actionguard_permission` zostaje publiczne.

Dalej:

- uprawnienia per grupa, zarządzane w bazie → [Dynamiczne grupy](#dynamiczne-grupy-oparte-o-bazę),
- zapisywanie kto co wywołał → [Audyt](#audyt-logowanie-dostępu),
- pełna lista obiektów → [Publiczne API](#publiczne-api).

## Egzekwowanie RBAC

ActionGuard nigdy nie rozmawia z Twoją bazą ani modelem użytkownika. Podpinasz
dwie rzeczy, a on robi z nich wielokrotnego użytku zależności zwracające `403`:

1. **principal dependency** — Twoja istniejąca zależność zwracająca bieżącego
   użytkownika, oraz
2. **permission checker** — `(user, permission) -> bool`. Tu żyje Twoje
   mapowanie rola→uprawnienie (RBAC).

```python
from fastapi import Depends, FastAPI
from pl.afya.actionguard import Guard, actionguard_permission

guard = Guard(
    principal_dependency=get_current_user,           # Twoja zależność auth
    permission_checker=lambda user, perm: user.has_permission(perm),
)

app = FastAPI()


@app.post("/users")
@actionguard_permission("user.create", label="Create users", group="Users")
async def create_user(actor=Depends(guard.requires("user.create"))):
    # `actor` to rozwiązany principal; dotarcie tutaj oznacza przyznany dostęp.
    return {"created_by": actor.id}
```

`guard.requires(...)` zwraca principala, więc możesz użyć go jako parametru
endpointu albo wstawić w `dependencies=[...]` trasy, gdy endpoint nie potrzebuje
obiektu użytkownika:

```python
@app.delete("/users/{user_id}", dependencies=[Depends(guard.requires("user.delete"))])
@actionguard_permission("user.delete", label="Delete users")
async def delete_user(user_id: int) -> None:
    ...
```

Checker może być synchroniczny lub asynchroniczny, a status odmowy (domyślnie
`403`) i komunikat są konfigurowalne.

### Przykład: podpięcie istniejącej aplikacji opartej o role

Jeśli Twoja aplikacja już rozwiązuje użytkownika przez typowaną zależność i ma
sprawdzanie uprawnień oparte o role — np. alias `VERIFIED_USER =
Annotated[UserModel, Depends(get_verified_user)]` oraz metodę
`user.has_permissions(...)` opartą o tablicę rola→uprawnienie — podpięcie to
jedna linijka. Zmapuj tekstowe identyfikatory ActionGuarda na własny enum
uprawnień w checkerze:

```python
PERMS = {"user.create": TypUprawnien.dodaj_uzytkownika}

guard = Guard(
    principal_dependency=get_verified_user,
    permission_checker=lambda user, perm: user.has_permissions(PERMS[perm]),
)
```

### Dynamiczne grupy (oparte o bazę)

Gdy grupy są zarządzane w czasie działania — admin tworzy grupę, przypisuje jej
uprawnienia i dodaje userów, wszystko trzymane w bazie — użyj `GroupRBAC`.
Podajesz dwa loadery, a on tworzy gotowy checker dla `Guard`:

* `group_loader(principal)` → identyfikatory grup, do których należy user
  (zwykle czytane wprost z obiektu użytkownika),
* `permission_loader(group_id)` → uprawnienia tej grupy (odczyt z bazy).

`GroupRBAC` sumuje uprawnienia ze wszystkich grup usera. Wyniki per-grupa są
cache'owane; wywołaj `invalidate(group_id)` zaraz po zmianie grupy w bazie, żeby
zmiana zadziałała natychmiast, bez restartu. Każdy loader może być sync albo
async.

```python
from pl.afya.actionguard import Guard, GroupRBAC

async def load_group_permissions(group_id: str) -> set[str]:
    doc = await db.groups.find_one({"_id": group_id})
    return set(doc["permissions"])  # np. {"place.*", "user.create"}

rbac = GroupRBAC(
    group_loader=lambda user: user.group_ids,     # z obiektu użytkownika
    permission_loader=load_group_permissions,     # z bazy
)

guard = Guard(
    principal_dependency=get_current_user,
    permission_checker=rbac.checker,
)

# Po edycji grupy przez admina w panelu:
rbac.invalidate(changed_group_id)
```

Grupa może nadawać uprawnienia z wildcardem: `"place.*"` spełnia `place.create`,
`place.photo.delete` itd., a `"*"` daje wszystko. Podaj `wildcard=False`, aby
wymagać wyłącznie dokładnych identyfikatorów.

## Polityki: RBAC, ABAC i własne reguły

Do czegokolwiek poza pojedynczym sprawdzeniem uprawnienia ActionGuard ma mały
silnik polityk. **Polityka** to dowolny callable, który dla `AccessRequest`
zwraca `Decision` (`PERMIT`, `DENY` lub `NOT_APPLICABLE`). RBAC, ABAC i Twoje
własne lokalne reguły to po prostu polityki, łączone w jeden punkt decyzyjny.

```python
from pl.afya.actionguard import (
    AccessRequest, Decision, RoleBasedPolicy, AttributePolicy,
    FunctionPolicy, PolicySet, deny_overrides, permit_overrides,
)
```

`AccessRequest` niesie wszystko, na co polityka może patrzeć: `principal`
(podmiot), `permission` (akcja), `resource` (obiekt) i dowolne `attributes`
(środowisko: region, IP, czas, marka, …).

### Gotowe polityki

```python
# RBAC — pozwól, gdy user ma żądane uprawnienie.
rbac = RoleBasedPolicy(lambda user, perm: perm in user.permissions)

# ABAC — decyzja z atrybutów podmiotu / zasobu / środowiska.
owns_resource = AttributePolicy(lambda r: r.resource.owner_id == r.principal.id)

# Zakaz (deny rail): twardo blokuj region.
region_block = AttributePolicy(
    lambda r: r.attributes.get("region") == "BLOCKED",
    on_match=Decision.DENY,
)
```

### Własne polityki (np. lokalizacja)

`FunctionPolicy` opakowuje dowolną funkcję — furtka na lokalnie dostrojone
reguły. Polityka zwracająca `NOT_APPLICABLE` wstrzymuje się, oddając głos innym.

```python
def regional_rule(req: AccessRequest) -> Decision:
    """Lokalnie dostrojone: edytor działa tylko we własnym regionie."""
    if "editor" not in req.principal.roles:
        return Decision.NOT_APPLICABLE
    if req.attributes.get("region") == req.principal.region:
        return Decision.PERMIT
    return Decision.DENY

localization = FunctionPolicy(regional_rule, name="regional")
```

### Łączenie polityk

`PolicySet` redukuje decyzje algorytmem łączenia — `deny_overrides` (domyślny,
najbezpieczniejszy), `permit_overrides` lub `first_applicable`. Zestawy się
zagnieżdżają, więc wyrazisz „RBAC musi przyznać **i** żaden zakaz nie zadziałał":

```python
policy = PolicySet(
    [rbac, owns_resource, region_block, localization],
    algorithm=deny_overrides,
)
```

### Egzekwowanie polityki

Przekaż politykę do `Guard`. Dwa sposoby:

```python
guard = Guard(principal_dependency=get_current_user, policy=policy)

# Deklaratywnie — podmiot + środowisko, bez ładowania obiektu per request:
@app.get("/reports", dependencies=[Depends(guard.enforce("report.read",
                                                          attributes={"region": "EU"}))])
async def reports(): ...

# Imperatywnie — najpierw załaduj zasób, potem autoryzuj (ABAC na zasobie):
@app.patch("/places/{place_id}")
@actionguard_permission("place.edit", label="Edit places")
async def edit_place(place_id: int, user=Depends(get_current_user)):
    place = await load_place(place_id)
    await guard.authorize(user, permission="place.edit", resource=place)
    ...  # dotarcie tutaj = polityka przyznała dostęp
```

### Pobieranie i przypisywanie polityk do userów

Same polityki to statyczny kod; **dynamiczne** są dane, które czytają —
pobierasz je z bazy i dokładasz do principala lub żądania.

```python
# 1) Przypisanie: trzymaj role/grupy/atrybuty na userze (czytane w zależności auth).
async def get_current_user(token: str = ...) -> User:
    user = await db.users.find_one_by_token(token)
    return User(id=user["_id"], roles=user["roles"],
                region=user["region"], group_ids=user["groups"])

# 2) Pobierz uprawnienia grup z bazy i użyj GroupRBAC jako polityki RBAC:
from pl.afya.actionguard import GroupRBAC
rbac_dynamic = GroupRBAC(
    group_loader=lambda u: u.group_ids,
    permission_loader=lambda gid: db.groups.permissions(gid),  # odczyt z bazy, cache
)
policy = PolicySet([RoleBasedPolicy(rbac_dynamic.checker), region_block])

# 3) Albo wczytaj cały per-user zestaw polityk z zapisanej definicji:
async def policy_for(user: User) -> PolicySet:
    rules = await db.policies.for_user(user.id)        # Twoja własna tabela
    return PolicySet([build_policy(r) for r in rules])
```

Po zmianie grupy/polityki przez admina w bazie wołaj
`rbac_dynamic.invalidate(group_id)`, żeby zmiana zadziałała natychmiast.

### Przekazywanie danych między żądaniami (POST → GET)

HTTP jest bezstanowy: każde żądanie na nowo rozwiązuje principala przez zależność
auth, więc tożsamość i role płyną automatycznie — nigdy nie przekazujesz usera
ręcznie. Per request zmienia się **zasób** i **atrybuty środowiska**, które
składasz w endpoincie:

```python
# Atrybuty środowiska z żądania (wspólne dla GET/POST):
def request_attributes(request: Request) -> dict:
    return {"ip": request.client.host,
            "region": request.headers.get("X-Region", "EU"),
            "brand": request.headers.get("X-Brand")}

@app.post("/places")
async def create_place(body: PlaceIn, user=Depends(get_current_user),
                       attrs: dict = Depends(request_attributes)):
    await guard.authorize(user, permission="place.create", attributes=attrs)
    place = await db.places.insert(body, owner_id=user.id)
    return {"id": place.id}            # POST zwraca nowe id

@app.get("/places/{place_id}")
async def read_place(place_id: int, user=Depends(get_current_user),
                     attrs: dict = Depends(request_attributes)):
    place = await db.places.get(place_id)          # klient oddaje id z powrotem
    await guard.authorize(user, permission="place.read",
                          resource=place, attributes=attrs)
    return place
```

Wzorzec: **principal** z auth w każdym żądaniu, **resource** ładowany po id
(to id wędruje między odpowiedzią POST a późniejszym GET), a **attributes**
budowane per request wspólną zależnością. ActionGuard nie trzyma żadnego ukrytego
stanu między żądaniami.

## Audyt (logowanie dostępu)

Każde uprawnienie może włączyć audyt przez `log=True` w deklaracji. ActionGuard
zapisuje zdarzenie, ale nigdy nie decyduje, gdzie ono trafi — Ty dajesz *ujście
audytu* (dowolny callable przyjmujący `AuditEvent`), a `Guard` przekazuje mu
każde audytowane sprawdzenie, zarówno dozwolone, jak i odrzucone:

```python
from pl.afya.actionguard import Guard, discover_permissions

registry = PermissionRegistry()

def audit_sink(event):  # zapisz tak, jak chcesz
    db.audit.insert_one({
        "permission": event.permission,
        "allowed": event.allowed,
        "user_id": event.principal.id,        # wyciągnij własny identyfikator
        "detail": event.detail,
        "at": event.timestamp,                # UTC, tz-aware
    })

guard = Guard(
    principal_dependency=get_current_user,
    permission_checker=rbac.checker,
    audit=audit_sink,
    registry=registry,        # audytowane tylko uprawnienia z log=True
)

discover_permissions(app, registry)   # wypełnia rejestr; może być po konfiguracji guarda
```

Gdy podasz `registry`, audytowane są tylko uprawnienia, których deklaracja ma
`log=True`. Bez registry audytowane jest każde sprawdzenie (sam sink jest zgodą).
Pojedynczą zależność wymusisz też przez `guard.requires("user.delete",
audit=True)`. Sink może być sync albo async.

`AuditEvent` niesie `permission`, `allowed`, `principal`, `timestamp` (UTC,
tz-aware) oraz `detail` (komunikat odmowy przy odrzuceniu, `None` przy
zezwoleniu). Na szybki start `logging_audit_sink()` zapisuje zdarzenia przez
logger biblioteki standardowej `pl.afya.actionguard.audit`.

## Pokrycie endpointów

`discover_permissions` zbiera tylko chronione endpointy. Aby sprawdzić, *które*
części aplikacji są pilnowane, `discover_endpoints` listuje każdą trasę
i oznacza ją jako chronioną lub publiczną:

```python
from pl.afya.actionguard import discover_endpoints

for e in discover_endpoints(app):
    flag = e.permission.permission if e.protected else "PUBLIC"
    print(f"{flag:15} {','.join(e.methods):10} {e.path}")
# user.create     POST       /api/v1/users
# PUBLIC          GET        /api/v1/health
```

Wewnętrzne trasy FastAPI (`/docs`, `/openapi.json`, …) są domyślnie pomijane;
podaj `include_internal=True`, aby je dołączyć. Każdy wpis to `EndpointInfo`
z polami `path`, `methods`, `name`, `protected` oraz (gdy chroniony) pełną
specyfikacją `permission`.

## Publiczne API

Wszystko importujemy z `pl.afya.actionguard`.

| Obiekt | Przeznaczenie |
| --- | --- |
| `actionguard_permission(...)` | Dekorator deklarujący uprawnienie endpointu. |
| `discover_permissions(app)` | Buduje `PermissionRegistry` z aplikacji. |
| `discover_endpoints(app)` | Widok pokrycia: każda trasa, chroniona lub publiczna. |
| `PermissionRegistry` | Kolekcja wykrytych uprawnień po kluczu. |
| `PermissionSpec` / `EndpointInfo` | Niezmienne modele uprawnienia / endpointu. |
| `get_permission_spec(endpoint)` | Odczyt specyfikacji doklejonej do endpointu. |
| `Guard` | Buduje `requires(...)`/`enforce(...)` oraz `authorize(...)`. |
| `PermissionDenied` | `HTTPException` (403) przy odmowie dostępu. |
| `GroupRBAC` | Dynamiczne, oparte o bazę rozwiązywanie grupa → uprawnienia. |
| `RoleBasedPolicy` / `AttributePolicy` / `FunctionPolicy` | Polityki RBAC / ABAC / własne. |
| `PolicySet`, `deny_overrides`, `permit_overrides`, `first_applicable` | Łączenie polityk. |
| `AccessRequest` / `Decision` | Kontekst decyzji polityki / jej wynik. |
| `AuditEvent` | Jedno audytowane sprawdzenie (kto, co, kiedy, wynik). |
| `logging_audit_sink(...)` | Gotowe ujście audytu piszące przez logging. |

> **Wskazówka:** umieść `@actionguard_permission` bezpośrednio **pod** dekoratorem trasy, aby
> specyfikacja doklejała się do funkcji, którą FastAPI rejestruje jako endpoint.

## Rozwój

```bash
uv sync            # utwórz środowisko z zależnościami dev
uv run pytest      # uruchom testy
# alternatywa na czystym pip:
pip install -e ".[test]" && pytest
```

## Licencja

GNU Affero General Public License v3.0 (AGPL-3.0-only). Patrz
[LICENSE](https://github.com/mchuc/fastapi-actionguard/blob/HEAD/LICENSE).

Licencjonowanie komercyjne, profesjonalne wsparcie i konsulting są dostępne
bezpośrednio od właściciela praw — dane kontaktowe w pliku
[NOTICE](https://github.com/mchuc/fastapi-actionguard/blob/HEAD/NOTICE).
