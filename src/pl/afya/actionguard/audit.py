# SPDX-FileCopyrightText: © 2026 Marcin Chuć <marcin-at-afya.pl>
# SPDX-License-Identifier: AGPL-3.0-only
#
# FastAPI ActionGuard
# Copyright (C) 2026 Marcin Chuć
# ORCID: https://orcid.org/0000-0002-8430-9763
#
# This file is part of FastAPI ActionGuard.
"""Audit logging of permission checks.

ActionGuard records *what* happened (an :class:`AuditEvent`) but never decides
*where* it goes. The application supplies an :data:`AuditSink` — any callable
receiving an event — and ActionGuard hands it every audited check. A ready-made
:func:`logging_audit_sink` writing through the standard library is included for
convenience.

Whether a given check is audited is governed by the per-permission ``log`` flag
declared with :func:`pl.afya.actionguard.permission`; see
:class:`pl.afya.actionguard.enforcement.Guard` for how the flag is consulted.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

#: A callable receiving an :class:`AuditEvent`. May be synchronous or async.
AuditSink = Callable[["AuditEvent"], "None | Awaitable[None]"]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A single audited permission check.

    Attributes:
        permission: The permission identifier that was checked, or ``None`` for
            a policy decision that is not tied to a single permission.
        allowed: ``True`` if access was granted, ``False`` if denied.
        principal: The principal the check ran against (your user object). The
            sink is responsible for extracting an identifier from it.
        timestamp: Timezone-aware UTC moment the check completed.
        detail: Optional message (e.g. the denial detail). ``None`` on allow.
    """

    permission: str | None
    allowed: bool
    principal: Any
    timestamp: datetime
    detail: str | None = None


def logging_audit_sink(
    logger: logging.Logger | None = None,
    *,
    level: int = logging.INFO,
) -> Callable[[AuditEvent], None]:
    """Return an :data:`AuditSink` that writes events via the standard library.

    Intended as a convenient default. Production systems will typically provide
    their own sink that persists a stable user identifier rather than the whole
    principal object.

    Args:
        logger: Logger to write to. Defaults to ``"pl.afya.actionguard.audit"``.
        level: Logging level for every event. Defaults to ``logging.INFO``.

    Returns:
        A synchronous sink callable.

    Example:
        >>> sink = logging_audit_sink()
        >>> callable(sink)
        True
    """
    log = logger or logging.getLogger("pl.afya.actionguard.audit")

    def sink(event: AuditEvent) -> None:
        log.log(
            level,
            "audit permission=%s allowed=%s principal=%r detail=%s at=%s",
            event.permission,
            event.allowed,
            event.principal,
            event.detail,
            event.timestamp.isoformat(),
        )

    return sink


__all__ = ["AuditEvent", "AuditSink", "logging_audit_sink"]
