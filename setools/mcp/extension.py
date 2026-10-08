# SPDX-License-Identifier: LGPL-2.1-only

from dataclasses import dataclass, field
import enum
from typing import Any, Awaitable, Callable, Mapping, Protocol


class AuditEventType(enum.StrEnum):

    """Reusable MCP server audit event types."""

    policy_acquire_started = enum.auto()
    policy_acquire_completed = enum.auto()
    policy_acquire_failed = enum.auto()
    policy_reference_used = enum.auto()
    session_evicted = enum.auto()


@dataclass(frozen=True)
class AuditEvent:

    """Structured, non-sensitive MCP server audit event."""

    event_type: AuditEventType
    session_id: str
    reference: str | None = None
    resolved_version: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


class AuditSink(Protocol):

    """Receive reusable MCP server audit events."""

    def emit(self, event: AuditEvent) -> None:
        """Record *event*."""


class NullAuditSink:

    """Discard audit events."""

    def emit(self, event: AuditEvent) -> None:
        """Discard *event*."""
        del event


@dataclass(frozen=True)
class ReadinessResult:

    """Result of one server readiness check."""

    name: str
    ready: bool
    detail: str | None = None


ReadinessCheck = Callable[[], ReadinessResult | Awaitable[ReadinessResult]]
