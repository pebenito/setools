# SPDX-License-Identifier: GPL-2.0-only

import enum

from setools.mcp.extension import (AuditEvent, AuditEventType, NullAuditSink,
                                   ReadinessResult)
from setools.mcp.policy import PolicyArtifact, SessionOwner


def test_audit_event_types_are_compatible_strings() -> None:
    """Audit event values are stable lower-case strings."""
    assert issubclass(AuditEventType, enum.StrEnum)
    assert all(event.value == event.name.lower() for event in AuditEventType)


def test_null_audit_sink_accepts_events() -> None:
    """The default audit sink accepts an event without side effects."""
    NullAuditSink().emit(AuditEvent(AuditEventType.session_evicted, "session"))


def test_extension_models(tmp_path) -> None:
    """Reusable extension models retain their supplied values."""
    owner = SessionOwner("session", "tenant", "caller")
    artifact = PolicyArtifact("1.2.3", tmp_path / "policy")
    readiness = ReadinessResult("provider", True)

    assert owner.caller_id == "caller"
    assert artifact.resolved_version == "1.2.3"
    assert readiness.ready
