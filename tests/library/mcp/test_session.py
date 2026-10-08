# SPDX-License-Identifier: GPL-2.0-only

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from setools.mcp.policy import PolicyArtifact, SessionOwner
from setools.mcp.session import (CALLER_SESSION, LOCAL_SESSION, FastMCPSessionOwnerProvider,
                                 SessionCache)


def test_artifact_references_are_session_owned(tmp_path) -> None:
    """An opaque reference cannot resolve in another session."""
    cache = SessionCache(2)
    session_a = cache.get(SessionOwner("a"))
    session_b = cache.get(SessionOwner("b"))
    reference = session_a.add_artifact(PolicyArtifact("1.2.3", tmp_path / "policy"))

    assert session_a.get_artifact(reference).resolved_version == "1.2.3"
    with pytest.raises(KeyError, match="Unknown policy reference"):
        session_b.get_artifact(reference)


def test_eviction_cleans_only_evicted_session(tmp_path) -> None:
    """LRU eviction invokes cleanup only for the evicted owner."""
    cleaned: list[str] = []
    cache = SessionCache(2)
    session_a = cache.get(SessionOwner("a"))
    session_a.add_artifact(PolicyArtifact("1.0.0",
                                          tmp_path / "a", cleanup=lambda: cleaned.append("a")))
    session_b = cache.get(SessionOwner("b"))
    session_b.add_artifact(PolicyArtifact("2.0.0",
                                          tmp_path / "b", cleanup=lambda: cleaned.append("b")))

    evicted: list[SessionOwner | None] = []
    cache.on_evict = lambda session: evicted.append(session.owner)

    cache.get(SessionOwner("c"))

    assert cleaned == ["a"]
    assert evicted == [SessionOwner("a")]
    assert session_b.artifacts


def test_cleanup_failure_does_not_leak_remaining_artifacts(tmp_path) -> None:
    """One failing artifact cleanup does not prevent releasing remaining artifacts or sessions."""
    cleaned: list[str] = []

    def fail_cleanup() -> None:
        raise OSError("cleanup failed")

    cache = SessionCache(2)
    session_a = cache.get(SessionOwner("a"))
    session_a.add_artifact(PolicyArtifact("1.0.0", tmp_path / "a1", cleanup=fail_cleanup))
    session_a.add_artifact(PolicyArtifact("2.0.0", tmp_path / "a2",
                                          cleanup=lambda: cleaned.append("a2")))
    session_b = cache.get(SessionOwner("b"))
    session_b.add_artifact(PolicyArtifact("3.0.0", tmp_path / "b",
                                          cleanup=lambda: cleaned.append("b")))

    cache.cleanup()

    assert cleaned == ["a2", "b"]
    assert session_a.closed and not session_a.artifacts
    assert session_b.closed and not session_b.artifacts


def test_released_session_rejects_new_artifacts(tmp_path) -> None:
    """An artifact added after eviction is not silently orphaned in a released session."""
    cache = SessionCache(1)
    session = cache.get(SessionOwner("a"))
    cache.get(SessionOwner("b"))

    with pytest.raises(ValueError, match="released"):
        session.add_artifact(PolicyArtifact("1.0.0", tmp_path / "a"))
    assert not session.artifacts


def test_session_artifact_limit_is_atomic(tmp_path) -> None:
    """A batch that would exceed the per-session limit stores nothing."""
    session = SessionCache(1, max_artifacts=2).get(SessionOwner("a"))
    session.add_artifact(PolicyArtifact("1.0.0", tmp_path / "a"))

    with pytest.raises(ValueError, match="at most 2"):
        session.add_artifacts((PolicyArtifact("2.0.0", tmp_path / "b"),
                               PolicyArtifact("3.0.0", tmp_path / "c")))
    assert len(session.artifacts) == 1


def test_same_session_id_is_isolated_by_caller(tmp_path) -> None:
    """Different principals presenting the same session ID do not share artifacts."""
    cache = SessionCache(2)
    session_a = cache.get(SessionOwner("shared", "issuer", "alice"))
    session_b = cache.get(SessionOwner("shared", "issuer", "bob"))
    reference = session_a.add_artifact(PolicyArtifact("1.2.3", tmp_path / "policy"))

    assert session_a is not session_b
    with pytest.raises(KeyError):
        session_b.get_artifact(reference)


def owner_context(monkeypatch, connection_session_id: str | None, token: object = None) -> None:
    """Install a fake FastMCP request context and access token."""
    context = SimpleNamespace(
        session=SimpleNamespace(_connection=SimpleNamespace(session_id=connection_session_id)),
        session_id="per-request-or-client-header")
    monkeypatch.setattr("setools.mcp.session.get_context", lambda: context)
    monkeypatch.setattr("setools.mcp.session.get_access_token", lambda: token)


def test_owner_binds_negotiated_session_to_principal(monkeypatch) -> None:
    """Owners combine the token principal with the negotiated session ID."""
    token = SimpleNamespace(client_id="app", subject="alice", claims={"iss": "https://issuer"})
    owner_context(monkeypatch, "negotiated", token)

    assert FastMCPSessionOwnerProvider().current_owner() == SessionOwner("negotiated",
                                                                         "https://issuer",
                                                                         "alice")


def test_owner_without_negotiated_session_is_principal_scoped(monkeypatch) -> None:
    """Stateless requests ignore per-request and client-supplied IDs."""
    token = SimpleNamespace(client_id="app", subject=None, claims={})
    owner_context(monkeypatch, None, token)

    assert FastMCPSessionOwnerProvider().current_owner() == SessionOwner(CALLER_SESSION,
                                                                         None,
                                                                         "client:app")


def test_owner_outside_request_is_local(monkeypatch) -> None:
    """Direct calls outside an MCP request use the local owner."""
    def no_context() -> None:
        raise RuntimeError("No active context found.")

    monkeypatch.setattr("setools.mcp.session.get_context", no_context)

    assert FastMCPSessionOwnerProvider().current_owner() == SessionOwner(LOCAL_SESSION)


def test_concurrent_sessions_remain_isolated(tmp_path) -> None:
    """Concurrent owners receive distinct session data and references."""
    cache = SessionCache(16)

    def add_artifact(session_id: str) -> tuple[object, str]:
        session = cache.get(SessionOwner(session_id))
        reference = session.add_artifact(PolicyArtifact("1.0.0", tmp_path / session_id))
        return session, reference

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(add_artifact, (str(i) for i in range(8))))

    assert len({id(session) for session, _ in results}) == 8
    assert len({reference for _, reference in results}) == 8


def test_max_sessions_must_be_positive() -> None:
    """Session caches reject an unusable capacity."""
    with pytest.raises(ValueError, match="at least 1"):
        SessionCache(0)
    with pytest.raises(ValueError, match="at least 1"):
        SessionCache(1, max_artifacts=0)
