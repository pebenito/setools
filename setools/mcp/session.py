# SPDX-License-Identifier: LGPL-2.1-only

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import json
import logging
import secrets
import threading
from typing import Any, Callable, Final, Sequence

from setools import FileContexts, SELinuxPolicy
from fastmcp.server.dependencies import get_access_token, get_context
from .policy import PolicyArtifact, SessionOwner


LOCAL_SESSION: Final[str] = "__local__"
CALLER_SESSION: Final[str] = "__caller__"
DEFAULT_MAX_SESSION_ARTIFACTS: Final[int] = 8


@dataclass
class SessionData:

    """Policy data and acquired artifacts owned by one MCP session."""

    policies: dict[str | None, SELinuxPolicy] = field(default_factory=dict)
    file_contexts: dict[str | None, FileContexts] = field(default_factory=dict)
    artifacts: dict[str, PolicyArtifact] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)
    owner: SessionOwner | None = None
    max_artifacts: int = DEFAULT_MAX_SESSION_ARTIFACTS
    closed: bool = False

    def add_artifact(self, artifact: PolicyArtifact) -> str:
        """Store *artifact* and return an opaque session-owned reference."""
        return self.add_artifacts((artifact,))[0]

    def add_artifacts(self, artifacts: Sequence[PolicyArtifact]) -> list[str]:
        """
        Store all *artifacts* and return their opaque session-owned references.

        Either every artifact is stored or none are.  The caller retains
        ownership of the artifacts if this raises.
        """
        with self.lock:
            if self.closed:
                raise ValueError("The session was released; retry the request.")
            if len(self.artifacts) + len(artifacts) > self.max_artifacts:
                raise ValueError(f"A session may hold at most {self.max_artifacts} "
                                 "policy references.")
            references = [secrets.token_urlsafe(24) for _ in artifacts]
            self.artifacts.update(zip(references, artifacts))
            return references

    def get_artifact(self, reference: str) -> PolicyArtifact:
        """Return the artifact identified by *reference*."""
        with self.lock:
            try:
                return self.artifacts[reference]
            except KeyError as ex:
                raise KeyError("Unknown policy reference.") from ex

    def cleanup(self) -> None:
        """Release all artifacts owned by this session."""
        with self.lock:
            self.closed = True
            try:
                for artifact in self.artifacts.values():
                    if artifact.cleanup is not None:
                        try:
                            artifact.cleanup()
                        except Exception as ex:  # pylint: disable=broad-except
                            logging.getLogger(__name__).error(
                                f"Failed to release policy artifact: {type(ex).__name__}")
            finally:
                self.artifacts.clear()
                self.policies.clear()
                self.file_contexts.clear()


class SessionCache:

    """Bounded least-recently-used cache of isolated session data."""

    def __init__(self, max_sessions: int, *,
                 max_artifacts: int = DEFAULT_MAX_SESSION_ARTIFACTS,
                 on_evict: Callable[[SessionData], None] | None = None) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        if max_artifacts < 1:
            raise ValueError("max_artifacts must be at least 1")

        self.max_sessions: int = max_sessions
        self.max_artifacts: int = max_artifacts
        self.on_evict: Callable[[SessionData], None] | None = on_evict
        self._sessions: OrderedDict[str, SessionData] = OrderedDict()
        self._lock: threading.RLock = threading.RLock()

    @staticmethod
    def owner_key(owner: SessionOwner) -> str:
        """Return a non-reversible cache key for *owner*."""
        identity = json.dumps((owner.tenant_id, owner.caller_id, owner.session_id))
        return hashlib.sha256(identity.encode()).hexdigest()

    def get(self, owner: SessionOwner) -> SessionData:
        """Return data owned by *owner* and mark it recently used."""
        key = self.owner_key(owner)
        evicted: SessionData | None = None
        with self._lock:
            try:
                data = self._sessions.pop(key)
            except KeyError:
                data = SessionData(owner=owner, max_artifacts=self.max_artifacts)
            self._sessions[key] = data

            if len(self._sessions) > self.max_sessions:
                _, evicted = self._sessions.popitem(last=False)

        # Release outside the cache lock so a busy session cannot stall other owners.
        if evicted is not None:
            evicted.cleanup()
            if self.on_evict is not None:
                self.on_evict(evicted)

        return data

    def cleanup(self) -> None:
        """Release all cached sessions."""
        with self._lock:
            sessions = tuple(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.cleanup()


class FastMCPSessionOwnerProvider:

    """
    Resolve owners from the active FastMCP request context.

    Owners are bound to the authenticated principal (token issuer and
    subject or client ID) and, when the transport negotiated one, the MCP
    session ID.  Requests without a negotiated session, such as stateless
    HTTP requests, are owned by the principal alone.
    """

    def current_owner(self) -> SessionOwner:
        """Return the owner of the active MCP request or a local fallback owner."""
        try:
            context = get_context()
        except RuntimeError:
            return SessionOwner(LOCAL_SESSION)

        tenant_id: str | None = None
        caller_id: str | None = None
        token = get_access_token()
        if token is not None:
            claims: dict[str, Any] = token.claims or {}
            issuer = claims.get("iss")
            tenant_id = str(issuer) if issuer is not None else None
            subject = getattr(token, "subject", None) or claims.get("sub")
            caller_id = str(subject) if subject else f"client:{token.client_id}"

        return SessionOwner(self._negotiated_session_id(context) or CALLER_SESSION,
                            tenant_id, caller_id)

    @staticmethod
    def _negotiated_session_id(context: Any) -> str | None:
        """Return the transport-negotiated MCP session ID, if any."""
        try:
            session = context.session
        except RuntimeError:
            return None
        # FastMCP falls back to per-request IDs or the raw client header when
        # no session was negotiated, so only trust the connection's own ID.
        connection = getattr(session, "_connection", None)
        session_id = getattr(connection, "session_id", None)
        return session_id if isinstance(session_id, str) and session_id else None
