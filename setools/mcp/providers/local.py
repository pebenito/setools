# SPDX-License-Identifier: LGPL-2.1-only

from pathlib import Path

from ..policy import PolicyArtifact, SessionOwner


class LocalPolicyProvider:

    """Acquire policies from paths on the server filesystem."""

    def acquire(self, reference: str, owner: SessionOwner) -> PolicyArtifact:
        """Return the local policy at *reference*."""
        del owner
        path = Path(reference)
        return PolicyArtifact(reference, path)
