# SPDX-License-Identifier: LGPL-2.1-only

from pathlib import Path
from typing import Mapping

from ..policy import PolicyArtifact, SessionOwner


class LocalPolicyProvider:

    """Acquire policies from paths on the server filesystem."""

    def acquire(self, reference: str, owner: SessionOwner) -> PolicyArtifact:
        """Return the local policy at *reference*."""
        del owner
        path = Path(reference)
        return PolicyArtifact(reference, path)


class LocalPolicyProviderFactory:

    """Create local-filesystem policy providers."""

    name = "local"

    def create(self, options: Mapping[str, str]) -> LocalPolicyProvider:
        """Create a local provider, which has no configuration options."""
        if options:
            raise ValueError(f"{min(options)} is not a valid local provider option")
        return LocalPolicyProvider()
