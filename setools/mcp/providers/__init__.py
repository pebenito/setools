# SPDX-License-Identifier: LGPL-2.1-only

"""Reusable policy-provider implementations."""

from .azure_devops import (AzureDevOpsProviderFactory, AzureDevOpsUniversalPackageProvider,
                           ExistingAzureCLIAuthentication, FeedScope,
                           ManagedIdentityAzureCLIAuthentication)
from .local import LocalPolicyProvider, LocalPolicyProviderFactory
from ..policy import PolicyProviderRegistry

__all__ = ("AzureDevOpsProviderFactory",
           "AzureDevOpsUniversalPackageProvider",
           "ExistingAzureCLIAuthentication",
           "FeedScope",
           "LocalPolicyProvider",
           "LocalPolicyProviderFactory",
           "ManagedIdentityAzureCLIAuthentication",
           "default_policy_provider_registry")


def default_policy_provider_registry(*, load_entry_points: bool = False) -> PolicyProviderRegistry:
    """Create the registry of built-in and optionally installed providers."""
    registry = PolicyProviderRegistry((LocalPolicyProviderFactory(), AzureDevOpsProviderFactory()))
    if load_entry_points:
        registry.load_entry_points()
    return registry
