# SPDX-License-Identifier: LGPL-2.1-only

"""Reusable policy-provider implementations."""

from .azure_devops import (AzureDevOpsProviderFactory, AzureDevOpsUniversalPackageProvider,
                           ExistingAzureCLIAuthentication, FeedScope,
                           ManagedIdentityAzureCLIAuthentication)
from .local import LocalPolicyProvider

__all__ = ("AzureDevOpsProviderFactory",
           "AzureDevOpsUniversalPackageProvider",
           "ExistingAzureCLIAuthentication",
           "FeedScope",
           "LocalPolicyProvider",
           "ManagedIdentityAzureCLIAuthentication")
