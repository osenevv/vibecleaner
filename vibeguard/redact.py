"""Replace secret values before they are sent to a model or written to a report."""

from __future__ import annotations


from vibeguard.deterministic import mask_secrets as redact_secrets

__all__ = ["redact_secrets"]
