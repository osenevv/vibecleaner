"""Adversarial probes: properties, mutation score, and differential checks."""

from vibecleaner.probes.differential import differential_check
from vibecleaner.probes.mutation import mutation_check
from vibecleaner.probes.properties import property_check
from vibecleaner.probes.spans import ChangedLines

__all__ = [
    "ChangedLines",
    "differential_check",
    "mutation_check",
    "property_check",
]
