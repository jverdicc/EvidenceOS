"""Evidence process and priors utilities."""

from evidenceos.evidence.bernoulli_evalue import bernoulli_e_increment
from evidenceos.evidence.eprocess import EProcessRecord
from evidenceos.evidence.ewl import EWLState
from evidenceos.evidence.priors import (
    PriorThreshold,
    compute_prior_threshold,
    prior_multiplier,
    validate_prior,
)

__all__ = [
    "bernoulli_e_increment",
    "EProcessRecord",
    "EWLState",
    "PriorThreshold",
    "compute_prior_threshold",
    "prior_multiplier",
    "validate_prior",
]
"""Evidence package for Reality Kernel scaffolding."""
