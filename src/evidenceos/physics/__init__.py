"""Physics modules for EvidenceOS."""

from evidenceos.physics.physhir import PhysHIR, PhysHIRCompiler, TargetSpec, VariableSpec
from evidenceos.physics.typecheck import Typechecker

__all__ = [
    "PhysHIR",
    "PhysHIRCompiler",
    "TargetSpec",
    "Typechecker",
    "VariableSpec",
]
"""Physics guards and invariants for EvidenceOS."""

from .constraints import (
    ConservationConstraint,
    ConstraintViolation,
    PinnedPrimary,
    RangeConstraint,
    validate_conservation,
    validate_pinned_primaries,
    validate_ranges,
)

__all__ = [
    "ConservationConstraint",
    "ConstraintViolation",
    "PinnedPrimary",
    "RangeConstraint",
    "validate_conservation",
    "validate_pinned_primaries",
    "validate_ranges",
]
"""Physics package for Reality Kernel scaffolding."""
