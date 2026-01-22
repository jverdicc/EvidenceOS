"""Mock kernel harness (scaffold)."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MockEvidenceKernel:
    """Placeholder for upcoming UVP syscall simulation.

    This class intentionally provides no behavior yet, but it can be instantiated
    safely so tests can build on it without raising at import time.
    """

    calls: list[dict[str, Any]] = field(default_factory=list)

    def record_call(self, name: str, payload: dict[str, Any]) -> None:
        """Record a syscall invocation for future assertions."""
        self.calls.append({"name": name, "payload": payload})

    def reset(self) -> None:
        """Clear recorded calls."""
        self.calls.clear()
