from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Tuple


@dataclass
class ClaimRecord:
    claim_id: str
    lineage_parent: str | None
    dependencies: Tuple[str, ...]
    status: str = "VERIFIED"  # VERIFIED / UNVERIFIED / TAINTED / REVOKED
    reason: str = ""


@dataclass
class RevocationLedger:
    claims: Dict[str, ClaimRecord] = field(default_factory=dict)
    dependents: Dict[str, set[str]] = field(default_factory=dict)

    def add_claim(
        self,
        claim_id: str,
        *,
        lineage_parent: str | None = None,
        dependencies: Iterable[str] = (),
    ) -> None:
        if not claim_id:
            raise ValueError("claim_id must be non-empty")
        deps = tuple(sorted(set(dependencies)))
        self.claims[claim_id] = ClaimRecord(
            claim_id=claim_id,
            lineage_parent=lineage_parent,
            dependencies=deps,
        )
        for dep in deps:
            self.dependents.setdefault(dep, set()).add(claim_id)
        if lineage_parent:
            self.dependents.setdefault(lineage_parent, set()).add(claim_id)

    def revoke(self, claim_id: str, reason: str) -> None:
        if claim_id not in self.claims:
            raise KeyError("claim_not_found")
        self._mark_recursive(claim_id, status="REVOKED", reason=reason)

    def _mark_recursive(self, claim_id: str, *, status: str, reason: str) -> None:
        record = self.claims[claim_id]
        record.status = status
        record.reason = reason
        for child in sorted(self.dependents.get(claim_id, set())):
            if child not in self.claims:
                continue
            child_record = self.claims[child]
            if status == "REVOKED":
                if child_record.status != "REVOKED":
                    child_record.status = "TAINTED"
                    child_record.reason = f"dependency_revoked:{claim_id}"
                self._mark_recursive(child, status="UNVERIFIED", reason=child_record.reason)
            else:
                if child_record.status != "REVOKED":
                    child_record.status = "UNVERIFIED"
                    child_record.reason = reason
