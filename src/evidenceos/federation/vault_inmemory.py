from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from evidenceos.common.canonical_json import canonical_dumps_bytes
from evidenceos.common.hashing import sha256_prefixed
from evidenceos.common.signing import Ed25519Keypair, sign_ed25519

from .types import (
    FederatedOracleQuery,
    FederatedOracleResponse,
    LocalLedgerSummary,
    ScoreBucket,
    VaultOracle,
)


@dataclass
class InMemoryVaultConfig:
    vault_id: str
    keypair: Ed25519Keypair
    integrity_state: str = "Trusted"
    dp_enabled: bool = False
    epsilon_spent: float = 0.0
    delta_spent: float = 0.0
    e_value: float = 1.0
    base_score: float = 0.80
    holdout_queries_max: int = 50


class InMemoryVault(VaultOracle):
    def __init__(self, cfg: InMemoryVaultConfig):
        self.cfg = cfg
        self._frozen: Dict[str, str] = {}
        self._queries: Dict[str, int] = {}

    def freeze(self, federation_id: str, frozen_plan_hash: str) -> str:
        self._frozen[federation_id] = frozen_plan_hash
        self._queries.setdefault(federation_id, 0)
        return frozen_plan_hash

    def query(self, q: FederatedOracleQuery) -> FederatedOracleResponse:
        if q.federation_id not in self._frozen:
            raise RuntimeError("vault_not_frozen")
        used = self._queries.get(q.federation_id, 0)
        if used >= self.cfg.holdout_queries_max:
            raise RuntimeError("vault_query_budget_exceeded")
        self._queries[q.federation_id] = used + 1

        lower = self.cfg.base_score - 0.001
        upper = self.cfg.base_score + 0.001

        canon = {
            "federation_id": q.federation_id,
            "query_id": q.query_id,
            "vault_id": self.cfg.vault_id,
            "mode": "INMEM",
            "score_bucket": {"lower": lower, "upper": upper},
            "e_value": self.cfg.e_value,
        }
        h = sha256_prefixed(canonical_dumps_bytes(canon))
        sig = sign_ed25519(self.cfg.keypair, canon)

        return FederatedOracleResponse(
            federation_id=q.federation_id,
            query_id=q.query_id,
            vault_id=self.cfg.vault_id,
            mode="INMEM",
            score_bucket=ScoreBucket(lower=lower, upper=upper),
            e_value=self.cfg.e_value,
            response_hash=h,
            signature=sig,
        )

    def ledger_summary(self, federation_id: str) -> LocalLedgerSummary:
        summ = {
            "vault_id": self.cfg.vault_id,
            "integrity_state": self.cfg.integrity_state,
            "evidence_lane": {"type": "e_wealth"},
            "privacy_lane": {
                "enabled": self.cfg.dp_enabled,
                "epsilon_spent": self.cfg.epsilon_spent,
                "delta_spent": self.cfg.delta_spent,
            },
            "adaptivity_lane": {
                "holdout_queries_used": self._queries.get(federation_id, 0),
                "holdout_queries_max": self.cfg.holdout_queries_max,
            },
        }
        h = sha256_prefixed(canonical_dumps_bytes(summ))
        sig = sign_ed25519(self.cfg.keypair, summ)
        return LocalLedgerSummary(
            vault_id=self.cfg.vault_id,
            integrity_state=self.cfg.integrity_state,  # type: ignore
            evidence_lane=summ["evidence_lane"],
            privacy_lane=summ["privacy_lane"],
            adaptivity_lane=summ["adaptivity_lane"],
            summary_hash=h,
            signature=sig,
        )
