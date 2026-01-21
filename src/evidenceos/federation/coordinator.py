from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from evidenceos.common.canonical_json import canonical_dumps_bytes
from evidenceos.common.hashing import sha256_prefixed
from evidenceos.common.signing import verify_ed25519

from .merger import MergeInputs, Merger
from .types import FederatedOracleQuery, FederatedOracleResponse, FederationContract, GlobalLedger, LocalLedgerSummary, VaultOracle
from .transcript_hash import transcript_hash


def _pubkey_from_hex(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


def _canonical_response_for_verify(r: FederatedOracleResponse) -> dict:
    # Exclude signature; hash is computed over these fields.
    return {
        "federation_id": r.federation_id,
        "query_id": r.query_id,
        "vault_id": r.vault_id,
        "mode": r.mode,
        "score_bucket": {"lower": r.score_bucket.lower, "upper": r.score_bucket.upper},
        "e_value": r.e_value,
    }


@dataclass
class FederationTranscript:
    federation_id: str
    frozen: bool = False
    queries: List[dict] = field(default_factory=list)
    responses: List[dict] = field(default_factory=list)
    local_ledgers: List[dict] = field(default_factory=list)
    quorum_not_met: bool = False

    def to_obj(self) -> dict:
        return {
            "federation_id": self.federation_id,
            "frozen": self.frozen,
            "quorum_not_met": self.quorum_not_met,
            "queries": self.queries,
            "responses": self.responses,
            "local_ledgers": self.local_ledgers,
        }

    def semantic_hash(self) -> str:
        # Redact nondeterministic fields before hashing.
        return "sha256:" + transcript_hash(self.to_obj())


class FederationCoordinator:
    def __init__(self, contract: FederationContract):
        self.contract = contract
        self.merger = Merger(contract.merge_policy)
        self.transcript = FederationTranscript(federation_id=contract.federation_id)

    def freeze(self, vaults: Dict[str, VaultOracle]) -> None:
        if self.transcript.frozen:
            return
        for v in self.contract.vaults:
            vaults[v.vault_id].freeze(self.contract.federation_id, self.contract.frozen_plan_hash)
        self.transcript.frozen = True

    def query_vaults(self, q: FederatedOracleQuery, vaults: Dict[str, VaultOracle]) -> List[FederatedOracleResponse]:
        if not self.transcript.frozen:
            raise RuntimeError("must_freeze_before_query")

        self.transcript.queries.append(q.__dict__)
        resps: List[FederatedOracleResponse] = []
        for vid in q.target_vaults:
            r = vaults[vid].query(q)
            # Verify hash + signature
            canon = _canonical_response_for_verify(r)
            expected_hash = sha256_prefixed(canonical_dumps_bytes(canon))
            if r.response_hash != expected_hash:
                raise RuntimeError("invalid_signature_or_hash")
            vd = next(v for v in self.contract.vaults if v.vault_id == r.vault_id)
            pk = _pubkey_from_hex(vd.vault_pubkey_hex)
            if not verify_ed25519(pk, canon, r.signature):
                raise RuntimeError("invalid_signature_or_hash")

            resps.append(r)
            # Store response dict with signature included for audit (not for semantic hash)
            self.transcript.responses.append({**canon, "response_hash": r.response_hash, "signature": r.signature})
        # quorum enforcement
        min_quorum = self.contract.merge_policy.dropout_policy.min_quorum
        if len(resps) < min_quorum:
            if self.contract.merge_policy.dropout_policy.mode == "fail_closed":
                raise RuntimeError("quorum_not_met")
            self.transcript.quorum_not_met = True
        return resps

    def collect_local_ledgers(self, vaults: Dict[str, VaultOracle]) -> List[LocalLedgerSummary]:
        ledgers: List[LocalLedgerSummary] = []
        for v in self.contract.vaults:
            ledgers.append(vaults[v.vault_id].ledger_summary(self.contract.federation_id))
        self.transcript.local_ledgers = [l.__dict__ for l in ledgers]
        return ledgers

    def compute_global_ledger(self) -> GlobalLedger:
        if self.contract.merge_policy.dropout_policy.mode == "fail_closed" and self.transcript.quorum_not_met:
            raise RuntimeError("quorum_not_met")

        local = [LocalLedgerSummary(**l) for l in self.transcript.local_ledgers]  # type: ignore[arg-type]

        weights = []
        for v in self.contract.vaults:
            weights.append(v.population_weight if v.population_weight is not None else 1.0)

        last_e: Dict[str, float] = {}
        for r in self.transcript.responses:
            if r.get("e_value") is not None:
                last_e[r["vault_id"]] = float(r["e_value"])

        evalues = [last_e.get(v.vault_id, 1.0) for v in self.contract.vaults]

        eps = []
        dls = []
        for l in local:
            eps.append(l.privacy_lane.get("epsilon_spent") if l.privacy_lane.get("enabled") else None)
            dls.append(l.privacy_lane.get("delta_spent") if l.privacy_lane.get("enabled") else None)

        inputs = MergeInputs(
            local_ledgers=tuple(local),
            local_evalues=tuple(evalues),
            weights=tuple(weights),
            epsilons=tuple(eps),
            deltas=tuple(dls),
        )
        return self.merger.merge_global(inputs)
