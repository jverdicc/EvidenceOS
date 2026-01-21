from __future__ import annotations

import uuid

from evidenceos.common.signing import Ed25519Keypair
from evidenceos.federation.coordinator import FederationCoordinator
from evidenceos.federation.types import (
    DropoutPolicy,
    FederatedOracleQuery,
    FederationContract,
    MergerCertificates,
    MergerPolicy,
    VaultDescriptor,
)
from evidenceos.federation.vault_inmemory import InMemoryVault, InMemoryVaultConfig


def main() -> None:
    kp_a = Ed25519Keypair.generate()
    kp_b = Ed25519Keypair.generate()
    kp_c = Ed25519Keypair.generate()

    vaults = {
        "A": InMemoryVault(InMemoryVaultConfig(vault_id="A", keypair=kp_a, e_value=2.0, base_score=0.81)),
        "B": InMemoryVault(InMemoryVaultConfig(vault_id="B", keypair=kp_b, e_value=1.5, base_score=0.80)),
        "C": InMemoryVault(InMemoryVaultConfig(vault_id="C", keypair=kp_c, e_value=1.2, base_score=0.79)),
    }

    policy = MergerPolicy(
        evidence_merge="weighted_mean_evalues",
        dp_merge="max_if_disjoint_else_sum",
        integrity_merge="any_corrupted_invalid",
        dropout_policy=DropoutPolicy(min_quorum=2, mode="fail_closed"),
        certificates=MergerCertificates(independence_certified=False, identity_disjointness_certified=True),
    )

    contract = FederationContract(
        federation_id="fed-" + uuid.uuid4().hex[:8],
        claim_id="claim-" + uuid.uuid4().hex[:8],
        frozen_plan_hash="sha256:" + "0" * 64,
        vaults=(
            VaultDescriptor(vault_id="A", oracle_endpoint="inmem://A", vault_pubkey_hex=kp_a.public_key_bytes().hex(), population_weight=0.4),
            VaultDescriptor(vault_id="B", oracle_endpoint="inmem://B", vault_pubkey_hex=kp_b.public_key_bytes().hex(), population_weight=0.35),
            VaultDescriptor(vault_id="C", oracle_endpoint="inmem://C", vault_pubkey_hex=kp_c.public_key_bytes().hex(), population_weight=0.25),
        ),
        merge_policy=policy,
    )

    coord = FederationCoordinator(contract)
    coord.freeze(vaults)

    q = FederatedOracleQuery(
        federation_id=contract.federation_id,
        query_id="q-" + uuid.uuid4().hex[:8],
        candidate_id="sha256:" + "1" * 64,
        query_kind="score",
        requested_metric="accuracy",
        split="locked_holdout_v1",
        target_vaults=("A", "B", "C"),
        nonce=uuid.uuid4().hex,
    )
    coord.query_vaults(q, vaults)
    coord.collect_local_ledgers(vaults)

    gl = coord.compute_global_ledger()
    print("Semantic transcript hash:", coord.transcript.semantic_hash())
    print("Global ledger:", gl)


if __name__ == "__main__":
    main()
