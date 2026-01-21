import uuid
import pytest

from evidenceos.common.signing import Ed25519Keypair
from evidenceos.federation.coordinator import FederationCoordinator
from evidenceos.federation.types import DropoutPolicy, FederatedOracleQuery, FederationContract, MergerCertificates, MergerPolicy, VaultDescriptor
from evidenceos.federation.vault_inmemory import InMemoryVault, InMemoryVaultConfig

def test_federation_quorum_fail_closed() -> None:
    kp_a = Ed25519Keypair.generate()
    kp_b = Ed25519Keypair.generate()
    vaults = {
        "A": InMemoryVault(InMemoryVaultConfig(vault_id="A", keypair=kp_a)),
        "B": InMemoryVault(InMemoryVaultConfig(vault_id="B", keypair=kp_b)),
    }
    policy = MergerPolicy(
        dropout_policy=DropoutPolicy(min_quorum=2, mode="fail_closed"),
        certificates=MergerCertificates(identity_disjointness_certified=True),
    )
    contract = FederationContract(
        federation_id="fed-"+uuid.uuid4().hex[:8],
        claim_id="claim-"+uuid.uuid4().hex[:8],
        frozen_plan_hash="sha256:"+"0"*64,
        vaults=(
            VaultDescriptor(vault_id="A", oracle_endpoint="inmem://A", vault_pubkey_hex=kp_a.public_key_bytes().hex()),
            VaultDescriptor(vault_id="B", oracle_endpoint="inmem://B", vault_pubkey_hex=kp_b.public_key_bytes().hex()),
        ),
        merge_policy=policy,
    )
    coord = FederationCoordinator(contract)
    coord.freeze(vaults)
    q = FederatedOracleQuery(
        federation_id=contract.federation_id,
        query_id="q-"+uuid.uuid4().hex[:8],
        candidate_id="sha256:"+"1"*64,
        query_kind="score",
        requested_metric="acc",
        split="holdout",
        target_vaults=("A",),  # only one => violates quorum=2
    )
    with pytest.raises(RuntimeError):
        coord.query_vaults(q, vaults)
