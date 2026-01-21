from evidenceos.common.canonical_json import canonical_dumps_bytes
from evidenceos.common.hashing import sha256_prefixed
from evidenceos.uvp.syscalls import UVPInterface


def test_uvp_transcript_hashes_and_ordering() -> None:
    uvp = UVPInterface()
    announce = uvp.announce(
        claim_id="claim-1",
        claim="System X is safe under policy Y.",
        safety_properties=["prop-b", "prop-a"],
        adversarial_hypotheses=["attack-2", "attack-1"],
    )
    proposal = uvp.propose(
        announcement_hash=announce.announcement_hash,
        evidence_items=["e2", "e1"],
        resources_requested=0.2,
    )
    evaluation = uvp.evaluate(
        proposal_hash=proposal.proposal_hash,
        reality_status="PASS",
        resources_spent=0.2,
        wealth_after=2.0,
    )
    uvp.certify(
        evaluation_hash=evaluation.evaluation_hash,
        decision_trace={"status": "Supported", "reason": "e_value_pass"},
    )

    transcript_obj = uvp.transcript.to_obj()
    assert transcript_obj["events"][0]["seq"] == 1
    assert announce.safety_properties == ("prop-a", "prop-b")
    assert announce.adversarial_hypotheses == ("attack-1", "attack-2")

    expected_payload = {
        "claim_id": "claim-1",
        "claim": "System X is safe under policy Y.",
        "safety_properties": ["prop-a", "prop-b"],
        "adversarial_hypotheses": ["attack-1", "attack-2"],
    }
    expected_hash = sha256_prefixed(canonical_dumps_bytes(expected_payload))
    assert transcript_obj["events"][0]["payload_hash"] == expected_hash
