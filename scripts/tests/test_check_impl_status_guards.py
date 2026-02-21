import unittest

from scripts import check_impl_status_guards as guards


class CheckImplStatusGuardsTests(unittest.TestCase):
    def test_oracle_signature_check_requires_verify_strict(self):
        src = """
fn verify_signed_oracle_record(
    oracle_id: &str,
) -> Result<(), Status> {
    verifying_key.verify_strict(&digest, &signature)
}

fn verify_epoch_control_record(
) -> Result<(), Status> {
    Ok(())
}
"""
        guards.check_oracle_signature_verification(src)

    def test_oracle_signature_check_rejects_missing_verify(self):
        src = """
fn verify_signed_oracle_record(
    oracle_id: &str,
) -> Result<(), Status> {
    Ok(())
}

fn verify_epoch_control_record(
) -> Result<(), Status> {
    Ok(())
}
"""
        with self.assertRaises(guards.GuardFailure):
            guards.check_oracle_signature_verification(src)

    def test_synthetic_holdout_gate_rejects_extra_callsite(self):
        src = "\n".join(
            [
                "derive_holdout_labels(a, b)",
                "derive_holdout_labels(c, d)",
                "derive_holdout_labels(e, f)",
                "derive_holdout_labels(g, h)",
                "EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT",
                "Arc::new(SyntheticHoldoutProvider)",
            ]
        )
        with self.assertRaises(guards.GuardFailure):
            guards.check_synthetic_holdout_gate(src)


if __name__ == "__main__":
    unittest.main()
