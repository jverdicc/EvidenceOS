import unittest

from scripts import check_impl_status_guards as guards


class CheckImplStatusGuardsTests(unittest.TestCase):
    def test_extract_fn_body_finds_named_function(self):
        src = """
fn helper() { }

fn verify_signed_oracle_record() -> Result<(), Status> {
    if enabled {
        verify_strict(
            &digest,
            &signature,
        )?;
    }
    Ok(())
}
"""
        body = guards.extract_fn_body(src, "verify_signed_oracle_record")
        self.assertIn("verify_strict(", body)

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

    def test_oracle_signature_extraction_not_adjacent_to_other_function(self):
        src = """
fn verify_signed_oracle_record(
    oracle_id: &str,
) -> Result<(), Status> {
    if enabled {
        verifying_key.verify_strict(&digest, &signature)?;
    }
    Ok(())
}

fn helper_unrelated() {
    let _x = 1;
}

fn verify_epoch_control_record(
) -> Result<(), Status> {
    Ok(())
}
"""
        guards.check_oracle_signature_verification(src)

    def test_synthetic_holdout_gate_accepts_gated_provider(self):
        src = """
if std::env::var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT").is_ok() {
    let provider = Arc::new(SyntheticHoldoutProvider);
}
"""
        guards.check_synthetic_holdout_gate(src)

    def test_synthetic_holdout_gate_rejects_provider_without_nearby_gate(self):
        src = "\n".join(
            [
                'if std::env::var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT").is_ok() {',
                "    let _ = true;",
                "}",
            ]
            + ["// spacer"] * 1200
            + ["let provider = Arc::new(SyntheticHoldoutProvider);"]
        )
        with self.assertRaises(guards.GuardFailure):
            guards.check_synthetic_holdout_gate(src)

    def test_synthetic_holdout_gate_rejects_provider_outside_gate(self):
        src = """
if std::env::var("EVIDENCEOS_INSECURE_SYNTHETIC_HOLDOUT").is_ok() {
    let _debug = true;
}
let provider = Arc::new(SyntheticHoldoutProvider);
"""
        with self.assertRaises(guards.GuardFailure):
            guards.check_synthetic_holdout_gate(src)


if __name__ == "__main__":
    unittest.main()
