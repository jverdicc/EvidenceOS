import unittest

from scripts import check_website_parity as parity


class CheckWebsiteParityTests(unittest.TestCase):
    def test_missing_phrases_detected_case_insensitive(self):
        text = "Deterministic Settlement Kernel only"
        missing = parity._missing_phrases(text)
        self.assertIn("discrete claim capsules", missing)
        self.assertIn("adapter/sidecar for continuous agents", missing)
        self.assertNotIn("deterministic settlement kernel", missing)

    def test_missing_phrases_none_when_all_present(self):
        text = (
            "deterministic settlement kernel "
            "discrete claim capsules "
            "adapter/sidecar for continuous agents"
        )
        self.assertEqual(parity._missing_phrases(text), [])


if __name__ == "__main__":
    unittest.main()
