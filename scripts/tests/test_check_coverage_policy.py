import unittest

from scripts.check_coverage_policy import parse_source_threshold


class ParseSourceThresholdTests(unittest.TestCase):
    def test_parses_threshold(self) -> None:
        text = "cargo llvm-cov --workspace --fail-under-lines 95"
        self.assertEqual(parse_source_threshold(text), 95)

    def test_raises_without_threshold(self) -> None:
        with self.assertRaises(ValueError):
            parse_source_threshold("cargo llvm-cov --workspace")


if __name__ == "__main__":
    unittest.main()
