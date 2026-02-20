import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "examples" / "exfiltration_demo" / "attack_bitflip.py"


def run_mode(mode: str) -> dict:
    result = subprocess.run(
        ["python3", str(SCRIPT), "--mode", mode, "--n", "64", "--seed", "7"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


class ExfiltrationDemoTests(unittest.TestCase):
    def test_baseline_leaks(self) -> None:
        data = run_mode("baseline")
        self.assertGreaterEqual(data["recovered_accuracy"], 0.95)

    def test_evidenceos_mock_reduces_leakage(self) -> None:
        data = run_mode("evidenceos-mock")
        self.assertLessEqual(data["recovered_accuracy"], 0.60)


if __name__ == "__main__":
    unittest.main()
