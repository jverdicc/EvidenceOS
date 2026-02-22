from __future__ import annotations

import json
import sys
from pathlib import Path

from reference_kernel import ReferenceLedger


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_reference.py <fixture.json>")

    fixture_path = Path(sys.argv[1])
    fixture = json.loads(fixture_path.read_text())

    ledger = ReferenceLedger(
        alpha=fixture["alpha"],
        k_bits_budget=fixture.get("k_bits_budget"),
        access_credit_budget=fixture.get("access_credit_budget"),
    )

    frozen_transitions = []
    for item in fixture["transcript"]:
        op = item["op"]
        kind = op["kind"]
        if kind == "charge_all":
            ledger.charge_all(
                k_bits=op["k_bits"],
                epsilon=op["epsilon"],
                delta=op["delta"],
                access_credit=op["access_credit"],
                event_kind=op["event_kind"],
                meta=op["meta"],
            )
        elif kind == "charge_kout_bits":
            ledger.charge_kout_bits(kout_bits=op["kout_bits"])
        elif kind == "settle_e_value":
            ledger.settle_e_value(
                e_value=op["e_value"],
                event_kind=op["event_kind"],
                meta=op["meta"],
            )
        else:
            raise ValueError(f"unknown op kind: {kind}")
        frozen_transitions.append(ledger.frozen)

    print(
        json.dumps(
            {
                "k_bits_total": ledger.k_bits_total,
                "alpha_prime": ledger.alpha_prime(),
                "certification_barrier": ledger.certification_barrier(),
                "frozen_transitions": frozen_transitions,
                "final_frozen": ledger.frozen,
            }
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
