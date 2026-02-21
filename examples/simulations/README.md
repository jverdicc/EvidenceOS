# EvidenceOS: Empirical Attack Demonstrations

These five simulations demonstrate that adaptive adversaries can extract arbitrarily large amounts of information from evaluation oracles, holdout datasets, and private databases when no transcript-level controls exist. Each simulation shows the same adversary against two oracle configurations: an unbounded baseline (status quo) and an EvidenceOS-bounded kernel. All simulations use numpy seed 42 and are fully reproducible.

## Demo 1: Leaderboard Gaming
- **Adversary behavior:** Iteratively probes a private benchmark and flips one wrong label per query to ratchet up score.
- **EvidenceOS bound:** A strict per-agent `k` budget (1 bit/query on a binary oracle) freezes adaptive extraction at the budget boundary.
- **Run command:** `python demo1_leaderboard_gaming.py`
- **Expected output:** `demo1.png` with unbounded accuracy continuing upward while the bounded line freezes after budget exhaustion.

## Demo 2: Clinical p-Hacking
- **Adversary behavior:** Repeatedly tests noise variables across subgroups seeking a lucky `p < 0.05`.
- **EvidenceOS bound:** `alpha_prime = alpha * 2^{-k_total}` decays exponentially, requiring much stronger evidence with each adaptive query.
- **Run command:** `python demo2_clinical_phacking.py`
- **Expected output:** `demo2.png` with raw p-values, static alpha line, and a decaying EvidenceOS certification threshold up to freeze.

## Demo 3: Trading Overfitting
- **Adversary behavior:** Perturbs strategy parameters on random-walk prices and reports the best in-sample Sharpe.
- **EvidenceOS bound:** `k` budget plus rising certification barrier `(2^k)/alpha`; evidence wealth cannot keep pace and the strategy freezes.
- **Run command:** `python demo3_trading_overfitting.py`
- **Expected output:** `demo3.png` dual-axis plot of Sharpe trajectories vs. certification barrier with a freeze marker.

## Demo 4: Sybil Attack
- **Adversary behavior:** Splits extraction over many identities to recover a secret bit-by-bit.
- **EvidenceOS bound:** TopicHash-style shared budget collapses all identities into one entropy pool and limits recoverable bits.
- **Run command:** `python demo4_sybil_attack.py`
- **Expected output:** `demo4.png` showing unbounded linear growth versus bounded flatline after shared budget saturation.

## Demo 5: Genomic Privacy
- **Adversary behavior:** Uses overlapping aggregate queries to incrementally reconstruct individual-level records.
- **EvidenceOS bound:** Joint entropy budget imposes a hard maximum recoverable fraction, preventing unlimited deanonymization.
- **Run command:** `python demo5_genomic_privacy.py`
- **Expected output:** `demo5.png` with bounded trajectory capped at the privacy ceiling and an explicit ceiling annotation.

## Run all demos

```bash
python run_all.py
```

This executes all five scripts, saves `demo1.png` ... `demo5.png`, and prints a summary table.
