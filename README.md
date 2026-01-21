# EvidenceOS / SafeClaim

EvidenceOS (and its core protocol, **SafeClaim**) is a **verification operating system** for the age of AI: a computing substrate that makes evaluation **statistically valid under adaptivity**, **resistant to gaming**, **auditable**, and **cost-aware**.

It is designed to be the “universal referee” for scientific and AI claims—across LLM evaluation, agentic discovery, benchmark leaderboards, and high‑stakes safety gates—by enforcing:

- **Validity under adaptivity** (repeated, adaptive querying)
- **Resistance to gaming** (oracle probing, leaderboard hacking, p‑hacking)
- **Replayable provenance** (proof‑carrying capsules)
- **Efficient evaluation** (multi‑fidelity + adaptive testing)
- **Sovereign / federated evaluation** (multiple data vaults; no raw data centralization)

> Core idea: **Evidence is finite.** Every query “spends” information. EvidenceOS makes that spending explicit and enforceable via ledgers, secure oracles, deterministic judging, and transparency logs.

---

## Quickstart (local dev)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e ".[dev]"

pytest
ruff check .
mypy src
```

Docs:

```bash
mkdocs serve
```

Run a demo (in-memory federated evaluation):

```bash
python -m evidenceos.examples.federated_demo
```

---

## Repository layout

```text
docs/                  # MkDocs site + RFCs
docs/rfc/              # Protocol RFCs (source of truth)
docs/diagrams/         # Architecture diagrams
schemas/               # JSON Schema (Draft 2020-12)
src/evidenceos/         # Reference kernel implementation
  common/              # canonical JSON, hashing, signing, schema validation
  federation/          # RFC-0011 coordinator, merger, vault stubs
  ledger/              # RFC-0001 conservation ledger
  judge/               # RFC-0004 DP-aware deterministic judge
  capsule/             # RFC-0005 claim capsules
  etl/                 # RFC-0006 Evidence Transparency Log
  oracle/              # Oracle modes (Ladder, Multi-fidelity)
tests/                 # pytest suites
.github/workflows/      # CI + docs deployment
```

---

## Status

This repo is a **reference kernel**. It is intentionally conservative: deterministic where required, fail-closed on integrity, and test-driven.

See `docs/rfc/` for protocol specifications and MUST/SHOULD requirements.
