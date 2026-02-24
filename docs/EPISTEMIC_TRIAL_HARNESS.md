# Epistemic Trial Harness (DiscOS/EvidenceOS)

This document specifies how to run and analyze "trial-like" experiments against the DiscOS + EvidenceOS blackbox interface **without relying on implementation internals**. It aligns statistical claims with what ETL currently records.

For extending EvidenceOS with new NullSpecs and e-process constructions, see docs/RESEARCH_EXTENSIBILITY.md. This document covers the statistical design and analysis pipeline only.

## 1) Trial unit definition

The harness supports three analysis units. Pick one before analysis and keep it fixed in the protocol.

- **Claim-level unit (default):** one analyzed row per `claim_id_hex` (or `participant_id` when present).
- **Session-level unit:** one analyzed row per session/principal/topic window (derived externally from ETL context).
- **Cluster-level unit:** a grouped randomization unit (for example shared operation key or deployment shard) analyzed with cluster-robust methods.

### Why this matters

Interference can occur when multiple requests share budgets, lineage, or operation/topic pools. If units are not isolated, IID assumptions are violated. Use cluster-aware analysis or isolate pools per arm.

## 2) Endpoints and ETL semantics

The harness uses mutually exclusive endpoint classes per trial unit:

1. **Adversary success endpoint** (primary): the unit reaches an accepted terminal outcome (typically `CERTIFIED`; protocol may pre-register inclusion of `SETTLED`).
2. **Freeze endpoint** (competing): the unit reaches containment/denial outcomes (`FREEZE`, optionally `REVOKED`/`TAINTED` if pre-registered as policy failure).
3. **Incident endpoint** (competing): policy/security incident evidence is observed (for example `probe_event` with `action=FREEZE` or `canary_incident`).

`analysis/trial_dataframe.py` expects explicit event coding in exported JSON rows:

- `event_code=0` or `event_type="censored"`
- `event_code=1` or `event_type="primary"`
- `event_code=2` or `event_type="competing"`

EvidenceOS ETL indexer semantics used for mapping:

- claim `state` values are mapped to outcomes (`CERTIFIED`, `SETTLED`, `REVOKED`, `TAINTED`, `FREEZE`, `STALE`),
- incident records are emitted as `probe_event` and `canary_incident` entries.

> Important: do **not** assume "W hits zero ⇒ `FROZEN`" unless the run configuration actually enforces a freeze transition and ETL records it.

## 3) Competing-risks model requirements

### Required reporting

For endpoints where freeze/incident can preclude adversary success:

- report **cause-specific Cox PH** estimates for each cause,
- report **cumulative incidence functions (CIF)** (Aalen-Johansen / Fine-Gray-compatible interpretation),
- do not interpret 1−KM as cause probability when competing events are present.

### What `analysis.survival` currently computes

- `cox_summary.csv`: cause-specific Cox for primary and competing causes.
- `cif_primary_by_arm.png`: Aalen-Johansen CIF for primary event.
- `km_by_arm.png`: all-cause failure KM (descriptive only unless censoring assumptions are justified).

KM is only valid for a specific cause if competing events are independent censoring for that cause; this is typically not a safe default for this harness.

## 4) Allocation concealment guarantees and limits

### Guarantees (from current implementation)

- Trial assignment fields (`trial_arm_id`, `trial_intervention_id`) are carried in claim capsules and persisted in ETL-derived settlements.
- ETL records are append-only and checksum-validated, supporting post-hoc auditability.

### Limits

- Concealment is a protocol/ops property, not a cryptographic guarantee from ETL alone.
- Shared topic/budget pools can leak cross-arm signal (interference) unless arms are isolated.
- Sessionized analysis can still be biased if one actor spans multiple identities/topics.

## 5) CONSORT-style accounting for AI safety studies

For legibility and reproducibility, publish:

- screened/eligible/randomized/received/followup/analyzed counts (`analysis/consort.py` flow),
- unit definition and randomization scope,
- endpoint mapping table from ETL fields to event codes,
- assumptions for censoring and interference handling.

## 6) Blackbox worked example (I/O only)

The example below is intentionally implementation-agnostic and uses only exported trial rows.

**Input (`trial_rows.jsonl`):**

```json
{"participant_id":"u-001","arm":"control","duration_days":8,"event_type":"competing","consort_status":"analyzed"}
{"participant_id":"u-002","arm":"control","duration_days":10,"event_type":"censored","consort_status":"followup_complete"}
{"participant_id":"u-101","arm":"treatment","duration_days":6,"event_type":"primary","consort_status":"analyzed"}
{"participant_id":"u-102","arm":"treatment","duration_days":7,"event_type":"competing","consort_status":"received_intervention"}
```

**Command:**

```bash
python -m analysis.survival --etl path/to/etl.log --out out_dir/
```

**Outputs (interpretable without Rust internals):**

- `out_dir/cif_primary_by_arm.png`: primary-endpoint incidence under competing risks.
- `out_dir/cox_summary.csv`: hazard ratios for primary vs competing causes.
- `out_dir/consort.dot` (`consort.png` when graphviz is available): participant flow.

## 7) Pre-registration checklist

Before running a trial harness report, lock:

- trial unit (claim/session/cluster),
- endpoint mapping (which ETL outcomes map to primary/competing/censoring),
- interference mitigation plan (isolation vs cluster-robust analysis),
- censoring assumptions and sensitivity analyses.

## 8) Configuring trial arms (runtime)

EvidenceOS now supports config-driven epistemic interventions via `config/trial_arms.json`.

- Default path: `config/trial_arms.json`
- Override path: `EVIDENCEOS_TRIAL_ARMS_CONFIG=/path/to/trial_arms.json`

Schema:

- `arms`: array of `{ arm_id, intervention_id, intervention_version, actions, descriptors, arm_parameters }`
- `assignment_mode`: `"hashed"` or `"blocked"`
- `stratify`: `true|false`
- `block_size`: required for `blocked` mode

`actions` are typed objects:

- `{ "type": "scale_alpha_ppm", "ppm": 1000000 }`
- `{ "type": "scale_access_credit_ppm", "ppm": 1000000 }`
- `{ "type": "scale_k_bits_budget_ppm", "ppm": 750000 }`

Built-in sample (`config/trial_arms.json`) defines:

- control arm: identity scaling (1.0x alpha/access-credit/k-budget)
- treatment arm: tightened `k` budget (`k_bits_scale_ppm = 750000`)

Labs can add additional arms without Rust code changes by editing this file.

## 9) Enable/disable behavior and auditability

- At startup, EvidenceOS loads the trial config and logs `trial_config_hash_hex`.
- The same hash is carried into telemetry lifecycle events and claim capsules (`trial_config_hash_hex`) to prevent silent configuration swaps.
- If no external config file exists, daemon uses the built-in two-arm control/treatment defaults.

## 10) Reproducing assignment from `trial_nonce` in hashed mode

For `assignment_mode = "hashed"`, assignment is deterministic:

```text
arm_id = SHA256("evidenceos:trial_assignment:v1" || trial_nonce || stratum_bytes)[0..2] mod arm_count
```

`stratum_bytes` is a tagged encoding of lane, holdout family, oracle ID, and nullspec ID.

Given `(trial_nonce_hex, stratum, arm_count)`, replaying the function above reproduces arm assignment exactly.

## 11) How to audit trial assignment

EvidenceOS supports two assignment modes with distinct audit procedures:

- **Hashed mode (default):**
  - Read `trial_nonce_hex` plus stratum fields (lane, holdout family, oracle ID, nullspec ID) from the claim/capsule context.
  - Recompute
    `SHA256("evidenceos:trial_assignment:v1" || trial_nonce || stratum_bytes)[0..2] mod arm_count`.
  - Compare the recomputed `arm_id` to recorded `trial_arm_id`.

- **Blocked mode (stateful allocator):**
  - `trial_arm_id` is recorded in claim/capsule metadata at assignment time.
  - Daemon state persists allocator internals in `state.json` so restart does not reset block position.
  - Each blocked assignment records `allocator_snapshot_hash` (SHA-256 of canonical allocator snapshot) so auditors can confirm assignment traces against persisted allocator state history.

This gives reproducible assignment in hashed mode and replayable/auditable state transitions in blocked mode.

## 12) Structured-claim envelope enforcement source

When trials rely on CBRN structured-claim (`CBRN_SC_V1`) acceptance behavior, envelope checks are performed against the daemon's active envelope registry (for example signed envelope packs loaded from `--envelope-packs-dir`, optionally required by `--require-signed-envelopes`). In non-production/development mode, builtin defaults may be used only when no active registry has been installed.

## 13) Commitment hash (schema v2, prefix-free)

Claim capsules carry both `trial_commitment_hash_hex` and `trial_commitment_schema_version`.

For new claims, EvidenceOS uses **schema version 2** with a prefix-free byte encoding:

```text
[schema:1B] [arm_id:2B] [len(intervention_id):2B][intervention_id bytes]
[len(intervention_version):2B][intervention_version bytes]
[arm_params_hash:32B] [trial_nonce:16B]
```

The explicit length prefixes remove ambiguity between adjacent variable-length strings (for example `("ab","c")` vs `("a","bc")`), so distinct assignments cannot share the same preimage.

Schema version 1 is retained only for backward compatibility with historical capsules; auditors should treat `(trial_commitment_schema_version, trial_commitment_hash_hex)` as the commitment identifier.

