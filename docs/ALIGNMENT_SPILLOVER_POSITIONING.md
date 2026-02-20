# Alignment Positioning: UVP and Capability Spillover Risk

## What spillover means in this context

In alignment discussions, "capability spillover" usually means safety/evaluation infrastructure unintentionally improving a model's capabilities, or leaking enough information that capability gains happen as a side effect. In the EvidenceOS/DiscOS context, the specific spillover channel UVP targets is **interactive transcript leakage from hidden evaluations** (for example, holdout structure or decision-boundary clues revealed over repeated queries).

So the scope is narrow on purpose: UVP models and meters what can be inferred through the evaluation interface itself (`k`), then enforces controls to keep that leakage bounded and auditable over time.

> Important: `k` is a measure of transcript leakage through the UVP interface. It is **not** a measure of all possible capability gains in the world.

## Where UVP helps

### 1) Evaluation leakage control (holdout / decision-boundary extraction)

UVP is designed for cases where repeated adaptive querying could otherwise recover hidden eval structure. EvidenceOS constrains this through canonicalized outputs, metered interaction, and fail-closed accounting, so extraction pressure is charged against a finite leakage budget instead of being "free" across many small interactions.

### 2) Preventing cross-oracle probing on shared holdouts

When multiple oracles expose different views of the same hidden holdout, UVP's joint accounting is intended to prevent callers from combining those views into an effectively larger side channel. In other words, correlated interfaces spend from shared leakage budgets rather than allowing additive extraction by cross-oracle subtraction.

### 3) Reducing timing channels in high-assurance modes

In higher-assurance operating modes, deterministic settlement windows (DLC) and optional policy-layer controls (PLN) reduce timing signal bandwidth. This does not remove timing risk entirely, but it can materially shrink practical leakage available through latency/order effects.

## Where UVP does **not** help

UVP is not a general solution to capability spillover from all sources. In particular, it does not stop:

- Capability gains from reading papers, model weights, public code, external tools, or other non-UVP information channels.
- Endpoint compromise, key theft, host/OS compromise, or direct exfiltration outside the trusted boundary.

These are separate security and governance problems that require additional controls beyond transcript-level leakage accounting.

## Why this matters for alignment research programs

Many alignment programs depend on hidden evals, private test sets, and interactive scoring loops. If that interface leaks too much, the evaluation can become self-undermining. UVP's contribution is to harden that interface so released information is bounded, metered, and auditable, helping teams reason about leakage risk explicitly rather than assuming it away.
