# Real-World Validation: Distillation Attacks at Scale

## Overview

On February 23, 2026, Anthropic published a security
report documenting industrial-scale distillation attacks
against Claude by three AI laboratories. This page maps
their published findings to the UVP threat model and
EvidenceOS mechanisms.

Full source:
https://www.anthropic.com/research/detecting-and-preventing-distillation-attacks

## The Attacks

Three campaigns were documented:

- DeepSeek: 150,000+ exchanges targeting reasoning
  capabilities and chain-of-thought data generation
- Moonshot AI: 3.4 million exchanges targeting agentic
  reasoning, tool use, and computer vision
- MiniMax: 13 million exchanges targeting agentic coding
  and tool orchestration

All three used rotating fraudulent accounts, proxy
services, and coordinated traffic patterns to evade
per-account detection.

## Why Per-Account Controls Failed

Anthropic's own report describes the core failure mode:
"When one account is banned, a new one takes its place."

This is the Sybil amplification problem formalized in
UVP Paper §12. Per-account limits are not a security
primitive. An adversary with sufficient account
infrastructure can always rotate past them.

UVP addresses this by making the budget shared across
the operation via TopicHash and MultiSignalTopicID.
It does not matter how many accounts the adversary
controls. The extraction cost accumulates against a
single shared topic pool. The 24,000th account faces
the same depleted budget as the first.

## Why Reactive Detection Is Insufficient

Anthropic describes detecting MiniMax "while it was
still active" as "unprecedented visibility." At the
point of detection, MiniMax had already generated
millions of exchanges and was days away from launching
a model trained on extracted capabilities.

Reactive detection identifies attacks after extraction
has occurred. The capability has already been
transferred. Banning accounts at that point is
remediation, not prevention.

UVP's Conservation Ledger enforces a hard ceiling on
what can be extracted before the attack succeeds.
Detection is not required for enforcement. The budget
runs out regardless of whether the adversary is
identified.

## The Chain-of-Thought Extraction Vector

Anthropic documents a specific technique where prompts
asked Claude to "imagine and articulate the internal
reasoning behind a completed response and write it out
step by step — effectively generating chain-of-thought
training data at scale."

EvidenceOS addresses this at two layers:

1. ASPEC admissibility checking rejects capsules
   designed to elicit unmetered internal reasoning
   traces. A capsule that attempts to extract
   chain-of-thought at scale is inadmissible before
   execution.

2. Quantized oracle + hysteresis collapses the
   precision of repeated near-identical queries.
   Small variations in prompts yield the same bucketed
   response, making high-resolution capability
   extraction expensive rather than free.

## The Pivot Problem

"When we released a new model during MiniMax's active
campaign, they pivoted within 24 hours, redirecting
nearly half their traffic to capture capabilities from
our latest system."

In UVP, a strategy pivot does not reset the budget.
The DLC epoch and Conservation Ledger track cumulative
leakage across the operation. An adversary who pivots
to a new target carries their accumulated k-bit spend
with them. The budget does not reset because the
account or target changed.

## Assurance Status

The mechanisms described above are sim-tested against
synthetic distillation-style attack patterns.
See docs/TEST_COVERAGE_MATRIX.md for evidence mapping.

Real-world deployment against production-scale
distillation infrastructure would require integration
with platform-level account management and API gateway
controls. That integration layer is architecture-
specified. See docs/INTEGRATION_PATTERNS.md for
enterprise integration guidance.

## Citation

Anthropic (2026). "Detecting and Preventing
Distillation Attacks." February 23, 2026.
https://www.anthropic.com/research/detecting-and-preventing-distillation-attacks

UVP Paper: "The Conservation of Epistemic Integrity:
A Kernel-Userland Protocol for Verifiable Reality."
Under review, FORC 2026.
DOI: 10.5281/zenodo.18685556
