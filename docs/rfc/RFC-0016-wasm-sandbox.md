# RFC-0016: WASM Sandbox (Layer 3 Stub)

## Summary

Define a future-proof sandbox interface for executing WebAssembly modules in a
fully deterministic, offline environment.

## Motivation

EvidenceOS needs a secure execution boundary for untrusted computation. This RFC
introduces the interface only, so downstream layers can wire in an actual WASM
engine later without changing call sites.

## Requirements

- Implementations **MUST** be deterministic given the same module, inputs, and
  configuration.
- Implementations **MUST** be offline (no runtime network access).
- Execution **MUST** fail-closed on invariant, capability, or resource limit
  violations.
- The initial implementation is a stub that raises `NotImplementedError`.

## Non-Goals

- Selecting a specific WASM runtime.
- Implementing resource metering or host function policies.

## Interfaces

- `WasmSandboxConfig` defines resource limits and execution constraints.
- `WasmExecutionRequest` packages a module, entrypoint, and inputs.
- `WasmExecutionResult` returns outputs and metadata.
- `WasmSandbox` is the primary execution interface.
