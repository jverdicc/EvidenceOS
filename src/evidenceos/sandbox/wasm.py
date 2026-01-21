from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class WasmSandboxConfig:
    max_memory_bytes: int
    max_fuel: int
    max_wall_time_ms: int


@dataclass(frozen=True)
class WasmExecutionRequest:
    module_bytes: bytes
    entrypoint: str
    inputs: Mapping[str, bytes]
    config: WasmSandboxConfig


@dataclass(frozen=True)
class WasmExecutionResult:
    outputs: Mapping[str, bytes]
    exit_code: int
    fuel_consumed: int
    wall_time_ms: int


class WasmSandbox:
    def __init__(self, config: WasmSandboxConfig) -> None:
        raise NotImplementedError("WASM sandbox is a stub interface.")

    def execute(self, request: WasmExecutionRequest) -> WasmExecutionResult:
        raise NotImplementedError("WASM sandbox is a stub interface.")
