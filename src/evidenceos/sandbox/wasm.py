from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from evidenceos.common.canonical_json import canonical_dumps_bytes


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
        self.config = config

    def execute(self, request: WasmExecutionRequest) -> WasmExecutionResult:
        try:
            import wasmtime
        except ImportError as exc:
            raise RuntimeError("wasmtime_not_available") from exc

        engine = wasmtime.Engine()
        store = wasmtime.Store(engine)
        store.set_fuel(request.config.max_fuel)
        module = wasmtime.Module(engine, request.module_bytes)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, module)

        exports = instance.exports(store)
        memory = exports.get("memory")
        if memory is None:
            raise RuntimeError("missing_memory_export")

        input_ptr = exports.get("input_ptr")
        input_len = exports.get("input_len")
        output_ptr = exports.get("output_ptr")
        output_len = exports.get("output_len")
        if None in (input_ptr, input_len, output_ptr, output_len):
            raise RuntimeError("missing_io_exports")

        input_payload = canonical_dumps_bytes(request.inputs)
        input_ptr_val = int(input_ptr.value(store))
        input_len_val = int(input_len.value(store))
        if len(input_payload) > input_len_val:
            raise RuntimeError("input_buffer_too_small")
        memory.write(store, input_payload, input_ptr_val)

        func = exports.get(request.entrypoint)
        if func is None or not isinstance(func, wasmtime.Func):
            raise RuntimeError("entrypoint_missing")
        func(store)

        output_ptr_val = int(output_ptr.value(store))
        output_len_val = int(output_len.value(store))
        output_bytes = memory.read(store, output_ptr_val, output_ptr_val + output_len_val)

        fuel_consumed = store.fuel_consumed()
        if fuel_consumed is None:
            fuel_consumed = request.config.max_fuel
        return WasmExecutionResult(
            outputs={"result": output_bytes},
            exit_code=0,
            fuel_consumed=int(fuel_consumed),
            wall_time_ms=request.config.max_wall_time_ms,
        )
