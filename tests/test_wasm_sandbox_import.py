from evidenceos.sandbox import wasm


def test_wasm_sandbox_import() -> None:
    assert wasm.WasmSandboxConfig
