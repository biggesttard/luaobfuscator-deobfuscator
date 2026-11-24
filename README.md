# LuaObfuscator Deobfuscator

![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Targets](https://img.shields.io/badge/targets-Chaotic%20Good%20%7C%20Chaotic%20Evil%20%7C%20Obfuscate%20v1-red)

A static Python deobfuscator for **LuaObfuscator** — a Lua obfuscator that encrypts string literals, flattens control flow into state machines, and compiles the entry chunk into a custom bytecode format with an inline VM. This tool recovers the original logic without executing the obfuscated code.

---

## Demo

**Input** — LuaObfuscator Chaotic Evil protected script:

```lua
-- LuaObfuscator | lura.ph / luaobfuscator.com
local LOL = "\76\79\76\33\..."  -- encoded bytecode payload
local function _(...)
    local __,_0,_1,_2 = ...; local _3={}
    -- dispatcher with XOR-encrypted string table ...
    while true do
        local op = ...; if op == 0x1A then ... end  -- state machine
    end
end
_(LOL)
```

**Default deobfuscation:**

```
$ deobf sample/sample.lua --out clean.lua
[det] ok evil
[cff] ok rep=2 rem=0
[bc]  ok 1468/1468
[str] ok outer=12 vm=48
[vm]  ok ops=27 used=19
[recon] ok
lines=63
clean.lua
```

```lua
-- oh my days deobfuscated this obfuscator with this special deobfuscator so insane

local Players = game:GetService("Players")
local function getCharacter(player)
    return player.Character or player.CharacterAdded:Wait()
end
-- ... full readable Lua source recovered
```

**JSON analysis mode:**

```
$ deobf sample/sample.lua --json | jq .detection
{
  "family": "luaobfuscator-chaotic-evil",
  "version": 2,
  "signals": ["lol_marker", "xor_bootstrap", "dispatch_tree", "double_reader"],
  "valid": true
}
```

---

## How It Works

The deobfuscator operates across 6 stages:

```
┌──────────────────────────────┐
│  LuaObfuscator Script        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 1. Detection                 │ ➔ Identifies obfuscator family and schema
│                              │   version from structural fingerprints
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 2. Control Flow Unflattening │ ➔ Rewrites state-machine dispatch loops
│                              │   back into straight-line if/else chains
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 3. String Recovery           │ ➔ Decrypts XOR-encrypted inline strings
│                              │   and constant-table ciphertext keys
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 4. Bytecode Extraction       │ ➔ Unwraps the LOL! payload, undoes
│                              │   run-length encoding, deserialises protos
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. VM Analysis               │ ➔ Locates fetch/dispatch pair, parses
│                              │   opcode tree, names each handler
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 6. Reconstruction            │ ➔ Propagates registers, drops dead stores,
│                              │   folds branches, rebuilds loops and Lua
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   Clean Lua Source Code      │
└──────────────────────────────┘
```

1. **Detection** (`luaio.py`): Looks for the decryption bootstrap, the `LOL!` bytecode payload header, double readers, dispatch trees, and watermark markers. Validates that all structural pieces required for the detected family are present. Returns the family (`luaobfuscator-chaotic-evil`, `luaobfuscator-chaotic-good`, `luaobfuscator-obfuscate-v1`), schema version, and a signal list. A script missing any critical structural signal is rejected — the tool never silently passes through unsupported input.

2. **Control Flow Unflattening** (`luaio.py`): Rewrites `while true do` state-machine dispatch loops back into straight-line code. Runs repeatedly until no flattening remains (`rep=N rem=0`). The result exposes the real structure of the outer Lua wrapper and simplifies string recovery in the next stage.

3. **String Recovery** (`luaio.py` / `deobf.py`): Decrypts inline XOR-encrypted string calls by exploiting key reuse across the script — no brute force on the outer strings. Then walks the bytecode constant tables and recovers VM-layer ciphertext keys from sibling constants and single-byte scoring. Reports how many outer strings and VM strings were recovered.

4. **Bytecode Extraction** (`luaio.py`): Unwraps the `LOL!` payload embedded in the outer wrapper, undoes the run-length encoding that compresses it, and deserializes the full prototype tree. Validates the prototype count against the expected structure.

5. **VM Analysis** (`luavm.py`): Locates the fetch/dispatch pair in the outer wrapper, parses the opcode dispatch tree (a large `if/elseif` chain), and names each opcode by its instruction shape, cross-checked against what the bytecode actually executes. Builds the full opcode→name map used by reconstruction. Reports total opcode count and how many were used.

6. **Reconstruction** (`luaout.py`): Translates the decoded bytecode back to readable Lua. Propagates registers to named locals, drops dead stores, folds constant branches, and rebuilds loop and conditional structures. Emits clean Lua that matches what the original unobfuscated script would have looked like.

For the full disassembly and VM report, run with `--disasm` or `--json`.

---

## Supported Families

| Family | Detection Signals | Reconstruction |
|---|---|---|
| **Chaotic Evil** | `LOL!` marker, XOR bootstrap, dispatch tree | Full — strings, bytecode, VM, Lua output |
| **Chaotic Good** | `LOL!` marker, `math.ldexp` double reader | Strings + bytecode; `math.ldexp` reader noted |
| **Obfuscate v1** | Watermark marker, simplified dispatch | Full — strings, bytecode, VM, Lua output |

---

## Quick Start

**Requirements:** Python 3.9 or newer. No third-party packages — standard library only.

```bash
# Install
pip install .

# Deobfuscate a script
deobf obfuscated.lua --out clean.lua

# Write to default output directory
deobf obfuscated.lua

# Print deobfuscated Lua to stdout as well
deobf obfuscated.lua --out clean.lua --stdout

# Inspect bytecode disassembly
deobf obfuscated.lua --disasm --out clean.lua

# Full JSON analysis report (safe to pipe)
deobf obfuscated.lua --json | jq .detection
deobf obfuscated.lua --json | jq -r .lua > clean.lua
```

Output is written to `output/<filename>/deobfuscated.lua` by default. Use `--out <path>` to override.

Every generated file begins with:
```lua
-- oh my days deobfuscated this obfuscator with this special deobfuscator so insane
```

---

## CLI Reference

| Flag | Effect |
|---|---|
| `--out <path>` | Write result to `<path>` instead of `output/<file>/deobfuscated.lua` |
| `--stdout` | Also print the reconstructed Lua to stdout |
| `--disasm` | Prepend bytecode disassembly and append the lifted `goto` listing |
| `--json` | Print a JSON report (`detection`, `vm`, `lua`, `disasm`) instead of Lua |

`--json` suppresses stderr progress, so it is safe to pipe into `jq` or other tools.

---

## Library

```python
from deobf import deobf, DeobfError

try:
    result = deobf(open('script.lua', encoding='utf-8').read())
except DeobfError as exc:
    raise SystemExit(f'not supported: {exc}')

print(result['detection']['family'])   # luaobfuscator-chaotic-evil
print(result['lua'])                   # reconstructed Lua
open('clean.lua', 'w', encoding='utf-8').write(result['lua'])
```

**Result fields:**

| Key | Contents |
|---|---|
| `lua` | Reconstructed Lua source, including the marker line |
| `reconstructed` | Same as `lua` |
| `lifted` | Flat, `goto`-based lift of the bytecode |
| `disasm` | Annotated instruction listing |
| `detection` | Family, schema version, signal list and validation reason |
| `vm` | Opcode count, opcode→name map and closure-local opcode |
| `strings` | Decrypted outer strings and VM constant-table maps |
| `cfg` | Jump statistics before and after control-flow cleanup |

Pass `{'force': True}` to skip detection and run the pipeline on any input:

```python
result = deobf(source, {'force': True})
```

---

## Project Layout

```
deobf/
    __init__.py       Public API surface (deobf, DeobfError)
    __main__.py       python -m deobf entry point
    cli.py            Command-line interface
    deobf.py          Pipeline orchestrator — ties all stages together
    luaio.py          Detection, unflattening, string recovery, bytecode extraction
    luavm.py          VM analysis — opcode dispatch parsing and naming
    luaout.py         Reconstruction — bytecode → readable Lua

sample/
    sample.lua        Real LuaObfuscator Chaotic Good script for local testing

tests/
    conftest.py               Pytest configuration
    helpers.py                Shared test utilities
    fixtures/                 Synthetic obfuscated input + expected golden outputs
    test_pipeline.py          End-to-end reconstruction regression tests
    test_cli.py               CLI flag and output path tests
    test_luaio.py             Detection, unflattening and string recovery tests
    test_luavm.py             VM analysis tests
    test_luaout.py            Reconstruction output tests
    test_good_family.py       Real Chaotic Good sample test (skipped if sample absent)
```

---

## Running the Tests

```bash
# Install with dev dependencies
pip install -e '.[dev]'

# Run the full suite
pytest

# Verbose output
pytest -v

# One module
pytest tests/test_pipeline.py
```

The test suite is self-contained. `tests/fixtures/` contains a synthetic obfuscated script and a raw prototype tree along with the exact Lua, disassembly, and VM report they must produce — regressions in any pipeline stage show up immediately.

`tests/test_good_family.py` runs against the real Chaotic Good script in `sample/sample.lua` and is automatically skipped when that file is absent.

---

## Limitations and Scope

- Targets **LuaObfuscator** output specifically (Chaotic Good, Chaotic Evil, Obfuscate v1). Scripts from other obfuscators are rejected by detection — the tool never silently passes through unsupported input.
- The **Chaotic Good** family's `math.ldexp` double reader is not fully resolved; such scripts report the limitation instead of producing a half-reconstructed output.
- Reconstruction is **heuristic**. Heavily modified payloads (truncated files, re-obfuscated output) may produce partial results. Use `--disasm` and `--json` to diagnose these cases.
- Output is **Lua 5.1** compatible. The reconstructed source targets the runtime the original script was written for.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `not supported: ...` | Input not recognized as LuaObfuscator output | Check the script is LuaObfuscator-protected; use `--json` to inspect detection signals |
| `[cff] warn ...` | Control flow unflattening left residual jumps | Usually still reconstructed; use `--disasm` to inspect the lifted output |
| `[str] warn ...` | Some string keys could not be recovered | Partial output still written; check `--json` `.strings` for coverage |
| Partial / empty output | Re-obfuscated or truncated input | Use `--disasm` to see how far the pipeline got |

---

## License

[MIT](LICENSE)
