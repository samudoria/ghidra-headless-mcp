# PLAN — non-blocking load for ghidra-headless-mcp

## Versions (recorded)
- Ghidra 12.1.2 (`/opt/ghidra`), also 11.2.1 available (`/opt/ghidra_11.2.1`)
- PyGhidra 3.1.0 (ships in `Ghidra/Features/PyGhidra/pypkg/dist`)
- mcp 2.3.0 (SDK, `MCPServer`), JPype 1.5.2

## Problem
`load_binary` blocked on `FlatProgramAPI.analyzeAll` (minutes). An impatient fast
model is stuck even though exports/imports/strings/symbol list need no full analysis.

## Design

### Load state machine (in `S`, guarded by `LOCK`)
```
idle --load_binary--> importing --(import done)--> ready
                                                     |  analyze needed & not done
                                                     v
                                                 analyzing --(bg thread done)--> ready(analyzed)
                                 (any step fails) --> error
```
- `S["state"]`: `idle | importing | analyzing | ready | error`
- `S["analyzed"]`: bool — program has had full auto-analysis (distinct from `ready`,
  because `analyze=False` reaches `ready` *un*analyzed).
- `load_status()` tool returns the single checkable object:
  `{"state":"ready","analyzed":true,"name":..,"functions":N}` is the go signal;
  `{"state":"analyzing","elapsed_s":N,"functions":M}` while running.

`load_binary(path, analyze=True)`:
1. `pyghidra.start()`, open/create cached project, import program (or open cached),
   open `DecompInterface` — all synchronous. State → `importing`, then `ready`.
2. If `analyze` and program not already analyzed → spawn **background thread** running
   `analyzeAll + markProgramAnalyzed + proj.save`, state → `analyzing`, **return now**.
3. If the cached project is already analyzed → straight to `ready` (analyzed), no thread.
Returns `{"state","name","functions","language","image_base","analyzed"}` (superset of
the old shape — only added fields).

Re-entrancy: a second `load_binary` while `state=="analyzing"` returns the current
status and does not disturb the running analysis. The whole import runs under `LOCK`,
so two imports cannot interleave.

### Per-tool needs-analysis classification

| Tool | Needs full analysis? | During `analyzing` / unanalyzed |
|------|----------------------|----------------------------------|
| `load_binary` | starts it | — |
| `load_status` | no | returns state |
| `list_functions` | no (raw function-manager list) | serve |
| `list_exports` | no (symbol table) | serve |
| `list_imports` | no (external symbols) | serve |
| `list_strings` | no (defined data)¹ | serve |
| `read_memory` | no (raw memory) | serve |
| `search_bytes` | no (raw memory scan) | serve |
| `get_function` | **yes** (decompiler) | soft `analyzing` status |
| `get_disassembly` | **yes** (needs instructions) | soft status |
| `search_constants` | **yes** (iterates instructions) | soft status |
| `get_callers` / `get_callees` | **yes** (call graph) | soft status |
| `get_xrefs` | **yes** (references) | soft status |
| `call_path` | **yes** (call graph) | soft status |
| `rename` | **yes** (functions + edit) | soft status |
| `rename_variable` / `retype_variable` | **yes** (decompiler + edit) | soft status |
| `set_signature` | **yes** (edit) | soft status |
| `add_comment` | **yes** (edit; single-writer) | soft status |

Soft status (returned instead of blocking/erroring, never a wrong answer):
`{"status":"analyzing","retry_after_s":N,"hint":"call load_status; exports/imports/strings/function list work now"}`.

¹ Strings: Ghidra's string analyzer *grows* the defined-string set during analysis. The
raw list is served immediately per the spec; it is a floor, not necessarily complete
until `analyzed`. Documented, not silently presented as final.

### Edit tools are the real thread-safety reason
The background analysis thread is the **only writer** while `state=="analyzing"`. All
edit tools return the soft status during analysis, so there is never a second concurrent
writer / transaction on the program DB. Pure-read structural tools may read concurrently;
Ghidra's program DB handles read/write concurrency, worst case a structural read sees
analysis-in-progress (more symbols appearing) — acceptable, documented ceiling.

### Locking
- `LOCK` (`threading.RLock`) guards every read/write of `S` (state, analyzed, timing,
  thread handle, prog/ifc/proj references) and serializes `load_binary`/`close`.
- The background analysis thread runs `analyzeAll` **without** holding `LOCK` (it would
  block everything for minutes); it takes `LOCK` only briefly to flip `analyzing→ready`
  / `→error`, and only if it is still the current program.
- Invariant: at most one analysis thread; `S["prog"]` does not change while `analyzing`
  (new loads return busy), so the single-writer guarantee holds.

### Phase 3
- **`analyze=False`**: imports and returns `ready` (unanalyzed), no `analyzeAll`.
  Structural tools work. A decompiler-driven tool then **triggers analysis on demand**
  (kicks the same background thread) and returns the soft `analyzing` status — poll,
  then retry. "Load cheap for triage, pay for analysis only when you decompile."
- **Analyzer trim** (reversible, default OFF): env `GHIDRA_MCP_TRIM_ANALYSIS=1` disables
  the analyzers named in `GHIDRA_MCP_DISABLE_ANALYZERS` (comma-separated,
  default `"Embedded Media"`) before `analyzeAll`. Default list is deliberately minimal —
  "Embedded Media" is a media-blob scanner that touches no code, functions, references or
  decompiler output. The analyst can extend the list; we do **not** disable anything the
  decompiler relies on (switch/param-id/stack/references stay on). Full behavior if unset.
  The main speed win is backgrounding; the trim is an opt-in bonus.
- **Decompiler timeout**: `GHIDRA_MCP_DECOMPILE_TIMEOUT` (default **30s**, was hardcoded
  120s). `get_function(..., timeout=0)` overrides per call (0 = env default; pass 120 for
  the old value). A timed-out decompile returns `{"status":"timeout","timeout_s":N,...}`,
  never hangs.

## Agent flow
`load_binary` → immediately read `list_exports` / `list_imports` / `list_strings` /
`list_functions` → poll `load_status` until `{"state":"ready","analyzed":true}` →
call decompiler-driven tools. With `analyze=False`, the first decompiler-driven call
starts analysis itself.

## Tests
- `tests/test_state.py` — pure Python, no JVM: state transitions, soft-status gating,
  `analyze=False` no-analysis, cached-analyzed → ready, timeout-status shape.
- `tests/smoke.py` — extended e2e (needs Ghidra): `load_status`, analyzing→ready poll.
