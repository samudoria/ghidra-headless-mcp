# PLAN — non-blocking load for ghidra-headless-mcp

## Versions (recorded)
- Ghidra 12.1.2 (`/opt/ghidra`), also 11.2.1 available (`/opt/ghidra_11.2.1`)
- PyGhidra 3.1.0 (ships in `Ghidra/Features/PyGhidra/pypkg/dist`)
- mcp 2.3.0 (SDK, `MCPServer`), JPype 1.5.2

## Problem
`load_binary` blocked on `FlatProgramAPI.analyzeAll` (minutes). An impatient fast
model is stuck even though exports/imports/strings/symbol list need no full analysis.

## Design

### Load state machine (per session, guarded by that session's `LOCK`)
```
idle --load_binary--> importing --(import done)--> ready
                                                     |  analyze needed & not done
                                                     v
                                                 analyzing --(bg thread done)--> ready(analyzed)
                                 (any step fails) --> error
```
- `SESSIONS`: `abspath -> session`; each session has its own `lock`, `prog`, `ifc`, `proj`,
  `state`, `analyzed`, timing, `thread`.
- `ACTIVE`: abspath of the most recently loaded binary — the default when a tool omits `binary`.
- `S["state"]`: `idle | importing | analyzing | ready | error`
- `S["analyzed"]`: bool — program has had full auto-analysis (distinct from `ready`,
  because `analyze=False` reaches `ready` *un*analyzed).
- `load_status(binary="")` tool returns the single checkable object:
  `{"id":..,"state":"ready","analyzed":true,"name":..,"functions":N}` is the go signal;
  `{"state":"analyzing","elapsed_s":N,"functions":M}` while running.
- `list_binaries()` returns every session plus `active`; `unload_binary(binary="")` frees one.

### Multiple binaries
- `load_binary` adds to `SESSIONS` instead of closing the previous binary; `ACTIVE` moves to the
  newly loaded one. Loading an already-loaded path returns its status (kicking analysis if needed).
- **Imports are serialized** under `IMPORT_LOCK` (`pyghidra.start` + project open/import are not
  thread-safe in one JVM). **Analysis threads run concurrently** across sessions, and queries on
  one binary are independent of another binary's analysis.
- Selector resolution (`_session`): exact abspath, else basename or program name; ambiguous matches
  raise with the candidate ids; empty = `ACTIVE`.
- `unload_binary` refuses while that session is analyzing (disposing mid-analysis is unsafe).

`load_binary(path, analyze=True, retry=False)`:
1. Register the session and set state → `importing`, then spawn a **background import thread**
   and return immediately. The thread calls `pyghidra.start()`, opens/creates the cached
   project, imports the program (or opens the cached one) and opens `DecompInterface`.
   On success state → `ready`; on failure state → `error` (the session is kept).
2. If `analyze` and program not already analyzed → the import thread spawns a second
   **background thread** running `analyzeAll + markProgramAnalyzed + proj.save`,
   state → `analyzing`.
3. If the cached project is already analyzed → straight to `ready` (analyzed), no thread.
Returns `{"id","state",...}` immediately; once imported, `load_status` adds
`name`/`functions`/`language`/`image_base`.

Re-entrancy: a second `load_binary` for a path that is already `importing`/`analyzing` returns
that session's status and does not disturb the running work. If the tracked job thread is dead
(stale), `load_binary` restarts it (analysis only when the program is already imported, otherwise
the import). A session in `error` stays there; `retry=True` disposes it and imports again.
`load_status` is strictly read-only and never restarts anything. Imports for different paths are
serialized by `IMPORT_LOCK`; their analyses then run in parallel.

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
- `REGISTRY_LOCK` (`threading.RLock`) guards `SESSIONS`/`ACTIVE` only.
- Each session has its own `RLock` guarding that session's state, prog/ifc/proj refs and edits.
- `IMPORT_LOCK` serializes `pyghidra.start` and project open/import across sessions.
- Lock order: `REGISTRY_LOCK` → `IMPORT_LOCK` → session lock (never reverse).
- The background import thread holds `IMPORT_LOCK` for the import, then takes the session lock
  briefly to publish `prog/ifc/proj` and flip `importing→ready`/`→error`.
- The background analysis thread runs `analyzeAll` **without** holding its session lock (it would
  block everything for minutes); it takes the lock only briefly to flip `analyzing→ready`/`→error`,
  and only if it is still the current program for that session.
- Invariant: at most one import/analysis job per session; a session's `prog` does not change while it is
  analyzing. Different sessions analyze concurrently.

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
  `analyze=False` no-analysis, cached-analyzed → ready, timeout-status shape, multi-binary
  selector resolution/isolation, parallel analysis, unload.
- `tests/smoke.py` — extended e2e (needs Ghidra): `load_status`, analyzing→ready poll, and
  (with a second binary) concurrent multi-binary load/query/unload.
