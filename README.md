# ghidra-headless-mcp

Minimal headless [MCP](https://modelcontextprotocol.io) server for Ghidra. No GUI, no plugin, no HTTP bridge:
it runs Ghidra in-process through [PyGhidra](https://pypi.org/project/pyghidra/). Sibling of
[Revoid](https://github.com/samudoria/revoid) (jadx) and uses the same tool style.

## Install

Requires Python 3.9+, JDK 21+ and [Ghidra](https://ghidra-sre.org) 11.3+ (tested on 12.1).

```bash
pip install git+https://github.com/samudoria/ghidra-headless-mcp   # or the wheel from Releases
```

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "ghidra-headless-mcp",
      "env": { "GHIDRA_INSTALL_DIR": "/opt/ghidra" }
    }
  }
}
```

### OpenCode

In `opencode.json` (project) or `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ghidra": {
      "type": "local",
      "command": ["ghidra-headless-mcp"],
      "environment": { "GHIDRA_INSTALL_DIR": "/opt/ghidra" },
      "enabled": true
    }
  }
}
```

## Use with Revoid

For Android apps: in [Revoid](https://github.com/samudoria/revoid) call `list_native_libraries`, then `extract_native_library`
to get a `.so` path on disk, and pass that path to `load_binary` here. Each server keeps its own renames and comments.
Tell the model to rename and comment as it goes; the notes are what the next analyst reads.

## Tools

| Tool | Description |
|------|-------------|
| `load_binary` | Import a binary (ELF/.so, PE, Mach-O...) and start auto-analysis **in the background**. **Call first.** Returns immediately with `state="importing"`; repeated calls are idempotent. Cached per file. `analyze=False` skips analysis (started on demand). After an error, pass `retry=True` to re-import. Several binaries may be loaded at once. |
| `load_status` | Load state: `idle`/`importing`/`analyzing`/`ready`/`error`, plus `name`/`functions`/`language`/`image_base` once imported. Poll until `{"state":"ready","analyzed":true}`. Never restarts a job. |
| `list_binaries` | All loaded binaries (id/path/name/state/analyzed/functions) and which one is active. |
| `unload_binary` | Free one loaded binary (refused while it is still analyzing). |
| `list_functions` | Functions (name, `address` = Ghidra address, `file_address` = ELF p_vaddr, signature); `filter` = regex. Paginated. Works right after import. |
| `resolve_symbol` | Resolve a name/address to `{name, address, file_address, signature}`. Use `file_address` when the address must match readelf/angr/a hex editor. |
| `get_function` | Decompiled C (`function` = name or any address inside, including a file-relative address). |
| `get_disassembly` | Assembly listing of a function. |
| `list_strings` / `list_imports` / `list_exports` | Paginated, `filter` = regex. |
| `get_callers` / `get_callees` | Call graph neighbours of a function. |
| `get_xrefs` | References to an address, function or string. |
| `call_path` | Shortest call chain from one function to another. |
| `read_memory` | Hex dump of bytes at an address (max 4096). |
| `search_bytes` | Byte pattern search, hex with `??` wildcards. Paginated. |
| `search_constants` | Instructions with a given scalar operand (crypto constants, magic numbers). Paginated. |
| `set_signature` | Apply a C prototype to a function (`int f(char *key, int n)`). |
| `retype_variable` | Change a local/parameter type as seen in the decompiled C. |
| `rename` | Rename a function or label. |
| `rename_variable` | Rename a local/parameter seen in the decompiled C. |
| `add_comment` | `pre` (default), `eol`, `post`, `plate`, `repeatable`. Empty text clears. |

All lists take `limit` (default 50) and `offset`; the reply contains `next_offset` (null at the end).
Edits are saved to the Ghidra project immediately and survive restarts: reloading the same file reopens your names and comments.

Every tool also takes an optional `binary` selector: an absolute path, a basename, or a program name
(see `list_binaries` for ids). Omitted = the most recently loaded binary, so single-binary use is unchanged.
Loading a new binary no longer closes the previous one; use `unload_binary` to free one.

## Multiple binaries

`load_binary` can be called repeatedly and each binary keeps its own analysis thread, decompiler and
edits. Imports are serialized (Ghidra project code is not thread-safe) but analysis and queries run in
parallel, so agents can load several libraries and work on them concurrently. Select one per call:

```python
load_binary("/tmp/liba.so")
load_binary("/tmp/libb.so")          # liba stays loaded and keeps analyzing
list_binaries()                       # ids + states; libb is active
list_exports(binary="liba.so")        # by basename
get_function("JNI_OnLoad", binary="/tmp/libb.so")
load_status(binary="libb.so")         # poll each binary independently
unload_binary(binary="liba.so")
```

## Load flow (non-blocking)

`load_binary` no longer blocks on either the import or Ghidra's multi-minute auto-analysis: both run on a
background thread that keeps running after the call returns. The intended agent flow:

1. `load_binary(path)` — returns at once with `{"state":"importing", ...}`. Calling it again for the same
   path is idempotent: it returns the current status and never restarts a live job. If a previous load
   ended in `error`, pass `retry=True` to discard it and import again.
2. Poll `load_status()` until `state` is no longer `importing`.
3. Read **immediately**, while analysis runs: `list_exports`, `list_imports`, `list_strings`, `list_functions`,
   `read_memory`, `search_bytes` — the structural questions (which exports? JNI functions? suspicious imports/strings?).
4. Poll `load_status()` until `{"state":"ready","analyzed":true}`.
5. Then call decompiler-driven tools: `get_function`, `get_disassembly`, `get_callers`/`get_callees`/`get_xrefs`,
   `call_path`, `search_constants`, `rename*`, `retype_variable`, `set_signature`, `add_comment`.

Called before analysis is done, a decompiler-driven tool returns a soft
`{"status":"analyzing","retry_after_s":N,"hint":...}` — not an error and never an under-analyzed answer. With
`analyze=False`, the first such call starts analysis itself (triage cheaply, pay for analysis only when you decompile).
A re-analyzed cached project loads straight to `ready` with no re-analysis.

## Environment

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` (or `GHIDRA_HOME`) | Ghidra install directory (required) |
| `GHIDRA_MCP_HOME` | Where projects are stored (default `~/ghidra_mcp`; no path element may start with `.`) |
| `GHIDRA_MCP_TRANSPORT` | `stdio` (default), `sse`, or `streamable-http` |
| `GHIDRA_MCP_HOST` / `GHIDRA_MCP_PORT` | Bind address for the HTTP transports (default `127.0.0.1:8000`) |
| `GHIDRA_MCP_DECOMPILE_TIMEOUT` | Per-function decompile timeout in seconds (default `30`; `get_function` takes a per-call `timeout`) |
| `GHIDRA_MCP_TRIM_ANALYSIS` | `1` to disable the analyzers in `GHIDRA_MCP_DISABLE_ANALYZERS` before analysis (default off = full analysis) |
| `GHIDRA_MCP_DISABLE_ANALYZERS` | Comma-separated analyzer names to skip when trimming (default `Embedded Media`; decompiler-critical analyzers are never dropped) |

### HTTP / SSE

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra GHIDRA_MCP_TRANSPORT=sse ghidra-headless-mcp
# SSE endpoint:        http://127.0.0.1:8000/sse
# streamable-http:     GHIDRA_MCP_TRANSPORT=streamable-http  -> http://127.0.0.1:8000/mcp
```

```json
{
  "mcpServers": {
    "ghidra": { "type": "sse", "url": "http://127.0.0.1:8000/sse" }
  }
}
```

Several binaries may be loaded at a time; `unload_binary` frees one. Only one server may open a given project at a time.
Logs go to stderr; stdout is reserved for the protocol.

## Test

```bash
python tests/test_state.py                                                      # state machine, no Ghidra needed
GHIDRA_INSTALL_DIR=/opt/ghidra python tests/smoke.py ./some_binary some_function # end-to-end over stdio
GHIDRA_INSTALL_DIR=/opt/ghidra python tests/smoke.py ./liba.so fn_a ./libb.so fn_b # + multi-binary flow
```
