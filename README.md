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
| `load_binary` | Import a binary (ELF/.so, PE, Mach-O...) and start auto-analysis **in the background**. **Call first.** Returns immediately. Cached per file. `analyze=False` skips analysis (started on demand). |
| `load_status` | Load state: `idle`/`importing`/`analyzing`/`ready`/`error`. Poll until `{"state":"ready","analyzed":true}`. |
| `list_functions` | Functions (name, address, signature); `filter` = regex. Paginated. Works right after import. |
| `get_function` | Decompiled C (`function` = name or any address inside). |
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

## Load flow (non-blocking)

`load_binary` no longer blocks on Ghidra's multi-minute auto-analysis. The import is synchronous (seconds);
full analysis then runs on a background thread. The intended agent flow:

1. `load_binary(path)` — returns at once with `{"state":"analyzing"|"ready", ...}`.
2. Read **immediately**, while analysis runs: `list_exports`, `list_imports`, `list_strings`, `list_functions`,
   `read_memory`, `search_bytes` — the structural questions (which exports? JNI functions? suspicious imports/strings?).
3. Poll `load_status()` until `{"state":"ready","analyzed":true}`.
4. Then call decompiler-driven tools: `get_function`, `get_disassembly`, `get_callers`/`get_callees`/`get_xrefs`,
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

One binary is loaded at a time; `load_binary` closes the previous one. Only one server may open a given project at a time.
Logs go to stderr; stdout is reserved for the protocol.

## Test

```bash
python tests/test_state.py                                                      # state machine, no Ghidra needed
GHIDRA_INSTALL_DIR=/opt/ghidra python tests/smoke.py ./some_binary some_function # end-to-end over stdio
```
