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
| `load_binary` | Import + auto-analyze a binary (ELF/.so, PE, Mach-O...). **Call first.** Cached per file. |
| `list_functions` | Functions (name, address, signature); `filter` = regex. Paginated. |
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

## Environment

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` (or `GHIDRA_HOME`) | Ghidra install directory (required) |
| `GHIDRA_MCP_HOME` | Where projects are stored (default `~/ghidra_mcp`; no path element may start with `.`) |

One binary is loaded at a time; `load_binary` closes the previous one. Only one server may open a given project at a time.
Logs go to stderr; stdout is reserved for the protocol.

## Test

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra python tests/smoke.py ./some_binary some_function
```
