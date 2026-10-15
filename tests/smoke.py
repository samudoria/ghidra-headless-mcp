"""End-to-end check over stdio. Usage: GHIDRA_INSTALL_DIR=... python tests/smoke.py <binary> <function>"""
import asyncio, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main(binary, fn):
    p = StdioServerParameters(command=sys.executable, args=["-m", "ghidra_mcp.server"], env=dict(os.environ))
    async with stdio_client(p) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        async def call(n, **a):
            res = await s.call_tool(n, a)
            t = res.content[0].text
            assert not res.isError, t
            print(f"--- {n}\n{t[:600]}")
            return t
        await call("load_binary", path=binary)
        await call("list_functions", filter=fn)
        await call("get_function", function=fn)
        if fn != "renamed_fn":
            await call("rename", target=fn, new_name="renamed_fn")
            await call("add_comment", target="renamed_fn", text="analyst note")
        assert "renamed_fn" in await call("get_function", function="renamed_fn")
        if "param_1" in await call("get_function", function="renamed_fn"):
            await call("rename_variable", function="renamed_fn", old_name="param_1", new_name="password")
            assert "password" in await call("get_function", function="renamed_fn")
        await call("get_callers", function="renamed_fn")
        await call("get_xrefs", target="renamed_fn")
        await call("list_strings", filter="s3cret")
        await call("list_imports")
        await call("get_disassembly", function="renamed_fn", max_lines=5)
        addr = (await call("list_functions", filter="renamed_fn")).split('"address": "')[1].split('"')[0]
        await call("read_memory", address=addr, length=16)
        await call("search_bytes", pattern="?? ??", limit=2)
        await call("search_constants", value="0x10", limit=2)
        await call("call_path", source="renamed_fn", target="renamed_fn")
        await call("set_signature", function="renamed_fn", signature="int renamed_fn(char *key)")
        await call("retype_variable", function="renamed_fn", variable="key", type="char *")
asyncio.run(main(*sys.argv[1:3]))
