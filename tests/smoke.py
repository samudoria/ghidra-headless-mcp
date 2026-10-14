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
asyncio.run(main(*sys.argv[1:3]))
