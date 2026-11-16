"""End-to-end check over stdio.

Usage: GHIDRA_INSTALL_DIR=... python tests/smoke.py <binary> <function> [<binary2> <function2>]

With a second binary it also exercises multi-binary loading: both are loaded at once, each is
queried through its `binary` selector, and one is unloaded without disturbing the other."""
import asyncio, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main(binary, fn, binary2=None, fn2=None):
    p = StdioServerParameters(command=sys.executable, args=["-m", "ghidra_mcp.server"], env=dict(os.environ))
    async with stdio_client(p) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        async def call(n, **a):
            res = await s.call_tool(n, a)
            t = res.content[0].text
            assert not res.is_error, t
            print(f"--- {n}\n{t[:600]}")
            return t
        import json
        ld = json.loads(await call("load_binary", path=binary))
        assert ld.get("state") in ("importing", "analyzing", "ready"), ld
        # import is asynchronous now: poll until the program exists before structural queries
        for _ in range(600):
            if ld.get("state") != "importing":
                break
            await asyncio.sleep(1)
            ld = json.loads(await call("load_status"))
        assert ld.get("state") != "error", ld
        # structural tools must work while analysis is still running in the background
        if ld.get("state") == "analyzing":
            assert "items" in json.loads(await call("list_exports")), "exports should work during analyzing"
            await call("list_imports")
            # a decompiler-driven tool returns the soft status, not a wrong answer
            gf = await call("get_function", function=fn)
            assert '"status": "analyzing"' in gf, f"expected analyzing status, got: {gf[:200]}"
        # poll load_status until ready
        for _ in range(600):
            st = json.loads(await call("load_status"))
            if st.get("state") == "ready" and st.get("analyzed"):
                break
            assert st.get("state") != "error", st
            await asyncio.sleep(1)
        else:
            raise AssertionError("analysis did not finish in 600s")
        assert st.get("language") and st.get("image_base"), st
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

        if binary2:
            first_id = ld["id"]
            ld2 = json.loads(await call("load_binary", path=binary2))
            assert ld2["id"] != first_id
            # both binaries are loaded at once; the first one is still queryable by selector
            await call("list_binaries")
            await call("list_functions", filter=fn2 or "", binary=first_id)
            await call("get_function", function="renamed_fn", binary=first_id)
            # poll the second binary independently
            for _ in range(600):
                st = json.loads(await call("load_status", binary=ld2["id"]))
                if st.get("state") == "ready" and st.get("analyzed"):
                    break
                assert st.get("state") != "error", st
                await asyncio.sleep(1)
            else:
                raise AssertionError("second analysis did not finish in 600s")
            await call("get_function", function=fn2, binary=ld2["id"])
            # unloading the second leaves the first intact
            await call("unload_binary", binary=ld2["id"])
            assert "renamed_fn" in await call("get_function", function="renamed_fn", binary=first_id)

asyncio.run(main(*sys.argv[1:5]))
