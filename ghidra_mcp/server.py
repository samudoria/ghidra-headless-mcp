"""Headless Ghidra MCP server (stdio). One binary loaded at a time; edits are saved immediately."""
import hashlib, json, os, re, sys

# JVM/Ghidra write to fd 1; keep it for MCP only and send everything else to stderr.
_proto = os.fdopen(os.dup(1), "w")
os.dup2(2, 1)
sys.stdout = _proto  # mcp's stdio transport reads sys.stdout at run time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ghidra-headless-mcp")
S = {}  # prog, ifc (decompiler), proj (GhidraProject), path
COMMENTS = ("pre", "eol", "post", "plate", "repeatable")


def _home():
    h = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    if not h:
        raise RuntimeError("Set GHIDRA_INSTALL_DIR to your Ghidra install directory.")
    os.environ["GHIDRA_INSTALL_DIR"] = h


def _prog():
    if "prog" not in S:
        raise RuntimeError("No binary loaded. Call load_binary first.")
    return S["prog"]


def _monitor():
    from ghidra.util.task import TaskMonitor
    return TaskMonitor.DUMMY


def _page(it, limit, offset):
    items = []
    for i, x in enumerate(it):
        if i < offset:
            continue
        if len(items) == limit:
            return {"items": items, "offset": offset, "next_offset": offset + limit}
        items.append(x)
    return {"items": items, "offset": offset, "next_offset": None}


def _match(filter_):
    if not filter_:
        return lambda s: True
    rx = re.compile(filter_, re.I)
    return lambda s: bool(rx.search(s))


def _addr(s):
    try:
        return _prog().addressFactory.getAddress(s)
    except Exception:
        return None


def _func(target):
    """Resolve a function by exact name or by any address inside it."""
    fm = _prog().functionManager
    hits = [f for f in fm.getFunctions(True) if f.getName() == target]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise ValueError(f"'{target}' is ambiguous; use an address: " + ", ".join(str(f.getEntryPoint()) for f in hits[:10]))
    a = _addr(target)
    f = fm.getFunctionContaining(a) if a else None
    if f is None:
        near = [f.getName() for f in fm.getFunctions(True) if target.lower() in f.getName().lower()][:10]
        raise ValueError(f"No function '{target}'." + (f" Similar: {near}" if near else ""))
    return f


def _fn(f):
    return {"name": f.getName(), "address": str(f.getEntryPoint()), "signature": f.getPrototypeString(False, False)}


def _edit(label, fn):
    p = _prog()
    tx = p.startTransaction(label)
    ok = False
    try:
        r = fn()
        ok = True
        return r
    finally:
        p.endTransaction(tx, ok)
        if ok:
            S["proj"].save(p)


def _decompile(f):
    res = S["ifc"].decompileFunction(f, 120, _monitor())
    if not res.decompileCompleted():
        raise RuntimeError("Decompile failed: " + str(res.getErrorMessage()))
    return res


def _json(x):
    return json.dumps(x, indent=1)


@mcp.tool()
def load_binary(path: str, analyze: bool = True) -> str:
    """Load a native binary (.so, ELF, PE, Mach-O...) and run Ghidra auto-analysis. Must be called first.
    The Ghidra project is cached, so edits (renames, comments) persist across sessions."""
    import pyghidra
    _home()
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    pyghidra.start()
    close()
    from pathlib import Path
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import ProjectLocator
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    root = Path(os.environ.get("GHIDRA_MCP_HOME") or Path.home() / ".ghidra_mcp")
    name = os.path.basename(path) + "_" + hashlib.sha1(path.encode()).hexdigest()[:8]
    loc = root / name
    if ProjectLocator(loc, name).exists():
        proj = GhidraProject.openProject(loc, name, True)
    else:
        loc.mkdir(parents=True, exist_ok=True)
        proj = GhidraProject.createProject(loc, name, False)
    fname = os.path.basename(path)
    if proj.getRootFolder().getFile(fname):
        prog = proj.openProgram("/", fname, False)
    else:
        prog = proj.importProgram(Path(path))
        if prog is None:
            raise RuntimeError(f"Ghidra could not import {path} (unsupported format?)")
        proj.saveAs(prog, "/", fname, True)
    if analyze and GhidraProgramUtilities.shouldAskToAnalyze(prog):
        FlatProgramAPI(prog).analyzeAll(prog)
        GhidraProgramUtilities.markProgramAnalyzed(prog)
        proj.save(prog)
    from ghidra.app.decompiler import DecompInterface
    ifc = DecompInterface()
    ifc.openProgram(prog)
    S.update(prog=prog, ifc=ifc, proj=proj, path=path)
    return _json({"name": prog.getName(), "language": str(prog.getLanguageID()), "image_base": str(prog.getImageBase()),
                  "functions": prog.functionManager.getFunctionCount()})


@mcp.tool()
def list_functions(filter: str = "", limit: int = 50, offset: int = 0) -> str:
    """List functions (name, address, signature). `filter` is a case-insensitive regex on the name."""
    m = _match(filter)
    return _json(_page((_fn(f) for f in _prog().functionManager.getFunctions(True) if m(f.getName())), limit, offset))


@mcp.tool()
def get_function(function: str, max_chars: int = 20000) -> str:
    """Decompiled C of a function. `function` = exact name or any address inside it (e.g. 0x101234)."""
    c = _decompile(_func(function)).getDecompiledFunction().getC()
    return c if len(c) <= max_chars else c[:max_chars] + f"\n/* truncated at {max_chars} of {len(c)} chars; raise max_chars */"


@mcp.tool()
def get_disassembly(function: str, max_lines: int = 500) -> str:
    """Assembly listing of a function (address, instruction, comments)."""
    p = _prog()
    f = _func(function)
    out = []
    for ins in p.listing.getInstructions(f.getBody(), True):
        out.append(f"{ins.getAddress()}  {ins}")
        if len(out) == max_lines:
            out.append(f"; truncated at {max_lines} lines")
            break
    return "\n".join(out)


@mcp.tool()
def list_strings(filter: str = "", limit: int = 50, offset: int = 0) -> str:
    """List defined strings (address, value). `filter` is a case-insensitive regex on the value."""
    m = _match(filter)
    def gen():
        for d in _prog().listing.getDefinedData(True):
            if d.hasStringValue():
                v = str(d.getValue())
                if m(v):
                    yield {"address": str(d.getAddress()), "value": v}
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def list_imports(filter: str = "", limit: int = 50, offset: int = 0) -> str:
    """List imported (external) symbols with their library. `filter` is a regex on the name."""
    m = _match(filter)
    gen = ({"name": s.getName(), "library": s.getParentNamespace().getName()}
           for s in _prog().symbolTable.getExternalSymbols() if m(s.getName()))
    return _json(_page(gen, limit, offset))


@mcp.tool()
def list_exports(filter: str = "", limit: int = 50, offset: int = 0) -> str:
    """List exported symbols (entry points). `filter` is a regex on the name."""
    st = _prog().symbolTable
    m = _match(filter)
    def gen():
        for a in st.getExternalEntryPointIterator():
            s = st.getPrimarySymbol(a)
            if s is not None and m(s.getName()):
                yield {"name": s.getName(), "address": str(a)}
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def get_callers(function: str, limit: int = 50, offset: int = 0) -> str:
    """Functions that call `function`."""
    return _json(_page((_fn(f) for f in _func(function).getCallingFunctions(_monitor())), limit, offset))


@mcp.tool()
def get_callees(function: str, limit: int = 50, offset: int = 0) -> str:
    """Functions called by `function`."""
    return _json(_page((_fn(f) for f in _func(function).getCalledFunctions(_monitor())), limit, offset))


@mcp.tool()
def get_xrefs(target: str, limit: int = 50, offset: int = 0) -> str:
    """References to an address, string, global or function. `target` = address or function name."""
    p = _prog()
    a = _addr(target)
    if a is None:
        a = _func(target).getEntryPoint()
    def gen():
        for r in p.referenceManager.getReferencesTo(a):
            f = p.functionManager.getFunctionContaining(r.getFromAddress())
            yield {"from": str(r.getFromAddress()), "type": str(r.getReferenceType()), "function": f.getName() if f else None}
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def rename(target: str, new_name: str) -> str:
    """Rename a function (by name/address) or, for a non-function address, create/replace its label.
    Do this often: good names are the most valuable output for the next analyst."""
    from ghidra.program.model.symbol import SourceType
    p = _prog()
    try:
        f = _func(target)
        old = f.getName()
        _edit("rename", lambda: f.setName(new_name, SourceType.USER_DEFINED))
        return f"{old} -> {new_name} @ {f.getEntryPoint()}"
    except ValueError:
        a = _addr(target)
        if a is None:
            raise
        _edit("rename", lambda: p.symbolTable.createLabel(a, new_name, SourceType.USER_DEFINED).setPrimary())
        return f"{a} -> {new_name}"


@mcp.tool()
def rename_variable(function: str, old_name: str, new_name: str) -> str:
    """Rename a local variable or parameter as shown in the decompiled C of `function`."""
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    f = _func(function)
    high = _decompile(f).getHighFunction()
    syms = [s for s in high.getLocalSymbolMap().getSymbols() if s.getName() == old_name]
    if not syms:
        have = [s.getName() for s in high.getLocalSymbolMap().getSymbols()]
        raise ValueError(f"No variable '{old_name}' in {f.getName()}. Have: {have}")
    _edit("rename variable", lambda: HighFunctionDBUtil.updateDBVariable(syms[0], new_name, None, SourceType.USER_DEFINED))
    return f"{old_name} -> {new_name} in {f.getName()}"


@mcp.tool()
def add_comment(target: str, text: str, kind: str = "pre") -> str:
    """Add a comment at an address or function entry. kind: pre (default, shown above the line in the
    decompiler), eol, post, plate, repeatable. Empty text clears it. Use liberally to document findings."""
    from ghidra.program.model.listing import CodeUnit
    if kind not in COMMENTS:
        raise ValueError(f"kind must be one of {COMMENTS}")
    a = _addr(target)
    if a is None:
        a = _func(target).getEntryPoint()
    ct = getattr(CodeUnit, kind.upper() + "_COMMENT")
    _edit("comment", lambda: _prog().listing.setComment(a, ct, text or None))
    return f"{kind} comment set at {a}"


def close():
    if "proj" in S:
        S["ifc"].dispose()
        S["proj"].close()
        S.clear()


def main():
    mcp.run()


if __name__ == "__main__":
    main()
