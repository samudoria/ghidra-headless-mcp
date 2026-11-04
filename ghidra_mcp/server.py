"""Headless Ghidra MCP server (stdio). One binary loaded at a time; edits are saved immediately.

Load is non-blocking: load_binary imports the program (fast) and runs Ghidra auto-analysis on a
background thread. Structural tools (exports/imports/strings/function list/memory) answer right
after import; decompiler-driven tools return a soft {"status":"analyzing"} until analysis is done.
Poll load_status() for the one clear ready signal. See PLAN.md for the state machine and locking."""
import hashlib, json, os, re, sys, threading, time

# JVM/Ghidra write to fd 1; keep it for MCP only and send everything else to stderr.
_proto = os.fdopen(os.dup(1), "w")
os.dup2(2, 1)
sys.stdout = _proto  # mcp's stdio transport reads sys.stdout at run time

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("ghidra-headless-mcp")
S = {}  # prog, ifc (decompiler), proj (GhidraProject), path, state, analyzed, analyze_start, analyze_err, thread
COMMENTS = ("pre", "eol", "post", "plate", "repeatable")

LOCK = threading.RLock()  # guards S (state + prog/ifc/proj refs) and serializes load_binary/close
DEFAULT_DISABLE = "Embedded Media"  # trimmed only when GHIDRA_MCP_TRIM_ANALYSIS is set; see PLAN.md
ANALYZING_HINT = ("analysis running in background; poll load_status. "
                  "list_exports/list_imports/list_strings/list_functions/read_memory/search_bytes work now")


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


def _dec_timeout(timeout):
    if timeout and timeout > 0:
        return int(timeout)
    return int(os.environ.get("GHIDRA_MCP_DECOMPILE_TIMEOUT", "30"))


def _decompile(f, timeout=0):
    """Returns the decompile result, or None on timeout (caller renders a status)."""
    res = S["ifc"].decompileFunction(f, _dec_timeout(timeout), _monitor())
    if not res.decompileCompleted():
        msg = str(res.getErrorMessage())
        if "timeout" in msg.lower() or "timed out" in msg.lower():
            return None
        raise RuntimeError("Decompile failed: " + msg)
    return res


def _json(x):
    return json.dumps(x, indent=1)


# --- load state machine -----------------------------------------------------

def _status_locked():
    """Build the status dict. Caller holds LOCK."""
    st = S.get("state", "idle")
    d = {"state": st}
    if "prog" in S:
        p = S["prog"]
        d["name"] = p.getName()
        d["functions"] = p.functionManager.getFunctionCount()
    if st == "analyzing":
        d["elapsed_s"] = round(time.time() - S.get("analyze_start", time.time()), 1)
    if st == "ready":
        d["analyzed"] = bool(S.get("analyzed"))
    if st == "error":
        d["error"] = S.get("analyze_err", "")
    return d


def _retry_after():
    el = time.time() - S.get("analyze_start", time.time())
    return 5 if el < 20 else 3


def _trim_analysis(prog):
    names = [n.strip() for n in os.environ.get("GHIDRA_MCP_DISABLE_ANALYZERS", DEFAULT_DISABLE).split(",") if n.strip()]
    if not names:
        return
    from ghidra.program.model.listing import Program
    opts = prog.getOptions(Program.ANALYSIS_PROPERTIES)
    tx = prog.startTransaction("trim analysis")
    try:
        for n in names:
            if opts.contains(n):
                opts.setBoolean(n, False)
    finally:
        prog.endTransaction(tx, True)


def _analyze(prog, proj):
    """Heavy, blocking full analysis. Kept small/overridable for testing."""
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.util import GhidraProgramUtilities
    if os.environ.get("GHIDRA_MCP_TRIM_ANALYSIS", "0") not in ("0", "", "false", "False"):
        _trim_analysis(prog)
    FlatProgramAPI(prog).analyzeAll(prog)
    GhidraProgramUtilities.markProgramAnalyzed(prog)
    proj.save(prog)


def _analysis_thread(prog, proj):
    try:
        _analyze(prog, proj)
        with LOCK:
            if S.get("prog") is prog:
                S.update(state="ready", analyzed=True, analyze_end=time.time())
    except Exception as e:  # analysis failure surfaces via load_status / tool error
        with LOCK:
            if S.get("prog") is prog:
                S.update(state="error", analyze_err=str(e))


def _kick_analysis_locked():
    """Start background analysis of the current program. Caller holds LOCK; program imported, not analyzed."""
    S.update(state="analyzing", analyze_start=time.time())
    S.pop("analyze_err", None)
    t = threading.Thread(target=_analysis_thread, args=(S["prog"], S["proj"]), daemon=True)
    S["thread"] = t
    t.start()


def _require_analysis():
    """None if analysis-dependent tools may proceed, else a soft status JSON string to return as-is.
    For a ready-but-unanalyzed program (analyze=False) this triggers analysis on demand."""
    with LOCK:
        st = S.get("state", "idle")
        if st == "idle":
            raise RuntimeError("No binary loaded. Call load_binary first.")
        if st == "importing":
            return _json({"status": "analyzing", "retry_after_s": 2, "hint": ANALYZING_HINT})
        if st == "error":
            raise RuntimeError("Analysis failed: " + S.get("analyze_err", ""))
        if st == "ready" and S.get("analyzed"):
            return None
        if st == "ready":  # imported but not analyzed -> trigger on demand
            _kick_analysis_locked()
        return _json({"status": "analyzing", "retry_after_s": _retry_after(), "hint": ANALYZING_HINT})


def _open_or_import(path):
    from pathlib import Path
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import ProjectLocator
    root = Path(os.environ.get("GHIDRA_MCP_HOME") or Path.home() / "ghidra_mcp")
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
    return prog, proj


@mcp.tool()
def load_binary(path: str, analyze: bool = True) -> str:
    """Load a native binary (.so, ELF, PE, Mach-O...). Must be called first. Returns immediately:
    the import is synchronous but Ghidra auto-analysis runs in the background. Read
    exports/imports/strings/function list right away; poll load_status() until {"state":"ready",
    "analyzed":true} before decompiler-driven tools. With analyze=False, analysis is skipped and
    started on demand the first time a decompiler tool is called. The project (and analysis) is
    cached, so edits and analysis persist across sessions."""
    import pyghidra
    _home()
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with LOCK:
        if S.get("state") == "analyzing":  # a previous load is still analyzing; don't disturb it
            return _json(_status_locked())
        if S.get("path") == path and S.get("state") == "ready":  # already loaded
            if analyze and not S.get("analyzed"):
                _kick_analysis_locked()
            return _json(_status_locked())
        pyghidra.start()
        close_locked()
        S["state"] = "importing"
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.decompiler import DecompInterface
        prog, proj = _open_or_import(path)
        already = not GhidraProgramUtilities.shouldAskToAnalyze(prog)
        ifc = DecompInterface()
        ifc.openProgram(prog)
        S.update(prog=prog, ifc=ifc, proj=proj, path=path, state="ready", analyzed=already)
        if analyze and not already:
            _kick_analysis_locked()
        return _json(_status_locked() | {"language": str(prog.getLanguageID()),
                                         "image_base": str(prog.getImageBase())})


@mcp.tool()
def load_status() -> str:
    """Current load state: idle / importing / analyzing / ready / error. The one signal to poll.
    {"state":"ready","analyzed":true} means decompiler-driven tools are good to go; while
    {"state":"analyzing",...} the structural tools (exports/imports/strings/function list) already work."""
    with LOCK:
        return _json(_status_locked())


@mcp.tool()
def list_functions(filter: str = "", limit: int = 50, offset: int = 0) -> str:
    """List functions (name, address, signature). `filter` is a case-insensitive regex on the name.
    Available right after import; the list grows as background analysis discovers more functions."""
    m = _match(filter)
    return _json(_page((_fn(f) for f in _prog().functionManager.getFunctions(True) if m(f.getName())), limit, offset))


@mcp.tool()
def get_function(function: str, max_chars: int = 20000, timeout: int = 0) -> str:
    """Decompiled C of a function. `function` = exact name or any address inside it (e.g. 0x101234).
    Needs analysis: returns {"status":"analyzing"} until ready. `timeout` = per-call decompile seconds
    (0 = GHIDRA_MCP_DECOMPILE_TIMEOUT, default 30; pass 120 for the old limit)."""
    busy = _require_analysis()
    if busy:
        return busy
    res = _decompile(_func(function), timeout)
    if res is None:
        return _json({"status": "timeout", "timeout_s": _dec_timeout(timeout), "function": function,
                      "hint": "raise the timeout param (e.g. timeout=120)"})
    c = res.getDecompiledFunction().getC()
    return c if len(c) <= max_chars else c[:max_chars] + f"\n/* truncated at {max_chars} of {len(c)} chars; raise max_chars */"


@mcp.tool()
def get_disassembly(function: str, max_lines: int = 500) -> str:
    """Assembly listing of a function (address, instruction, comments). Needs analysis: returns
    {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
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
    """List defined strings (address, value). `filter` is a case-insensitive regex on the value.
    Available right after import; the set grows as background analysis defines more strings."""
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
    """List imported (external) symbols with their library. `filter` is a regex on the name.
    Available right after import (no analysis needed)."""
    m = _match(filter)
    gen = ({"name": s.getName(), "library": s.getParentNamespace().getName()}
           for s in _prog().symbolTable.getExternalSymbols() if m(s.getName()))
    return _json(_page(gen, limit, offset))


@mcp.tool()
def list_exports(filter: str = "", limit: int = 50, offset: int = 0) -> str:
    """List exported symbols (entry points). `filter` is a regex on the name.
    Available right after import (no analysis needed)."""
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
    """Functions that call `function`. Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    return _json(_page((_fn(f) for f in _func(function).getCallingFunctions(_monitor())), limit, offset))


@mcp.tool()
def get_callees(function: str, limit: int = 50, offset: int = 0) -> str:
    """Functions called by `function`. Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    return _json(_page((_fn(f) for f in _func(function).getCalledFunctions(_monitor())), limit, offset))


@mcp.tool()
def get_xrefs(target: str, limit: int = 50, offset: int = 0) -> str:
    """References to an address, string, global or function. `target` = address or function name.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
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
    Do this often: good names are the most valuable output for the next analyst.
    Needs analysis (edits the program): returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
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


def _var(function, name):
    """(function, high symbol) for a variable as named in the decompiled C."""
    f = _func(function)
    res = _decompile(f)
    if res is None:
        raise RuntimeError(f"Decompilation of {f.getName()} timed out; raise GHIDRA_MCP_DECOMPILE_TIMEOUT")
    syms = list(res.getHighFunction().getLocalSymbolMap().getSymbols())
    hits = [s for s in syms if s.getName() == name]
    if not hits:
        raise ValueError(f"No variable '{name}' in {f.getName()}. Have: {[s.getName() for s in syms]}")
    return f, hits[0]


@mcp.tool()
def rename_variable(function: str, old_name: str, new_name: str) -> str:
    """Rename a local variable or parameter as shown in the decompiled C of `function`.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    f, sym = _var(function, old_name)
    _edit("rename variable", lambda: HighFunctionDBUtil.updateDBVariable(sym, new_name, None, SourceType.USER_DEFINED))
    return f"{old_name} -> {new_name} in {f.getName()}"


@mcp.tool()
def retype_variable(function: str, variable: str, type: str) -> str:
    """Change the type of a local/parameter as shown in the decompiled C, e.g. type='char *' or 'uint8_t[16]'.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    from ghidra.util.data import DataTypeParser
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    f, sym = _var(function, variable)
    dtm = _prog().getDataTypeManager()
    dt = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL).parse(type)
    _edit("retype variable", lambda: HighFunctionDBUtil.updateDBVariable(sym, None, dt, SourceType.USER_DEFINED))
    return f"{variable}: {dt.getName()} in {f.getName()}"


@mcp.tool()
def set_signature(function: str, signature: str) -> str:
    """Apply a C prototype to a function, e.g. 'int check_license(char *key, int len)'.
    Fixes return type, parameter names/types and count in the decompiled output.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.program.model.symbol import SourceType
    p = _prog()
    f = _func(function)
    fd = FunctionSignatureParser(p.getDataTypeManager(), None).parse(f.getSignature(), signature)
    cmd = ApplyFunctionSignatureCmd(f.getEntryPoint(), fd, SourceType.USER_DEFINED)
    if not _edit("set signature", lambda: cmd.applyTo(p)):
        raise RuntimeError(f"Could not apply signature: {cmd.getStatusMsg()}")
    return f"{f.getName()}: {f.getPrototypeString(False, False)}"


@mcp.tool()
def read_memory(address: str, length: int = 64) -> str:
    """Hex dump of `length` bytes (max 4096) at an address, e.g. to read a string table or JNI method table.
    Available right after import (raw memory, no analysis needed)."""
    a = _addr(address)
    if a is None:
        raise ValueError(f"Bad address '{address}'")
    length = min(length, 4096)
    from jpype import JArray, JByte
    buf = JArray(JByte)(length)
    n = _prog().memory.getBytes(a, buf)
    data = bytes(b & 0xFF for b in buf[:n])
    length = n
    return "\n".join(f"{a.add(i)}  {data[i:i + 16].hex(' ')}" for i in range(0, length, 16))


@mcp.tool()
def search_bytes(pattern: str, limit: int = 50, offset: int = 0) -> str:
    """Find a byte pattern in memory. Hex with '??' wildcards, e.g. '48 8b ?? 05' or 'deadbeef'.
    Available right after import (raw memory scan, no analysis needed)."""
    toks = re.findall(r"\?\?|[0-9a-fA-F]{2}", pattern)
    if not toks or re.sub(r"\?\?|[0-9a-fA-F]{2}|\s", "", pattern):
        raise ValueError("pattern must be hex bytes, optionally with ?? wildcards")
    val = bytes(0 if t == "??" else int(t, 16) for t in toks)
    mask = bytes(0 if t == "??" else 0xFF for t in toks)
    p = _prog()
    def gen():
        a = p.minAddress
        while a is not None:
            a = p.memory.findBytes(a, val, mask, True, _monitor())
            if a is None:
                return
            f = p.functionManager.getFunctionContaining(a)
            yield {"address": str(a), "function": f.getName() if f else None}
            a = a.next()
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def search_constants(value: str, limit: int = 50, offset: int = 0) -> str:
    """Find instructions with a scalar operand equal to `value` (decimal or 0x hex): crypto constants,
    magic numbers, flags. Needs analysis (iterates instructions): returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    from ghidra.program.model.scalar import Scalar
    v = int(value, 0)
    p = _prog()
    def gen():
        for ins in p.listing.getInstructions(True):
            for i in range(ins.getNumOperands()):
                if any(isinstance(o, Scalar) and v in (o.getValue(), o.getUnsignedValue()) for o in ins.getOpObjects(i)):
                    f = p.functionManager.getFunctionContaining(ins.getAddress())
                    yield {"address": str(ins.getAddress()), "instruction": str(ins), "function": f.getName() if f else None}
                    break
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def call_path(source: str, target: str, max_depth: int = 10) -> str:
    """Shortest call chain from function `source` to `target` (e.g. JNI_OnLoad -> some_sink), or null if none.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    s, t = _func(source), _func(target)
    prev = {s.getEntryPoint(): None}
    frontier = [s]
    for _ in range(max_depth):
        nxt = []
        for f in frontier:
            for c in f.getCalledFunctions(_monitor()):
                if c.getEntryPoint() not in prev:
                    prev[c.getEntryPoint()] = f
                    nxt.append(c)
        if t.getEntryPoint() in prev:
            break
        frontier = nxt
    if t.getEntryPoint() not in prev:
        return _json(None)
    path, f = [], t
    while f is not None:
        path.append(_fn(f))
        f = prev[f.getEntryPoint()]
    return _json(path[::-1])  # ponytail: one shortest path only, enumerate all if ever needed


@mcp.tool()
def add_comment(target: str, text: str, kind: str = "pre") -> str:
    """Add a comment at an address or function entry. kind: pre (default, shown above the line in the
    decompiler), eol, post, plate, repeatable. Empty text clears it. Use liberally to document findings.
    Needs analysis (edits the program): returns {"status":"analyzing"} until ready."""
    busy = _require_analysis()
    if busy:
        return busy
    from ghidra.program.model.listing import CodeUnit
    if kind not in COMMENTS:
        raise ValueError(f"kind must be one of {COMMENTS}")
    a = _addr(target)
    if a is None:
        a = _func(target).getEntryPoint()
    ct = getattr(CodeUnit, kind.upper() + "_COMMENT")
    _edit("comment", lambda: _prog().listing.setComment(a, ct, text or None))
    return f"{kind} comment set at {a}"


def close_locked():
    """Dispose the current program/project. Caller holds LOCK. Never called while analyzing."""
    if "proj" in S:
        S["ifc"].dispose()
        S["proj"].close()
    S.clear()


def close():
    with LOCK:
        close_locked()


def main():
    # Transport: stdio (default), sse or streamable-http. Host/port via env for the HTTP ones.
    transport = os.environ.get("GHIDRA_MCP_TRANSPORT", "stdio")
    kwargs = {}
    if transport != "stdio":
        kwargs["host"] = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
        kwargs["port"] = int(os.environ.get("GHIDRA_MCP_PORT", "8000"))
    mcp.run(transport=transport, **kwargs)


if __name__ == "__main__":
    main()
