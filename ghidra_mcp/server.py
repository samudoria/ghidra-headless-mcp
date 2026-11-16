"""Headless Ghidra MCP server (stdio). Several binaries can be loaded at once; edits are saved immediately.

Load is non-blocking: load_binary starts the import and Ghidra auto-analysis on background
threads and returns at once. Imports are serialized (Ghidra project code is not thread-safe);
analysis and queries run in parallel across binaries. Structural tools (exports/imports/strings/
function list/memory) answer once the import is done; decompiler-driven tools return a soft
{"status":"analyzing"} until analysis is done. Poll load_status() for the ready signal. Every tool takes an optional
`binary` selector (path, basename or program name); omitted = most recently loaded. See PLAN.md."""
import hashlib, json, os, re, sys, threading, time, traceback

# JVM/Ghidra write to fd 1; keep it for MCP only and send everything else to stderr.
_proto = os.fdopen(os.dup(1), "w")
os.dup2(2, 1)
sys.stdout = _proto  # mcp's stdio transport reads sys.stdout at run time

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("ghidra-headless-mcp")
SESSIONS = {}  # abspath -> {id, path, name, lock, prog, ifc, proj, state, analyzed, analyze_start, analyze_end, analyze_err, thread}
ACTIVE = None  # abspath of the most recently loaded binary
REGISTRY_LOCK = threading.RLock()  # guards SESSIONS/ACTIVE
IMPORT_LOCK = threading.Lock()  # serializes pyghidra.start + project open/import (not thread-safe)
_STARTED = False
COMMENTS = ("pre", "eol", "post", "plate", "repeatable")
DEFAULT_DISABLE = "Embedded Media"  # trimmed only when GHIDRA_MCP_TRIM_ANALYSIS is set; see PLAN.md
ANALYZING_HINT = ("analysis running in background; poll load_status. "
                  "list_exports/list_imports/list_strings/list_functions/read_memory/search_bytes work now")


def _home():
    h = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    if not h:
        raise RuntimeError("Set GHIDRA_INSTALL_DIR to your Ghidra install directory.")
    os.environ["GHIDRA_INSTALL_DIR"] = h


def _new_session(path):
    return {"id": path, "path": path, "lock": threading.RLock(), "state": "importing"}


def _session(binary=""):
    """Resolve a binary selector to its session. Empty = most recently loaded."""
    with REGISTRY_LOCK:
        if not SESSIONS:
            raise RuntimeError("No binary loaded. Call load_binary first.")
        if not binary:
            return SESSIONS[ACTIVE] if ACTIVE in SESSIONS else next(reversed(SESSIONS.values()))
        if binary in SESSIONS:
            return SESSIONS[binary]
        hits = [s for s in SESSIONS.values()
                if os.path.basename(s["path"]) == binary or s.get("name") == binary]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise ValueError(f"'{binary}' is ambiguous; use one of: " + ", ".join(s["id"] for s in hits))
        raise ValueError(f"No loaded binary '{binary}'. Loaded: " + ", ".join(s["id"] for s in SESSIONS.values()))


def _prog(binary=""):
    sess = _session(binary)
    with sess["lock"]:
        if "prog" not in sess:
            raise RuntimeError(f"{sess['path']} is still importing; poll load_status.")
        return sess["prog"]


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


_ELF_MAGIC = b"\x7fELF"
_ELF_MIN_VADDR = {}  # path -> lowest PT_LOAD p_vaddr


def _elf_min_vaddr(path):
    """Lowest PT_LOAD virtual address of an ELF file (0 for shared objects).

    Ghidra may relocate the image (a .so usually lands at 0x100000), so a Ghidra
    address is not the address a file viewer / readelf / angr reports.  The
    difference is exactly ``image_base - min(p_vaddr)``.  Parsing the program
    headers here keeps the conversion independent of pyelftools.
    """
    cached = _ELF_MIN_VADDR.get(path)
    if cached is not None:
        return cached
    result = 0
    try:
        with open(path, "rb") as fh:
            header = fh.read(64)
            if header[:4] == _ELF_MAGIC:
                is64 = header[4] == 2
                endian = "little" if header[5] == 1 else "big"
                if is64:
                    phoff = int.from_bytes(header[32:40], endian)
                    phentsize = int.from_bytes(header[54:56], endian)
                    phnum = int.from_bytes(header[56:58], endian)
                else:
                    phoff = int.from_bytes(header[28:32], endian)
                    phentsize = int.from_bytes(header[42:44], endian)
                    phnum = int.from_bytes(header[44:46], endian)
                fh.seek(phoff)
                table = fh.read(phentsize * phnum)
                vaddrs = []
                for i in range(phnum):
                    entry = table[i * phentsize:(i + 1) * phentsize]
                    if len(entry) < phentsize:
                        break
                    if int.from_bytes(entry[0:4], endian) != 1:  # PT_LOAD
                        continue
                    offset = 16 if is64 else 8
                    size = 8 if is64 else 4
                    vaddrs.append(int.from_bytes(entry[offset:offset + size], endian))
                if vaddrs:
                    result = min(vaddrs)
    except OSError:
        pass
    _ELF_MIN_VADDR[path] = result
    return result


def _file_address(prog, address, path=""):
    """Ghidra address -> the address the file itself uses (ELF p_vaddr)."""
    try:
        value = int(address.getOffset()) if hasattr(address, "getOffset") else int(address)
        base = int(prog.getImageBase().getOffset())
        return value - base + (_elf_min_vaddr(path) if path else 0)
    except Exception:
        return int(address)


def _addr(s, binary=""):
    """Resolve an address. Accepts Ghidra addresses, file-relative addresses and
    ``name@0xADDR`` selectors (the address part wins)."""
    text = str(s or "").strip()
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    prog = _prog(binary)
    try:
        a = prog.addressFactory.getAddress(text)
        if a is not None and prog.memory.contains(a):
            return a
    except Exception:
        pass
    try:
        value = int(text, 0)
    except (TypeError, ValueError):
        return None
    try:  # file-relative address: shift it into Ghidra's address space
        base = int(prog.getImageBase().getOffset())
        return prog.addressFactory.getAddress(hex(value + base))
    except Exception:
        return None


def _func(target, binary=""):
    """Resolve a function by exact name or by any address inside it."""
    fm = _prog(binary).functionManager
    hits = [f for f in fm.getFunctions(True) if f.getName() == target]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise ValueError(f"'{target}' is ambiguous; use an address: " + ", ".join(str(f.getEntryPoint()) for f in hits[:10]))
    a = _addr(target, binary)
    f = fm.getFunctionContaining(a) if a else None
    if f is None:
        near = [f.getName() for f in fm.getFunctions(True) if target.lower() in f.getName().lower()][:10]
        raise ValueError(f"No function '{target}'." + (f" Similar: {near}" if near else ""))
    return f


def _fn(f, binary=""):
    prog = _prog(binary)
    entry = f.getEntryPoint()
    return {
        "name": f.getName(),
        "address": str(entry),
        "file_address": f"0x{_file_address(prog, entry, _session(binary)['path']):x}",
        "signature": f.getPrototypeString(False, False),
    }


def _edit(label, fn, binary=""):
    sess = _session(binary)
    with sess["lock"]:
        p = sess["prog"]
        tx = p.startTransaction(label)
        ok = False
        try:
            r = fn()
            ok = True
            return r
        finally:
            p.endTransaction(tx, ok)
            if ok:
                sess["proj"].save(p)


def _dec_timeout(timeout):
    if timeout and timeout > 0:
        return int(timeout)
    return int(os.environ.get("GHIDRA_MCP_DECOMPILE_TIMEOUT", "30"))


def _decompile(f, timeout=0, binary=""):
    """Returns the decompile result, or None on timeout (caller renders a status)."""
    sess = _session(binary)
    res = sess["ifc"].decompileFunction(f, _dec_timeout(timeout), _monitor())
    if not res.decompileCompleted():
        msg = str(res.getErrorMessage())
        if "timeout" in msg.lower() or "timed out" in msg.lower():
            return None
        raise RuntimeError("Decompile failed: " + msg)
    return res


def _json(x):
    return json.dumps(x, indent=1)


# --- load state machine -----------------------------------------------------

def _status(sess):
    """Build the status dict for one session."""
    with sess["lock"]:
        st = sess.get("state", "idle")
        d = {"id": sess["id"], "state": st}
        if "prog" in sess:
            p = sess["prog"]
            d["name"] = p.getName()
            d["functions"] = p.functionManager.getFunctionCount()
            d["language"] = str(p.getLanguageID())
            d["image_base"] = str(p.getImageBase())
        if st == "analyzing":
            d["elapsed_s"] = round(time.time() - sess.get("analyze_start", time.time()), 1)
        if st == "ready":
            d["analyzed"] = bool(sess.get("analyzed"))
        if st == "error":
            d["error"] = sess.get("analyze_err", "")
        return d


def _retry_after(sess):
    el = time.time() - sess.get("analyze_start", time.time())
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


def _analysis_thread(sess):
    prog = None
    try:
        prog, proj = sess["prog"], sess["proj"]
        _analyze(prog, proj)
        with sess["lock"]:
            if sess.get("prog") is prog:
                sess.update(state="ready", analyzed=True, analyze_end=time.time())
    except Exception as e:  # analysis failure surfaces via load_status / tool error
        traceback.print_exc()
        with sess["lock"]:
            if prog is None or sess.get("prog") is prog:
                sess.update(state="error", analyze_err=str(e))


def _kick_analysis_locked(sess):
    """Start background analysis of a session. Caller holds sess["lock"]; program imported, not analyzed."""
    t = sess.get("thread")
    if t is not None and t.is_alive() and t is not threading.current_thread():
        return  # a job is already running; never start a second one
    sess.update(state="analyzing", analyze_start=time.time())
    sess.pop("analyze_err", None)
    t = threading.Thread(target=_analysis_thread, args=(sess,), daemon=True)
    sess["thread"] = t
    t.start()


def _import_thread(sess, analyze):
    """Background import + optional analysis. Runs independently of the MCP request, so a slow
    import never blocks the client (which would time out and close the stdio stream)."""
    global _STARTED
    path = sess["path"]
    prog = proj = ifc = None
    try:
        import pyghidra
        with IMPORT_LOCK:  # Ghidra project open/import is not thread-safe
            if not _STARTED:
                pyghidra.start()
                _STARTED = True
            from ghidra.program.util import GhidraProgramUtilities
            from ghidra.app.decompiler import DecompInterface
            prog, proj = _open_or_import(path)
            already = not GhidraProgramUtilities.shouldAskToAnalyze(prog)
            ifc = DecompInterface()
            ifc.openProgram(prog)
        with sess["lock"]:
            if SESSIONS.get(path) is not sess:  # unloaded while importing
                try:
                    ifc.dispose()
                    proj.close()
                except Exception:
                    pass
                return
            sess.update(prog=prog, ifc=ifc, proj=proj, name=prog.getName(),
                        state="ready", analyzed=already)
            if analyze and not already:
                _kick_analysis_locked(sess)
    except Exception as e:  # import failure surfaces via load_status; session is kept (idempotent)
        traceback.print_exc()
        with sess["lock"]:
            if SESSIONS.get(path) is sess:
                sess.update(state="error", analyze_err=str(e))


def _require_analysis(binary=""):
    """None if analysis-dependent tools may proceed, else a soft status JSON string to return as-is.
    For a ready-but-unanalyzed program (analyze=False) this triggers analysis on demand."""
    sess = _session(binary)
    with sess["lock"]:
        st = sess.get("state", "idle")
        if st == "idle":
            raise RuntimeError("No binary loaded. Call load_binary first.")
        if st == "importing":
            return _json({"status": "analyzing", "retry_after_s": 2, "hint": ANALYZING_HINT})
        if st == "error":
            raise RuntimeError("Analysis failed: " + sess.get("analyze_err", ""))
        if st == "ready" and sess.get("analyzed"):
            return None
        if st == "ready":  # imported but not analyzed -> trigger on demand
            _kick_analysis_locked(sess)
        return _json({"status": "analyzing", "retry_after_s": _retry_after(sess), "hint": ANALYZING_HINT})


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


def _dispose_session(sess):
    """Dispose the session's program/project. Caller holds sess["lock"] and no job is running."""
    if "ifc" in sess:
        sess["ifc"].dispose()
    if "proj" in sess:
        sess["proj"].close()
    for k in ("prog", "ifc", "proj", "thread"):
        sess.pop(k, None)


@mcp.tool()
def load_binary(path: str, analyze: bool = True, retry: bool = False) -> str:
    """Load a native binary (.so, ELF, PE, Mach-O...). Several binaries may be loaded at once; each
    keeps its own analysis and edits. Returns immediately with state "importing": both the import
    and Ghidra auto-analysis run on a background thread, which keeps running even if this call
    returns. Poll load_status() until {"state":"ready","analyzed":true} before decompiler-driven
    tools; exports/imports/strings/function list work once state is "ready". Calling this again for
    the same path is idempotent: it never re-imports or restarts a running job (a dead job is
    restarted automatically). With analyze=False, analysis is skipped and started on demand the
    first time a decompiler tool is called. On a previous failure the session stays in state
    "error"; pass retry=True to discard it and import again. The project (and analysis) is cached,
    so edits and analysis persist across sessions. The loaded binary becomes the default for tools
    that omit their `binary` selector."""
    global ACTIVE
    _home()
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with REGISTRY_LOCK:
        sess = SESSIONS.get(path)
        if sess is not None:
            with sess["lock"]:
                st = sess.get("state", "idle")
                if st in ("importing", "analyzing"):
                    t = sess.get("thread")
                    if t is not None and t.is_alive():  # job alive: never disturb it
                        ACTIVE = path
                        return _json(_status(sess))
                    if st == "analyzing" and "prog" in sess:  # stale analysis: restart analysis only
                        sess.pop("thread", None)
                        _kick_analysis_locked(sess)
                        ACTIVE = path
                        return _json(_status(sess))
                    # stale import: fall through and restart the import job
                elif st == "ready":  # already loaded
                    if analyze and not sess.get("analyzed"):
                        _kick_analysis_locked(sess)
                    ACTIVE = path
                    return _json(_status(sess))
                elif st == "error" and not retry:
                    ACTIVE = path
                    return _json(_status(sess))
                _dispose_session(sess)  # retry after error, or restart a dead import
                sess["state"] = "importing"
        else:
            sess = _new_session(path)
            SESSIONS[path] = sess
        ACTIVE = path
        sess.update(state="importing", analyze_requested=bool(analyze))
        sess.pop("analyze_err", None)
        t = threading.Thread(target=_import_thread, args=(sess, analyze), daemon=True)
        sess["thread"] = t
        t.start()
        return _json(_status(sess))


@mcp.tool()
def load_status(binary: str = "") -> str:
    """Current load state of one binary: idle / importing / analyzing / ready / error. The one signal
    to poll. {"state":"ready","analyzed":true} means decompiler-driven tools are good to go; while
    {"state":"analyzing",...} the structural tools (exports/imports/strings/function list) already work.
    `binary` selects the loaded binary; omitted = the most recently loaded."""
    with REGISTRY_LOCK:
        if not SESSIONS:
            return _json({"state": "idle"})
    return _json(_status(_session(binary)))


@mcp.tool()
def list_binaries() -> str:
    """All loaded binaries with their id/path/name/state/analyzed/functions, plus which one is active
    (the default when a tool omits `binary`). Use the id as the `binary` selector."""
    with REGISTRY_LOCK:
        return _json({"active": ACTIVE, "binaries": [_status(s) for s in SESSIONS.values()]})


@mcp.tool()
def unload_binary(binary: str = "") -> str:
    """Unload one binary, freeing its program/project. Refused while it is still importing or
    analyzing. The active binary falls back to the most recently loaded remaining one. `binary`
    omitted = the active binary."""
    global ACTIVE
    sess = _session(binary)
    with sess["lock"]:
        t = sess.get("thread")
        if sess.get("state") in ("importing", "analyzing") and t is not None and t.is_alive():
            raise RuntimeError("Still loading/analyzing; poll load_status until ready before unloading.")
        _dispose_session(sess)
    with REGISTRY_LOCK:
        SESSIONS.pop(sess["id"], None)
        if ACTIVE == sess["id"]:
            ACTIVE = next(reversed(SESSIONS), None)
    return f"unloaded {sess['id']}"


@mcp.tool()
def list_functions(filter: str = "", limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """List functions (name, address, signature). `filter` is a case-insensitive regex on the name.
    Available right after import; the list grows as background analysis discovers more functions."""
    m = _match(filter)
    p = _prog(binary)
    return _json(_page((_fn(f, binary) for f in p.functionManager.getFunctions(True) if m(f.getName())), limit, offset))


@mcp.tool()
def get_function(function: str, max_chars: int = 20000, timeout: int = 0, binary: str = "") -> str:
    """Decompiled C of a function. `function` = exact name or any address inside it (e.g. 0x101234).
    Needs analysis: returns {"status":"analyzing"} until ready. `timeout` = per-call decompile seconds
    (0 = GHIDRA_MCP_DECOMPILE_TIMEOUT, default 30; pass 120 for the old limit)."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    res = _decompile(_func(function, binary), timeout, binary)
    if res is None:
        return _json({"status": "timeout", "timeout_s": _dec_timeout(timeout), "function": function,
                      "hint": "raise the timeout param (e.g. timeout=120)"})
    c = res.getDecompiledFunction().getC()
    return c if len(c) <= max_chars else c[:max_chars] + f"\n/* truncated at {max_chars} of {len(c)} chars; raise max_chars */"


@mcp.tool()
def get_disassembly(function: str, max_lines: int = 500, binary: str = "") -> str:
    """Assembly listing of a function (address, instruction, comments). Needs analysis: returns
    {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    p = _prog(binary)
    f = _func(function, binary)
    out = []
    for ins in p.listing.getInstructions(f.getBody(), True):
        out.append(f"{ins.getAddress()}  {ins}")
        if len(out) == max_lines:
            out.append(f"; truncated at {max_lines} lines")
            break
    return "\n".join(out)


@mcp.tool()
def list_strings(filter: str = "", limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """List defined strings (address, value). `filter` is a case-insensitive regex on the value.
    Available right after import; the set grows as background analysis defines more strings."""
    m = _match(filter)
    p = _prog(binary)
    def gen():
        for d in p.listing.getDefinedData(True):
            if d.hasStringValue():
                v = str(d.getValue())
                if m(v):
                    yield {"address": str(d.getAddress()), "value": v}
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def list_imports(filter: str = "", limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """List imported (external) symbols with their library. `filter` is a regex on the name.
    Available right after import (no analysis needed)."""
    m = _match(filter)
    p = _prog(binary)
    gen = ({"name": s.getName(), "library": s.getParentNamespace().getName()}
           for s in p.symbolTable.getExternalSymbols() if m(s.getName()))
    return _json(_page(gen, limit, offset))


@mcp.tool()
def list_exports(filter: str = "", limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """List exported symbols (entry points). `filter` is a regex on the name.
    Available right after import (no analysis needed)."""
    st = _prog(binary).symbolTable
    m = _match(filter)
    prog = _prog(binary)
    path = _session(binary)["path"]
    def gen():
        for a in st.getExternalEntryPointIterator():
            s = st.getPrimarySymbol(a)
            if s is not None and m(s.getName()):
                yield {"name": s.getName(), "address": str(a),
                       "file_address": f"0x{_file_address(prog, a, path):x}"}
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def resolve_symbol(symbol: str, binary: str = "") -> str:
    """Resolve a function name or address to both address spaces.

    Returns {"name", "address", "file_address", "signature"}. `address` is the
    Ghidra address; `file_address` is the address the file itself uses (the ELF
    p_vaddr, i.e. what readelf / a hex editor / angr show). Use `file_address`
    when a selector must survive outside Ghidra. Accepts a bare name, an address,
    or a `name@0xADDR` selector."""
    prog = _prog(binary)
    path = _session(binary)["path"]
    try:
        return _json(_fn(_func(symbol, binary), binary))
    except ValueError:
        a = _addr(symbol, binary)
        if a is None:
            raise
        return _json({"name": None, "address": str(a),
                      "file_address": f"0x{_file_address(prog, a, path):x}"})


@mcp.tool()
def get_callers(function: str, limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """Functions that call `function`. Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    return _json(_page((_fn(f, binary) for f in _func(function, binary).getCallingFunctions(_monitor())), limit, offset))


@mcp.tool()
def get_callees(function: str, limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """Functions called by `function`. Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    return _json(_page((_fn(f, binary) for f in _func(function, binary).getCalledFunctions(_monitor())), limit, offset))


@mcp.tool()
def get_xrefs(target: str, limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """References to an address, string, global or function. `target` = address or function name.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    p = _prog(binary)
    a = _addr(target, binary)
    if a is None:
        a = _func(target, binary).getEntryPoint()
    def gen():
        for r in p.referenceManager.getReferencesTo(a):
            f = p.functionManager.getFunctionContaining(r.getFromAddress())
            yield {"from": str(r.getFromAddress()), "type": str(r.getReferenceType()), "function": f.getName() if f else None}
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def rename(target: str, new_name: str, binary: str = "") -> str:
    """Rename a function (by name/address) or, for a non-function address, create/replace its label.
    Do this often: good names are the most valuable output for the next analyst.
    Needs analysis (edits the program): returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    from ghidra.program.model.symbol import SourceType
    p = _prog(binary)
    try:
        f = _func(target, binary)
        old = f.getName()
        _edit("rename", lambda: f.setName(new_name, SourceType.USER_DEFINED), binary)
        return f"{old} -> {new_name} @ {f.getEntryPoint()}"
    except ValueError:
        a = _addr(target, binary)
        if a is None:
            raise
        _edit("rename", lambda: p.symbolTable.createLabel(a, new_name, SourceType.USER_DEFINED).setPrimary(), binary)
        return f"{a} -> {new_name}"


def _var(function, name, binary=""):
    """(function, high symbol) for a variable as named in the decompiled C."""
    f = _func(function, binary)
    res = _decompile(f, binary=binary)
    if res is None:
        raise RuntimeError(f"Decompilation of {f.getName()} timed out; raise GHIDRA_MCP_DECOMPILE_TIMEOUT")
    syms = list(res.getHighFunction().getLocalSymbolMap().getSymbols())
    hits = [s for s in syms if s.getName() == name]
    if not hits:
        raise ValueError(f"No variable '{name}' in {f.getName()}. Have: {[s.getName() for s in syms]}")
    return f, hits[0]


@mcp.tool()
def rename_variable(function: str, old_name: str, new_name: str, binary: str = "") -> str:
    """Rename a local variable or parameter as shown in the decompiled C of `function`.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    f, sym = _var(function, old_name, binary)
    _edit("rename variable", lambda: HighFunctionDBUtil.updateDBVariable(sym, new_name, None, SourceType.USER_DEFINED), binary)
    return f"{old_name} -> {new_name} in {f.getName()}"


@mcp.tool()
def retype_variable(function: str, variable: str, type: str, binary: str = "") -> str:
    """Change the type of a local/parameter as shown in the decompiled C, e.g. type='char *' or 'uint8_t[16]'.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    from ghidra.util.data import DataTypeParser
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    f, sym = _var(function, variable, binary)
    dtm = _prog(binary).getDataTypeManager()
    dt = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL).parse(type)
    _edit("retype variable", lambda: HighFunctionDBUtil.updateDBVariable(sym, None, dt, SourceType.USER_DEFINED), binary)
    return f"{variable}: {dt.getName()} in {f.getName()}"


@mcp.tool()
def set_signature(function: str, signature: str, binary: str = "") -> str:
    """Apply a C prototype to a function, e.g. 'int check_license(char *key, int len)'.
    Fixes return type, parameter names/types and count in the decompiled output.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.program.model.symbol import SourceType
    p = _prog(binary)
    f = _func(function, binary)
    fd = FunctionSignatureParser(p.getDataTypeManager(), None).parse(f.getSignature(), signature)
    cmd = ApplyFunctionSignatureCmd(f.getEntryPoint(), fd, SourceType.USER_DEFINED)
    if not _edit("set signature", lambda: cmd.applyTo(p), binary):
        raise RuntimeError(f"Could not apply signature: {cmd.getStatusMsg()}")
    return f"{f.getName()}: {f.getPrototypeString(False, False)}"


@mcp.tool()
def read_memory(address: str, length: int = 64, binary: str = "") -> str:
    """Hex dump of `length` bytes (max 4096) at an address, e.g. to read a string table or JNI method table.
    Available right after import (raw memory, no analysis needed)."""
    a = _addr(address, binary)
    if a is None:
        raise ValueError(f"Bad address '{address}'")
    length = min(length, 4096)
    from jpype import JArray, JByte
    buf = JArray(JByte)(length)
    n = _prog(binary).memory.getBytes(a, buf)
    data = bytes(b & 0xFF for b in buf[:n])
    length = n
    return "\n".join(f"{a.add(i)}  {data[i:i + 16].hex(' ')}" for i in range(0, length, 16))


@mcp.tool()
def search_bytes(pattern: str, limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """Find a byte pattern in memory. Hex with '??' wildcards, e.g. '48 8b ?? 05' or 'deadbeef'.
    Available right after import (raw memory scan, no analysis needed)."""
    toks = re.findall(r"\?\?|[0-9a-fA-F]{2}", pattern)
    if not toks or re.sub(r"\?\?|[0-9a-fA-F]{2}|\s", "", pattern):
        raise ValueError("pattern must be hex bytes, optionally with ?? wildcards")
    val = bytes(0 if t == "??" else int(t, 16) for t in toks)
    mask = bytes(0 if t == "??" else 0xFF for t in toks)
    p = _prog(binary)
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
def search_constants(value: str, limit: int = 50, offset: int = 0, binary: str = "") -> str:
    """Find instructions with a scalar operand equal to `value` (decimal or 0x hex): crypto constants,
    magic numbers, flags. Needs analysis (iterates instructions): returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    from ghidra.program.model.scalar import Scalar
    v = int(value, 0)
    p = _prog(binary)
    def gen():
        for ins in p.listing.getInstructions(True):
            for i in range(ins.getNumOperands()):
                if any(isinstance(o, Scalar) and v in (o.getValue(), o.getUnsignedValue()) for o in ins.getOpObjects(i)):
                    f = p.functionManager.getFunctionContaining(ins.getAddress())
                    yield {"address": str(ins.getAddress()), "instruction": str(ins), "function": f.getName() if f else None}
                    break
    return _json(_page(gen(), limit, offset))


@mcp.tool()
def call_path(source: str, target: str, max_depth: int = 10, binary: str = "") -> str:
    """Shortest call chain from function `source` to `target` (e.g. JNI_OnLoad -> some_sink), or null if none.
    Needs analysis: returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    s, t = _func(source, binary), _func(target, binary)
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
        path.append(_fn(f, binary))
        f = prev[f.getEntryPoint()]
    return _json(path[::-1])  # ponytail: one shortest path only, enumerate all if ever needed


@mcp.tool()
def add_comment(target: str, text: str, kind: str = "pre", binary: str = "") -> str:
    """Add a comment at an address or function entry. kind: pre (default, shown above the line in the
    decompiler), eol, post, plate, repeatable. Empty text clears it. Use liberally to document findings.
    Needs analysis (edits the program): returns {"status":"analyzing"} until ready."""
    busy = _require_analysis(binary)
    if busy:
        return busy
    from ghidra.program.model.listing import CodeUnit
    if kind not in COMMENTS:
        raise ValueError(f"kind must be one of {COMMENTS}")
    a = _addr(target, binary)
    if a is None:
        a = _func(target, binary).getEntryPoint()
    ct = getattr(CodeUnit, kind.upper() + "_COMMENT")
    _edit("comment", lambda: _prog(binary).listing.setComment(a, ct, text or None), binary)
    return f"{kind} comment set at {a}"


def close():
    """Dispose every loaded program/project (skips ones still importing/analyzing)."""
    global ACTIVE
    with REGISTRY_LOCK:
        sessions = list(SESSIONS.values())
    for sess in sessions:
        with sess["lock"]:
            t = sess.get("thread")
            if sess.get("state") not in ("importing", "analyzing") or t is None or not t.is_alive():
                _dispose_session(sess)
        with REGISTRY_LOCK:
            SESSIONS.pop(sess["id"], None)
    with REGISTRY_LOCK:
        ACTIVE = None


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
