"""State-machine unit tests — no JVM/Ghidra needed. Run: python tests/test_state.py

Covers the non-blocking load logic: state transitions, the soft "analyzing" gating of
decompiler-driven tools, on-demand analysis for analyze=False, cached-analyzed -> ready,
the decompiler-timeout signal, and multi-binary sessions (selector resolution, isolation,
parallel analysis, unloading). The Java-touching paths are covered by tests/smoke.py."""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ghidra_mcp.server as srv


class FakeFM:
    def getFunctionCount(self):
        return 7


class FakeProg:
    def __init__(self, name="libfake.so"):
        self._name = name
    def getName(self):
        return self._name
    functionManager = FakeFM()


class FakeRes:
    def __init__(self, completed, msg=""):
        self._c, self._m = completed, msg
    def decompileCompleted(self):
        return self._c
    def getErrorMessage(self):
        return self._m


class FakeIfc:
    def __init__(self, res=None):
        self._res = res
    def decompileFunction(self, f, t, mon):
        return self._res
    def dispose(self):
        pass


class FakeProj:
    def close(self):
        pass


def reset():
    srv.SESSIONS.clear()
    srv.ACTIVE = None


def add(path, name="libfake.so", **kw):
    sess = srv._new_session(path)
    sess.update(name=name, prog=FakeProg(name), proj=FakeProj(), ifc=FakeIfc(), **kw)
    srv.SESSIONS[sess["id"]] = sess
    srv.ACTIVE = sess["id"]
    return sess


def test_idle_raises():
    reset()
    try:
        srv._require_analysis()
        assert False, "expected RuntimeError on idle"
    except RuntimeError as e:
        assert "load_binary" in str(e)
    assert json.loads(srv.load_status())["state"] == "idle"
    print("ok: idle -> raises / status idle")


def test_cached_analyzed_ready():
    reset()
    sess = add("/x/libfake.so", state="ready", analyzed=True)
    assert srv._require_analysis() is None  # proceed, no thread
    assert "thread" not in sess
    st = json.loads(srv.load_status())
    assert st["state"] == "ready" and st["name"] == "libfake.so" and st["functions"] == 7 and st["analyzed"] is True, st
    print("ok: cached-analyzed -> ready, no re-analysis")


def test_on_demand_analysis():
    reset()
    started = {"v": False}
    def fake_analyze(prog, proj):
        started["v"] = True
        time.sleep(0.2)
    srv._analyze = fake_analyze  # monkeypatch heavy step
    sess = add("/x/libfake.so", state="ready", analyzed=False)  # analyze=False load

    busy = srv._require_analysis()  # first decompiler-driven call -> kicks analysis
    d = json.loads(busy)
    assert d["status"] == "analyzing" and "retry_after_s" in d and "hint" in d, d
    assert sess["state"] == "analyzing"
    # a second analysis-dependent call while running also gets the soft status, no 2nd thread
    t1 = sess["thread"]
    assert json.loads(srv._require_analysis())["status"] == "analyzing"
    assert sess["thread"] is t1

    st = json.loads(srv.load_status())
    assert st["state"] == "analyzing" and "elapsed_s" in st, st

    sess["thread"].join(5)
    assert started["v"]
    assert sess["state"] == "ready" and sess["analyzed"] is True
    assert srv._require_analysis() is None  # now proceeds
    print("ok: analyze=False -> on-demand analysis -> ready")


def test_error_state():
    reset()
    def boom(prog, proj):
        raise RuntimeError("analyzeAll blew up")
    srv._analyze = boom
    sess = add("/x/libfake.so", state="ready", analyzed=False)
    srv._require_analysis()
    sess["thread"].join(5)
    assert sess["state"] == "error"
    assert json.loads(srv.load_status())["error"] == "analyzeAll blew up"
    try:
        srv._require_analysis()
        assert False, "expected RuntimeError on error state"
    except RuntimeError as e:
        assert "Analysis failed" in str(e)
    print("ok: analysis failure -> error state surfaced")


def test_decompile_timeout_signal():
    reset()
    srv._monitor = lambda: None  # avoid importing ghidra
    sess = add("/x/libfake.so", state="ready", analyzed=True)
    sess["ifc"] = FakeIfc(FakeRes(False, "Decompile process timed out"))
    assert srv._decompile("f") is None  # timeout -> None, no hang, no raise
    sess["ifc"] = FakeIfc(FakeRes(False, "something else broke"))
    try:
        srv._decompile("f")
        assert False, "expected RuntimeError on non-timeout failure"
    except RuntimeError as e:
        assert "Decompile failed" in str(e)
    ok = FakeRes(True)
    sess["ifc"] = FakeIfc(ok)
    assert srv._decompile("f") is ok
    print("ok: decompile timeout -> None, other failure -> raise")


def test_dec_timeout_config():
    assert srv._dec_timeout(120) == 120  # per-call override
    os.environ.pop("GHIDRA_MCP_DECOMPILE_TIMEOUT", None)
    assert srv._dec_timeout(0) == 30  # default lowered from 120
    os.environ["GHIDRA_MCP_DECOMPILE_TIMEOUT"] = "45"
    assert srv._dec_timeout(0) == 45
    os.environ.pop("GHIDRA_MCP_DECOMPILE_TIMEOUT", None)
    print("ok: decompile timeout config (default 30, overridable)")


def test_selector_resolution():
    reset()
    a = add("/x/liba.so", name="liba.so", state="ready", analyzed=True)
    b = add("/y/libb.so", name="libb.so", state="ready", analyzed=True)
    assert srv._session() is b  # active = last loaded
    assert srv._session("/x/liba.so") is a  # exact path
    assert srv._session("liba.so") is a  # basename
    assert srv._session("libb.so") is b  # program name
    try:
        srv._session("nope.so")
        assert False, "expected ValueError for unknown selector"
    except ValueError as e:
        assert "No loaded binary" in str(e)
    # ambiguous basenames
    add("/z/liba.so", name="liba.so", state="ready", analyzed=True)
    try:
        srv._session("liba.so")
        assert False, "expected ValueError for ambiguous selector"
    except ValueError as e:
        assert "ambiguous" in str(e)
    print("ok: binary selector (active/path/basename/name/ambiguous/unknown)")


def test_multi_session_isolation():
    reset()
    a = add("/x/liba.so", name="liba.so", state="ready", analyzed=True)
    b = add("/y/libb.so", name="libb.so", state="ready", analyzed=False)
    srv._analyze = lambda prog, proj: time.sleep(0.1)
    assert srv._require_analysis(a["id"]) is None  # a is already analyzed
    busy = srv._require_analysis(b["id"])  # only b starts analysis
    assert json.loads(busy)["status"] == "analyzing"
    assert a["state"] == "ready" and a.get("analyzed") is True
    assert b["state"] == "analyzing"
    b["thread"].join(5)
    assert b["state"] == "ready" and b["analyzed"] is True
    assert srv._require_analysis(a["id"]) is None
    st = json.loads(srv.list_binaries())
    assert st["active"] == b["id"] and len(st["binaries"]) == 2
    print("ok: multi-session isolation + list_binaries")


def test_parallel_analysis():
    reset()
    a = add("/x/liba.so", name="liba.so", state="ready", analyzed=False)
    b = add("/y/libb.so", name="libb.so", state="ready", analyzed=False)
    srv._analyze = lambda prog, proj: time.sleep(0.3)
    srv._require_analysis(a["id"])
    srv._require_analysis(b["id"])
    assert a["thread"] is not b["thread"]
    assert a["thread"].is_alive() and b["thread"].is_alive()  # both run concurrently
    a["thread"].join(5)
    b["thread"].join(5)
    assert a["state"] == "ready" and b["state"] == "ready"
    print("ok: two binaries analyze in parallel")


def test_unload():
    reset()
    a = add("/x/liba.so", name="liba.so", state="ready", analyzed=True)
    b = add("/y/libb.so", name="libb.so", state="ready", analyzed=True)
    srv.unload_binary(b["id"])
    assert b["id"] not in srv.SESSIONS
    assert srv.ACTIVE == a["id"]
    assert srv._session() is a
    assert "prog" not in b and "proj" not in b
    # refuse to unload while analyzing
    c = add("/z/libc.so", name="libc.so", state="analyzing")
    try:
        srv.unload_binary(c["id"])
        assert False, "expected RuntimeError while analyzing"
    except RuntimeError as e:
        assert "Still analyzing" in str(e)
    print("ok: unload frees a session, active falls back, refuses while analyzing")


def demo():
    test_idle_raises()
    test_cached_analyzed_ready()
    test_on_demand_analysis()
    test_error_state()
    test_decompile_timeout_signal()
    test_dec_timeout_config()
    test_selector_resolution()
    test_multi_session_isolation()
    test_parallel_analysis()
    test_unload()
    print("\nall state tests passed")


if __name__ == "__main__":
    demo()
