"""State-machine unit tests — no JVM/Ghidra needed. Run: python tests/test_state.py

Covers the non-blocking load logic: state transitions, the soft "analyzing" gating of
decompiler-driven tools, on-demand analysis for analyze=False, cached-analyzed -> ready,
and the decompiler-timeout signal. The Java-touching paths are covered by tests/smoke.py."""
import json, os, sys, time, types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ghidra_mcp.server as srv


class FakeFM:
    def getFunctionCount(self):
        return 7


class FakeProg:
    def getName(self):
        return "libfake.so"
    functionManager = FakeFM()


class FakeRes:
    def __init__(self, completed, msg=""):
        self._c, self._m = completed, msg
    def decompileCompleted(self):
        return self._c
    def getErrorMessage(self):
        return self._m


class FakeIfc:
    def __init__(self, res):
        self._res = res
    def decompileFunction(self, f, t, mon):
        return self._res


def reset():
    srv.S.clear()


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
    srv.S.update(prog=FakeProg(), proj=object(), state="ready", analyzed=True)
    assert srv._require_analysis() is None  # proceed, no thread
    assert "thread" not in srv.S
    st = json.loads(srv.load_status())
    assert st == {"state": "ready", "name": "libfake.so", "functions": 7, "analyzed": True}, st
    print("ok: cached-analyzed -> ready, no re-analysis")


def test_on_demand_analysis():
    reset()
    started = {"v": False}
    def fake_analyze(prog, proj):
        started["v"] = True
        time.sleep(0.2)
    srv._analyze = fake_analyze  # monkeypatch heavy step
    srv.S.update(prog=FakeProg(), proj=object(), state="ready", analyzed=False)  # analyze=False load

    busy = srv._require_analysis()  # first decompiler-driven call -> kicks analysis
    d = json.loads(busy)
    assert d["status"] == "analyzing" and "retry_after_s" in d and "hint" in d, d
    assert srv.S["state"] == "analyzing"
    # a second analysis-dependent call while running also gets the soft status, no 2nd thread
    t1 = srv.S["thread"]
    assert json.loads(srv._require_analysis())["status"] == "analyzing"
    assert srv.S["thread"] is t1

    st = json.loads(srv.load_status())
    assert st["state"] == "analyzing" and "elapsed_s" in st, st

    srv.S["thread"].join(5)
    assert started["v"]
    assert srv.S["state"] == "ready" and srv.S["analyzed"] is True
    assert srv._require_analysis() is None  # now proceeds
    print("ok: analyze=False -> on-demand analysis -> ready")


def test_error_state():
    reset()
    def boom(prog, proj):
        raise RuntimeError("analyzeAll blew up")
    srv._analyze = boom
    srv.S.update(prog=FakeProg(), proj=object(), state="ready", analyzed=False)
    srv._require_analysis()
    srv.S["thread"].join(5)
    assert srv.S["state"] == "error"
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
    srv.S["ifc"] = FakeIfc(FakeRes(False, "Decompile process timed out"))
    assert srv._decompile("f") is None  # timeout -> None, no hang, no raise
    srv.S["ifc"] = FakeIfc(FakeRes(False, "something else broke"))
    try:
        srv._decompile("f")
        assert False, "expected RuntimeError on non-timeout failure"
    except RuntimeError as e:
        assert "Decompile failed" in str(e)
    ok = FakeRes(True)
    srv.S["ifc"] = FakeIfc(ok)
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


def demo():
    test_idle_raises()
    test_cached_analyzed_ready()
    test_on_demand_analysis()
    test_error_state()
    test_decompile_timeout_signal()
    test_dec_timeout_config()
    print("\nall state tests passed")


if __name__ == "__main__":
    demo()
