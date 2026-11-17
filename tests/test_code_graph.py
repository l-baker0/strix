import asyncio
import importlib.machinery
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.agents import prompt as prompt_mod
from strix.config.settings import CodeGraphSettings
from strix.runtime import code_graph


CLI = Path(__file__).resolve().parents[1] / "containers" / "codegraph" / "strix-codegraph"


def _load_cli():
    loader = importlib.machinery.SourceFileLoader("strix_codegraph_cli", str(CLI))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


cli = _load_cli()


class FakeSession:
    def __init__(self, stdout: str = "", exit_code: int = 0, error: Exception | None = None):
        self.calls: list[tuple[tuple, dict]] = []
        self._stdout, self._exit, self._error = stdout, exit_code, error

    async def exec(self, *cmd, **kw):
        self.calls.append((cmd, kw))
        if self._error:
            raise self._error
        return SimpleNamespace(stdout=self._stdout.encode(), exit_code=self._exit)


def _settings(monkeypatch, **overrides):
    cfg = CodeGraphSettings(**overrides)
    monkeypatch.setattr(code_graph, "load_settings", lambda: SimpleNamespace(code_graph=cfg))
    return cfg


READY = json.dumps(
    {
        "state": "ready",
        "db": "/workspace/.strix-codegraph/app/cg.rl",
        "functions": 12,
        "calls": 30,
        "flows": 1,
        "derived": {"exposed": 2},
        "warnings": [],
    }
)
SOURCES = [{"source_path": "/h/app", "workspace_subdir": "app"}]


def run(coro):
    return asyncio.run(coro)


def test_mode_off_never_touches_the_sandbox(monkeypatch):
    _settings(monkeypatch, STRIX_CODE_GRAPH="off")
    session = FakeSession(READY)
    result = run(code_graph.prepare_code_graphs(session, SOURCES))
    assert result["ready"] is False and result["graphs"] == []
    assert session.calls == []


def test_no_mounted_source_means_no_graph(monkeypatch):
    _settings(monkeypatch)
    session = FakeSession(READY)
    assert run(code_graph.prepare_code_graphs(session, []))["ready"] is False
    assert session.calls == []


def test_ready_build_is_reported_and_policy_is_forwarded(monkeypatch):
    _settings(monkeypatch, STRIX_CODE_GRAPH="on", STRIX_CODE_GRAPH_MIN_FILES=7)
    session = FakeSession("log line\n" + READY)
    result = run(code_graph.prepare_code_graphs(session, SOURCES))
    assert result["ready"] is True
    graph = result["graphs"][0]
    assert graph["source"] == "/workspace/app" and graph["db"].endswith("cg.rl")
    cmd = session.calls[0][0]
    assert cmd[:2] == ("strix-codegraph", "build")
    assert cmd[cmd.index("--policy") + 1] == "on"
    assert cmd[cmd.index("--min-files") + 1] == "7"
    assert cmd[cmd.index("--out") + 1] == "/workspace/.strix-codegraph/app"


@pytest.mark.parametrize(
    "session",
    [
        FakeSession(json.dumps({"state": "skipped", "reason": "below complexity threshold"})),
        FakeSession("", exit_code=127),
        FakeSession("not json"),
        FakeSession(error=TimeoutError("exec timed out")),
    ],
)
def test_skipped_or_failed_builds_never_make_a_graph_ready(monkeypatch, session):
    _settings(monkeypatch)
    result = run(code_graph.prepare_code_graphs(session, SOURCES))
    assert result["ready"] is False and result["graphs"] == []
    assert len(result["skipped"]) == 1


def test_root_mount_uses_workspace_root_and_root_dir_name(monkeypatch):
    _settings(monkeypatch)
    session = FakeSession(READY)
    run(
        code_graph.prepare_code_graphs(session, [{"source_path": "/h/app", "workspace_subdir": ""}])
    )
    cmd = session.calls[0][0]
    assert cmd[cmd.index("--source") + 1] == "/workspace"
    assert cmd[cmd.index("--out") + 1] == "/workspace/.strix-codegraph/root"


def test_query_skill_loads_only_for_whitebox_with_a_ready_graph():
    kw = {"requested": None, "scan_mode": "deep", "is_root": False, "is_diff_scoped": False}
    ready = prompt_mod._resolve_skills(is_whitebox=True, code_graph_ready=True, **kw)
    assert "custom/querying_code_graph" in ready and "tooling/querying_relate_graphs" in ready
    assert "custom/querying_code_graph" not in prompt_mod._resolve_skills(
        is_whitebox=True, code_graph_ready=False, **kw
    )
    # Black-box runs never see it, even if a graph context were somehow present.
    assert "custom/querying_code_graph" not in prompt_mod._resolve_skills(
        is_whitebox=False, code_graph_ready=True, **kw
    )


def test_scope_block_lists_graph_only_when_ready():
    ctx = {
        "authorized_targets": [],
        "code_graph": {
            "ready": True,
            "graphs": [
                {
                    "source": "/workspace/app",
                    "db": "/workspace/.strix-codegraph/app/cg.rl",
                    "functions": 12,
                    "calls": 30,
                    "flows": 1,
                }
            ],
        },
    }
    assert "CODE GRAPH" in prompt_mod.render_scope_prompt(ctx)
    assert "CODE GRAPH" not in prompt_mod.render_scope_prompt({"authorized_targets": []})


# --- strix-codegraph (baked into the sandbox image) ---


def test_gate_thresholds():
    assert cli.gate("auto", 3, 400)[0] is False
    assert cli.gate("auto", 60, 20_000)[0] is True
    assert cli.gate("auto", 60, 500)[0] is False  # many tiny files is not complex
    assert cli.gate("on", 3, 400)[0] is True
    assert cli.gate("on", 0, 0)[0] is False
    assert cli.gate("auto", 5, 100, min_files=5, min_loc=100)[0] is True


def test_survey_skips_vendored_and_minified(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "b.js").write_text("a\n" * 50)
    (tmp_path / "app" / "c.min.js").write_text("a\n" * 50)
    files, loc, langs = cli.survey(tmp_path)
    assert (files, loc, langs) == (1, 2, {"python": 1})


def _match(check, path, start, end, **mv):
    return {
        "check_id": f"x.{check}",
        "path": path,
        "start": {"line": start},
        "end": {"line": end},
        "extra": {"metavars": {k: {"abstract_content": v} for k, v in mv.items()}},
    }


def test_build_graph_resolves_calls_roles_and_entries(tmp_path):
    cg = {
        "results": [
            _match("cg-def-python", "a.py", 1, 3, **{"$F": "handler"}),
            _match("cg-def-python", "a.py", 5, 6, **{"$F": "verify_jwt"}),
            _match("cg-def-python", "b.py", 1, 2, **{"$F": "helper"}),
            _match("cg-entry-python-route", "a.py", 1, 3, **{"$F": "handler"}),
            _match("cg-call-python", "a.py", 2, 2, **{"$F": "verify_jwt"}),
            _match("cg-call-python", "a.py", 2, 2, **{"$F": "helper"}),
            _match("cg-method-python", "a.py", 3, 3, **{"$O": "yaml", "$F": "load"}),
            _match("cg-method-python", "a.py", 3, 3, **{"$O": "render", "$F": "render"}),  # noise
        ]
    }
    graph, stats = cli.build_graph(cg, None, tmp_path)
    funcs = {f["id"]: f for f in graph["functions"]}
    assert funcs["a.py::handler"]["entry"] and funcs["a.py::verify_jwt"]["guard"]
    assert funcs["ext::yaml.load"]["sink"] and funcs["ext::yaml.load"]["external"]
    edges = {(c["src"], c["dst"]) for c in graph["calls"]}
    assert ("a.py::handler", "a.py::verify_jwt") in edges
    assert ("a.py::handler", "b.py::helper") in edges  # unique name across files resolves
    assert not any(c["dst"] == "ext::render.render" for c in graph["calls"])
    assert stats["entries_from_rules"] == 1


def test_trace_formats_2x_and_1x_both_normalize():
    loc = lambda line: {"path": "a.py", "start": {"line": line}}  # noqa: E731
    v2 = [
        {"kind": "source", "location": loc(1), "content": "req", "children": []},
        {
            "kind": "sink_in_call",
            "location": loc(2),
            "content": "run",
            "children": [
                {"kind": "sink", "location": loc(9), "content": "os.system", "children": []}
            ],
        },
    ]
    v1 = {
        "taint_source": ["CliLoc", [loc(1), "req"]],
        "intermediate_vars": [],
        "taint_sink": ["CliLoc", [loc(9), "os.system"]],
    }
    for trace in (v2, v1):
        kinds = [s[0] for s in cli.steps(trace)]
        assert kinds[0] == "source" and "sink" in kinds


def test_cross_file_taint_creates_a_confirmed_call_edge(tmp_path):
    cg = {
        "results": [
            _match("cg-def-python", "web.py", 1, 3, **{"$F": "handler"}),
            _match("cg-def-python", "util.py", 1, 3, **{"$F": "run_cmd"}),
        ]
    }
    loc = lambda p, line: {"path": p, "start": {"line": line}}  # noqa: E731
    trace = [
        {"kind": "source", "location": loc("web.py", 2), "content": "req", "children": []},
        {
            "kind": "sink_in_call",
            "location": loc("web.py", 3),
            "content": "run_cmd",
            "children": [
                {
                    "kind": "sink",
                    "location": loc("util.py", 2),
                    "content": "os.system",
                    "children": [],
                }
            ],
        },
    ]
    taint = {
        "results": [
            {
                "check_id": "r.t-cmd",
                "path": "util.py",
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {
                    "dataflow_trace": trace,
                    "severity": "ERROR",
                    "lines": "os.system(c)",
                    "metavars": {},
                },
            }
        ]
    }
    graph, _ = cli.build_graph(cg, taint, tmp_path)
    assert any(
        c.get("taint") and c["src"] == "web.py::handler" and c["dst"] == "util.py::run_cmd"
        for c in graph["calls"]
    )
    flow = graph["flows"][0]
    assert flow["source_path"] == "web.py" and flow["path"] == "util.py"
