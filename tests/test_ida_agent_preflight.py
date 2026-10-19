"""Blinding and fixed-denominator checks that never contact a model API."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decbench.decompilers.agent_ida import IDAAgentDecompiler
from decbench.decompilers.base import DecompilerConfig
from decbench.decompilers.llm_dec import _AgentDecompiler
from decbench.utils.blinding import validate_stripped_elf
from scripts import prepare_ida_agent_eval as prep
from scripts.run_benchmark import _relabel_to_dwarf, _stripped_copy


@pytest.fixture
def original(tmp_path: Path) -> Path:
    if not shutil.which("gcc") or not shutil.which("strip"):
        pytest.skip("native gcc and strip required")
    source = tmp_path / "secret_project.c"
    source.write_text("int secret_name(int x) { return x + 1; }\nint main(void) { return 0; }\n")
    binary = tmp_path / "secret_project"
    subprocess.run(["gcc", "-g", "-O0", str(source), "-o", str(binary)], check=True)
    return binary


def test_rejects_ground_truth_before_opening_ida(original: Path) -> None:
    with pytest.raises(ValueError, match="not stripped"):
        IDAAgentDecompiler().decompile_binary(original, function_names={0x1000})


def test_strip_preserves_code_and_checks_cached_inputs(original: Path, tmp_path: Path) -> None:
    stripped = _stripped_copy(original, tmp_path / "stripped")
    validate_stripped_elf(stripped)
    with stripped.open("rb") as stream:
        offset = ELFFile(stream).get_section_by_name(".text")["sh_offset"]
    raw = bytearray(stripped.read_bytes())
    raw[offset] ^= 0xFF
    stripped.write_bytes(raw)
    repaired = _stripped_copy(original, stripped.parent)
    assert repaired.read_bytes()[offset] != raw[offset]
    shutil.copyfile(original, stripped)
    _stripped_copy(original, stripped.parent)
    validate_stripped_elf(stripped)


def test_strip_failure_never_admits_unstripped_copy(
    original: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from decbench.evalkit import EvalKitError, export

    def fail(source: Path, dest: Path) -> None:
        shutil.copy2(source, dest)
        raise EvalKitError("strip failed")

    monkeypatch.setattr(export, "_strip_into", fail)
    with pytest.raises(EvalKitError, match="strip failed"):
        _stripped_copy(original, tmp_path / "stripped")
    assert not (tmp_path / "stripped" / original.name).exists()


def test_rejects_named_targets_and_silent_truncation(original: Path, tmp_path: Path) -> None:
    stripped = _stripped_copy(original, tmp_path / "stripped")
    agent = IDAAgentDecompiler()
    with pytest.raises(ValueError, match="anonymous"):
        agent.decompile_binary(stripped, functions=[("secret_name", 0x1000)])
    with pytest.raises(ValueError, match="explicit target"):
        agent.decompile_binary(stripped)
    with pytest.raises(ValueError, match="refusing to truncate"):
        agent.decompile_binary(stripped, function_names=set(range(100, 109)))


def test_ida_session_receives_only_anonymous_filename(
    original: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stripped = _stripped_copy(original, tmp_path / "stripped")
    opened = []
    agent = IDAAgentDecompiler()
    monkeypatch.setattr(agent, "_ensure_session", lambda path: opened.append(path.name))
    monkeypatch.setattr(agent, "_close_session", lambda: None)
    monkeypatch.setattr(_AgentDecompiler, "decompile_binary", lambda *args: None)
    agent.decompile_binary(stripped, function_names={0x1000})
    assert opened == ["target.bin"]


def test_selection_is_seeded_unique_and_covers_size_buckets() -> None:
    rows = [{"size_bytes": n, "address": n} for n in range(60)]
    selected = prep.select(rows, 6, 1337)
    assert selected == prep.select(rows, 6, 1337)
    assert [row["size_bytes"] // 10 for row in selected] == list(range(6))
    with pytest.raises(ValueError, match="eligible"):
        prep.select(rows[:2], 6, 1337)


def test_check_detects_frozen_input_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "input"
    data.write_text("original")
    lock = {
        "files": {"input": prep.digest(data)},
        "code": {},
        "tools": {},
        "versions": {},
        "inventory": [],
        "target_count": 1,
    }
    prep.write_json(tmp_path / "experiment.lock.json", lock)
    monkeypatch.setattr(prep, "runtime_versions", lambda: {})
    prep.check(tmp_path)
    data.write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        prep.check(tmp_path)


def test_coverage_audit_keeps_missing_metrics_distinct_from_zero(tmp_path: Path) -> None:
    prep.write_json(
        tmp_path / "sample_set_manifest.json",
        {"functions": [{"project": "p", "opt": "O0", "binary": "b", "function": "f"}]},
    )
    prep.write_json(
        tmp_path / "function_results.json",
        {
            "groups": [
                {
                    "project": "p",
                    "opt_level": "O0",
                    "binary": "b",
                    "functions": [
                        {
                            "function": "f",
                            "decompiled": {"ida": True},
                            "values": {"ida": {"ged": 0}},
                        }
                    ],
                }
            ]
        },
    )
    result = prep.audit(tmp_path, "ida")
    assert result["missing_metric_values"]["ged"] == []
    assert len(result["missing_metric_values"]["type_match"]) == 1
    prep.write_json(tmp_path / "function_results.json", {"groups": []})
    with pytest.raises(ValueError, match="denominator"):
        prep.audit(tmp_path, "ida")
    assert json.loads((tmp_path / "coverage-ida.json").read_text())["expected"] == 1


def test_local_thinking_is_explicit_and_default_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DECBENCH_IDA_AGENT_CONFIG_DIR", str(tmp_path / "config"))
    config = DecompilerConfig(extra_options={"thinking": "disabled"})
    agent = IDAAgentDecompiler(config)
    options = agent._sdk_options(tmp_path, {})
    assert options.thinking == {"type": "disabled"}
    assert options.effort is None
    default = IDAAgentDecompiler()._sdk_options(tmp_path, {})
    assert default.thinking is None
    assert agent._agent_env().get("CLAUDE_CODE_DISABLE_TERMINAL_TITLE", "") != "1"
    agent.config.extra_options["disable_title"] = "1"
    assert agent._agent_env()["CLAUDE_CODE_DISABLE_TERMINAL_TITLE"] == "1"
    agent.config.extra_options["thinking"] = "adaptive"
    assert agent._sdk_options(tmp_path, {}).thinking == {"type": "adaptive"}
    agent.config.extra_options["thinking"] = "typo"
    with pytest.raises(ValueError, match="thinking"):
        agent._sdk_options(tmp_path, {})


def test_environment_uses_frozen_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://wrong.example")
    prep.write_json(
        tmp_path / "experiment.lock.json",
        {"environment": {**prep.ENV, "ANTHROPIC_BASE_URL": "http://127.0.0.1:8000"}},
    )
    assert prep.environment(tmp_path)["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8000"


def test_reference_input_drift_leaves_no_experiment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = tmp_path / "reference"
    binary = reference / "O0/p/compiled/binary"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"original")
    prep.write_json(
        reference / "experiment.lock.json",
        {
            "per_binary": 4,
            "seed": 1337,
            "files": {"O0/p/compiled/binary": prep.digest(binary)},
        },
    )
    binary.write_bytes(b"changed")
    monkeypatch.setattr(prep, "environment", lambda tree: {})
    destination = tmp_path / "new-experiment"
    with pytest.raises(ValueError, match="reference input changed"):
        prep.prepare(reference, destination, 4, 1337, reference_tree=reference)
    assert not destination.exists()


def test_check_rejects_changed_model_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    weights = tmp_path / "model.safetensors"
    weights.write_bytes(b"original")
    prep.write_json(
        tmp_path / "experiment.lock.json",
        {
            "files": {},
            "code": {},
            "tools": {},
            "versions": {},
            "inventory": [],
            "target_count": 24,
            "deployment": {
                "files": {str(weights): prep.digest(weights)},
                "command": ["python"],
                "versions": {},
            },
        },
    )
    monkeypatch.setattr(prep, "runtime_versions", lambda: {})
    monkeypatch.setattr(prep.subprocess, "check_output", lambda *args, **kwargs: "{}")
    prep.check(tmp_path)
    weights.write_bytes(b"changed")
    with pytest.raises(ValueError, match="deployment file changed"):
        prep.check(tmp_path)


def test_comparison_retains_failure_denominator() -> None:
    from scripts.compare_ida_agent_pilot import aggregate

    data = aggregate(
        [
            {
                "decompiled": {"local": True},
                "values": {"local": {"ged": 0.0}},
                "perfects": {"local": {"ged": True}},
            },
            {"decompiled": {"local": False}},
            {},
        ],
        "local",
    )
    assert data["expected"] == 3
    assert data["decompiled"] == 1
    assert data["ged"] == {"valid": 1, "missing": 2, "mean": 0.0, "median": 0.0, "perfect": 1}
    assert data["type_match"]["mean"] is None
    assert data["compiles"] is None
    assert data["compiles_unknown"] == 1
    known = aggregate(
        [
            {"decompiled": {"local": True}, "compiles": {"local": True}},
            {"decompiled": {"local": True}, "compiles": {"local": False}},
            {"decompiled": {"local": False}},
        ],
        "local",
    )
    assert known["compiles"] == 1
    assert known["compiles_unknown"] == 0


def test_session_audit_deduplicates_split_tool_messages(tmp_path: Path) -> None:
    from scripts.compare_ida_agent_pilot import session_audit

    transcript = tmp_path / "agent-config/projects/test/session.jsonl"
    transcript.parent.mkdir(parents=True)
    events = [
        {
            "type": "assistant",
            "message": {
                "id": "same-response",
                "model": "local",
                "content": [],
                "usage": {"input_tokens": 100, "output_tokens": output},
            },
        }
        for output in (0, 12, 12)
    ]
    transcript.write_text("\n".join(json.dumps(e) for e in events))
    result = session_audit(tmp_path, "local")
    assert result["unique_model_responses"] == 1
    assert result["usage"]["input_tokens"] == 100
    assert result["usage"]["output_tokens"] == 12
    assert result["thinking_blocks"] == 0


def test_relabel_preserves_failed_targets_in_source_denominator(original: Path) -> None:
    from decbench.models.decompilation import DecompilationResult, DecompilerMetadata

    with original.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        address = int(symbols.get_symbol_by_name("secret_name")[0]["st_value"])
    result = DecompilationResult(
        binary_path=original,
        binary_name=original.name,
        decompiler=DecompilerMetadata(
            decompiler_name="ida-agent@local",
            failed_functions=[f"sub_{address:x}", "already_named", "all"],
        ),
    )
    _relabel_to_dwarf(result, {address: "secret_name"}, original)
    assert result.decompiler.failed_functions == ["secret_name", "already_named", "all"]


def test_offline_failure_repair_archives_and_is_idempotent(original: Path, tmp_path: Path) -> None:
    import pickle

    from decbench.models.decompilation import DecompilationResult, DecompilerMetadata
    from decbench.models.project import OptimizationLevel
    from scripts.repair_pilot_failures import repair

    tree = tmp_path / "experiment"
    binary = tree / "O0/p/compiled/b"
    binary.parent.mkdir(parents=True)
    shutil.copy2(original, binary)
    with binary.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        address = int(symbols.get_symbol_by_name("secret_name")[0]["st_value"])
    backend = "ida-agent@local"
    result = DecompilationResult(
        binary_path=binary,
        binary_name="b",
        decompiler=DecompilerMetadata(
            decompiler_name=backend, failed_functions=[f"sub_{address:x}"]
        ),
    )
    checkpoint = tree / "checkpoints/p.pkl"
    checkpoint.parent.mkdir()
    checkpoint.write_bytes(
        pickle.dumps(
            {
                "decompile": {OptimizationLevel.O0: {"b": {backend: result}}},
                "evaluate": {"preserved": "scores"},
            }
        )
    )
    before = checkpoint.read_bytes()
    prep.write_json(
        tree / "experiment.lock.json",
        {
            "model": backend,
            "files": {"O0/p/compiled/b": prep.digest(binary)},
            "code": {"scripts/run_benchmark.py": "original-driver"},
            "inventory": [
                {
                    "project": "p",
                    "opt": "O0",
                    "binary": "b",
                    "path": "O0/p/compiled/b",
                    "targets": [{"address": address, "function": "secret_name"}],
                }
            ],
        },
    )
    provenance = repair(tree)
    assert provenance["model_calls"] == 0
    assert (tree / "first-pass-failure-labels/checkpoints/p.pkl").read_bytes() == before
    repaired = pickle.loads(checkpoint.read_bytes())
    assert repaired["evaluate"] == {"preserved": "scores"}
    assert repaired["decompile"][OptimizationLevel.O0]["b"][
        backend
    ].decompiler.failed_functions == ["secret_name"]
    assert repair(tree) == {"changes": [], "model_calls": 0}
    binary.write_bytes(b"changed")
    with pytest.raises(ValueError, match="frozen binary changed"):
        repair(tree)


def test_nonthinking_template_resists_request_effort() -> None:
    Template = pytest.importorskip("jinja2").Template

    from scripts.serve_qwen_pilot import nonthinking_template

    source = (
        "{% if enable_thinking is defined and enable_thinking is true %}"
        "<think>\n{% else %}<think>\n\n</think>\n\n{% endif %}"
    )
    template = Template(nonthinking_template(source))
    assert template.render(enable_thinking=True) == "<think>\n\n</think>\n\n"
    assert template.render(enable_thinking=False) == "<think>\n\n</think>\n\n"
    with pytest.raises(ValueError, match="unexpected Qwen template"):
        nonthinking_template("changed upstream template")


@pytest.mark.parametrize("enabled", [False, True])
def test_nonthinking_middleware_overrides_sdk_effort(
    enabled: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from scripts.qwen_nonthinking_middleware import NonThinkingMiddleware, QwenPilotMiddleware

    incoming = {
        "model": "qwen3.5-0.8b",
        "thinking": {"type": "disabled"},
        "temperature": 1.0,
        "top_p": 1.0,
        "top_k": 1,
        "messages": [{"role": "user", "content": "test"}],
        "output_config": {"effort": "high"},
        "chat_template_kwargs": {"enable_thinking": True, "other": 1},
        "stream": True,
    }
    raw = json.dumps(incoming).encode()
    events = iter(
        [
            {"type": "http.request", "body": raw[:10], "more_body": True},
            {"type": "http.request", "body": raw[10:], "more_body": False},
            {"type": "http.disconnect"},
        ]
    )
    observed = {}

    async def receive() -> dict:
        return next(events)

    async def app(scope: dict, receive: object, send: object) -> None:
        message = await receive()
        observed.update(json.loads(message["body"]))
        assert int(dict(scope["headers"])[b"content-length"]) == len(message["body"])
        assert (await receive())["type"] == "http.disconnect"

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/messages",
        "headers": [(b"content-length", str(len(raw)).encode())],
    }
    if enabled:
        monkeypatch.setenv(
            "QWEN_PILOT_POLICY",
            json.dumps(
                {
                    "thinking": "enabled",
                    "sampling": {"temperature": 0.6, "top_p": 0.95, "top_k": 20},
                }
            ),
        )
        middleware = QwenPilotMiddleware(app)
    else:
        middleware = NonThinkingMiddleware(app)
    asyncio.run(middleware(scope, receive, None))
    assert observed["thinking"] == {"type": "adaptive" if enabled else "disabled"}
    assert observed["chat_template_kwargs"] == {"enable_thinking": enabled, "other": 1}
    if enabled:
        assert observed["temperature"] == 0.6
        assert observed["top_p"] == 0.95
        assert observed["top_k"] == 20
    for key in ("messages", "model", "output_config", "stream"):
        assert observed[key] == incoming[key]


def test_comparison_labels_additional_model_and_checks_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import compare_ida_agent_pilot as comparison

    manifest = {"functions": [{"project": "p", "opt": "O0", "binary": "b", "function": "f"}]}
    trees = [tmp_path / name for name in ("new", "reference", "small")]
    for tree, model in zip(trees, ("qwen3.5-4b", "deepseek-flash", "qwen3.5-0.8b"), strict=True):
        tree.mkdir()
        (tree / "sample_set_manifest.json").write_text(json.dumps(manifest))
        (tree / "experiment.lock.json").write_text(json.dumps({"model": f"ida-agent@{model}"}))
        (tree / "function_results.json").write_text(
            json.dumps(
                {
                    "groups": [
                        {
                            "project": "p",
                            "opt_level": "O0",
                            "binary": "b",
                            "functions": [{"function": "f"}],
                        }
                    ]
                }
            )
        )
    monkeypatch.setattr(comparison, "syntax_audit", lambda *args: {"passed": 0, "checked": 0})
    result = comparison.compare(trees[0], trees[1], [trees[2]])
    assert len(result["overall"]) == 4
    assert len(result["score_sources"]) == 3
    report = (trees[0] / "evaluation-summary.zh.md").read_text()
    assert report.startswith("# qwen3.5-4b")
    assert "qwen3.5-0.8b + IDA" in report
    (trees[2] / "sample_set_manifest.json").write_text('{"functions": []}')
    with pytest.raises(ValueError, match="identical frozen manifests"):
        comparison.compare(trees[0], trees[1], [trees[2]])
