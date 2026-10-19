"""RL task boundaries, split leakage, and fail-closed reward checks."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from decbench.rl.bridge import EpisodeClient, WorkerError
from decbench.rl.tasks import (
    ENVIRONMENT_VERSION,
    REWARD_VERSION,
    digest,
    load_task,
    public_row,
    tool_schemas,
)
from decbench.rl.worker import Episode, InvalidAction
from scripts.prepare_verl_tasks import validate_splits


def task(tmp_path: Path) -> dict:
    original, stripped = tmp_path / "original", tmp_path / "stripped"
    original.write_bytes(b"private original")
    stripped.write_bytes(b"public binary")
    return {
        "task_id": "opaque-id",
        "project": "project",
        "split": "train",
        "is_malware": False,
        "function": "secret_name",
        "address": 4096,
        "original_binary": str(original),
        "original_binary_sha256": digest(original),
        "stripped_binary": str(stripped),
        "stripped_binary_sha256": digest(stripped),
    }


def test_public_prompt_does_not_expose_private_registry(tmp_path: Path) -> None:
    row = public_row(task(tmp_path), 0)
    text = json.dumps(row)
    for hidden in ("secret_name", "private original", str(tmp_path), "original_binary"):
        assert hidden not in text
    assert "sub_1000" in text
    assert row["reward_model"]["ground_truth"] == ""


def test_registry_rejects_mutated_inputs_and_malware(tmp_path: Path) -> None:
    row = task(tmp_path)
    registry = tmp_path / "registry.json"
    data = {
        "schema_version": 1,
        "reward_version": REWARD_VERSION,
        "environment_version": ENVIRONMENT_VERSION,
        "tasks": [row],
    }
    registry.write_text(json.dumps(data))
    assert load_task(registry, row["task_id"])["address"] == 4096
    Path(row["stripped_binary"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        load_task(registry, row["task_id"])
    row["is_malware"] = True
    registry.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="non-malware"):
        load_task(registry, row["task_id"])


def test_project_and_binary_splits_cannot_leak(tmp_path: Path) -> None:
    row = task(tmp_path)
    other = {**row, "split": "validation"}
    with pytest.raises(ValueError, match="one split"):
        validate_splits([row, other], set())
    other["project"] = "renamed-project"
    with pytest.raises(ValueError, match="identical binaries"):
        validate_splits([row, other], set())
    with pytest.raises(ValueError, match="held-out"):
        validate_splits([row], {"project"})


def bare_episode(tmp_path: Path) -> Episode:
    episode = Episode.__new__(Episode)
    episode.outfile = tmp_path / "decompiled.c"
    episode.calls = 0
    episode.syntax_check = lambda: "checked"
    return episode


@pytest.mark.parametrize("path", ["../truth.c", "/etc/passwd", "target.bin", "sub/decompiled.c"])
def test_only_deliverable_is_accessible(tmp_path: Path, path: str) -> None:
    episode = bare_episode(tmp_path)
    for name in ("Read", "Write"):
        args = {"file_path": path}
        if name == "Write":
            args["content"] = "bad"
        with pytest.raises(InvalidAction, match="only decompiled.c"):
            episode.execute(name, args)
    assert not episode.outfile.exists()


def test_edits_are_ordered_and_episodes_independent(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    first, second = bare_episode(a), bare_episode(b)
    first.execute("Write", {"file_path": "decompiled.c", "content": "return 1;"})
    first.execute(
        "Edit",
        {
            "file_path": "decompiled.c",
            "old_string": "1",
            "new_string": "2",
        },
    )
    assert first.execute("Read", {"file_path": "decompiled.c"}) == "return 2;"
    assert second.execute("Read", {"file_path": "decompiled.c"}) == "No output file yet."
    with pytest.raises(InvalidAction, match="exactly once"):
        first.execute("Edit", {"file_path": "decompiled.c", "old_string": "", "new_string": "x"})


def test_tool_schema_rejects_shell_and_wrong_argument_types(tmp_path: Path) -> None:
    assert len(tool_schemas()) == 9
    episode = bare_episode(tmp_path)
    with pytest.raises(InvalidAction):
        episode.execute("Bash", {"command": "cat secret"})
    with pytest.raises(InvalidAction, match="argument type"):
        episode.execute("Write", {"file_path": "decompiled.c", "content": 7})


def test_infrastructure_error_never_becomes_tool_feedback(tmp_path: Path) -> None:
    class Process:
        stdout = asyncio.StreamReader()

    async def check() -> None:
        client = EpisodeClient(
            Path("python"), tmp_path, tmp_path / "registry", "id", tmp_path / "log"
        )
        process = Process()
        process.stdout.feed_data(b'{"ok":false,"kind":"infrastructure","error":"no compiler"}\n')
        client.process = process
        with pytest.raises(WorkerError, match="no compiler"):
            await client._read(1)

    asyncio.run(check())


@pytest.mark.parametrize("error", [FileNotFoundError("gcc"), subprocess.TimeoutExpired("gcc", 30)])
def test_compiler_infrastructure_failure_is_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    episode = Episode.__new__(Episode)
    episode.sandbox = []
    episode.compiler = "gcc"
    episode.flags = []
    episode.outfile = tmp_path / "decompiled.c"
    episode.workdir = tmp_path

    def fail(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(type(error)):
        episode.syntax_check()


def test_failed_worker_launch_cleans_private_workdir(tmp_path: Path) -> None:
    async def check() -> None:
        client = EpisodeClient(
            tmp_path / "missing-python",
            tmp_path,
            tmp_path / "registry",
            "id",
            tmp_path / "worker.log",
        )
        with pytest.raises(FileNotFoundError):
            await client.start()
        assert client.stderr is None and client.work is None
        assert not list(tmp_path.glob("work-*"))

    asyncio.run(check())


def test_registry_rejects_old_tool_environment(tmp_path: Path) -> None:
    row = task(tmp_path)
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps({"schema_version": 1, "reward_version": REWARD_VERSION, "tasks": [row]})
    )
    with pytest.raises(ValueError, match="environment changed"):
        load_task(registry, row["task_id"])


def test_verl_ida_schemas_match_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    from decbench.decompilers.agent_ida import _build_mcp_server

    def tool(name: str, description: str, schema: dict) -> Any:
        def decorate(fn: Any) -> dict:
            return {
                "name": "mcp__ida__" + name,
                "description": description,
                "parameters": schema or {"type": "object", "properties": {}, "required": []},
            }

        return decorate

    monkeypatch.setitem(
        sys.modules,
        "claude_agent_sdk",
        SimpleNamespace(tool=tool, create_sdk_mcp_server=lambda **kwargs: kwargs),
    )
    backend = _build_mcp_server(SimpleNamespace())
    offered = [
        row["function"] for row in tool_schemas() if row["function"]["name"].startswith("mcp__")
    ]
    assert backend["version"] == "1.1.0"
    assert offered == backend["tools"]
    assert not any(row["name"].endswith("list_functions") for row in offered)


def test_new_ida_arguments_and_removed_tools(tmp_path: Path) -> None:
    from unittest.mock import Mock

    session = Mock()
    session._resolve.return_value = 0x1000
    episode = bare_episode(tmp_path)
    episode._ida = lambda: session
    episode.execute("mcp__ida__decompile_function", {"addr": "sub_1000"})
    session._resolve.assert_called_with("sub_1000")
    session.decompile.assert_called_with(0x1000, False)
    episode.execute(
        "mcp__ida__disassemble_function",
        {"addr": "sub_1000", "offset": 2, "length": 3, "force": True},
    )
    session.disassemble.assert_called_with(0x1000, 2, 3, True)
    episode.execute("mcp__ida__read_bytes", {"addr": "dword_1000"})
    session.read_bytes.assert_called_with(0x1000, 64)
    episode.execute("mcp__ida__get_xrefs_from", {"addr": "sub_1000", "offset": 5})
    session.xrefs_from.assert_called_with(0x1000, 5)
    for name, args in (
        ("mcp__ida__list_functions", {"page": 0, "name_contains": ""}),
        ("mcp__ida__decompile_function", {"addr": "1000", "force": "false"}),
        ("mcp__ida__read_bytes", {"addr": "1000", "size": True}),
        ("mcp__ida__get_xrefs_to", {"addr": "1000", "unknown": 1}),
        ("mcp__ida__read_bytes", {}),
    ):
        with pytest.raises(InvalidAction):
            episode.execute(name, args)
    session._resolve.side_effect = ValueError("cannot resolve name")
    with pytest.raises(InvalidAction, match="cannot resolve"):
        episode.execute("mcp__ida__read_bytes", {"addr": "absent"})


@pytest.mark.parametrize("recognized_code", [False, True])
def test_ida_force_requires_recognized_code(
    monkeypatch: pytest.MonkeyPatch, recognized_code: bool
) -> None:
    from unittest.mock import Mock

    from decbench.decompilers.agent_ida import _IdaSession

    function = SimpleNamespace(start_ea=0x1000)
    funcs = SimpleNamespace(get_func=Mock(return_value=None), add_func=Mock())
    monkeypatch.setitem(sys.modules, "ida_funcs", funcs)
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        SimpleNamespace(get_flags=lambda ea: 0, is_code=lambda flags: recognized_code),
    )
    session = object.__new__(_IdaSession)
    session.to_ida = lambda addr: addr
    with pytest.raises(ValueError, match="no function"):
        session._func_at(0x1000)
    funcs.add_func.assert_not_called()
    if recognized_code:
        funcs.get_func.side_effect = [None, function]
        assert session._func_at(0x1000, force=True) is function
        funcs.add_func.assert_called_once_with(0x1000)
    else:
        with pytest.raises(ValueError, match="not recognized code"):
            session._func_at(0x1000, force=True)
        funcs.add_func.assert_not_called()


@pytest.mark.parametrize("size", [0, 513])
def test_ida_read_bytes_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch, size: int) -> None:
    from decbench.decompilers.agent_ida import _IdaSession

    for module in ("ida_bytes", "ida_segment", "idaapi"):
        monkeypatch.setitem(sys.modules, module, SimpleNamespace())
    session = object.__new__(_IdaSession)
    with pytest.raises(ValueError, match="out of range"):
        session.read_bytes(0x1000, size)
