"""One sequential IDA session per subprocess; compiler runs inside bubblewrap."""

from __future__ import annotations

import argparse
import json
import math
import os
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from decbench.rl.tasks import ENVIRONMENT_VERSION, REWARD_VERSION, load_task, tool_schemas

MAX_CODE_BYTES = 128 * 1024


class InvalidAction(ValueError):
    """A policy error that should be returned to the model."""


class Episode:
    def __init__(self, task: dict[str, Any], workdir: Path) -> None:
        from decbench.utils import binfmt
        from decbench.utils.blinding import validate_stripped_elf

        self.task = task
        self.workdir = workdir
        self.outfile = workdir / "decompiled.c"
        self.target = workdir / "target.bin"
        self.session: Any = None
        self.calls = 0
        validate_stripped_elf(Path(task["stripped_binary"]))
        shutil.copyfile(task["stripped_binary"], self.target)
        self.target.chmod(0o400)
        self.original = Path(task["original_binary"])
        info = binfmt.detect(self.original)
        if info is None:
            raise RuntimeError("unrecognized original binary")
        compiler = binfmt.recompiler_for(info)
        executable = shutil.which(compiler) if compiler else None
        if not executable or not shutil.which("bwrap"):
            raise RuntimeError("matching compiler and bubblewrap are required")
        self.compiler_name = str(compiler)
        self.compiler = str(Path(executable).resolve())
        self.flags = binfmt.producer_flags(self.original)
        self.sandbox = self._compiler_sandbox()
        probe = subprocess.run(
            [*self.sandbox, "/usr/bin/true"], capture_output=True, timeout=10, check=False
        )
        if probe.returncode:
            raise RuntimeError("compiler sandbox unavailable; refusing unsandboxed compilation")
        wrappers = workdir / "compiler-bin"
        wrappers.mkdir()
        wrapper = wrappers / self.compiler_name
        wrapper.write_text(
            "#!/bin/sh\nexec " + shlex.join([*self.sandbox, self.compiler]) + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        os.environ["PATH"] = str(wrappers) + os.pathsep + os.environ.get("PATH", "")

    def _compiler_sandbox(self) -> list[str]:
        command = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent"]
        for directory in ("/usr", "/lib", "/lib64", "/bin"):
            if Path(directory).exists():
                command += ["--ro-bind", directory, directory]
        tool_root = Path(self.compiler).parent.parent
        if not self.compiler.startswith("/usr/"):
            command += ["--ro-bind", str(tool_root), str(tool_root)]
        command += [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--bind",
            str(self.workdir),
            str(self.workdir),
            "--chdir",
            str(self.workdir),
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "TMPDIR",
            str(self.workdir),
        ]
        return command

    def _ida(self) -> Any:
        if self.session is None:
            import idapro  # noqa: F401

            from decbench.decompilers.agent_ida import _IdaSession

            self.session = _IdaSession(self.target)
        return self.session

    def syntax_check(self) -> str:
        result = subprocess.run(
            [*self.sandbox, self.compiler, *self.flags, "-fsyntax-only", str(self.outfile)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode < 0 or result.returncode in (124, 137):
            raise RuntimeError("compiler process was interrupted")
        if result.returncode == 0:
            return "File saved. Syntax check passed; this does not establish semantic correctness."
        diagnostics = (result.stderr + result.stdout).replace(str(self.workdir), ".")
        return "File saved. Syntax check failed:\n" + diagnostics[:4000]

    def execute(self, name: str, parameters: dict[str, Any]) -> str:
        schemas = {row["function"]["name"]: row["function"]["parameters"] for row in tool_schemas()}
        if name not in schemas or not isinstance(parameters, dict):
            raise InvalidAction("unknown tool or invalid arguments")
        schema = schemas[name]
        if not set(schema["required"]) <= set(parameters) <= set(schema["properties"]):
            raise InvalidAction("arguments must match the tool schema")
        for key, value in parameters.items():
            expected = {"integer": int, "string": str, "boolean": bool}[
                schema["properties"][key]["type"]
            ]
            if type(value) is not expected:
                raise InvalidAction(f"invalid argument type: {key}")
        self.calls += 1
        if name in ("Read", "Write", "Edit"):
            if parameters["file_path"] not in ("decompiled.c", "./decompiled.c"):
                raise InvalidAction("only decompiled.c is accessible")
            if name == "Read":
                return self.outfile.read_text() if self.outfile.exists() else "No output file yet."
            if name == "Write":
                code = parameters["content"]
            else:
                old = parameters["old_string"]
                code = self.outfile.read_text() if self.outfile.exists() else ""
                if not old or code.count(old) != 1:
                    raise InvalidAction("old_string must occur exactly once")
                code = code.replace(old, parameters["new_string"], 1)
            if len(code.encode()) > MAX_CODE_BYTES or "\x00" in code:
                raise InvalidAction("output exceeds size limit or contains NUL")
            self.outfile.write_text(code)
            return self.syntax_check()
        session = self._ida()
        if name.endswith("get_metadata"):
            return session.metadata()
        try:
            address = session._resolve(parameters["addr"])
            if not 0 <= address < 2**64:
                raise ValueError("out of range")
            offset = max(0, parameters.get("offset", 0))
            force = parameters.get("force", False)
            if name == "mcp__ida__decompile_function":
                return session.decompile(address, force)
            if name == "mcp__ida__disassemble_function":
                return session.disassemble(
                    address, offset, max(1, parameters.get("length", 4000)), force
                )
            if name == "mcp__ida__read_bytes":
                return session.read_bytes(address, parameters.get("size", 64))
            method = {
                "mcp__ida__get_xrefs_to": session.xrefs_to,
                "mcp__ida__get_xrefs_from": session.xrefs_from,
            }[name]
            return method(address, offset)
        except ValueError as exc:
            raise InvalidAction(str(exc)) from exc

    def score(self) -> dict[str, Any]:
        from decbench.decompilers.llm_dec import _rename_func, _sanitize
        from decbench.metrics.byte_match import ByteMatchMetric
        from decbench.models.decompilation import FunctionDecompilation

        code = self.outfile.read_text() if self.outfile.exists() else ""
        result: dict[str, Any] = {
            "score": 0.0,
            "reward_version": REWARD_VERSION,
            "environment_version": ENVIRONMENT_VERSION,
            "calls": self.calls,
            "code": code,
            "status": "no_output",
            "compilable": False,
        }
        if not code.strip():
            return result
        fn = FunctionDecompilation(
            name=self.task["function"],
            address=int(self.task["address"]),
            decompiled_code=_rename_func(_sanitize(code), self.task["function"]),
        )
        metric = ByteMatchMetric().compute_for_function(fn, original_binary_path=self.original)
        if not math.isfinite(metric.value) or not 0 <= metric.value <= 1:
            raise RuntimeError("reward must be finite and in [0,1]")
        metadata = metric.metadata
        if metadata.get("skipped") or "compilable" not in metadata:
            raise RuntimeError("reward infrastructure failed: " + str(metadata))
        if metadata.get("error") == "Could not extract recompiled bytes":
            result.update(status="invalid_output", metric_metadata=metadata)
            return result
        if metadata.get("compilable") and metadata.get("error"):
            raise RuntimeError("reward extraction failed: " + str(metadata))
        result.update(
            score=float(metric.value),
            status="scored",
            compilable=bool(metadata["compilable"]),
            metric_metadata=metadata,
        )
        return result

    def close(self) -> None:
        if self.session is not None:
            self.session.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    args = parser.parse_args()
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", buffering=1)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    os.environ["DECBENCH_NO_CACHE"] = "1"
    resource.setrlimit(resource.RLIMIT_AS, (16 * 1024**3, 16 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    with tempfile.TemporaryDirectory(prefix="decbench-rl-") as tmp:
        tempfile.tempdir = tmp
        episode = Episode(load_task(args.registry.resolve(), args.task_id), Path(tmp))
        protocol.write(json.dumps({"ok": True, "ready": True}) + "\n")
        try:
            for line in sys.stdin:
                try:
                    request = json.loads(line)
                    if request["op"] == "score":
                        value = episode.score()
                    elif request["op"] == "execute":
                        value = episode.execute(request["name"], request["parameters"])
                    else:
                        raise InvalidAction("unknown operation")
                    response = {"ok": True, "value": value}
                except InvalidAction as exc:
                    response = {"ok": False, "kind": "action", "error": str(exc)}
                except Exception as exc:
                    response = {"ok": False, "kind": "infrastructure", "error": str(exc)}
                protocol.write(json.dumps(response) + "\n")
        finally:
            episode.close()


if __name__ == "__main__":
    main()
