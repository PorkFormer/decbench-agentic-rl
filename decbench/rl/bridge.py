"""Async JSON transport to the separate DecBench Python/IDA runtime."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import tempfile
from pathlib import Path
from typing import Any


class WorkerError(RuntimeError):
    """Infrastructure failure: abort the rollout instead of issuing a reward."""


class EpisodeClient:
    def __init__(self, python: Path, repo: Path, registry: Path, task_id: str, log: Path) -> None:
        self.python, self.repo, self.registry = python, repo, registry
        self.task_id, self.log = task_id, log
        self.process: asyncio.subprocess.Process | None = None
        self.stderr: Any = None
        self.work: tempfile.TemporaryDirectory[str] | None = None

    async def start(self) -> None:
        env = {
            key: os.environ[key]
            for key in ("HOME", "USER", "LANG", "LC_ALL", "TMPDIR")
            if key in os.environ
        }
        env.update(
            PYTHONPATH=str(self.repo),
            PYTHONUNBUFFERED="1",
            IDADIR=str(self.repo / ".tools/ida-pro-9.3"),
            HEXRAYS_LICENSE_FILE=str(self.repo / ".tools/ida-pro-9.3/idapro.hexlic"),
            DECBENCH_NO_CACHE="1",
            PATH=os.pathsep.join(
                [
                    str(self.repo / ".tools/host-gcc-12.3.0/usr/bin"),
                    str(self.repo / ".tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/bin"),
                    "/usr/bin",
                    "/bin",
                ]
            ),
        )
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.work = tempfile.TemporaryDirectory(prefix="work-", dir=self.log.parent)
        env["TMPDIR"] = self.work.name
        self.stderr = self.log.open("w")
        try:
            self.process = await asyncio.create_subprocess_exec(
                str(self.python),
                "-m",
                "decbench.rl.worker",
                "--registry",
                str(self.registry),
                "--task-id",
                self.task_id,
                cwd=self.repo,
                env=env,
                start_new_session=True,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=self.stderr,
                limit=2 * 1024**2,
            )
            ready = await self._read(60)
            if not ready.get("ready"):
                raise WorkerError("worker did not initialize")
        except BaseException:
            await self.close()
            raise

    async def _read(self, timeout: float) -> dict[str, Any]:
        assert self.process is not None and self.process.stdout is not None
        try:
            line = await asyncio.wait_for(self.process.stdout.readline(), timeout)
        except asyncio.TimeoutError as exc:
            raise WorkerError(f"worker timed out; inspect {self.log}") from exc
        if not line:
            raise WorkerError(f"worker exited; inspect {self.log}")
        try:
            response = json.loads(line)
        except (ValueError, UnicodeError) as exc:
            raise WorkerError("invalid worker protocol") from exc
        if not response.get("ok") and response.get("kind") != "action":
            raise WorkerError(response.get("error", "worker failure"))
        return response

    async def request(self, request: dict[str, Any], timeout: float = 120) -> dict[str, Any]:
        assert self.process is not None and self.process.stdin is not None
        self.process.stdin.write((json.dumps(request) + "\n").encode())
        await self.process.stdin.drain()
        return await self._read(timeout)

    async def close(self) -> None:
        if self.process is not None:
            if self.process.returncode is None:
                if self.process.stdin is not None:
                    self.process.stdin.close()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.process.wait(), timeout=5)
            if self.process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
            await self.process.wait()
            self.process = None
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None
        if self.work is not None:
            self.work.cleanup()
            self.work = None
