"""verl v0.8 AgentLoop adapter with one private IDA worker per trajectory."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from verl.experimental.agent_loop.agent_loop import AgentLoopOutput, ToolListWrap
from verl.experimental.agent_loop.tool_agent_loop import AgentData, ToolAgentLoop
from verl.tools.schemas import OpenAIFunctionToolSchema, ToolResponse

from decbench.rl.bridge import EpisodeClient, WorkerError
from decbench.rl.tasks import tool_schemas

_worker_slots: dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}


class DecbenchAgentLoop(ToolAgentLoop):
    def __init__(
        self,
        *args: Any,
        registry: str,
        worker_python: str,
        repo: str,
        artifact_dir: str,
        episode_timeout: float = 900,
        **kwargs: Any,
    ) -> None:
        kwargs["tools"] = ToolListWrap(
            [
                SimpleNamespace(
                    name=row["function"]["name"],
                    tool_schema=OpenAIFunctionToolSchema.model_validate(row),
                )
                for row in tool_schemas()
            ]
        )
        super().__init__(*args, **kwargs)
        self.registry, self.worker_python = Path(registry), Path(worker_python)
        self.repo, self.artifact_dir = Path(repo), Path(artifact_dir)
        self.episode_timeout = float(episode_timeout)
        self.worker: EpisodeClient | None = None
        self.events: list[dict[str, Any]] = []

    async def run(self, sampling_params: dict[str, Any], **kwargs: Any) -> AgentLoopOutput:
        task_id = kwargs["extra_info"]["task_id"]
        rollout_id = uuid4().hex
        directory = self.artifact_dir / rollout_id
        directory.mkdir(parents=True, exist_ok=False)
        loop = asyncio.get_running_loop()
        semaphore = _worker_slots.setdefault(loop, asyncio.Semaphore(1))
        async with semaphore:
            self.worker = EpisodeClient(
                self.worker_python, self.repo, self.registry, task_id, directory / "worker.log"
            )
            try:
                await self.worker.start()
                output = await asyncio.wait_for(
                    super().run(sampling_params, **kwargs), timeout=self.episode_timeout
                )
                if not output.response_ids or output.response_mask[-1] != 1:
                    raise WorkerError("trajectory must terminate on a generated token")
                started = time.monotonic()
                response = await self.worker.request({"op": "score"})
                score = response["value"]
                output.reward_score = float(score["score"])
                output.metrics.compute_score = time.monotonic() - started
                output.extra_fields["reward_extra_info"] = {
                    "byte_proxy": output.reward_score,
                    "compilable": int(score["compilable"]),
                    "no_output": int(score["status"] == "no_output"),
                    "tool_calls": len(self.events),
                }
                (directory / "decompiled.c").write_text(score.pop("code"))
                (directory / "trajectory.json").write_text(
                    json.dumps(
                        {
                            "task_id": task_id,
                            "rollout_id": rollout_id,
                            "sampling_params": sampling_params,
                            "events": self.events,
                            "score": score,
                            "trajectory": output.model_dump(),
                        },
                        indent=2,
                    )
                    + "\n"
                )
                return output
            except BaseException as exc:
                (directory / "failure.json").write_text(
                    json.dumps(
                        {
                            "task_id": task_id,
                            "kind": "infrastructure",
                            "error": str(exc),
                            "events": self.events,
                        },
                        indent=2,
                    )
                    + "\n"
                )
                raise
            finally:
                await self.worker.close()

    async def _call_tool(
        self,
        tool_call: Any,
        tools_kwargs: dict[str, Any],
        agent_data: AgentData,
    ) -> tuple[ToolResponse, float, dict[str, Any]]:
        assert self.worker is not None
        try:
            parameters = json.loads(tool_call.arguments)
        except (TypeError, ValueError):
            parameters = None
        if tool_call.name not in self.tools or not isinstance(parameters, dict):
            response = {"ok": False, "kind": "action", "error": "Unknown tool or invalid JSON."}
        else:
            response = await self.worker.request(
                {
                    "op": "execute",
                    "name": tool_call.name,
                    "parameters": parameters,
                }
            )
        text = str(response["value"] if response["ok"] else response["error"])
        self.events.append({"tool": tool_call.name, "parameters": parameters, "response": response})
        limit = self.max_tool_response_length
        if len(text) > limit:
            text = text[:limit] + "\n(truncated)"
        return ToolResponse(text=text), 0.0, {}
