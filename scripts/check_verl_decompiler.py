"""Exercise real verl token masking, Qwen tool parsing, IDA, and scoring without inference."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


class ScriptedServer:
    def __init__(self, tokenizer: Any, address: int) -> None:
        self.tokenizer = tokenizer

        def call(name: str, **parameters: Any) -> str:
            body = "".join(
                f"<parameter={key}>{value if isinstance(value, str) else json.dumps(value)}"
                "</parameter>\n"
                for key, value in parameters.items()
            )
            return f"<tool_call>\n<function={name}>\n{body}</function>\n</tool_call>"

        self.responses = [
            call("mcp__ida__get_metadata"),
            call("mcp__ida__decompile_function", addr=f"{address:x}"),
            call(
                "mcp__ida__disassemble_function",
                addr=f"sub_{address:X}",
                offset=1,
                length=2,
                force=False,
            ),
            call("mcp__ida__get_xrefs_to", addr=f"{address:x}"),
            call("mcp__ida__get_xrefs_from", addr=f"{address:x}", offset=0),
            call("mcp__ida__read_bytes", addr=f"sub_{address:X}", size=16),
            call(
                "Write",
                file_path="decompiled.c",
                content=f"unsigned sub_{address:x}(unsigned x) {{ "
                "if (x > 3u) return x * 2u; return x + 1u; }",
            ),
            call("Read", file_path="decompiled.c"),
            call(
                "Edit",
                file_path="decompiled.c",
                old_string="return x + 1u;",
                new_string="return x + 1u; /* verified */",
            ),
            "Saved decompiled.c.<|im_end|>",
        ]

    async def generate(self, **kwargs: Any) -> SimpleNamespace:
        if not self.responses:
            raise AssertionError("scripted model exhausted before rollout completed")
        ids = self.tokenizer.encode(self.responses.pop(0), add_special_tokens=False)
        return SimpleNamespace(
            token_ids=ids,
            log_probs=[-0.5] * len(ids),
            num_preempted=0,
            routed_experts=None,
            extra_fields={},
        )


async def check(dataset: Path, output_dir: Path, model: Path) -> None:
    from hydra import compose, initialize_config_dir
    from hydra.utils import instantiate
    from omegaconf import OmegaConf
    from transformers import AutoTokenizer
    from verl.experimental.agent_loop.agent_loop import DictConfigWrap
    from verl.utils.dataset.rl_dataset import RLHFDataset

    from decbench.rl.tasks import ENVIRONMENT_VERSION, public_row, tool_schemas

    registry = json.loads((dataset / "tasks.private.json").read_text())
    if not registry["smoke_only"]:
        raise ValueError("scripted fixture may only use the synthetic smoke dataset")
    task = registry["tasks"][0]
    os.environ["DECBENCH_RL_REPO"] = str(REPO)
    os.environ["DECBENCH_RL_MODEL"] = str(model)
    os.environ["DECBENCH_RL_DATASET"] = str(dataset)
    os.environ["DECBENCH_RL_RUN"] = str(output_dir)
    with initialize_config_dir(config_dir=str(REPO / "configs/verl"), version_base=None):
        config = compose(config_name="decbench_grpo")
    tokenizer = AutoTokenizer.from_pretrained(str(model), local_files_only=True)
    loop = instantiate(
        OmegaConf.load(dataset / "agent.yaml")[0],
        trainer_config=DictConfigWrap(config),
        server_manager=ScriptedServer(tokenizer, int(task["address"])),
        tokenizer=tokenizer,
        processor=None,
        dataset_cls=RLHFDataset,
        data_config=DictConfigWrap(config.data),
    )
    row = public_row(task, 0)
    result = await loop.run(
        {"temperature": 1.0}, raw_prompt=row["prompt"], extra_info=row["extra_info"]
    )
    assert result.reward_score == 1.0
    assert len(result.response_ids) == len(result.response_mask) == len(result.response_logprobs)
    assert 0 in result.response_mask and 1 in result.response_mask
    assert all(
        p == 0.0
        for p, m in zip(result.response_logprobs, result.response_mask, strict=True)
        if not m
    )
    assert len(loop.events) == 9 and all(event["response"]["ok"] for event in loop.events)
    assert {event["tool"] for event in loop.events} == {
        row["function"]["name"] for row in tool_schemas()
    }
    assert "showing 2-3" in loop.events[2]["response"]["value"]
    assert "16 bytes at" in loop.events[5]["response"]["value"]
    summary = {
        "kind": "scripted_verl_integration_not_model_training",
        "environment_version": ENVIRONMENT_VERSION,
        "reward": result.reward_score,
        "prompt_tokens": len(result.prompt_ids),
        "generated_tokens": sum(result.response_mask),
        "tool_observation_tokens": result.response_mask.count(0),
        "tool_calls": len(loop.events),
        "tool_names": [event["tool"] for event in loop.events],
    }
    (output_dir / "check.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(os.environ.get("DECBENCH_RL_MODEL", REPO / "models/Qwen/Qwen3.5-4B")),
        help="model directory; relative CLI/env paths are resolved from the calling directory",
    )
    args = parser.parse_args()
    asyncio.run(check(args.dataset.resolve(), args.output.resolve(), args.model.resolve()))


if __name__ == "__main__":
    main()
