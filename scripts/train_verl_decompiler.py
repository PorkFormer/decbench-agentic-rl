"""Validate frozen inputs and launch an isolated Qwen3.5 verl experiment."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from decbench.rl.tasks import VERL_REVISION, digest, load_task  # noqa: E402


def check_dataset(dataset: Path) -> None:
    lock = json.loads((dataset / "dataset.lock.json").read_text())
    for base, entries in (
        (dataset, lock["files"]),
        (REPO, lock["adapter"]),
        (REPO, lock["scorer"]),
    ):
        for relative, expected in entries.items():
            if digest(base / relative) != expected:
                raise ValueError(
                    f"frozen dataset or adapter changed: {relative}; prepare a new tree"
                )
    registry = dataset / "tasks.private.json"
    for task in json.loads(registry.read_text())["tasks"]:
        load_task(registry, task["task_id"])


def select_gpus(indices: str) -> list[str]:
    selected = [int(value) for value in indices.split(",")]
    if len(selected) != len(set(selected)) or len(selected) != 4:
        raise ValueError("the initial configuration requires four distinct GPU indices")
    result = subprocess.check_output(
        [
            "nvidia-smi",
            "--query-gpu=index,uuid,memory.used,utilization.gpu",
            "--format=csv,noheader,nounits",
        ],
        text=True,
    )
    devices = {}
    for row in result.splitlines():
        index, uuid, used, utilization = [field.strip() for field in row.split(",")]
        devices[int(index)] = (uuid, int(used), int(utilization))
    for index in selected:
        if index not in devices or devices[index][1] > 512 or devices[index][2] > 5:
            raise RuntimeError(
                f"GPU {index} is unavailable or busy; existing jobs will not be stopped"
            )
    return [devices[index][0] for index in selected]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(os.environ.get("DECBENCH_RL_MODEL", REPO / "models/Qwen/Qwen3.5-4B")),
        help="model directory; relative CLI/env paths are resolved from the calling directory",
    )
    parser.add_argument("--gpus", help="four idle physical GPU indices; required for training")
    parser.add_argument("--config-only", action="store_true")
    args, overrides = parser.parse_known_args()
    dataset, run_dir = args.dataset.resolve(), args.run_dir.resolve()
    check_dataset(dataset)
    if not args.model.is_dir():
        raise ValueError("local model directory does not exist")
    env = dict(os.environ)
    env.update(
        DECBENCH_RL_REPO=str(REPO),
        DECBENCH_RL_DATASET=str(dataset),
        DECBENCH_RL_RUN=str(run_dir),
        DECBENCH_RL_MODEL=str(args.model.resolve()),
        PYTHONPATH=str(REPO),
        HF_HUB_OFFLINE="1",
        WANDB_MODE="disabled",
        TOKENIZERS_PARALLELISM="false",
        HYDRA_FULL_ERROR="1",
        VLLM_WORKER_MULTIPROC_METHOD="spawn",
    )
    command = [
        sys.executable,
        "-m",
        "verl.trainer.main_ppo",
        "--config-path",
        str(REPO / "configs/verl"),
        "--config-name",
        "decbench_grpo",
        *overrides,
    ]
    if args.config_only:
        subprocess.run([*command, "--cfg", "job", "--resolve"], env=env, cwd=REPO, check=True)
        return
    if not args.gpus:
        raise ValueError("specify --gpus; the launcher never chooses or evicts GPUs automatically")
    gpu_uuids = select_gpus(args.gpus)
    env["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
    env["CUDA_VISIBLE_DEVICES"] = args.gpus
    run_dir.mkdir(parents=True, exist_ok=False)
    env["RAY_TMPDIR"] = tempfile.mkdtemp(prefix="dbrl-")
    provenance = {
        "command": command,
        "gpu_uuids": gpu_uuids,
        "cuda_visible_devices": env["CUDA_VISIBLE_DEVICES"],
        "dataset_lock_sha256": digest(dataset / "dataset.lock.json"),
        "verl_revision": VERL_REVISION,
        "ray_temp_dir": env["RAY_TMPDIR"],
        "training_config_sha256": digest(REPO / "configs/verl/decbench_grpo.yaml"),
        "launcher_sha256": digest(Path(__file__)),
        "verl_attention_utils_sha256": digest(
            Path(importlib.util.find_spec("verl.utils.attention_utils").origin)
        ),
        "verl_padding_patch_sha256": digest(REPO / "configs/verl/sdpa-padding.patch"),
        "verl_fsdp_engine_sha256": digest(
            Path(importlib.util.find_spec("verl").origin).parent
            / "workers/engine/fsdp/transformer_impl.py"
        ),
        "verl_checkpoint_patch_sha256": digest(REPO / "configs/verl/fsdp2-cpu-checkpoint.patch"),
        "model_config_sha256": digest(args.model / "config.json"),
        "versions": {
            dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()
        },
    }
    (run_dir / "launch.json").write_text(json.dumps(provenance, indent=2) + "\n")
    with (run_dir / "runtime-check.log").open("w") as log:
        check = subprocess.run(
            [
                sys.executable,
                "-c",
                "from verl.workers.rollout.base import get_rollout_class; "
                "get_rollout_class('vllm', 'async'); "
                "from verl.utils.attention_utils import unpad_input; import torch; "
                "unpad_input(torch.zeros(1, 1, 1), torch.ones(1, 1)); "
                "print('rollout and padding imports OK')",
            ],
            env=env,
            cwd=REPO,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    if check.returncode:
        (run_dir / "exit.json").write_text(
            json.dumps({"exit_code": check.returncode, "stage": "runtime-check"}) + "\n"
        )
        raise RuntimeError(
            f"training runtime incompatible; inspect {run_dir / 'runtime-check.log'}"
        )
    with (run_dir / "train.log").open("w") as log:
        process = subprocess.Popen(command, env=env, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
        (run_dir / "pid").write_text(str(process.pid) + "\n")
        print(f"Training PID {process.pid}; log: {run_dir / 'train.log'}", flush=True)
        result = process.wait()
    (run_dir / "exit.json").write_text(json.dumps({"exit_code": result}) + "\n")
    raise SystemExit(result)


if __name__ == "__main__":
    main()
