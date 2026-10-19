"""Run the four-GPU Qwen pilot service and record its immutable inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SAMPLING_PRESETS = {
    "legacy-08b": dict(
        temperature=1.0,
        top_p=1.0,
        top_k=20,
        min_p=0.0,
        presence_penalty=2.0,
        repetition_penalty=1.0,
    ),
    "official-thinking-coding": dict(
        temperature=0.6,
        top_p=0.95,
        top_k=20,
        min_p=0.0,
        presence_penalty=0.0,
        repetition_penalty=1.0,
    ),
}


def nonthinking_template(source: str) -> str:
    return fixed_thinking_template(source, enabled=False)


def fixed_thinking_template(source: str, *, enabled: bool) -> str:
    conditions = [
        f"enable_thinking is defined and enable_thinking is {v}" for v in ("true", "false")
    ]
    if sum(source.count(c) for c in conditions) != 1:
        raise ValueError("unexpected Qwen template thinking condition")
    condition = next(c for c in conditions if c in source)
    selected = enabled if condition.endswith("true") else not enabled
    return source.replace(condition, "true" if selected else "false")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / ".tools/qwen-service")
    parser.add_argument("--served-model-name", default="qwen3.5-0.8b")
    parser.add_argument("--thinking", choices=("enabled", "disabled"), default="disabled")
    parser.add_argument("--sampling-preset", choices=SAMPLING_PRESETS, default="legacy-08b")
    parser.add_argument("--model-path", type=Path, default=REPO / "models/Qwen/Qwen3.5-0.8B")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    python = REPO / ".tools/qwen-vllm/bin/python"
    model = args.model_path.resolve()
    enabled = args.thinking == "enabled"
    template = output / f"{args.thinking}-thinking.jinja"
    template.write_text(
        fixed_thinking_template((model / "chat_template.jinja").read_text(), enabled=enabled)
    )
    sampling = SAMPLING_PRESETS[args.sampling_preset]
    command = [
        str(python),
        "-m",
        "vllm.entrypoints.cli.main",
        "serve",
        str(model),
        "--served-model-name",
        args.served_model_name,
        "--host",
        "127.0.0.1",
        "--port",
        "18080",
        "--tensor-parallel-size",
        "4",
        "--dtype",
        "bfloat16",
        "--language-model-only",
        "--max-model-len",
        "262144",
        "--max-num-seqs",
        "1",
        "--gpu-memory-utilization",
        "0.8",
        "--enable-auto-tool-choice",
        "--tool-call-parser",
        "qwen3_coder",
        "--reasoning-parser",
        "qwen3",
        "--default-chat-template-kwargs",
        json.dumps({"enable_thinking": enabled}),
        "--chat-template",
        str(template),
        "--middleware",
        "scripts.qwen_nonthinking_middleware.QwenPilotMiddleware",
        "--override-generation-config",
        json.dumps(sampling),
        "--seed",
        "1337",
    ]
    overrides = {
        "CUDA_VISIBLE_DEVICES": "0,1,2,3",
        "VLLM_WORKER_MULTIPROC_METHOD": "spawn",
        "HF_HUB_OFFLINE": "1",
        "HF_HOME": str(output / "hf-cache"),
        "XDG_CACHE_HOME": str(output / "cache"),
        "TORCHINDUCTOR_CACHE_DIR": str(output / "inductor-cache"),
        "TRITON_CACHE_DIR": str(output / "triton-cache"),
        "PYTHONPATH": str(REPO),
        "QWEN_PILOT_POLICY": json.dumps({"thinking": args.thinking, "sampling": sampling}),
    }
    versions = json.loads(
        subprocess.check_output(
            [
                str(python),
                "-c",
                "import importlib.metadata as m,json; "
                "print(json.dumps({d.metadata['Name']: d.version for d in m.distributions()}))",
            ],
            text=True,
        )
    )
    if versions.get("vllm") != "0.31.0":
        raise ValueError("this deployment requires vLLM 0.31.0")
    files = [p for p in model.iterdir() if p.is_file()] + [Path(__file__).resolve(), template]
    files.append(REPO / "scripts/qwen_nonthinking_middleware.py")
    requirements = REPO / ".tools/qwen-requirements-hashed.lock"
    if requirements.is_file():
        files.append(requirements)
    provenance = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "served_model_name": args.served_model_name,
        "model_path": str(model),
        "command": command,
        "environment": overrides,
        "versions": versions,
        "sampling": sampling,
        "thinking": args.thinking,
        "sampling_preset": args.sampling_preset,
        "thinking_enforcement": "request middleware plus fixed generation prefix",
        "gpus": subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=index,uuid,name,driver_version",
                "--format=csv",
            ],
            text=True,
        ),
        "files": {str(p): digest(p) for p in files},
    }
    (output / "deployment.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Deployment recorded in {output}; starting service", flush=True)
    with (output / "server.log").open("a") as log:
        result = subprocess.run(
            command, env={**os.environ, **overrides}, stdout=log, stderr=subprocess.STDOUT, cwd=REPO
        )
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
