"""Build frozen, non-malware RL tasks and verl parquet inputs in a new directory."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from decbench.rl.tasks import (  # noqa: E402
    ENVIRONMENT_VERSION,
    REWARD_VERSION,
    VERL_REVISION,
    digest,
    public_row,
    tool_schemas,
)
from decbench.utils.blinding import validate_stripped_elf  # noqa: E402


def validate_splits(tasks: list[dict[str, Any]], heldout_projects: set[str]) -> None:
    projects: dict[str, str] = {}
    binaries: dict[str, str] = {}
    for task in tasks:
        split = task["split"]
        if split not in ("train", "validation") or task.get("is_malware") is not False:
            raise ValueError("tasks require train/validation split and is_malware=false")
        project = task["project"]
        if split == "train" and project in heldout_projects:
            raise ValueError(f"training project overlaps held-out benchmark: {project}")
        if project in projects and projects[project] != split:
            raise ValueError("all versions and functions of a project must stay in one split")
        projects[project] = split
        binary_hash = digest(Path(task["original_binary"]))
        if binary_hash in binaries and binaries[binary_hash] != split:
            raise ValueError("identical binaries cannot cross splits")
        binaries[binary_hash] = split
    if {row["split"] for row in tasks} != {"train", "validation"}:
        raise ValueError("both training and validation tasks are required")


def smoke_inputs(directory: Path) -> list[dict[str, Any]]:
    from elftools.elf.elffile import ELFFile

    rows = []
    for split, count in (("train", 8), ("validation", 2)):
        functions = []
        for index in range(count):
            if split == "train":
                body = f"if (x > {index + 3}u) return x * {index + 2}u; return x + {index + 1}u;"
            else:
                body = f"unsigned y = x ^ {index + 17}u; return (y << 3) | (y >> 29);"
            functions.append(f"unsigned task_{index}(unsigned x) {{ {body} }}")
        source = directory / f"{split}.c"
        binary = directory / split
        source.write_text("\n".join(functions) + "\nint main(void) { return 0; }\n")
        subprocess.run(["gcc", "-g", "-O0", str(source), "-o", str(binary)], check=True)
        with binary.open("rb") as stream:
            symbols = ELFFile(stream).get_section_by_name(".symtab")
            addresses = {sym.name: int(sym["st_value"]) for sym in symbols.iter_symbols()}
        for index in range(count):
            rows.append(
                {
                    "project": f"synthetic-smoke-{split}",
                    "split": split,
                    "is_malware": False,
                    "original_binary": str(binary),
                    "function": f"task_{index}",
                    "address": addresses[f"task_{index}"],
                }
            )
    return rows


def build(
    tasks: list[dict[str, Any]],
    output: Path,
    export_python: Path,
    heldout_projects: set[str],
    *,
    smoke: bool = False,
) -> None:
    validate_splits(tasks, heldout_projects)
    output = output.resolve()
    if output.exists():
        raise ValueError("output must be a new directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prepare-verl-", dir=output.parent) as tmp:
        staging = Path(tmp) / "dataset"
        staging.mkdir()
        (staging / "binaries").mkdir()
        frozen = []
        seen = set()
        for row in tasks:
            original = Path(row["original_binary"]).resolve()
            binary_hash = digest(original)
            name = row["function"]
            address = int(row["address"])
            from decbench.utils import binfmt

            if not binfmt.producer_flags(original):
                raise ValueError("original binary must retain DWARF compiler flags")
            if binfmt.function_bytes(original, name, address) is None:
                raise ValueError("target is not recoverable from the original binary")
            task_id = digest_task(binary_hash, address)
            if task_id in seen:
                raise ValueError("duplicate binary/address task")
            seen.add(task_id)
            stored = staging / "binaries" / f"{binary_hash}.elf"
            stripped = staging / "binaries" / f"{binary_hash}.stripped"
            if not stored.exists():
                shutil.copyfile(original, stored)
                from scripts.run_benchmark import _stripped_copy

                generated = _stripped_copy(stored, staging / "strip-temp")
                shutil.move(str(generated), stripped)
                stored.chmod(0o400)
                stripped.chmod(0o400)
            validate_stripped_elf(stripped)
            frozen.append(
                {
                    "task_id": task_id,
                    "project": row["project"],
                    "split": row["split"],
                    "is_malware": False,
                    "function": name,
                    "address": address,
                    "original_binary": str(stored.relative_to(staging)),
                    "original_binary_sha256": binary_hash,
                    "stripped_binary": str(stripped.relative_to(staging)),
                    "stripped_binary_sha256": digest(stripped),
                }
            )
        registry = {
            "schema_version": 1,
            "reward_version": REWARD_VERSION,
            "environment_version": ENVIRONMENT_VERSION,
            "verl_revision": VERL_REVISION,
            "smoke_only": smoke,
            "heldout_projects": sorted(heldout_projects),
            "tasks": frozen,
        }
        (staging / "tasks.private.json").write_text(json.dumps(registry, indent=2) + "\n")
        (staging / "tools.json").write_text(json.dumps(tool_schemas(), indent=2) + "\n")
        for split in ("train", "validation"):
            rows = [
                public_row(row, index) for index, row in enumerate(frozen) if row["split"] == split
            ]
            jsonl = staging / f"{split}.jsonl"
            jsonl.write_text("".join(json.dumps(row) + "\n" for row in rows))
            subprocess.run(
                [
                    str(export_python),
                    "-c",
                    "import json,sys,pyarrow as pa,pyarrow.parquet as pq; "
                    "rows=[json.loads(s) for s in open(sys.argv[1])]; "
                    "pq.write_table(pa.Table.from_pylist(rows),"
                    "sys.argv[2])",
                    str(jsonl),
                    str(staging / f"{split}.parquet"),
                ],
                check=True,
            )
        agent_config = [
            {
                "name": "decbench_ida",
                "_target_": "decbench.rl.verl_agent.DecbenchAgentLoop",
                "registry": "${oc.env:DECBENCH_RL_DATASET}/tasks.private.json",
                "worker_python": "${oc.env:DECBENCH_RL_REPO}/.venv/bin/python",
                "repo": "${oc.env:DECBENCH_RL_REPO}",
                "artifact_dir": "${oc.env:DECBENCH_RL_RUN}/episodes",
                "episode_timeout": 900,
            }
        ]
        (staging / "agent.yaml").write_text(json.dumps(agent_config, indent=2) + "\n")
        provenance = {
            "files": {p.name: digest(p) for p in staging.iterdir() if p.is_file()},
            "adapter": {
                str(p.relative_to(REPO)): digest(p)
                for p in sorted((REPO / "decbench/rl").glob("*.py"))
            },
            "scorer": {
                name: digest(REPO / name)
                for name in (
                    "decbench/metrics/byte_match.py",
                    "decbench/metrics/fixup.py",
                    "decbench/utils/binfmt.py",
                    "decbench/utils/blinding.py",
                    "decbench/decompilers/llm_dec.py",
                    "decbench/decompilers/agent_ida.py",
                )
            },
        }
        (staging / "dataset.lock.json").write_text(json.dumps(provenance, indent=2) + "\n")
        staging.rename(output)
    print(f"Prepared {len(frozen)} tasks in {output}; smoke_only={smoke}")


def digest_task(binary_hash: str, address: int) -> str:
    import hashlib

    return hashlib.sha256(f"{binary_hash}:{address:x}".encode()).hexdigest()[:24]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--smoke", action="store_true")
    source.add_argument("--manifest", type=Path)
    parser.add_argument("--export-python", type=Path, default=REPO / ".tools/verl-env/bin/python")
    parser.add_argument(
        "--heldout-manifest",
        type=Path,
        help="optional benchmark manifest; otherwise use configs/verl/heldout-projects.json",
    )
    args = parser.parse_args()
    if args.heldout_manifest:
        heldout = {
            row["project"] for row in json.loads(args.heldout_manifest.read_text())["functions"]
        }
    else:
        heldout = set(json.loads((REPO / "configs/verl/heldout-projects.json").read_text()))
    with tempfile.TemporaryDirectory(prefix="verl-smoke-source-") as tmp:
        if args.smoke:
            tasks = smoke_inputs(Path(tmp))
        else:
            tasks = json.loads(args.manifest.read_text())["tasks"]
            for row in tasks:
                row["original_binary"] = str(
                    (args.manifest.parent / row["original_binary"]).resolve()
                )
        build(tasks, args.output, args.export_python.resolve(), heldout, smoke=args.smoke)


if __name__ == "__main__":
    main()
