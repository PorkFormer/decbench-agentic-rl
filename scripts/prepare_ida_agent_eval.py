"""Freeze and validate a local ELF pilot before spending model API tokens.

Run with the repository virtualenv: prepare SOURCE_TREE OUTPUT_TREE, then
check OUTPUT_TREE or run OUTPUT_TREE --backend ida|ida-agent@deepseek-flash.
This is a custom pilot, not the published DecBench sample-set.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from elftools.elf.elffile import ELFFile

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from decbench.decompilers.limits import require_resource_scopes  # noqa: E402
from decbench.metrics.type_match import extract_ground_truth_types  # noqa: E402
from decbench.models.project import OptimizationLevel, Project  # noqa: E402
from decbench.pipeline.executor import PipelineConfig, PipelineExecutor  # noqa: E402
from decbench.utils import binfmt  # noqa: E402
from decbench.utils.blinding import validate_stripped_elf  # noqa: E402
from scripts.run_benchmark import _stripped_copy, project_source_functions  # noqa: E402

PROJECTS = ("projects/sailr/bzip2.toml", "projects/cps/chibios.toml")
OPTS = ("O0", "O2")
MODEL = "ida-agent@deepseek-flash"
TOOL_FILES = (
    ".tools/ida-pro-9.3/libida.so",
    ".tools/ida-pro-9.3/libidalib.so",
    ".tools/ida-pro-9.3/plugins/hexx64.so",
    ".tools/ida-pro-9.3/plugins/hexarm.so",
    ".tools/host-gcc-12.3.0/usr/bin/gcc",
    ".tools/host-gcc-12.3.0/usr/bin/strip",
    ".tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc",
    ".tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-strip",
    ".tools/bin/strip",
)
ENV = {
    "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
    "DECBENCH_OPT_LEVELS": ",".join(OPTS),
    "DECBENCH_WORKERS": "1",
    "DECBENCH_METRICS": "ged,type_match,byte_match",
    "DECBENCH_DWARF_ABSTRACT_ORIGIN": "0",
    "DECBENCH_GED_MAX_NODES": "200",
    "DECBENCH_DECOMPILE_TIMEOUT": "3600",
    "DECBENCH_BINARY_MEMORY_LIMIT_GIB": "16",
    "DECBENCH_LLM_SAVE_TRACES": "1",
    "DECBENCH_AGENT_KEEP_SESSION": "1",
}


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def runtime_versions() -> dict[str, str]:
    versions = {"python": sys.version.split()[0]}
    for name in ("claude-agent-sdk", "idapro", "pyjoern", "angr", "pydantic"):
        versions[name] = importlib.metadata.version(name)
    versions["claude"] = subprocess.check_output(["claude", "--version"], text=True).strip()
    return versions


def environment(tree: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("DECBENCH_")}
    env.update(ENV)
    lock_path = tree / "experiment.lock.json"
    if lock_path.exists():
        env.update(json.loads(lock_path.read_text())["environment"])
    env.update(
        IDADIR=str(REPO / ".tools/ida-pro-9.3"),
        HEXRAYS_LICENSE_FILE=str(REPO / ".tools/ida-pro-9.3/idapro.hexlic"),
        JAVA_HOME=str(REPO / ".tools/jdk-17.0.20.1+1-jre"),
        DECBENCH_SAMPLESET_MANIFEST=str(tree / "sample_set_manifest.json"),
        DECBENCH_DECOMPILERS_CONFIG=str(tree / "decompilers.toml"),
        DECBENCH_IDA_AGENT_CONFIG_DIR=str(tree / "agent-config"),
        DECBENCH_CACHE_DIR=str(tree / "cache"),
        PYTHONPATH=str(REPO),
    )
    env["PATH"] = (
        os.pathsep.join(
            str(REPO / p)
            for p in (
                ".venv/bin",
                ".tools/bin",
                ".tools/host-gcc-12.3.0/usr/bin",
                ".tools/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/bin",
            )
        )
        + os.pathsep
        + os.environ.get("PATH", "")
    )
    return env


def candidates(binary: Path, stems: set[str]) -> list[dict[str, Any]]:
    owners: dict[int, str] = {}
    functions = project_source_functions(binary, stems, stem_out=owners)
    counts = Counter(functions.values())
    types = extract_ground_truth_types(binary)
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        if symbols is None:
            raise ValueError(f"no symbol sizes in ground truth: {binary}")
        sizes = {
            int(s["st_value"]) & ~1 if elf["e_machine"] == "EM_ARM" else int(s["st_value"]): int(
                s["st_size"]
            )
            for s in symbols.iter_symbols()
            if s["st_info"]["type"] == "STT_FUNC"
        }
    info = binfmt.detect(binary)
    assert info is not None
    rows = []
    for address, name in functions.items():
        size = sizes.get(address & ~1 if info.arch == "arm" else address, 0)
        if counts[name] != 1 or not 32 <= size <= 4096 or not types.get(name):
            continue
        rows.append(
            {
                "function": name,
                "address": address,
                "size_bytes": size,
                "source_stem": owners[address],
                "gt_variables": len(types[name]),
            }
        )
    return sorted(rows, key=lambda row: (row["size_bytes"], row["address"]))


def select(rows: list[dict[str, Any]], count: int, seed: int) -> list[dict[str, Any]]:
    if len(rows) < count:
        raise ValueError(f"only {len(rows)} eligible functions for {count} requested")
    rng = random.Random(seed)
    chosen = []
    for index in range(count):
        bucket = rows[index * len(rows) // count : (index + 1) * len(rows) // count]
        chosen.append(rng.choice(bucket))
    return chosen


def prepare(
    source: Path,
    tree: Path,
    count: int,
    seed: int,
    *,
    model: str = "deepseek-flash",
    base_url: str = ENV["ANTHROPIC_BASE_URL"],
    reference_tree: Path | None = None,
    deployment: Path | None = None,
    disable_session_title: bool = False,
) -> None:
    if tree.exists():
        raise ValueError(f"refusing to overwrite existing experiment: {tree}")
    if count < 1:
        raise ValueError("per-binary count must be positive")
    tree.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prepare-pilot-", dir=tree.parent) as tmp:
        staged = Path(tmp) / "tree"
        _prepare(
            source,
            staged,
            count,
            seed,
            model,
            base_url,
            reference_tree,
            deployment,
            disable_session_title,
        )
        staged.replace(tree)
    print(f"Experiment ready: {tree}")


def _prepare(
    source: Path,
    tree: Path,
    count: int,
    seed: int,
    model: str,
    base_url: str,
    reference_tree: Path | None,
    deployment: Path | None,
    disable_session_title: bool = False,
) -> None:
    tree.mkdir(parents=True)
    os.environ.update(environment(tree))
    manifest: list[dict[str, str]] = []
    inventory = []
    frozen: dict[str, str] = {}
    reference = None
    if reference_tree is not None:
        reference = json.loads((reference_tree / "experiment.lock.json").read_text())
        if count != reference["per_binary"] or seed != reference["seed"]:
            raise ValueError("reference sample count or seed differs")
        for relative, expected in reference["files"].items():
            if ("/compiled/" in relative or "/stripped/" in relative) and digest(
                reference_tree / relative
            ) != expected:
                raise ValueError(f"reference input changed: {relative}")
    cfg = PipelineConfig(optimization_levels=[OptimizationLevel(o) for o in OPTS])
    for spec in PROJECTS:
        project = Project.from_toml(REPO / spec)
        PipelineExecutor(cfg)._discover_existing_binaries([project], source)
        for opt_name in OPTS:
            opt = OptimizationLevel(opt_name)
            binaries = project.compiled_binaries.get(opt, [])
            sources = project.preprocessed_sources.get(opt, {})
            if not binaries or not sources:
                raise ValueError(f"missing binaries or .i files: {project.name}/{opt_name}")
            compiled = tree / opt_name / project.name / "compiled"
            compiled.mkdir(parents=True)
            for path in sources.values():
                shutil.copy2(path, compiled / path.name)
            for binary in binaries:
                rows = candidates(binary, set(sources))
                selected = select(rows, count, seed)
                if reference is not None:
                    prior = next(
                        b
                        for b in reference["inventory"]
                        if (b["project"], b["opt"], b["binary"])
                        == (project.name, opt_name, binary.stem)
                    )
                    if selected != prior["targets"]:
                        raise ValueError("reference target addresses or selection changed")
                    if digest(binary) != reference["files"][prior["path"]]:
                        raise ValueError("reference binary differs from source")
                    selected = prior["targets"]
                copied = compiled / binary.name
                shutil.copy2(binary, copied)
                stripped = _stripped_copy(copied, compiled.parent / "stripped")
                info = binfmt.detect(copied)
                assert info is not None
                inventory.append(
                    {
                        "project": project.name,
                        "opt": opt_name,
                        "binary": binary.stem,
                        "path": str(copied.relative_to(tree)),
                        "arch": info.arch,
                        "stripped": str(stripped.relative_to(tree)),
                        "eligible_count": len(rows),
                        "targets": selected,
                    }
                )
                for row in selected:
                    manifest.append(
                        {
                            "project": project.name,
                            "opt": opt_name,
                            "binary": binary.stem,
                            "function": row["function"],
                        }
                    )
    write_json(
        tree / "sample_set_manifest.json",
        {"method": "local-pilot-size-stratified", "k": 0, "threshold": 0, "functions": manifest},
    )
    if reference_tree is not None:
        reference_manifest = reference_tree / "sample_set_manifest.json"
        if json.loads(reference_manifest.read_text())["functions"] != manifest:
            raise ValueError("reference manifest differs from selected targets")
        shutil.copy2(reference_manifest, tree / "sample_set_manifest.json")
        assert reference is not None
        for relative, expected in reference["files"].items():
            if "/compiled/" in relative and digest(tree / relative) != expected:
                raise ValueError(f"copied reference input differs: {relative}")
    local = urlparse(base_url).hostname in ("127.0.0.1", "localhost", "::1")
    if model != "deepseek-flash" and not local:
        raise ValueError("custom pilot models require a loopback endpoint")
    if local and deployment is None:
        raise ValueError("local models require --deployment provenance")
    deployment_data = json.loads(deployment.read_text()) if deployment else None
    mode = deployment_data.get("thinking", "disabled") if deployment_data else "disabled"
    if mode not in ("enabled", "disabled"):
        raise ValueError("invalid deployment thinking mode")
    sdk_thinking = "adaptive" if mode == "enabled" else "disabled"
    (tree / "decompilers.toml").write_text(
        f"[ida-agent.versions.{json.dumps(model)}]\n"
        f"max_funcs = {count}\nmax_turns = 40\ntimeout = 300\n"
        'compile_check = "1"\ncompile_retries = 1\npath_guard = "1"\n'
        + (f'thinking = "{sdk_thinking}"\n' if local else 'effort = "high"\n')
        + ('disable_title = "1"\n' if disable_session_title else "")
    )
    if deployment_data:
        if deployment_data["served_model_name"] != model:
            raise ValueError("deployment model name differs")
        shutil.copy2(deployment, tree / "deployment.json")
    for path in sorted(tree.rglob("*")):
        if path.is_file():
            frozen[str(path.relative_to(tree))] = digest(path)
    code = (
        sorted((REPO / "decbench").rglob("*.py"))
        + [
            REPO / "scripts" / name
            for name in ("run_benchmark.py", "decompile_one.py", "prepare_ida_agent_eval.py")
        ]
        + [REPO / spec for spec in PROJECTS]
    )
    lock = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": f"ida-agent@{model}",
        "model_version_at_preparation": model if local else "DeepSeek-V4.1-Flash",
        "model_reference": (
            deployment_data["model_path"]
            if deployment_data
            else "https://api-docs.deepseek.com/quick_start/pricing"
        ),
        "seed": seed,
        "per_binary": count,
        "target_count": len(manifest),
        "selection": "unique DWARF source names, 32..4096 code bytes, nonempty type ground truth; "
        "one seeded draw from each equal-population size bucket per binary",
        "scope": "custom bzip2/ChibiOS pilot; not the published 250-function sample-set",
        "thinking": mode if local else "SDK/server default; effort explicitly high",
        "auxiliary_session_titles": "disabled" if disable_session_title else "SDK default",
        "environment": {**ENV, "ANTHROPIC_BASE_URL": base_url},
        "versions": runtime_versions(),
        "inventory": inventory,
        "files": frozen,
        "code": {str(p.relative_to(REPO)): digest(p) for p in code},
        "tools": {p: digest(REPO / p) for p in TOOL_FILES},
        "reference": (
            {
                "tree": str(reference_tree),
                "lock_sha256": digest(reference_tree / "experiment.lock.json"),
                "manifest_sha256": digest(reference_tree / "sample_set_manifest.json"),
            }
            if reference_tree
            else None
        ),
        "deployment": deployment_data,
    }
    write_json(tree / "experiment.lock.json", lock)
    print(f"Frozen {len(manifest)} functions across {len(inventory)} binaries: {tree}")


def check(tree: Path, resources: bool = False) -> dict[str, Any]:
    lock = json.loads((tree / "experiment.lock.json").read_text())
    for base, entries in ((tree, lock["files"]), (REPO, lock["code"]), (REPO, lock["tools"])):
        for relative, expected in entries.items():
            if digest(base / relative) != expected:
                raise ValueError(f"frozen input/config/code changed: {base / relative}")
    if runtime_versions() != lock["versions"]:
        raise ValueError("runtime dependency versions changed since preparation")
    for binary in lock["inventory"]:
        validate_stripped_elf(tree / binary["stripped"])
    if deployment := lock.get("deployment"):
        for path, expected in deployment["files"].items():
            if digest(Path(path)) != expected:
                raise ValueError(f"deployment file changed: {path}")
        versions = json.loads(
            subprocess.check_output(
                [
                    deployment["command"][0],
                    "-c",
                    "import importlib.metadata as m,json; "
                    "print(json.dumps({d.metadata['Name']: d.version for d in m.distributions()}))",
                ],
                text=True,
            )
        )
        if versions != deployment["versions"]:
            raise ValueError("model serving dependencies changed since preparation")
    if resources:
        require_resource_scopes()
    print(f"Preflight OK: {lock['target_count']} frozen targets; no API request made")
    return lock


def audit(tree: Path, backend: str) -> dict[str, Any]:
    manifest = json.loads((tree / "sample_set_manifest.json").read_text())["functions"]
    expected = {(r["project"], r["opt"], r["binary"], r["function"]) for r in manifest}
    data = json.loads((tree / "function_results.json").read_text())
    found = {}
    for group in data["groups"]:
        for row in group["functions"]:
            key = (group["project"], group["opt_level"], group["binary"], row["function"])
            if key in expected:
                found[key] = row
    absent = sorted(expected - found.keys())
    failed = sorted(k for k, v in found.items() if not v.get("decompiled", {}).get(backend))
    missing = {
        metric: sorted(
            k
            for k in expected
            if found.get(k, {}).get("values", {}).get(backend, {}).get(metric) is None
        )
        for metric in ("ged", "type_match", "byte_match")
    }
    result = {
        "backend": backend,
        "expected": len(expected),
        "rows": len(found),
        "decompiled": len(found) - len(failed),
        "absent_rows": absent,
        "failed_or_unattempted": failed,
        "missing_metric_values": missing,
    }
    write_json(tree / f"coverage-{backend.replace('@', '-')}.json", result)
    print(json.dumps(result, indent=2))
    if absent:
        raise ValueError("result rows missing from the frozen denominator")
    return result


def run(tree: Path, backend: str, key_file: Path) -> None:
    env = environment(tree)
    os.environ.update(env)
    lock = check(tree, resources=True)
    if backend not in ("ida", lock["model"]):
        raise ValueError("backend differs from frozen experiment")
    env["DECBENCH_DECOMPILERS"] = backend
    if backend == lock["model"]:
        local = urlparse(env["ANTHROPIC_BASE_URL"]).hostname in ("127.0.0.1", "localhost", "::1")
        env["ANTHROPIC_AUTH_TOKEN"] = (
            "local-no-key" if local else key_file.expanduser().read_text().strip()
        )
        if not env["ANTHROPIC_AUTH_TOKEN"]:
            raise ValueError("empty DeepSeek key file")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    command = [sys.executable, "scripts/run_benchmark.py", str(tree), "--", "bzip2", "chibios"]
    with (tree / f"run-{backend.replace('@', '-')}-{stamp}.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=REPO, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
            log.flush()
        if process.wait():
            raise RuntimeError(f"benchmark driver exited {process.returncode}")
    audit(tree, backend)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prep = subs.add_parser("prepare")
    prep.add_argument("source", type=Path)
    prep.add_argument("tree", type=Path)
    prep.add_argument("--per-binary", type=int, default=4)
    prep.add_argument("--seed", type=int, default=1337)
    prep.add_argument("--model", default="deepseek-flash")
    prep.add_argument("--base-url", default=ENV["ANTHROPIC_BASE_URL"])
    prep.add_argument("--reference-tree", type=Path)
    prep.add_argument("--deployment", type=Path)
    prep.add_argument("--disable-session-title", action="store_true")
    for name in ("check", "run", "audit"):
        sub = subs.add_parser(name)
        sub.add_argument("tree", type=Path)
        if name == "check":
            sub.add_argument("--resources", action="store_true")
        else:
            sub.add_argument("--backend", required=True)
        if name == "run":
            sub.add_argument("--key-file", type=Path, default=Path("~/.key/deepseek"))
    args = parser.parse_args()
    os.chdir(REPO)
    tree = args.tree.resolve()
    if args.command == "prepare":
        prepare(
            args.source.resolve(),
            tree,
            args.per_binary,
            args.seed,
            model=args.model,
            base_url=args.base_url,
            reference_tree=args.reference_tree.resolve() if args.reference_tree else None,
            deployment=args.deployment.resolve() if args.deployment else None,
            disable_session_title=args.disable_session_title,
        )
    elif args.command == "check":
        check(tree, resources=args.resources)
    elif args.command == "audit":
        audit(tree, args.backend)
    else:
        run(tree, args.backend, args.key_file)


if __name__ == "__main__":
    main()
