"""Restore frozen pilot failure names after a run, preserving original checkpoints."""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.run_benchmark import _relabel_to_dwarf  # noqa: E402


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repair(tree: Path) -> dict[str, Any]:
    lock = json.loads((tree / "experiment.lock.json").read_text())
    backend = lock["model"]
    inventory = {(b["project"], b["opt"], b["binary"]): b for b in lock["inventory"]}
    staged: dict[Path, bytes] = {}
    changes = []
    for path in sorted((tree / "checkpoints").glob("*.pkl")):
        checkpoint = pickle.loads(path.read_bytes())
        original_scores = pickle.dumps(checkpoint.get("evaluate"))
        changed = False
        for opt, binaries in checkpoint["decompile"].items():
            for binary, backends in binaries.items():
                if backend not in backends:
                    continue
                item = inventory[(path.stem, opt.value, binary)]
                if digest(tree / item["path"]) != lock["files"][item["path"]]:
                    raise ValueError("frozen binary changed before failure-label repair")
                result = backends[backend]
                addresses = {t["address"]: t["function"] for t in item["targets"]}
                expected = set(addresses.values())
                if not set(result.functions) <= expected:
                    raise ValueError(f"unexpected successful targets in {path}/{binary}")
                old_outputs = {k: v.model_dump() for k, v in result.functions.items()}
                old_failures = list(result.decompiler.failed_functions)
                _relabel_to_dwarf(result, addresses, tree / item["path"])
                if {k: v.model_dump() for k, v in result.functions.items()} != old_outputs:
                    raise ValueError("failure repair must not change successful code or addresses")
                failures = result.decompiler.failed_functions
                if failures == ["all"]:
                    failures = sorted(expected - result.functions.keys())
                if not set(failures) <= expected:
                    raise ValueError(f"unresolved failures: {failures}")
                failures = sorted(set(failures) | (expected - result.functions.keys()))
                result.decompiler.failed_functions = failures
                if old_failures != failures:
                    changed = True
                    changes.append(
                        {
                            "project": path.stem,
                            "opt": opt.value,
                            "binary": binary,
                            "before": old_failures,
                            "after": failures,
                        }
                    )
        if changed:
            if pickle.dumps(checkpoint.get("evaluate")) != original_scores:
                raise ValueError("failure repair must not change metric results")
            staged[path] = pickle.dumps(checkpoint)
    if not staged:
        return {"changes": [], "model_calls": 0}
    archive = tree / "first-pass-failure-labels"
    archive.mkdir(exist_ok=False)
    (archive / "checkpoints").mkdir()
    before = {}
    for path in staged:
        shutil.copy2(path, archive / "checkpoints" / path.name)
        before[str(path.relative_to(tree))] = digest(path)
    for path in tree.iterdir():
        if path.is_file() and (
            path.name
            in (
                "function_results.json",
                "scoreboard.toml",
                "report.html",
            )
            or path.name.startswith("coverage-")
        ):
            shutil.copy2(path, archive / path.name)
    for path, data in staged.items():
        temporary = path.with_suffix(".repair.tmp")
        temporary.write_bytes(data)
        temporary.replace(path)
    provenance = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reason": "Anonymous failed-function names were filtered out of source-named rows.",
        "changes": changes,
        "model_calls": 0,
        "metric_values_changed": False,
        "original_lock_preserved": True,
        "before_sha256": before,
        "after_sha256": {str(p.relative_to(tree)): digest(p) for p in staged},
        "repair_script_sha256": digest(Path(__file__)),
        "driver_sha256_at_run": lock["code"]["scripts/run_benchmark.py"],
        "driver_sha256_after_repair": digest(REPO / "scripts/run_benchmark.py"),
    }
    (tree / "failure-label-repair-provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n"
    )
    return provenance


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    args = parser.parse_args()
    print(json.dumps(repair(args.tree.resolve()), indent=2))


if __name__ == "__main__":
    main()
