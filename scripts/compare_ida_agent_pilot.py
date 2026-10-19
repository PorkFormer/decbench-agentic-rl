"""Compare frozen local pilot results without modifying either score data file."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import math
import re
import statistics
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

METRICS = ("ged", "type_match", "byte_match")
Key = tuple[str, str, str, str]


def rows(tree: Path) -> dict[Key, dict[str, Any]]:
    data = json.loads((tree / "function_results.json").read_text())
    return {
        (g["project"], g["opt_level"], g["binary"], r["function"]): r
        for g in data["groups"]
        for r in g["functions"]
    }


def aggregate(records: list[dict[str, Any]], backend: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "expected": len(records),
        "decompiled": sum(bool(r.get("decompiled", {}).get(backend)) for r in records),
        "compiles": sum(bool(r.get("compiles", {}).get(backend)) for r in records),
        "type_evidence": dict(
            Counter(
                r.get("metric_evidence", {}).get(backend, {}).get("type_match", "missing")
                for r in records
            )
        ),
    }
    result["union_perfect"] = sum(
        any(r.get("perfects", {}).get(backend, {}).get(m, False) for m in METRICS) for r in records
    )
    result["compiles_unknown"] = sum(
        bool(r.get("decompiled", {}).get(backend)) and backend not in r.get("compiles", {})
        for r in records
    )
    if result["compiles_unknown"]:
        result["compiles"] = None
    for metric in METRICS:
        values = [r.get("values", {}).get(backend, {}).get(metric) for r in records]
        valid = [float(v) for v in values if v is not None and math.isfinite(v)]
        result[metric] = {
            "valid": len(valid),
            "missing": len(records) - len(valid),
            "mean": statistics.mean(valid) if valid else None,
            "median": statistics.median(valid) if valid else None,
            "perfect": sum(
                bool(r.get("perfects", {}).get(backend, {}).get(metric)) for r in records
            ),
        }
    return result


def trace_audit(tree: Path, backend: str) -> dict[str, Any]:
    totals: Counter[str] = Counter()
    tokens: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    for path in sorted(tree.glob("O*/*/decompiled/traces/*.md")):
        body = path.read_text()
        if not body.startswith(f"# {backend} trace"):
            continue
        totals["traces"] += 1
        totals["timeout_events"] += body.count("AGENT TIMEOUT")
        totals["agent_errors"] += body.count("AGENT ERROR:")
        totals["turn_limit_events"] += body.count("Reached maximum number of turns")
        totals["compile_revision_events"] += body.count("revision round ")
        totals["failed_traces"] += int("- status: FAILED" in body)
        elapsed = re.search(r"^- elapsed: ([\d.]+)s", body, re.M)
        if elapsed:
            totals["agent_seconds_rounded"] += float(elapsed[1])
        for field, counter in (("tokens", tokens), ("tool_calls", tools)):
            match = re.search(rf"^- {field}: (.+)$", body, re.M)
            if match and match[1] != "None":
                counter.update(ast.literal_eval(match[1]))
    return {**totals, "tokens": dict(tokens), "tool_calls": dict(tools)}


def syntax_audit(tree: Path, backend: str) -> dict[str, Any]:
    results = []
    compiler = Path(__file__).resolve().parent.parent / ".tools/host-gcc-12.3.0/usr/bin/gcc"
    with tempfile.TemporaryDirectory(prefix="pilot-syntax-") as temporary:
        source = Path(temporary) / "function.c"
        for artifact in sorted(tree.glob(f"O*/*/decompiled/{backend}_*.c")):
            parts = re.split(
                r"^// Function: (\S+) @ 0x[0-9a-fA-F]+\n", artifact.read_text(), flags=re.M
            )
            for index in range(1, len(parts), 2):
                source.write_text(parts[index + 1])
                process = subprocess.run(
                    [str(compiler), "-fsyntax-only", "-std=gnu11", str(source)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                results.append(
                    {
                        "artifact": str(artifact.relative_to(tree)),
                        "function": parts[index],
                        "passed": process.returncode == 0,
                        "diagnostic": process.stderr.replace(str(source), "function.c")[:500],
                    }
                )
    return {
        "compiler": str(compiler),
        "checked": len(results),
        "passed": sum(r["passed"] for r in results),
        "functions": results,
    }


def session_audit(tree: Path, model: str) -> dict[str, Any]:
    responses: dict[str, dict[str, int]] = {}
    thinking_blocks = 0
    files = list((tree / "agent-config/projects").glob("*/*.jsonl"))
    for path in files:
        for line in path.read_text().splitlines():
            event = json.loads(line)
            message = event.get("message", {})
            if event.get("type") != "assistant" or message.get("model") != model:
                continue
            identifier = message.get("id")
            if not identifier:
                continue
            thinking_blocks += sum(
                b.get("type") == "thinking"
                for b in message.get("content", [])
                if isinstance(b, dict)
            )
            usage = message.get("usage", {})
            record = responses.setdefault(identifier, {})
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_read_input_tokens",
                "cache_creation_input_tokens",
            ):
                record[key] = max(record.get(key, 0), int(usage.get(key, 0)))
            record["thinking_tokens"] = max(
                record.get("thinking_tokens", 0),
                int(usage.get("output_tokens_details", {}).get("thinking_tokens", 0)),
            )
    return {
        "session_files": len(files),
        "unique_model_responses": len(responses),
        "thinking_blocks": thinking_blocks,
        "usage": {
            key: sum(r.get(key, 0) for r in responses.values())
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_read_input_tokens",
                "cache_creation_input_tokens",
                "thinking_tokens",
            )
        },
        "basis": "deduplicated recorded assistant response IDs; "
        "excludes unrecorded auxiliary or interrupted responses",
    }


def run_timing(tree: Path, backend: str) -> list[dict[str, Any]]:
    result = []
    for path in sorted(tree.glob(f"run-{backend.replace('@', '-')}-*.log")):
        start = datetime.strptime(path.stem.rsplit("-", 1)[1], "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc
        )
        end = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        result.append(
            {
                "log": path.name,
                "start_utc": start.isoformat(),
                "last_output_utc": end.isoformat(),
                "seconds": (end - start).total_seconds(),
                "basis": "approximate driver wall time from log start stamp to last write",
            }
        )
    return result


def compare(tree: Path, reference: Path, additional: list[Path] | None = None) -> dict[str, Any]:
    manifest = json.loads((tree / "sample_set_manifest.json").read_text())["functions"]
    if manifest != json.loads((reference / "sample_set_manifest.json").read_text())["functions"]:
        raise ValueError("comparison requires identical frozen manifests")
    keys = [(r["project"], r["opt"], r["binary"], r["function"]) for r in manifest]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate frozen targets")
    lock = json.loads((tree / "experiment.lock.json").read_text())
    backend = lock["model"]
    old = rows(reference)
    current = rows(tree)
    columns = [(backend, current)]
    for extra in additional or []:
        if json.loads((extra / "sample_set_manifest.json").read_text())["functions"] != manifest:
            raise ValueError("additional comparison requires identical frozen manifests")
        extra_backend = json.loads((extra / "experiment.lock.json").read_text())["model"]
        if extra_backend in {b for b, _ in columns} | {"ida-agent@deepseek-flash", "ida"}:
            raise ValueError("duplicate comparison backend")
        columns.append((extra_backend, rows(extra)))
    columns += [("ida-agent@deepseek-flash", old), ("ida", old)]
    overall = {b: aggregate([data.get(k, {}) for k in keys], b) for b, data in columns}
    groups = sorted({k[:2] for k in keys})
    grouped = {
        f"{p}/{o}": {
            b: aggregate([data.get(k, {}) for k in keys if k[:2] == (p, o)], b)
            for b, data in columns
        }
        for p, o in groups
    }
    summary = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reporter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "24-function bzip2/ChibiOS tool-assisted pilot",
        "configuration": {
            "model": backend,
            "thinking": lock.get("thinking"),
            "auxiliary_session_titles": lock.get("auxiliary_session_titles", "SDK default"),
            "sampling": (lock.get("deployment") or {}).get("sampling", {}),
        },
        "overall": overall,
        "by_project_opt": grouped,
        "trace_audit": trace_audit(tree, backend),
        "independent_host_syntax_check": syntax_audit(tree, backend),
        "session_audit": session_audit(tree, backend.split("@", 1)[1]),
        "mode_verification": (
            json.loads((tree / "mode-verification.json").read_text())
            if (tree / "mode-verification.json").exists()
            else {"status": "unverified"}
        ),
        "run_timing": run_timing(tree, backend),
        "failure_label_repair": (
            json.loads((tree / "failure-label-repair-provenance.json").read_text())
            if (tree / "failure-label-repair-provenance.json").exists()
            else None
        ),
        "absent_rows": [k for k in keys if k not in current],
        "score_sources": {
            str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [r / "function_results.json" for r in [tree, reference, *(additional or [])]]
        },
    }
    (tree / "evaluation-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (tree / "evaluation-functions.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "project",
                "opt",
                "binary",
                "function",
                "backend",
                "decompiled",
                "compiles",
                *METRICS,
                "type_evidence",
            ]
        )
        for key in keys:
            for b, data in columns:
                row = data.get(key, {})
                writer.writerow(
                    [
                        *key,
                        b,
                        bool(row.get("decompiled", {}).get(b)),
                        row.get("compiles", {}).get(b),
                        *(row.get("values", {}).get(b, {}).get(m) for m in METRICS),
                        row.get("metric_evidence", {}).get(b, {}).get("type_match"),
                    ]
                )
    lines = [
        f"# {backend.split('@', 1)[-1]} 四卡本地反编译评测",
        "",
        "固定样本：bzip2、ChibiOS × O0/O2，6 个 binary、24 个函数。"
        "采用与 DeepSeek 实验相同的匿名输入、IDA 工具、提示词和轮数/时间预算。",
        "",
        "Qwen 使用 GPU 0–3、四卡张量并行、BF16。思考模式审计："
        + summary["mode_verification"].get("description", "未验证，不应据配置推断实际模式。"),
        "",
        "本轮采样参数："
        + "、".join(f"`{k}={v}`" for k, v in summary["configuration"]["sampling"].items()),
        "自动会话标题：" + summary["configuration"]["auxiliary_session_titles"],
        "",
        "| 指标 | "
        + " | ".join(
            "原生 IDA" if b == "ida" else b.split("@", 1)[-1] + " + IDA" for b, _ in columns
        )
        + " |",
        "| --- | " + " | ".join("---:" for _ in columns) + " |",
    ]
    for field, label in (
        ("decompiled", "产生反编译输出"),
        ("compiles", "评分流程可编译"),
        ("union_perfect", "至少一项指标满分"),
    ):
        lines.append(
            f"| {label} | "
            + " | ".join(
                "未完整记录" if overall[b][field] is None else f"{overall[b][field]}/{len(keys)}"
                for b, _ in columns
            )
            + " |"
        )
    for metric in METRICS:
        for field, label in (("perfect", "满分数"), ("mean", "均值")):
            cells = []
            for b, _ in columns:
                score = overall[b][metric]
                if field == "perfect":
                    cells.append(f"{score[field]}/{len(keys)}")
                else:
                    value = "缺失" if score[field] is None else f"{score[field]:.4f}"
                    cells.append(f"{value}（n={score['valid']}）")
            lines.append(f"| {metric} {label} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "GED 越低越好；type_match、byte_match 越高越好。缺失不填零，均值标注有效分母。",
        "byte_match 使用 ARM/Thumb 修正后的 v8；DeepSeek/IDA 使用旧实验修正后的结果，"
        "未重新调用 DeepSeek。模型类型证据为 fallback，原生 IDA 使用 native 地址证据。",
        "",
        f"Qwen 独立 host GCC 语法复核："
        f"{summary['independent_host_syntax_check']['passed']}/"
        f"{summary['independent_host_syntax_check']['checked']} 份输出通过；"
        "没有生成输出的目标不计入语法检查分母。",
        "",
        "## 运行诊断",
        "",
        "评测驱动墙钟时间（日志近似，排除环境安装和模型冷启动）：",
        "```json",
        json.dumps(summary["run_timing"], ensure_ascii=False, indent=2),
        "```",
        "",
        "```json",
        json.dumps(summary["trace_audit"], ensure_ascii=False, indent=2),
        "```",
        "工具调用计数包含模型提出但不存在或被拒绝的调用，不等于实际执行次数。",
        "",
        "会话级 token 核对（按响应 ID 去重；不含未记录的辅助或中断请求）：",
        "```json",
        json.dumps(summary["session_audit"], ensure_ascii=False, indent=2),
        "```",
        "兼容接口的 thinking_tokens 可能为 0；思考模式需结合模板、实际请求和思考块审计判断。",
        "",
        "本轮所有正式失败保留，不择优重试。Agent 秒数从逐函数 trace 汇总，"
        "不含模型部署冷启动；SDK 美元估价不作为本地 GPU 成本。",
        "",
        "评分流程可编译包含确定性修补，并非语义等价证明。"
        "该小样本不代表完整语料或通用模型排名；未发布网站或数据集。",
        "",
        "产物：[逐函数 CSV](evaluation-functions.csv)、"
        "[机器可读摘要](evaluation-summary.json)、[交互报告](report.html)。",
        "",
    ]
    if excluded := summary["mode_verification"].get("excluded_run"):
        reason = summary["mode_verification"].get("excluded_reason", "模式配置未生效")
        lines += [
            f"因{reason}的首轮 `{excluded}` 整轮排除，仅作诊断保留；"
            "修正后完整重跑 24 个目标，本报告不混用两轮输出或分数。",
            "",
        ]
    if summary["failure_label_repair"]:
        lines += [
            "失败记录已按冻结地址离线回填源函数名，防止匿名失败行被过滤而缩小分母。"
            "修复不改变成功输出或指标值，不重新调用模型；原始 checkpoint 和首轮报告"
            "保存在 `first-pass-failure-labels/`，原实验锁保持不变。",
            "",
        ]
    (tree / "evaluation-summary.zh.md").write_text("\n".join(lines))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--additional", type=Path, action="append", default=[])
    args = parser.parse_args()
    print(
        json.dumps(
            compare(
                args.tree.resolve(),
                args.reference.resolve(),
                [p.resolve() for p in args.additional],
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
