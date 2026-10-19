"""Frozen private task registry and public rollout inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

REWARD_VERSION = "byte-match-v8-proxy-v1"
ENVIRONMENT_VERSION = "ida-mcp-1.1.0"
VERL_REVISION = "7aed6b230776f963fa09509c10d9c3a767d1102c"
SYSTEM_PROMPT = """You are reconstructing one C function using IDA analysis tools.
Start from Hex-Rays pseudocode and audit it against disassembly. Inspect references
and raw bytes as needed. Addresses may be ELF hex addresses or names known to IDA.
Use offset to continue paginated disassembly or references. Use force=true only
after decompilation or disassembly without force failed because IDA had no function;
this creates a function only in the current episode's temporary IDA database.
Write the reconstructed function and its necessary declarations to decompiled.c.
Use the anonymous target function name from the task. Preserve the binary's behavior.
Read, Write, and Edit operate only on decompiled.c. Write/Edit return a compiler check;
fix reported errors. There is no shell. Finish with a short final response after writing
your answer. Only the file is graded; your final response is not the deliverable.
"""


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def load_task(registry: Path, task_id: str) -> dict[str, Any]:
    data = json.loads(registry.read_text())
    if data.get("schema_version") != 1 or data.get("reward_version") != REWARD_VERSION:
        raise ValueError("unsupported task registry or reward version")
    if data.get("environment_version") != ENVIRONMENT_VERSION:
        raise ValueError("task environment changed; prepare a new frozen dataset")
    rows = [row for row in data["tasks"] if row["task_id"] == task_id]
    if len(rows) != 1:
        raise ValueError("task ID must identify exactly one frozen task")
    task = rows[0]
    if task.get("is_malware") is not False:
        raise ValueError("this training adapter accepts explicitly non-malware tasks only")
    for key in ("original_binary", "stripped_binary"):
        path = (registry.parent / task[key]).resolve()
        if digest(path) != task[f"{key}_sha256"]:
            raise ValueError(f"frozen {key} changed")
        task[key] = str(path)
    return task


def public_row(task: dict[str, Any], index: int) -> dict[str, Any]:
    address = int(task["address"])
    return {
        "data_source": "decbench/ida-byte-proxy",
        "agent_name": "decbench_ida",
        "prompt": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Recover sub_{address:x} at ELF virtual address 0x{address:x} "
                    "in target.bin. Write your C to decompiled.c."
                ),
            },
        ],
        "ability": "decompilation",
        "reward_model": {"style": "rule", "ground_truth": ""},
        "extra_info": {
            "task_id": task["task_id"],
            "split": task["split"],
            "index": index,
            "environment_version": ENVIRONMENT_VERSION,
        },
    }


def tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "mcp__ida__get_metadata",
                "description": "Binary metadata: file name, platform (OS + binary format), "
                "architecture and bitness, image base, function count, "
                "stripped status.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "mcp__ida__decompile_function",
                "description": "Decompile one function. Returns C-like pseudocode.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "addr": {
                            "type": "string",
                            "description": "Hex address (e.g. "
                            '"0x1000") or a name in '
                            "the binary (e.g. "
                            '"sub_1000", '
                            '"dword_1000")',
                        },
                        "force": {
                            "type": "boolean",
                            "description": "Create the function "
                            "at this address if "
                            "IDA has none; use "
                            "only after the same "
                            "call without force "
                            "failed (default "
                            "false)",
                        },
                    },
                    "required": ["addr"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "mcp__ida__disassemble_function",
                "description": "Disassemble one function, one instruction per line as "
                '"address: mnemonic operands". Known names (sub_1000, '
                "dword_1000, aText) replace raw operand values, and a "
                'referenced string\'s content is appended as ; "text". Long '
                "output is capped — pass offset to continue past a truncation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "addr": {
                            "type": "string",
                            "description": "Hex address (e.g. "
                            '"0x1000") or a name in '
                            "the binary (e.g. "
                            '"sub_1000", '
                            '"dword_1000")',
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Number of "
                            "instructions to skip "
                            "from the function "
                            "start",
                        },
                        "length": {
                            "type": "integer",
                            "description": "Max instructions to " "return (default " "4000)",
                        },
                        "force": {
                            "type": "boolean",
                            "description": "Create the function "
                            "at this address if "
                            "IDA has none; use "
                            "only after the same "
                            "call without force "
                            "failed (default "
                            "false)",
                        },
                    },
                    "required": ["addr"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "mcp__ida__get_xrefs_to",
                "description": "All cross-references to one function or global: every call, "
                "jump, data read, and data write that targets it, each with "
                "the referencing address and the function containing that "
                "reference.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "addr": {
                            "type": "string",
                            "description": "Hex address (e.g. "
                            '"0x1000") or a name in '
                            "the binary (e.g. "
                            '"sub_1000", '
                            '"dword_1000")',
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Number of entries to " "skip",
                        },
                    },
                    "required": ["addr"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "mcp__ida__get_xrefs_from",
                "description": "All cross-references from one function: every call, jump, and "
                "global it reads or writes, each with the instruction address "
                "and the target's address and name.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "addr": {
                            "type": "string",
                            "description": "Hex address (e.g. "
                            '"0x1000") or a name in '
                            "the binary (e.g. "
                            '"sub_1000", '
                            '"dword_1000")',
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Number of entries to " "skip",
                        },
                    },
                    "required": ["addr"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "mcp__ida__read_bytes",
                "description": "Read raw bytes at an address as a hexdump: 16 bytes per line, "
                "hex values plus an ASCII column ('.' for non-printable). The "
                "containing segment is named (.bss bytes read as zeros — it "
                "has no file contents).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "addr": {
                            "type": "string",
                            "description": "Hex address (e.g. "
                            '"0x1000") or a name in '
                            "the binary (e.g. "
                            '"sub_1000", '
                            '"dword_1000")',
                        },
                        "size": {
                            "type": "integer",
                            "description": "Number of bytes to " "read (1-512, default " "64)",
                        },
                    },
                    "required": ["addr"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "Read",
                "description": "Read decompiled.c only.",
                "parameters": {
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}},
                    "required": ["file_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "Write",
                "description": "Replace decompiled.c, then receive compiler diagnostics.",
                "parameters": {
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["file_path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "Edit",
                "description": "Replace one unique literal occurrence in decompiled.c; "
                "receive compiler diagnostics.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "old_string": {"type": "string"},
                        "new_string": {"type": "string"},
                    },
                    "required": ["file_path", "old_string", "new_string"],
                },
            },
        },
    ]
