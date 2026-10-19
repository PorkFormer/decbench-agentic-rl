"""AI-agent + IDA Pro backend: Claude Agent SDK driving headless IDA via MCP.

The LLM backends in :mod:`llm_dec` treat the decompiler ban as the point of
the exercise. This backend is the opposite experiment: an AI agent that is
GIVEN a decompiler. For every target function a Claude Agent SDK agent is
handed a stripped binary plus an in-process MCP server (``mcp__ida__*``)
wrapping one headless IDA session (``idalib``, opened once per binary):

* analysis tools — disassembly, Hex-Rays pseudocode, xrefs, raw byte reads;
  optional ``force`` creates functions at recognized code in the temporary IDB

The agent gets no shell: every binary-inspection capability is an
``mcp__ida__*`` tool, and file access is path-guarded to the deliverable.
Its final C answer is wrapped into the same :class:`DecompilationResult`
contract as every other backend, so GED / type_match / byte_match score it
identically.

Model + transport come from the Anthropic-compatible environment
(``ANTHROPIC_BASE_URL`` / ``ANTHROPIC_AUTH_TOKEN``); the default model is
``glm-5.3-flash``. Identity/versioning: run it as ``ida-agent`` or
``ida-agent@<model>`` — the model is the version, exactly like the CLI-agent
backends.

Like the other agent backends this is a sample-set backend: the run driver
gates it with ``DECBENCH_SAMPLESET_MANIFEST`` and the per-binary cap from
:mod:`llm_dec` still applies as a belt-and-suspenders cost bound.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import DecompilerConfig
from decbench.decompilers.llm_dec import (
    _OUTFILE,
    _AgentDecompiler,
    _extract_c,
    _rename_func,
    _sanitize,
)
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import DecompilationResult
from decbench.utils.blinding import validate_stripped_elf

_l = logging.getLogger(__name__)


def _archive_existing(path: Path) -> None:
    """Move an existing trace artifact into ``_archive/`` with an mtime stamp."""
    if path.exists():
        archive = path.parent / "_archive"
        archive.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(path.stat().st_mtime))
        dest = archive / f"{path.stem}.{stamp}{path.suffix}"
        n = 1
        while dest.exists():
            dest = archive / f"{path.stem}.{stamp}-{n}{path.suffix}"
            n += 1
        path.replace(dest)


def _write_incremental(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` without destroying a previous version."""
    _archive_existing(path)
    path.write_text(text)


def _gcc_syntax_errors(code: str, workdir: Path) -> str | None:
    """gcc -fsyntax-only gate: None when it compiles, else the compiler output.

    A missing/busy gcc returns None (the gate never blocks the pipeline, it
    only triggers revision rounds).
    """
    src = workdir / "_compile_check.c"
    src.write_text(code)
    try:
        proc = subprocess.run(
            ["gcc", "-fsyntax-only", "-std=gnu11", str(src)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        return None
    return (proc.stdout + proc.stderr).strip()[:4000] or "gcc failed with no diagnostics"


_DEFAULT_MAX_TURNS = 40
_PAGE_SIZE = 200
_DISASM_MAX_INSNS = 4000
_READ_MAX_BYTES = 512
_BIG_ENDIAN_ARCHES = frozenset({"ppc64", "m68k", "sparc", "mips"})

# CLI behavior knobs the backend owns: blanked with every other CLAUDE*/ANTHROPIC*
# variable, then set to these values (a host Claude Code session cannot leak or
# override them). MAX_RETRIES=10 (user decision, 2026-09-17) fails a misconfigured
# endpoint fast instead of the historical host-inherited 100-retry ~40min hang;
# the rest match what every recorded run inherited from the host session. The
# auto-compact window alone is overridable per run (``compact_window`` option /
# ``DECBENCH_{IDA,ISCG}_AGENT_COMPACT_WINDOW``); unset keeps the historical value.
# The CLI clamps that window to the context window it assumes for the model (200k
# for one it does not recognise, e.g. deepseek-flash), so a larger window also needs
# the model handed to the CLI as ``<model>[1m]`` (``context_1m`` option /
# ``DECBENCH_{IDA,ISCG}_AGENT_CONTEXT_1M``; the CLI strips the suffix from requests).
_PINNED_CLI_ENV = {
    "CLAUDE_CODE_ATTRIBUTION_HEADER": "0",
    "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "140000",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "128000",
    "CLAUDE_CODE_MAX_RETRIES": "10",
    "API_TIMEOUT_MS": "3000000",
}
# The only CLAUDE*/ANTHROPIC* variables passed through from the launch env
# (endpoint selection + auth; ANTHROPIC_API_KEY is deliberately NOT here).
_AGENT_ENV_KEEP = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS")

# The CLI's built-in toolset. The agent gets only the slice it needs (file
# I/O for the deliverable); the rest is removed from the offered set via
# `disallowed_tools`, and the permission callback is the hard backstop, so a
# CLI-version tool rename cannot leak a tool through.
_BUILTIN_TOOLS = (
    "Agent",
    "Bash",
    "CronCreate",
    "CronDelete",
    "CronList",
    "Edit",
    "EnterWorktree",
    "ExitWorktree",
    "Glob",
    "Grep",
    "ListAgents",
    "NotebookEdit",
    "Read",
    "ReportFindings",
    "ScheduleWakeup",
    "SendMessage",
    "Skill",
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "TaskUpdate",
    "WebFetch",
    "WebSearch",
    "Workflow",
    "Write",
)
_AGENT_TOOLS = ("Edit", "Read", "Write")


def _resolve_tool_path(raw: object, workdir: Path) -> Path | None:
    """Resolve a tool-call path argument the way the CLI's cwd would."""
    if not isinstance(raw, str) or not raw:
        return None
    p = Path(raw)
    if not p.is_absolute():
        p = workdir / p
    with contextlib.suppress(OSError):
        p = p.resolve()
    return p


def _within(p: Path, base: Path) -> bool:
    return p == base or base in p.parents


def _is_deliverable(raw: object, workdir: Path) -> bool:
    """True if ``raw`` names the one writable deliverable inside ``workdir``.

    ``decompiled.c``, ``./decompiled.c`` and the absolute workdir path are all
    equivalent; every other target (absolute elsewhere, other file names,
    parent escapes) is not.
    """
    p = _resolve_tool_path(raw, workdir)
    return p is not None and p == workdir.resolve() / _OUTFILE


def _read_scope_ok(raw: object, workdir: Path, config_root: Path) -> bool:
    """True if a read target stays in the workdir or the agent config cache.

    The config cache carries the CLI's persisted large tool outputs, which the
    agent legitimately needs to read back.
    """
    p = _resolve_tool_path(raw, workdir)
    if p is None:
        return True
    return _within(p, workdir.resolve()) or _within(p, config_root.resolve())


AGENT_SYSTEM_PROMPT = """\
You are an expert reverse engineer working with IDA Pro through MCP tools.

You are reconstructing the C source of ONE target function in a stripped
binary. You have full access to a headless IDA session via the `mcp__ida__*`
tools: read disassembly, read Hex-Rays pseudocode, follow cross-references,
and read raw bytes.

WORK METHOD
- Start from the Hex-Rays pseudocode of the target; audit it against the
  disassembly rather than trusting it blindly (wrong types, missed
  struct/array structure, collapsed switches, inlined idioms).
- Use xrefs to understand callees and callers, and to
  recover prototypes of local helper functions. All binary inspection flows
  through the mcp__ida__* tools — there is no shell. Audit the pseudocode
  against the disassembly as the cross-check.
- Produce the C a competent human would have written: real control flow
  (`for`/`while`/`switch`, not jump transliteration), specific types, and
  meaningful names. Keep the behavior exactly faithful to the binary.

OUTPUT CONTRACT
- Write ONLY the reconstructed C for the target function (plus any local
  typedef/struct/enum declarations it needs) to the output file named in the
  task: exactly one top-level definition, no markdown fences, no commentary.
"""


class _IdaSession:
    """One headless idalib database open on a binary, plus tool helpers.

    All addresses crossing the boundary are ELF-file-space (DWARF space):
    IDA's image base is translated on the way in and out, mirroring the
    raw IDA backend. Every method returns plain strings so the MCP layer
    stays trivially serializable.
    """

    def __init__(self, binary_path: Path) -> None:
        import importlib

        # idapro must load first: its __init__ puts IDA's python dir on sys.path
        # (importlib, not import statements, so the linter cannot reorder them).
        idapro = importlib.import_module("idapro")
        ida_hexrays = importlib.import_module("ida_hexrays")

        self._ida_hexrays = ida_hexrays
        self.binary_path = binary_path
        idapro.open_database(str(binary_path), run_auto_analysis=True)
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler not available in idalib")
        self.elf_base = common.elf_min_vaddr(binary_path)

    def close(self) -> None:
        import idapro

        with contextlib.suppress(Exception):
            idapro.close_database(save=False)

    def _image_base(self) -> int:
        import idaapi

        return int(idaapi.get_imagebase())

    def to_ida(self, addr: int) -> int:
        return (addr - self.elf_base) + self._image_base()

    def to_elf(self, ea: int) -> int:
        return (ea - self._image_base()) + self.elf_base

    def _func_at(self, addr: int, force: bool = False) -> Any:
        import ida_bytes
        import ida_funcs

        ea = self.to_ida(addr)
        f = ida_funcs.get_func(ea)
        if f is None and force and ida_bytes.is_code(ida_bytes.get_flags(ea)):
            # Only already-analyzed code may become a function (a data or
            # garbage address must not); IDA itself refuses overlapping ranges.
            ida_funcs.add_func(ea)
            f = ida_funcs.get_func(ea)
        if f is None:
            hint = (
                "force failed: address is not recognized code"
                if force
                else "IDA built no function here; pass force=true to create one"
            )
            raise ValueError(f"no function contains 0x{addr:x} ({hint})")
        return f

    def _resolve(self, raw: object) -> int:
        """Turn a tool ``addr`` argument into an ELF-space address.

        Hex strings (``0x1000``, ``1000``) are addresses; anything else must
        be a name IDA knows (``sub_1000``, ``dword_1000``).
        """
        import ida_name
        import idaapi

        text = str(raw).strip()
        with contextlib.suppress(ValueError):
            addr = int(text, 16)
            if addr >= 0:
                return addr
        ea = ida_name.get_name_ea(idaapi.BADADDR, text)
        if ea != idaapi.BADADDR:
            return self.to_elf(int(ea))
        raise ValueError(
            f"cannot resolve '{text}' — pass an address like \"0x1000\" "
            f'or a name like "sub_1000"'
        )

    def _name_at(self, ea: int) -> str:
        import ida_name

        return ida_name.get_ea_name(ea) or ""

    @staticmethod
    def _xref_label(xref: Any) -> str:
        import ida_xref

        return {
            ida_xref.fl_CN: "call",
            ida_xref.fl_CF: "call",
            ida_xref.fl_JN: "jump",
            ida_xref.fl_JF: "jump",
            ida_xref.dr_R: "data read",
            ida_xref.dr_W: "data write",
        }.get(xref.type, "data ref")

    def metadata(self) -> str:
        import idautils

        try:
            from decbench.utils import binfmt

            info = binfmt.detect(self.binary_path)
        except Exception:  # noqa: BLE001
            info = None
        if info is not None:
            os_name = {"elf": "Linux", "pe": "Windows"}.get(info.fmt, "unknown")
            endian = "big-endian" if info.arch in _BIG_ENDIAN_ARCHES else "little-endian"
            platform = f"{os_name} ({info.fmt.upper()} {info.arch}, {info.bits}-bit, {endian})"
        else:
            platform = "unknown"
        return (
            f"file: {self.binary_path.name}\n"
            f"platform: {platform}\n"
            f"image base: 0x{self.elf_base:x}\n"
            f"functions: {len(list(idautils.Functions()))}\n"
            f"stripped: {self._is_stripped()}"
        )

    def _is_stripped(self) -> str:
        """'yes' / 'no' from the on-disk headers (symbol table presence)."""
        import struct

        try:
            with open(self.binary_path, "rb") as f:
                head = f.read(64)
                if head[:4] == b"\x7fELF":
                    end = ">" if head[5] == 2 else "<"
                    is64 = head[4] == 2
                    fmt = end + ("Q" if is64 else "I")
                    shoff = struct.unpack_from(fmt, head, 0x28 if is64 else 0x20)[0]
                    entsize, shnum, strndx = struct.unpack_from(
                        end + "HHH", head, 0x3A if is64 else 0x2E
                    )
                    if not shoff or not shnum or not entsize or strndx >= shnum:
                        return "unknown"
                    f.seek(shoff + strndx * entsize)
                    shstr = f.read(entsize)
                    sh_off_at, sh_size_at = (0x18, 0x20) if is64 else (0x10, 0x14)
                    str_off = struct.unpack_from(fmt, shstr, sh_off_at)[0]
                    str_size = struct.unpack_from(fmt, shstr, sh_size_at)[0]
                    f.seek(str_off)
                    strtab = f.read(str_size)
                    for i in range(shnum):
                        f.seek(shoff + i * entsize)
                        name_off = struct.unpack_from(end + "I", f.read(entsize))[0]
                        if strtab[name_off : strtab.find(b"\0", name_off)] == b".symtab":
                            return "no"
                    return "yes"
                if head[:2] == b"MZ" and struct.unpack_from("<I", head, 0x3C)[0] > 0:
                    f.seek(struct.unpack_from("<I", head, 0x3C)[0] + 4 + 12)
                    ptr, num = struct.unpack("<II", f.read(8))
                    return "yes" if ptr == 0 or num == 0 else "no"
        except (OSError, struct.error):
            pass
        return "unknown"

    def disassemble(self, addr: int, offset: int, length: int, force: bool = False) -> str:
        import idautils
        import idc

        f = self._func_at(addr, force)
        items = list(idautils.FuncItems(f.start_ea))
        total = len(items)
        if offset >= total:
            raise ValueError(f"offset {offset} is beyond the function ({total} instructions)")
        length = max(1, min(length, _DISASM_MAX_INSNS))
        page = items[offset : offset + length]
        lines = [f"0x{self.to_elf(int(ea)):x}: {idc.GetDisasm(ea)}" for ea in page]
        if offset + len(page) < total:
            lines.append(
                f"... (showing {offset + 1}-{offset + len(page)} of {total} instructions "
                f"— pass offset to continue)"
            )
        return "\n".join(lines)

    def decompile(self, addr: int, force: bool = False) -> str:
        f = self._func_at(addr, force)
        try:
            cfunc = self._ida_hexrays.decompile(f.start_ea)
        except Exception:  # noqa: BLE001
            cfunc = None
        if cfunc is None:
            name = self._name_at(f.start_ea) or f"0x{addr:x}"
            raise ValueError(f"decompilation of {name} failed")
        return str(cfunc)

    def read_bytes(self, addr: int, size: int) -> str:
        import ida_bytes
        import ida_segment
        import idaapi

        if not 1 <= size <= _READ_MAX_BYTES:
            raise ValueError(f"size {size} out of range (1-{_READ_MAX_BYTES})")
        ea = self.to_ida(addr)
        if not ida_bytes.is_mapped(ea):
            raise ValueError(f"address 0x{addr:x} is not mapped")
        seg = idaapi.getseg(ea)
        segname = idaapi.get_segm_name(seg) if seg else "?"
        data = ida_bytes.get_bytes(ea, size)
        if data is None:
            bss = seg is not None and seg.type == ida_segment.SEG_BSS
            data = b"\x00" * size if bss else b""
        return f"{len(data)} bytes at 0x{addr:x} (segment {segname}):\n{_hexdump(addr, data)}"

    def xrefs_to(self, addr: int, offset: int) -> str:
        import ida_funcs
        import ida_xref
        import idautils

        ea = self.to_ida(addr)
        rows: list[str] = []
        for xref in idautils.XrefsTo(ea, 0):
            if xref.type == ida_xref.fl_F:  # fall-through into the address: noise
                continue
            label = self._xref_label(xref)
            frm = self.to_elf(int(xref.frm))
            owner = ida_funcs.get_func(xref.frm)
            if owner is not None:
                rows.append(f"{label} from 0x{frm:x} in {self._name_at(owner.start_ea)}")
            else:
                rows.append(f"{label} from 0x{frm:x}")
        if not rows:
            return f"no xrefs to 0x{addr:x}"
        name = self._name_at(ea)
        target = f"0x{addr:x}" + (f" ({name})" if name else "")
        head = f"{len(rows)} xref{'s' if len(rows) != 1 else ''} to {target}:"
        return _page_rows(rows, head, offset)

    def xrefs_from(self, addr: int, offset: int) -> str:
        import ida_xref
        import idautils

        f = self._func_at(addr)
        rows: list[str] = []
        for ea in idautils.FuncItems(f.start_ea):
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.type == ida_xref.fl_F:  # fall-through to the next insn: noise
                    continue
                label = self._xref_label(xref)
                at = self.to_elf(int(ea))
                to = self.to_elf(int(xref.to))
                name = self._name_at(xref.to)
                if name:
                    rows.append(f"{label} at 0x{at:x} to 0x{to:x} ({name})")
                else:
                    rows.append(f"{label} at 0x{at:x} to 0x{to:x}")
        if not rows:
            return f"no xrefs from 0x{addr:x}"
        fname = self._name_at(f.start_ea)
        src = f"0x{self.to_elf(int(f.start_ea)):x}" + (f" ({fname})" if fname else "")
        head = f"{len(rows)} xref{'s' if len(rows) != 1 else ''} from {src}:"
        return _page_rows(rows, head, offset)


def _build_mcp_server(session: _IdaSession) -> Any:
    """The in-process SDK MCP server exposing the IDA session as read-only tools."""
    from claude_agent_sdk import create_sdk_mcp_server, tool

    addr_desc = (
        'Hex address (e.g. "0x1000") or a name in the binary ' '(e.g. "sub_1000", "dword_1000")'
    )

    def _schema(properties: dict, required: list[str]) -> dict:
        return {"type": "object", "properties": properties, "required": required}

    def _run(fn: Any, *args: Any) -> dict:
        try:
            return _tool_text(fn(*args))
        except ValueError as exc:
            return _tool_text(f"error: {exc}")

    @tool(
        "get_metadata",
        "Binary metadata: file name, platform (OS + binary format), architecture and "
        "bitness, image base, function count, stripped status.",
        {},
    )
    async def get_metadata(args: dict) -> dict:
        return _tool_text(session.metadata())

    force_desc = (
        "Create the function at this address if IDA has none; use only after "
        "the same call without force failed (default false)"
    )

    @tool(
        "decompile_function",
        "Decompile one function. Returns C-like pseudocode.",
        _schema(
            {
                "addr": {"type": "string", "description": addr_desc},
                "force": {"type": "boolean", "description": force_desc},
            },
            ["addr"],
        ),
    )
    async def decompile_function(args: dict) -> dict:
        return _run(
            session.decompile, session._resolve(args["addr"]), bool(args.get("force", False))
        )

    @tool(
        "disassemble_function",
        'Disassemble one function, one instruction per line as "address: mnemonic '
        'operands". Known names (sub_1000, dword_1000, aText) replace raw operand '
        'values, and a referenced string\'s content is appended as ; "text". Long '
        "output is capped — pass offset to continue past a truncation.",
        _schema(
            {
                "addr": {"type": "string", "description": addr_desc},
                "offset": {
                    "type": "integer",
                    "description": "Number of instructions to skip from the function start",
                },
                "length": {
                    "type": "integer",
                    "description": f"Max instructions to return (default {_DISASM_MAX_INSNS})",
                },
                "force": {"type": "boolean", "description": force_desc},
            },
            ["addr"],
        ),
    )
    async def disassemble_function(args: dict) -> dict:
        return _run(
            session.disassemble,
            session._resolve(args["addr"]),
            max(0, int(args.get("offset", 0))),
            max(1, int(args.get("length", _DISASM_MAX_INSNS))),
            bool(args.get("force", False)),
        )

    @tool(
        "get_xrefs_to",
        "All cross-references to one function or global: every call, jump, data read, "
        "and data write that targets it, each with the referencing address and the "
        "function containing that reference.",
        _schema(
            {
                "addr": {"type": "string", "description": addr_desc},
                "offset": {"type": "integer", "description": "Number of entries to skip"},
            },
            ["addr"],
        ),
    )
    async def get_xrefs_to(args: dict) -> dict:
        return _run(
            session.xrefs_to, session._resolve(args["addr"]), max(0, int(args.get("offset", 0)))
        )

    @tool(
        "get_xrefs_from",
        "All cross-references from one function: every call, jump, and global it reads "
        "or writes, each with the instruction address and the target's address and name.",
        _schema(
            {
                "addr": {"type": "string", "description": addr_desc},
                "offset": {"type": "integer", "description": "Number of entries to skip"},
            },
            ["addr"],
        ),
    )
    async def get_xrefs_from(args: dict) -> dict:
        return _run(
            session.xrefs_from, session._resolve(args["addr"]), max(0, int(args.get("offset", 0)))
        )

    @tool(
        "read_bytes",
        "Read raw bytes at an address as a hexdump: 16 bytes per line, hex values "
        "plus an ASCII column ('.' for non-printable). The containing segment is "
        "named (.bss bytes read as zeros — it has no file contents).",
        _schema(
            {
                "addr": {"type": "string", "description": addr_desc},
                "size": {
                    "type": "integer",
                    "description": f"Number of bytes to read (1-{_READ_MAX_BYTES}, default 64)",
                },
            },
            ["addr"],
        ),
    )
    async def read_bytes(args: dict) -> dict:
        return _run(session.read_bytes, session._resolve(args["addr"]), int(args.get("size", 64)))

    tools: list[Any] = [
        get_metadata,
        decompile_function,
        disassemble_function,
        get_xrefs_to,
        get_xrefs_from,
        read_bytes,
    ]
    return create_sdk_mcp_server(
        name="ida",
        version="1.1.0",
        tools=tools,
    )


def _hexdump(addr: int, data: bytes) -> str:
    """Classic 16-per-line hexdump: hex in 8+8 groups plus an ASCII column."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        halves = (
            " ".join(f"{b:02x}" for b in chunk[:8]),
            " ".join(f"{b:02x}" for b in chunk[8:]),
        )
        hexpart = "  ".join(halves).ljust(2 * 23 + 2)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr + i:x}  {hexpart}  {text}")
    return "\n".join(lines)


def _page_rows(rows: list[str], head: str, offset: int) -> str:
    if offset >= len(rows):
        raise ValueError(f"offset {offset} is beyond the {len(rows)} entries")
    page = rows[offset : offset + _PAGE_SIZE]
    out = [head, *page]
    if offset + len(page) < len(rows):
        out.append(
            f"... (showing {offset + 1}-{offset + len(page)} of {len(rows)} "
            f"— pass offset to continue)"
        )
    return "\n".join(out)


def _tool_text(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


@register_decompiler("ida-agent")
class IDAAgentDecompiler(_AgentDecompiler):
    """Claude Agent SDK agent + headless IDA (idalib) via in-process MCP."""

    name = "ida-agent"
    display_name = "AI Agent + IDA (MCP)"
    cli = "claude"
    default_model = "glm-5.3-flash"
    cred_env = ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")
    compact_window_env = "DECBENCH_IDA_AGENT_COMPACT_WINDOW"
    context_1m_env = "DECBENCH_IDA_AGENT_CONTEXT_1M"

    def __init__(self, config: DecompilerConfig | None = None) -> None:
        super().__init__(config)
        self._session: _IdaSession | None = None
        self._binary_open: Path | None = None
        self._shared_source: Path | None = None

    def _keep_session(self) -> bool:
        """One shared session per binary, opened on a per-binary copy.

        ``idapro.close_database()`` can hit a fatal internal error after a
        long MCP-served session and calls ``qexit`` — killing the whole
        Python process silently. With this on, one database is opened on one
        shared copy, all functions reuse it serially, and it is closed only
        once, right before the shared copy is removed (closing after removal
        — or letting a per-function copy get removed under an open database,
        as in the non-keep mode — makes IDA's database write-back fail and
        qexit the process).
        """
        return os.environ.get("DECBENCH_AGENT_KEEP_SESSION", "1") == "1"

    def _session_source(self, local: Path) -> Path:
        """The copy the session opens on: the per-binary shared copy if set."""
        return self._shared_source or local

    def _sdk_available(self) -> bool:
        try:
            import claude_agent_sdk  # noqa: F401

            return True
        except Exception:  # noqa: BLE001
            return False

    def _idalib_available(self) -> bool:
        try:
            import importlib

            importlib.import_module("idapro")
            importlib.import_module("ida_hexrays")
            return True
        except Exception:  # noqa: BLE001
            return False

    def is_available(self) -> bool:
        if shutil.which(self.cli) is None:
            return False
        if not self._sdk_available() or not self._idalib_available():
            return False
        return any(os.environ.get(e) for e in self.cred_env)

    def get_version(self) -> str | None:
        model = self._model()
        sdk = ""
        try:
            import claude_agent_sdk

            sdk = str(getattr(claude_agent_sdk, "__version__", "") or "")
        except Exception:  # noqa: BLE001
            sdk = ""
        parts = [p for p in (model, f"claude-agent-sdk {sdk}" if sdk else "") if p]
        return " / ".join(parts) or None

    def _max_turns(self) -> int:
        try:
            raw = self._opt("max_turns", "DECBENCH_IDA_AGENT_MAX_TURNS", _DEFAULT_MAX_TURNS)
            return max(1, int(raw))
        except (TypeError, ValueError):
            return _DEFAULT_MAX_TURNS

    def _compile_check_enabled(self) -> bool:
        return str(
            self._opt("compile_check", "DECBENCH_IDA_AGENT_COMPILE_CHECK", "1")
        ).lower() not in ("0", "false", "no")

    def _compile_retries(self) -> int:
        try:
            raw = self._opt("compile_retries", "DECBENCH_IDA_AGENT_COMPILE_RETRIES", 2)
            return max(0, int(raw))
        except (TypeError, ValueError):
            return 2

    def _fn_workers(self) -> int:
        return 1

    def _path_guard_enabled(self) -> bool:
        return str(self._opt("path_guard", "DECBENCH_IDA_AGENT_PATH_GUARD", "1")).lower() not in (
            "0",
            "false",
            "no",
        )

    def _path_guard_callback(self, workdir: Path) -> Any:
        """SDK permission callback: hard tool whitelist + deliverable-only writes.

        Structural replacement for prompt-side pleading: the native tools stay
        untouched (models are trained on them) and violations get a corrective
        denial message naming the exact valid call, so a small model can
        self-correct instead of wandering. Write/Edit may only touch the
        deliverable ``decompiled.c`` in the working directory; reads stay
        inside the workdir plus the agent's own config cache (persisted tool
        output); tools outside the slice are denied outright.
        """
        from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny

        write_tools = ("Write", "Edit", "NotebookEdit")
        read_tools = ("Read", "Glob", "Grep")
        config_root = self._isolated_config_dir()

        async def _can_use_tool(tool_name: str, inp: dict, ctx: Any) -> Any:
            if not tool_name.startswith("mcp__") and tool_name not in _AGENT_TOOLS:
                _l.info("ida-agent: tool guard denied %s", tool_name)
                return PermissionResultDeny(
                    message=(
                        f"{tool_name} is not available for this task. Use the "
                        f"mcp__ida__* tools for all binary inspection, and "
                        f"Read/Edit/Write only for the `decompiled.c` deliverable."
                    )
                )
            if tool_name in write_tools:
                raw = inp.get("file_path", inp.get("notebook_path"))
                if not _is_deliverable(raw, workdir):
                    _l.info("ida-agent: write guard denied %s to %r", tool_name, raw)
                    return PermissionResultDeny(
                        message=(
                            f"Permission denied: the only writable file is the "
                            f"deliverable `{_OUTFILE}` in the current working "
                            f"directory (the directory holding target.bin). You "
                            f"sent file_path={raw!r}. Call the tool again with "
                            f"file_path exactly `{_OUTFILE}` or `./{_OUTFILE}`."
                        )
                    )
            if tool_name in read_tools:
                raw = inp.get("file_path", inp.get("notebook_path", inp.get("path")))
                if not _read_scope_ok(raw, workdir, config_root):
                    _l.info("ida-agent: read guard denied %s to %r", tool_name, raw)
                    return PermissionResultDeny(
                        message=(
                            f"Permission denied: reading outside your working "
                            f"directory is not allowed. You sent {raw!r}. Inspect "
                            f"the binary with the mcp__ida__* tools instead."
                        )
                    )
            return PermissionResultAllow()

        return _can_use_tool

    def _ensure_session(self, binary_path: Path) -> _IdaSession:
        if self._session is not None and self._binary_open == binary_path:
            return self._session
        if self._session is not None:
            self._session.close()
            self._session = None
        self._session = _IdaSession(binary_path)
        self._binary_open = binary_path
        return self._session

    def _close_session(self) -> None:
        if self._session is not None:
            self._session.close()
        self._session = None
        self._binary_open = None

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
        progress_path: Path | None = None,
        **_: Any,
    ) -> DecompilationResult:
        validate_stripped_elf(Path(binary_path))
        targets = self._select_targets(Path(binary_path), functions, function_names)
        if not targets or not (functions or function_names):
            raise ValueError("ida-agent requires explicit target addresses; use run_benchmark.py")
        if any(name != f"sub_{addr:x}" for name, addr in targets):
            raise ValueError("ida-agent requires anonymous sub_<address> target labels")
        if len(targets) > self._max_funcs():
            raise ValueError(
                f"{len(targets)} targets exceed DECBENCH_LLM_MAX_FUNCS={self._max_funcs()}; "
                "refusing to truncate the frozen sample"
            )
        shared_tmp: Any = None
        keep = self._keep_session()
        try:
            if keep:
                shared_tmp = tempfile.TemporaryDirectory(prefix="idaagent_bin_")
                shared_copy = Path(shared_tmp.name) / "target.bin"
                shutil.copy2(binary_path, shared_copy)
                self._shared_source = shared_copy
                self._ensure_session(shared_copy)
            return super().decompile_binary(
                binary_path, functions, output_dir, function_names, progress_path
            )
        finally:
            self._shared_source = None
            if shared_tmp is not None:
                # Close the database BEFORE the shared copy (and its .i64)
                # is removed: deleting files under an open idalib session
                # makes a later IDA access die via qexit — killing the whole
                # Python process with exit 1 and no traceback.
                self._close_session()
                shared_tmp.cleanup()
            if not keep:
                self._close_session()

    def _agent_env(self) -> dict[str, str]:
        """Environment for the SDK-spawned claude CLI subprocess.

        The SDK merges ``options.env`` OVER the inherited process env (it can
        override but not delete), so exclusion = blank the key. This is an
        allowlist, not a blacklist: every ``CLAUDE*``/``CLAUDECODE``/
        ``ANTHROPIC*`` variable is blanked except the endpoint auth trio in
        ``_AGENT_ENV_KEEP``, then the ``_PINNED_CLI_ENV`` knobs are set — a
        host Claude Code session can no longer leak behavior knobs (e.g.
        ``CLAUDE_CODE_MAX_RETRIES``) into the agent grandchildren, and runs
        reproduce identically from any shell. The CLI also gets an isolated
        config dir (no host session state).
        """
        env = dict(os.environ)
        for key in env:
            if key.startswith(("CLAUDE", "CLAUDECODE", "ANTHROPIC")) and key not in _AGENT_ENV_KEEP:
                env[key] = ""
        env.update(_PINNED_CLI_ENV)
        if str(self._opt("disable_title", "DECBENCH_IDA_AGENT_DISABLE_TITLE", "0")) == "1":
            env["CLAUDE_CODE_DISABLE_TERMINAL_TITLE"] = "1"
        window = self._opt("compact_window", self.compact_window_env, "")
        if window:
            env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = str(int(window))
        env["CLAUDE_CONFIG_DIR"] = str(self._isolated_config_dir())
        return env

    def _cli_model(self) -> str:
        model = self._model()
        if str(self._opt("context_1m", self.context_1m_env, "")).lower() in ("1", "true", "yes"):
            return f"{model}[1m]"
        return model

    def _isolated_config_dir(self) -> Path:
        override = self._opt("claude_config_dir", "DECBENCH_IDA_AGENT_CONFIG_DIR", "")
        if override:
            cfg = Path(override)
        else:
            cfg = Path.home() / ".cache" / "decbench" / "ida-agent-config"
        cfg.mkdir(parents=True, exist_ok=True)
        return cfg

    def _build_prompt(
        self, binary_path: Path, local_name: str, name: str, addr: int, outfile: str
    ) -> str:
        return (
            f"TARGET\n"
            f"- Stripped binary in your working directory: ./{local_name}\n"
            f"- Target function: entry ELF virtual address 0x{addr:x}. Pass this "
            f"address (hex string) to the mcp__ida__* tools.\n"
            f"- The binary is stripped; IDA names it by address. Identify the "
            f"target strictly by its entry address, not by a guessed name.\n"
            f"- Name the reconstructed function `{name}` in your C output.\n\n"
            f"Deliverable: write the reconstructed C with the Write tool to exactly "
            f"`./{outfile}` — a RELATIVE path in your working directory, the same "
            f"directory as `./{local_name}` (`{outfile}` without the leading `./` is "
            f"equally valid; absolute paths and any other file name are rejected). "
            f"The file must hold exactly one top-level definition of `{name}`, plus "
            f"any local typedefs/structs it needs. When finished, verify the file "
            f"exists and contains only compilable C.\n"
        )

    def _decompile_one(
        self, binary_path: Path, name: str, addr: int, output_dir: Path | None = None
    ) -> tuple[str | None, float, dict[str, int] | None]:
        t0 = time.time()
        with tempfile.TemporaryDirectory(prefix="idaagent_") as tmp:
            workdir = Path(tmp)
            local = workdir / "target.bin"
            shutil.copy2(binary_path, local)
            # The session opens on this call's private copy (idalib keeps its
            # .id0/.nam/.til artifacts next to the database, so two concurrent
            # tasks on the same results-tree binary would otherwise clobber one
            # shared IDB) — or, in subprocess mode, on the per-binary shared
            # copy so no close_database() ever runs mid-run.
            session = self._ensure_session(self._session_source(local))
            outfile = workdir / _OUTFILE
            prompt = self._build_prompt(binary_path, local.name, name, addr, outfile.name)
            code, events, tokens, info = asyncio.run(
                self._agent_call(session, workdir, prompt, outfile, name)
            )
            # Rename before the gate (as the ISCG backend does) so name
            # collisions surface inside the gated region the revision can fix.
            final = _rename_func(_sanitize(code), name) if code else None
            round_label = self._trace_label(binary_path, name, addr)
            self._save_round_c(output_dir, round_label, 0, final)
            # Workflow-owned compile gate (same contract as the ISCG backend):
            # the agent gets no shell, gcc checking happens here, and a failed
            # check triggers a bounded revision round with the errors fed back.
            if final and self._compile_check_enabled():
                retries = self._compile_retries()
                resume_sid = (info.get("session_ids") or [None])[-1]
                for attempt in range(retries + 1):
                    errs = _gcc_syntax_errors(final, workdir)
                    if errs is None:
                        events.append("[compile gate] passed")
                        break
                    if attempt >= retries:
                        events.append(
                            f"[compile gate] still failing after {attempt} "
                            f"revision(s): {errs[:200]}"
                        )
                        break
                    # Archive the error text (flattened) so per-error-class
                    # analysis works from the md alone, like the iscg backend.
                    flat = " | ".join(errs.splitlines()[:5])[:400]
                    events.append(f"[compile gate] failed — revision round {attempt + 1}: {flat}")
                    # Linear revision: resume the SAME conversation so the model
                    # sees its own exploration history and only the new user
                    # message (the compiler errors) — no task re-statement.
                    rev_prompt = (
                        f"Your previously written C does not compile. "
                        f"Compiler output:\n{errs[:2000]}\nFix the errors and "
                        f"write the corrected C to `{outfile.name}` again."
                    )
                    rcode, revents, rtokens, rinfo = asyncio.run(
                        self._agent_call(
                            session, workdir, rev_prompt, outfile, name, resume_sid=resume_sid
                        )
                    )
                    resume_sid = (rinfo.get("session_ids") or [resume_sid])[-1]
                    events.extend(revents)
                    tokens = _sum_tokens(tokens, rtokens)
                    info["num_turns"] = (info.get("num_turns") or 0) + (rinfo.get("num_turns") or 0)
                    info["cost_usd"] = (info.get("cost_usd") or 0) + (rinfo.get("cost_usd") or 0)
                    for tk, tv in (rinfo.get("tool_calls") or {}).items():
                        merged = info.get("tool_calls") or {}
                        merged[tk] = merged.get(tk, 0) + tv
                        info["tool_calls"] = merged
                    info["session_ids"] = (info.get("session_ids") or []) + (
                        rinfo.get("session_ids") or []
                    )
                    if rcode:
                        final = _rename_func(_sanitize(rcode), name)
                        self._save_round_c(output_dir, round_label, attempt + 1, final)
        elapsed = time.time() - t0
        self._save_agent_trace(
            output_dir,
            binary_path,
            name,
            addr,
            prompt,
            events,
            final,
            elapsed,
            info,
            tokens,
            workdir,
        )
        return final, elapsed, tokens

    async def _agent_call(
        self,
        session: _IdaSession,
        workdir: Path,
        prompt: str,
        outfile: Path,
        fn_name: str,
        resume_sid: str | None = None,
    ) -> tuple[str | None, list[str], dict[str, int] | None, dict[str, Any]]:
        """One SDK conversation. Returns (code, trace_events, tokens, info).

        ``resume_sid`` continues that earlier conversation instead of starting
        a fresh one — the compile-gate revision rounds use it to append the
        compiler errors to the SAME dialogue (prefix-cache friendly) rather
        than re-stating the task in a new session.
        """
        from claude_agent_sdk import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ToolResultBlock,
            ToolUseBlock,
            UserMessage,
        )

        options = self._sdk_options(workdir, _build_mcp_server(session), resume_sid)
        events: list[str] = []
        usage_total: dict[str, int] = {}
        result_usage: dict[str, Any] = {}
        tool_calls: dict[str, int] = {}
        last_text = ""
        info: dict[str, Any] = {}

        async def _run() -> None:
            nonlocal last_text, result_usage
            async for msg in _sdk_query(prompt, options):
                if isinstance(msg, AssistantMessage):
                    for block in getattr(msg, "content", []) or []:
                        if isinstance(block, TextBlock) and block.text:
                            last_text = block.text
                            events.append(f"ASSISTANT: {block.text[:600]}")
                        elif isinstance(block, ToolUseBlock):
                            inp = str(getattr(block, "input", {}))
                            events.append(f"TOOL_CALL {block.name}: {inp[:300]}")
                            tool_calls[block.name] = tool_calls.get(block.name, 0) + 1
                    for k, v in (getattr(msg, "usage", None) or {}).items():
                        with contextlib.suppress(TypeError, ValueError):
                            usage_total[k] = usage_total.get(k, 0) + int(v)
                elif isinstance(msg, UserMessage):
                    for block in getattr(msg, "content", []) or []:
                        if isinstance(block, ToolResultBlock):
                            content = str(getattr(block, "content", ""))
                            # errors are the self-correction signal we diagnose
                            # runs by — keep them legible in the trace
                            cap = 1000 if "<tool_use_error>" in content else 300
                            events.append(f"TOOL_RESULT: {content[:cap]}")
                elif isinstance(msg, ResultMessage):
                    info["result"] = getattr(msg, "result", "")
                    info["num_turns"] = getattr(msg, "num_turns", None)
                    info["cost_usd"] = getattr(msg, "total_cost_usd", None)
                    info["duration_ms"] = getattr(msg, "duration_ms", None)
                    sid = getattr(msg, "session_id", None)
                    if sid:
                        info.setdefault("session_ids", []).append(sid)
                    # Only the ResultMessage carries the real cumulative usage
                    # in this CLI generation; AssistantMessage.usage is zeros.
                    result_usage = getattr(msg, "usage", None) or {}

        try:
            await asyncio.wait_for(_run(), timeout=self._timeout())
        except asyncio.TimeoutError:
            events.append("AGENT TIMEOUT")
            _l.warning("ida-agent: agent timed out on %s", fn_name)
        except Exception as e:  # noqa: BLE001 - CLI/API crash mid-query: salvage the run
            events.append(f"AGENT ERROR: {type(e).__name__}: {e}")
            _l.warning("ida-agent: agent query failed on %s: %s", fn_name, e)

        code: str | None = None
        if outfile.is_file():
            text = outfile.read_text(errors="replace").strip()
            code = text or None
        if not code:
            # the guard makes this near-unreachable; kept as a net for
            # no-guard runs and future tool additions — the newest .c
            # defining the target function is the deliverable attempt
            try:
                cands = sorted(
                    outfile.parent.glob("*.c"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
            except OSError:
                cands = []
            for cand in cands:
                text = cand.read_text(errors="replace").strip()
                if fn_name in text:
                    code = text
                    break
        if not code:
            code = _extract_c(last_text) or _extract_c(info.get("result", ""))
        with contextlib.suppress(TypeError, ValueError):
            if any(int(v) for v in result_usage.values() if isinstance(v, (int, float))):
                usage_total = {
                    k: int(v) for k, v in result_usage.items() if isinstance(v, (int, float))
                }
        info["tool_calls"] = tool_calls
        return code, events, _normalize_tokens(usage_total), info

    def _sdk_options(self, workdir: Path, mcp_server: Any, resume_sid: str | None = None) -> Any:
        from claude_agent_sdk import ClaudeAgentOptions

        kwargs: dict[str, Any] = dict(
            model=self._cli_model(),
            cwd=str(workdir),
            env=self._agent_env(),
            system_prompt=AGENT_SYSTEM_PROMPT,
            mcp_servers={"ida": mcp_server},
            setting_sources=[],
            max_turns=self._max_turns(),
        )
        if self._path_guard_enabled():
            kwargs["permission_mode"] = "default"
            kwargs["can_use_tool"] = self._path_guard_callback(workdir)
            kwargs["disallowed_tools"] = [t for t in _BUILTIN_TOOLS if t not in _AGENT_TOOLS]
        else:
            kwargs["permission_mode"] = "bypassPermissions"
        if resume_sid:
            kwargs["resume"] = resume_sid
        effort = self._opt("effort", "DECBENCH_IDA_AGENT_EFFORT", "")
        if str(effort) not in ("", "none", "None"):
            kwargs["effort"] = str(effort)
        thinking = self._opt("thinking", "DECBENCH_IDA_AGENT_THINKING", "default")
        if thinking in ("disabled", "adaptive"):
            kwargs["thinking"] = {"type": thinking}
        elif thinking != "default":
            raise ValueError("thinking must be default, disabled or adaptive")
        return ClaudeAgentOptions(**kwargs)

    def _save_round_c(
        self, output_dir: Path | None, label: str, round_no: int, code: str | None
    ) -> None:
        """Persist one compile-gate round's deliverable next to the trace md.

        ``r0`` is the main turn's C as delivered (before any revision), ``r1+``
        each revision round's — so per-round offline eval (accuracy after 0/1/2
        fixes) never has to re-mine the JSONL transcripts. ``label`` is the
        same trace label the caller's md uses.
        """
        if not code or not self._traces_enabled():
            return
        root = self._opt("trace_dir", "DECBENCH_LLM_TRACE_DIR", "")
        if root:
            trace_dir = Path(root) / self.id.replace("@", "-")
        elif output_dir is not None:
            trace_dir = Path(output_dir) / "traces"
        else:
            return
        try:
            trace_dir.mkdir(parents=True, exist_ok=True)
            _write_incremental(trace_dir / f"{label}.r{round_no}.c", code)
        except OSError as e:
            _l.debug("ida-agent: round-C save failed for %s: %s", label, e)

    def _save_agent_trace(
        self,
        output_dir: Path | None,
        binary_path: Path,
        name: str,
        addr: int,
        prompt: str,
        events: list[str],
        code: str | None,
        elapsed: float,
        info: dict[str, Any],
        tokens: dict[str, int] | None,
        workdir: Path,
    ) -> None:
        if not self._traces_enabled():
            return
        root = self._opt("trace_dir", "DECBENCH_LLM_TRACE_DIR", "")
        if root:
            trace_dir = Path(root) / self.id.replace("@", "-")
        elif output_dir is not None:
            trace_dir = Path(output_dir) / "traces"
        else:
            return
        try:
            trace_dir.mkdir(parents=True, exist_ok=True)
            label = self._trace_label(binary_path, name, addr)
            status = "ok" if code else "FAILED"
            slug = re.sub(r"[^a-zA-Z0-9]", "-", str(workdir))
            transcripts = self._isolated_config_dir() / "projects" / slug
            body = (
                f"# {self.id} trace — {label}\n\n"
                f"- model: {self._model()}\n"
                f"- status: {status}\n"
                f"- elapsed: {elapsed:.0f}s\n"
                f"- turns: {info.get('num_turns')}\n"
                f"- cost_usd: {info.get('cost_usd')}\n"
                f"- tokens: {tokens}\n"
                f"- tool_calls: {info.get('tool_calls')}\n"
                f"- session: {','.join(info.get('session_ids') or []) or 'n/a'}\n"
                f"- transcripts: {transcripts}\n\n"
                f"## Prompt\n\n```\n{prompt}\n```\n\n"
                f"## Agent events (assistant / MCP calls / results)\n\n"
                + "\n\n".join(events)
                + f"\n\n## Reconstructed C\n\n```c\n{code or '(none — failed)'}\n```\n"
            )
            _write_incremental(trace_dir / f"{label}.md", body)
        except Exception as e:  # noqa: BLE001 - tracing must never break a run
            _l.debug("ida-agent: trace save failed for %s: %s", name, e)


def _normalize_tokens(usage: dict[str, int]) -> dict[str, int] | None:
    """Map Anthropic usage keys onto the axes ``pricing.toml`` prices."""
    if not usage:
        return None
    out = {
        "input": usage.get("input_tokens", 0),
        "output": usage.get("output_tokens", 0),
        "cached_input": usage.get("cache_read_input_tokens", 0),
        "cache_write": usage.get("cache_creation_input_tokens", 0),
    }
    return out if any(out.values()) else None


def _sum_tokens(a: dict[str, int] | None, b: dict[str, int] | None) -> dict[str, int] | None:
    """Sum two normalized usage dicts (agent call + revision rounds)."""
    if not a:
        return b
    if not b:
        return a
    return {k: a.get(k, 0) + b.get(k, 0) for k in set(a) | set(b)}


def _sdk_query(prompt: str, options: Any) -> Any:
    from claude_agent_sdk import query

    return query(prompt=prompt, options=options)
