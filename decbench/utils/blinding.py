"""Validate the ELF inputs admitted to the IDA agent benchmark."""

from pathlib import Path

from elftools.elf.elffile import ELFFile


def validate_stripped_elf(path: Path) -> None:
    """Reject debug information and static symbols, preserving dynamic imports."""
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("ida-agent currently requires a verified stripped ELF input")
        stream.seek(0)
        elf = ELFFile(stream)
        leftovers = [
            section.name
            for section in elf.iter_sections()
            if section["sh_type"] == "SHT_SYMTAB"
            or section.name.startswith((".debug", ".zdebug", ".stab"))
            or section.name in {".gnu_debuglink", ".gnu_debugaltlink", ".gdb_index"}
        ]
    if leftovers:
        raise ValueError(f"input is not stripped: {', '.join(sorted(leftovers))}")
