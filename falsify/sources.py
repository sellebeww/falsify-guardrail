"""Constrained source bundles: paths cannot escape a disposable project."""
import re
from pathlib import Path, PurePosixPath


def write_sources(root: Path, name: str, source: str, support: dict[str, str]) -> None:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("contract_name must be a Solidity identifier")
    files = {f"{name}.sol": source}
    for filename, text in support.items():
        path = PurePosixPath(filename)
        if path.is_absolute() or ".." in path.parts or "\\" in filename:
            raise ValueError(f"unsafe source path: {filename}")
        if path.suffix != ".sol" or str(path) in files:
            raise ValueError(f"invalid or duplicate source path: {filename}")
        files[str(path)] = text
    for filename, text in files.items():
        target = root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
