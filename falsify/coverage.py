"""Parse Foundry LCOV; report only production sources, never test harnesses."""
from pathlib import PurePosixPath


def parse_lcov(text: str) -> dict:
    files = {}
    current = None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key == "SF":
            path = PurePosixPath(value)
            current = None
            if not path.is_absolute() and path.parts and path.parts[0] == "src":
                current = files.setdefault(value, {"lines_found": 0, "lines_hit": 0,
                                                       "functions_found": 0, "functions_hit": 0})
        elif current is not None:
            field = {"LF": "lines_found", "LH": "lines_hit",
                     "FNF": "functions_found", "FNH": "functions_hit"}.get(key)
            if field:
                current[field] = int(value)
    totals = {k: sum(f[k] for f in files.values()) for k in
              ("lines_found", "lines_hit", "functions_found", "functions_hit")}
    return {"available": bool(files), "files": files, **totals}
