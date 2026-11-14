"""Small, dependency-free path glob matcher (gitignore-flavoured).

``*`` matches within one path segment, ``**`` crosses segments, ``?`` matches a
single non-slash character. A pattern without wildcards matches the file itself
or everything beneath it when it names a directory ("services/billing").
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, Pattern


def _normalize(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.strip("/")


@lru_cache(maxsize=2048)
def compile_glob(pattern: str) -> Pattern[str]:
    pattern = _normalize(pattern)
    if not any(ch in pattern for ch in "*?"):
        return re.compile(rf"^{re.escape(pattern)}(?:/.*)?$")
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern[i : i + 2] == "**":
                i += 2
                if pattern[i : i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def match_path(path: str, pattern: str) -> bool:
    return bool(compile_glob(pattern).match(_normalize(path)))


def match_any(path: str, patterns: Iterable[str]) -> bool:
    return any(match_path(path, pattern) for pattern in patterns)


def specificity(pattern: str) -> int:
    """Longer literal prefix wins when two activities claim the same file."""
    pattern = _normalize(pattern)
    literal = re.split(r"[*?]", pattern, maxsplit=1)[0]
    return len(literal) * 2 + (0 if any(ch in pattern for ch in "*?") else 1)
