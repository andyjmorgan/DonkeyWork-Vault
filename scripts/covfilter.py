#!/usr/bin/env python3
"""Filter a Go coverprofile before the coverage total is computed.

Two kinds of code are removed from the denominator:

  1. Whole files matching the exclude regex (generated clients, main() entrypoints).
  2. Individual blocks tagged in source with a `//coverage:ignore` comment — used for
     genuinely-unreachable defensive branches (constructor errors on already-validated
     inputs, crypto/rand failures, embed.FS read errors, Close/Sync after a successful
     write, OS-specific branches that can't run on the test host).

Put the comment on the *statement* being ignored (e.g. the `return err` inside a defensive
`if`), not on the `if` line — a block is dropped when any ignored source line falls within
its line range, and tagging the `if` line would also drop the surrounding covered block.

Usage: covfilter.py <profile> <module-import-path> <module-dir> <exclude-regex>
Writes the filtered profile to stdout; a one-line summary to stderr.
"""
import re
import sys

prof, modpath, moddir, exclude_re = sys.argv[1:5]
exc = re.compile(exclude_re)
moddir = moddir.rstrip("/")
prefix = modpath.rstrip("/") + "/"
_ignore_cache: dict[str, set[int]] = {}


def ignored_lines(localfile: str) -> set[int]:
    if localfile not in _ignore_cache:
        s: set[int] = set()
        try:
            with open(localfile, encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if "//coverage:ignore" in line or "// coverage:ignore" in line:
                        s.add(i)
        except OSError:
            pass
        _ignore_cache[localfile] = s
    return _ignore_cache[localfile]


block_re = re.compile(r"(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ \d+$")
out: list[str] = []
n_excluded = n_ignored = 0

with open(prof) as f:
    out.append(f.readline().rstrip("\n"))  # mode: line
    for line in f:
        line = line.rstrip("\n")
        m = block_re.match(line)
        if not m:
            continue
        path, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        if exc.search(path):
            n_excluded += 1
            continue
        rel = path[len(prefix):] if path.startswith(prefix) else path
        ig = ignored_lines(f"{moddir}/{rel}")
        if ig and any(start <= L <= end for L in ig):
            n_ignored += 1
            continue
        out.append(line)

print("\n".join(out))
print(
    f"covfilter: dropped {n_excluded} excluded-file blocks, {n_ignored} //coverage:ignore blocks",
    file=sys.stderr,
)
