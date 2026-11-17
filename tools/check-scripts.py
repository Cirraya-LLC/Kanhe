#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Refuses a shell script that starts one of its own functions in the background.

`fn args &`, where fn is a shell function, runs fn in a subshell: `$!` is that
subshell, not the program fn starts, so `kill "$!"` stops bash and leaves the
program (a server, often) running with no parent, after the test has ended.
Start such programs directly ("$KANHE" serve ... &).

Usage: check-scripts.py FILE...   (exit 1 if any is refused)
"""

import re
import sys

FUNCTION = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_-]*)\s*\(\)\s*[{(]")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")


def logical_lines(text):
    """Each command line with its continuations joined, and where it starts."""
    start, parts = 0, []
    for number, line in enumerate(text.splitlines(), 1):
        if not parts:
            start = number
        if line.endswith("\\"):
            parts.append(line[:-1])
            continue
        parts.append(line)
        yield start, " ".join(parts)
        parts = []
    if parts:
        yield start, " ".join(parts)


def check(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    functions = {m.group(1) for m in map(FUNCTION.match, text.splitlines()) if m}
    refused = []
    for number, line in logical_lines(text):
        code = line.split(" #", 1)[0].rstrip()
        if not code.endswith("&") or code.endswith("&&"):
            continue
        words = code.split()
        while words and ASSIGNMENT.match(words[0]):
            words.pop(0)
        if words and words[0] in functions:
            refused.append(f"{path}:{number}: '{words[0]}' is a shell function started "
                           "with &: $! would be its subshell; start the program directly")
    return refused


def main(paths):
    refused = [line for path in paths for line in check(path)]
    for line in refused:
        print(line, file=sys.stderr)
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
