#!/usr/bin/env python3
"""File hygiene checks for every tracked file. Standard library only.

Run from anywhere inside the repository:  python3 .github/scripts/check_files.py
"""
import json
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

MAX_BYTES = 5 * 1024 * 1024
CONFLICT_MARKER = re.compile(r"^(<{7}|>{7}|\|{7})( |$)")
# [text](target) and [text](target "title"); images too. Targets with spaces need <...>.
MARKDOWN_LINK = re.compile(r"\[[^\]\n]*\]\(\s*(<[^>\n]*>|[^)\s]+)(?:\s+\"[^\"\n]*\")?\s*\)")
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`\n]*`")


def tracked_files(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    return [name for name in out.decode().split("\0") if name]


def check_text(name, text):
    problems = []
    if text and not text.endswith("\n"):
        problems.append(f"{name}: no newline at end of file")
    for number, line in enumerate(text.split("\n"), 1):
        if line.endswith("\r"):
            problems.append(f"{name}:{number}: CRLF line ending")
            line = line[:-1]
        if line != line.rstrip():
            problems.append(f"{name}:{number}: trailing whitespace")
        if CONFLICT_MARKER.match(line):
            problems.append(f"{name}:{number}: merge conflict marker")
    return problems


def check_yaml(name, path):
    # Ruby ships with macOS and the GitHub runners and has a YAML parser in its
    # standard library; Python does not.
    script = "require 'yaml'; YAML.safe_load(File.read(ARGV[0]), aliases: true)"
    try:
        result = subprocess.run(["ruby", "-e", script, str(path)], capture_output=True, text=True)
    except FileNotFoundError:
        return [f"{name}: cannot check YAML, ruby is not installed"]
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines()
        return [f"{name}: invalid YAML: {lines[0] if lines else 'parse error'}"]
    return []


def check_syntax(name, path, data):
    suffix = Path(name).suffix.lower()
    try:
        if suffix == ".json":
            json.loads(data.decode("utf-8"))
        elif suffix == ".plist":
            plistlib.loads(data)
        elif suffix in (".yml", ".yaml"):
            return check_yaml(name, path)
    except Exception as error:  # every parser failure is a finding, whatever its type
        return [f"{name}: invalid {suffix[1:]}: {error}"]
    return []


def markdown_links(text):
    """Yield (line number, target) for links outside code blocks and inline code."""
    in_fence = False
    for number, line in enumerate(text.split("\n"), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in MARKDOWN_LINK.finditer(INLINE_CODE.sub("", line)):
            yield number, match.group(1).strip("<>")


def check_markdown_links(name, text, root):
    """Relative links must point at a file or directory inside the repository.

    Links to other sites and pure #anchors are not checked: fetching them would
    make every pull request depend on the network.
    """
    problems = []
    root = root.resolve()
    for number, target in markdown_links(text):
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith(("#", "//")):
            continue
        relative = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not relative:
            continue
        base = root if relative.startswith("/") else (root / name).parent
        resolved = (base / relative.lstrip("/")).resolve()
        if resolved != root and root not in resolved.parents:
            problems.append(f"{name}:{number}: link leaves the repository: {target}")
        elif not resolved.exists():
            problems.append(f"{name}:{number}: broken link: {target}")
    return problems


def check_repository(root, names=None):
    root = Path(root)
    problems = []
    for name in names if names is not None else tracked_files(root):
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        size = path.stat().st_size
        if size > MAX_BYTES:
            problems.append(f"{name}: {size} bytes, larger than {MAX_BYTES} (5 MiB)")
            continue
        data = path.read_bytes()
        problems += check_syntax(name, path, data)
        if b"\0" in data:
            continue  # binary
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{name}: not valid UTF-8")
            continue
        problems += check_text(name, text)
        if Path(name).suffix.lower() == ".md":
            problems += check_markdown_links(name, text, root)
    return problems


def main():
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=Path(__file__).parent,
                          check=True, capture_output=True, text=True).stdout.strip()
    problems = check_repository(root)
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} problem(s) found.", file=sys.stderr)
        return 1
    print("All tracked files pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
