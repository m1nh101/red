#!/usr/bin/env python3
"""Measure the byte footprint of environment variables on the stack.

In the Linux process-startup layout (System V ABI), the kernel copies the
environment *strings* to the top of the stack, one after another, each stored
as the NUL-terminated string ``KEY=VALUE\\0``. The total size of this region
shifts the address of everything below it (argv strings, then the stack frames).

This is the classic reason a buffer's stack address differs between a binary
run directly and the same binary run under GDB: GDB injects/changes env vars
(``LINES``, ``COLUMNS``, ``_``, ...) and may change ``argv[0]``, so the env
block has a different size and everything shifts.

Usage:
    # Measure the env defined in scripts/.env
    python3 scripts/envsize.py

    # Measure the *current* process environment instead of the file
    python3 scripts/envsize.py --current

    # Compare two .env files (e.g. a dump of the GDB env vs the direct env)
    python3 scripts/envsize.py --diff scripts/env_direct scripts/env_gdb
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Default location the task asked for.
DEFAULT_ENV_PATH = Path(__file__).resolve().parent / ".env"


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE .env file into an ordered dict.

    - Blank lines and ``# comments`` are ignored.
    - A leading ``export`` keyword is stripped.
    - Surrounding single/double quotes on the value are stripped.
    - The value may itself contain ``=`` (we split only on the first one).
    """
    env: dict[str, str] = {}
    if not path.exists():
        raise FileNotFoundError(f"env file not found: {path}")

    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            print(f"warning: {path}:{lineno}: no '=' found, skipping: {raw!r}",
                  file=sys.stderr)
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env[key] = value
    return env


def env_byte_size(env: dict[str, str], *, verbose: bool = False) -> int:
    """Return the total bytes the env occupies on the stack.

    Each variable is stored as ``KEY=VALUE`` followed by a single NUL byte,
    so its on-stack size is ``len("KEY=VALUE") + 1``. We encode to bytes so
    multibyte values (UTF-8) are counted correctly.
    """
    total = 0
    if verbose:
        print(f"{'bytes':>7}  variable")
        print(f"{'-----':>7}  --------")
    for key, value in env.items():
        entry = f"{key}={value}".encode("utf-8")
        size = len(entry) + 1  # +1 for the terminating NUL byte
        total += size
        if verbose:
            shown = key if len(key) <= 40 else key[:37] + "..."
            print(f"{size:>7}  {shown}")
    return total


def argv_byte_size(argv: list[str]) -> int:
    """Return the bytes the argv *strings* occupy on the stack.

    Like envp, each argument is stored as a NUL-terminated string, so an
    argument contributes ``len(arg) + 1`` bytes. argv[0] (the program path)
    is the piece that usually differs between a direct run (``./target``) and a
    GDB run (``/abs/path/to/target``), which is why it shifts stack addresses.
    """
    return sum(len(arg.encode("utf-8")) + 1 for arg in argv)


def report(env: dict[str, str], label: str, argv: list[str] | None = None) -> int:
    total = env_byte_size(env, verbose=True)
    print(f"\n{label}:")
    print(f"  variables : {len(env)}")
    print(f"  env total : {total} bytes "
          f"(string block, including one NUL per variable)")
    # The array of char* pointers (envp) also lives on the stack: one pointer
    # per variable plus a NULL terminator. 8 bytes each on x86-64.
    ptr_bytes = (len(env) + 1) * 8
    print(f"  envp ptrs : {ptr_bytes} bytes (x86-64: {len(env)}+1 pointers * 8)")

    if argv is not None:
        argv_total = argv_byte_size(argv)
        argv_ptr_bytes = (len(argv) + 1) * 8
        print(f"  argv      : {argv_total} bytes "
              f"({len(argv)} arg string(s), incl. one NUL each): {argv!r}")
        print(f"  argv ptrs : {argv_ptr_bytes} bytes (x86-64: {len(argv)}+1 pointers * 8)")
        total += argv_total
        print(f"  COMBINED  : {total} bytes (env strings + argv strings)")
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", nargs="?", default=str(DEFAULT_ENV_PATH),
                        help="path to a .env file (default: scripts/.env)")
    parser.add_argument("--current", action="store_true",
                        help="measure the current process environment instead of a file")
    parser.add_argument("--diff", nargs=2, metavar=("A", "B"),
                        help="compare two env files and print the byte delta")
    parser.add_argument("--argv", nargs="+", metavar="ARG",
                        help="fold argv strings into the total. In --diff mode pass "
                             "two program paths (A then B) to compare, e.g. "
                             "--argv ./target /abs/path/to/target; otherwise pass the "
                             "full argv (program path and its arguments).")
    args = parser.parse_args(argv)

    if args.diff:
        # In diff mode --argv is two program paths: one per side.
        argv_a: list[str] | None = None
        argv_b: list[str] | None = None
        if args.argv is not None:
            if len(args.argv) != 2:
                parser.error("--argv with --diff needs exactly two program paths "
                             "(A then B)")
            argv_a, argv_b = [args.argv[0]], [args.argv[1]]

        a = parse_env_file(Path(args.diff[0]))
        b = parse_env_file(Path(args.diff[1]))
        total_a = report(a, f"[A] {args.diff[0]}", argv=argv_a)
        print()
        total_b = report(b, f"[B] {args.diff[1]}", argv=argv_b)
        delta = total_b - total_a
        what = "env+argv string-block" if args.argv else "env string-block"
        print(f"\n{what} delta (B - A): {delta:+d} bytes")
        print("A stack address that appears in B will be shifted by roughly "
              f"{-delta:+d} bytes relative to A (more bytes -> lower addresses).")
        return 0

    if args.current:
        env = dict(os.environ)
        report(env, "current process environment", argv=args.argv)
        return 0

    env = parse_env_file(Path(args.path))
    report(env, f"env file: {args.path}", argv=args.argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
