#!/usr/bin/env python3
"""
Generate manpages from RST sources.
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

MAPPINGS = [
    ("doc/dhcpy6d.rst", "man/man8/dhcpy6d.8"),
    ("doc/dhcpy6d.conf.rst", "man/man5/dhcpy6d.conf.5"),
    ("doc/dhcpy6d-clients.conf.rst", "man/man5/dhcpy6d-clients.conf.5"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default=".", help="target repository/build root")
    args = parser.parse_args()

    out_root = pathlib.Path(args.out_dir).resolve()
    try:
        rst2man = subprocess.run(
            ["which", "rst2man"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        print("rst2man not found. Install python3-docutils.", file=sys.stderr)
        return 1

    for src_rel, dst_rel in MAPPINGS:
        src = ROOT / src_rel
        dst = out_root / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([rst2man, str(src), str(dst)], check=True)
        print(f"generated {dst}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
