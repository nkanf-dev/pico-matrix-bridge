#!/usr/bin/env python3
"""Build a reviewed profile using its own source tree and build script."""
import argparse
from pathlib import Path
import subprocess
import sys

from profile_registry import load

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key', required=True)
    args, options = parser.parse_known_args()
    load(args.key)
    builder = ROOT / 'profiles' / args.key / 'scripts/build.py'
    if not builder.is_file():
        raise ValueError(f'Profile has no build script: {args.key}')
    subprocess.run([sys.executable, str(builder), *options], check=True)


if __name__ == '__main__':
    main()
