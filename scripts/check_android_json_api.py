#!/usr/bin/env python3
"""Reject desktop-only org.json calls in code shipped to Android."""
import argparse
import os
from pathlib import Path
import re
import subprocess


def check(android_jar, paths):
    javap = str(Path(os.environ['JAVA_HOME']) / 'bin/javap') if os.environ.get('JAVA_HOME') else 'javap'
    classes = [str(file) for path in paths for file in path.rglob('*.class')]
    if not classes:
        raise ValueError('Compile the Android-shared classes before checking their JSON API')
    bytecode = subprocess.check_output([javap, '-verbose', *classes], text=True)
    references = set(re.findall(r'= (?:Interface)?Methodref\s+.*?// (org/json/\w+)\."?([\w<>]+)"?:([^\s]+)', bytecode))
    failures = []
    for owner in sorted({owner for owner, _, _ in references}):
        signatures = subprocess.check_output([javap, '-s', '-public', '-classpath', str(android_jar), owner.replace('/', '.')], text=True)
        supported = set()
        previous = ''
        for line in signatures.splitlines():
            if line.strip().startswith('descriptor:') and '(' in previous:
                name = previous.split('(', 1)[0].split()[-1]
                if name == owner.replace('/', '.'):
                    name = '<init>'
                supported.add((name, line.split('descriptor:', 1)[1].strip()))
            previous = line.strip()
        for target, name, descriptor in sorted(references):
            if target == owner and (name, descriptor) not in supported:
                failures.append(f'{owner}.{name}{descriptor}')
    if failures:
        raise ValueError('JSON calls absent on Android:\n' + '\n'.join(failures))
    print(f'Android JSON API: {len(references)} method references checked')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--android-jar', type=Path, required=True)
    parser.add_argument('paths', type=Path, nargs='+')
    args = parser.parse_args()
    check(args.android_jar, args.paths)
