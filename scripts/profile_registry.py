#!/usr/bin/env python3
"""Check independently maintained profile match rules before packaging."""
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
MANIFESTS=ROOT/'profiles'
KEY=re.compile(r'[a-z][a-z0-9_]{0,63}')
PACKAGE=re.compile(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+')


def validate(directory=MANIFESTS):
    profiles={}
    routes={}
    for path in sorted(Path(directory).glob('*/manifest.json')):
        profile=json.loads(path.read_text())
        key=path.parent.name
        if not KEY.fullmatch(key) or profile.get('schema')!=1 or profile.get('profileKey')!=key:
            raise ValueError(f'Invalid profile identity: {path}')
        matcher=profile.get('packageMatcher')
        priority=profile.get('priority')
        if not isinstance(matcher,str) or not (matcher=='*' or PACKAGE.fullmatch(matcher)) or \
           type(priority) is not int or not -10000<=priority<=10000:
            raise ValueError(f'Invalid profile match rule: {path}')
        route=(matcher,priority)
        if route in routes:
            raise ValueError(f'Ambiguous profile match rule {route}: {routes[route]} and {key}')
        routes[route]=key
        profiles[key]=profile
    if not profiles:raise ValueError('No profile manifests found')
    return profiles


def load(key):
    return validate()[key]


if __name__=='__main__':
    profiles=validate()
    print(f'Validated {len(profiles)} profile match rules.')
