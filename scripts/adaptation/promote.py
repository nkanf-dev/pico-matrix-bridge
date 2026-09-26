#!/usr/bin/env python3
"""Promote checked data only. Signing remains in the separate publisher workflow."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from policy import read_json, require, validate_bundle

ROOT = Path(__file__).resolve().parents[2]


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def published(input_sha):
    releases = json.loads(command('gh', 'api', f'repos/{os.environ["GITHUB_REPOSITORY"]}/releases?per_page=100'))
    return any(not r['draft'] and r['tag_name'].startswith('vd-profile-') and
               f'Input APK SHA-256: `{input_sha}`' in (r.get('body') or '') and
               {'matrix-profile-vd.apk', 'SHA256SUMS'} <= {a['name'] for a in r['assets'] if a['state'] == 'uploaded'} for r in releases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    args = parser.parse_args()
    head = command('git', 'rev-parse', 'HEAD')
    require(command('git', 'ls-remote', 'origin', 'refs/heads/main').split()[0] == head, 'Main changed; retry next run')
    current_recipe = read_json(ROOT / 'profiles/vd/recipe.json')
    current = current_recipe['profile']
    old = read_json(ROOT / 'profiles/vd' / f"client-{current['appVersion']}-{current['versionCode']}-research.json")
    proof = read_json(ROOT / 'profiles/vd/adaptation-baseline.json')
    result = validate_bundle(args.bundle, old, proof, head)
    target = old
    if result is not None:
        target, recipe, new_proof = result
        if target['inputSha256'] != old['inputSha256']:
            source_path = ROOT / 'profiles/vd' / f"client-{target['appVersion']}-{target['versionCode']}-research.json"
            require(not source_path.exists(), 'Refusing to replace an existing pinned source')
            paths = [source_path, ROOT / 'profiles/vd/recipe.json', ROOT / 'profiles/vd/adaptation-baseline.json']
            for path, value in zip(paths, (target, recipe, new_proof)):
                path.write_text(json.dumps(value, indent=2) + '\n')
            command('git', 'add', '--', *(str(p) for p in paths))
            command('git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                    'commit', '-m', f"feat(vd): adapt build {target['versionCode']}")
            # No force push, no merge of a different base. A race rejects the push.
            command('git', '-c', 'credential.helper=!gh auth git-credential', 'push', 'origin', 'HEAD:main')
            head = command('git', 'rev-parse', 'HEAD')
    if not published(target['inputSha256']):
        command('gh', 'workflow', 'run', 'publish-profile.yml', '--ref', 'main', '-f', 'profile=vd', '-f', f'expected_sha={head}')
        print('Verified profile queued for isolated signing')
    else:
        print('This input already has a published profile')


if __name__ == '__main__':
    main()
