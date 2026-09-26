#!/usr/bin/env python3
"""Cheap authenticated metadata poll: no SDK build, APK or model invocation."""
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import zipfile
from pico_store_lab.client import PicoStoreClient
from pico_store_lab.protocol import PicoAuth, StoreTarget
from policy import require, read_json

ROOT = Path(__file__).resolve().parents[2]


def previous_review(metadata):
    """Avoid repeatedly downloading a rejected build while its evidence is retained."""
    if not os.environ.get('GH_TOKEN'):
        return False
    repo = os.environ['GITHUB_REPOSITORY']
    response = subprocess.check_output(['gh', 'api', f'repos/{repo}/actions/artifacts?name=vd-candidate&per_page=20'], text=True)
    for artifact in json.loads(response)['artifacts']:
        if artifact['expired'] or artifact['size_in_bytes'] > 512 * 1024:
            continue
        run_id = artifact['workflow_run']['id']
        run = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repo}/actions/runs/{run_id}'], text=True))
        if run.get('path') != '.github/workflows/adapt-vd.yml' or run.get('head_branch') != 'main':
            continue
        content = subprocess.check_output(['gh', 'api', f'repos/{repo}/actions/artifacts/{artifact["id"]}/zip'])
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            item = archive.getinfo('report.json')
            if item.file_size > 65536:
                continue
            report = json.loads(archive.read(item))
            if report.get('state') == 'review-required' and report.get('observedMetadata') == metadata:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recheck', action='store_true')
    args = parser.parse_args()
    profile = read_json(ROOT / 'profiles/vd/recipe.json')['profile']
    baseline = read_json(ROOT / 'profiles/vd/adaptation-baseline.json')
    raw = os.environ.get('PICO_AUTH_JSON')
    require(bool(raw), 'PICO session is missing')
    info = PicoStoreClient().download_info(StoreTarget('3540', 'VirtualDesktop.Android'), PicoAuth(**json.loads(raw)))
    metadata = {'versionCode': info.version_code, 'md5': info.md5, 'bytes': info.size}
    require(info.version_code >= profile['versionCode'], 'Store offered an older build; review required')
    changed = (info.version_code != profile['versionCode'] or info.md5 != baseline['apkMd5'] or info.size != baseline['apkBytes'])
    state = 'pending' if changed or args.recheck else 'unchanged'
    if changed and not args.recheck and previous_review(metadata):
        state = 'review-required'
    report = {'schema': 1, 'state': state, 'baseCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'previousInputSha256': profile['inputSha256'], 'inputSha256': profile['inputSha256'],
              'observedVersionCode': info.version_code, 'observedMetadata': metadata, 'agentUsed': False}
    args.output.mkdir(parents=True)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write(f'state={state}\n')
    print(json.dumps({'state': state, 'versionCode': info.version_code}))
    if state == 'review-required':
        print('This build already requires review; use recheck_current after changing the trusted rules.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Metadata observation failed: ' + type(error).__name__)
        raise SystemExit(1)
