#!/usr/bin/env python3
"""Verify a publisher-signed profile and prepare its GitHub Release metadata."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile

from profile_registry import load
from profile_signing import apk_signer, certificate_sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key', required=True)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    definition = load(args.key)
    apk = args.apk.resolve(strict=True)
    expected_name = f'matrix-profile-{args.key}.apk'
    if apk.name != expected_name or apk_signer(apk) != certificate_sha256():
        raise ValueError('Profile name or publisher signature does not match')
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '')
    aapt = sorted((sdk / 'build-tools').glob('*/aapt'), reverse=True)
    if not aapt:
        raise ValueError('ANDROID_HOME must provide Android build-tools/aapt')
    badging = subprocess.run([str(aapt[0]), 'dump', 'badging', str(apk)],
                             check=True, capture_output=True, text=True).stdout
    identity = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging, re.M)
    if not identity or identity[1] != f'org.picomatrix.bridge.profile.{args.key}':
        raise ValueError('Wrong profile package')
    version = int(identity[2])
    if version not in range(1, 2_100_000_001):
        raise ValueError('Invalid profile version')
    built_at = datetime.fromtimestamp(version, timezone.utc)
    iso = built_at.strftime('%Y-%m-%dT%H:%M:%SZ')
    if identity[3] != iso:
        raise ValueError('Profile version is not a UTC timestamp')
    with ZipFile(apk) as archive:
        if archive.namelist().count('assets/profile.json') != 1:
            raise ValueError('Expected one profile recipe')
        entry = archive.getinfo('assets/profile.json')
        if entry.file_size > 4 * 1024 * 1024:
            raise ValueError('Profile recipe is too large')
        recipe = json.loads(archive.read(entry))
    profile = recipe['profile']
    if (recipe['profileVersionCode'] != version or recipe['profileVersionUtc'] != iso or
        profile['profileVersionCode'] != version or profile['profileKey'] != args.key or
        profile['packageMatcher'] != definition['packageMatcher'] or profile['priority'] != definition['priority']):
        raise ValueError('Profile recipe does not match package or manifest')
    stamp = built_at.strftime('%Y%m%dT%H%M%SZ')
    tag = f'{args.key}-profile-{stamp}'
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'SHA256SUMS').write_text(f'{digest}  {expected_name}\n')
    source = os.environ.get('GITHUB_SHA', 'local build')
    (output / 'release-notes.md').write_text(
        f'# {args.key} profile — {iso}\n\n'
        f'Package match: `{definition["packageMatcher"]}`  \n'
        f'Priority: `{definition["priority"]}`  \n'
        f'Source commit: `{source}`  \n'
        f'Input APK SHA-256: `{profile.get("inputSha256", "not-pinned")}`  \n'
        f'APK SHA-256: `{digest}`\n')
    (output / 'receipt.json').write_text(json.dumps({
        'tag': tag, 'key': args.key, 'versionCode': version, 'versionName': iso,
        'sha256': digest, 'signerSha256': certificate_sha256(), 'sourceCommit': source,
    }, sort_keys=True, indent=2) + '\n')
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as stream:
            stream.write(f'tag={tag}\nasset={apk}\nnotes={output / "release-notes.md"}\nchecksums={output / "SHA256SUMS"}\n')
    print(json.dumps({'tag': tag, 'sha256': digest, 'signerSha256': certificate_sha256()}))


if __name__ == '__main__':
    main()
