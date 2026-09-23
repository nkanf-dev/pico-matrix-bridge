#!/usr/bin/env python3
"""Build the explicitly opted-in local Lab integration; never installs or publishes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def signer(path):
    sdk=Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '')
    binaries=sorted((sdk/'build-tools').glob('*/apksigner'),reverse=True)
    if not binaries:raise ValueError('ANDROID_HOME must provide Android build-tools/apksigner')
    result=subprocess.run([str(binaries[0]),'verify','--print-certs',str(path)],check=True,capture_output=True,text=True)
    matches=re.findall(r'Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})',result.stdout)
    if len(matches)!=1:raise ValueError('Cannot establish APK signer')
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path, help='signed profile APK')
    args = parser.parse_args()
    android = args.lab.resolve(strict=True) / 'apps/android'
    bundle = args.bundle.resolve(strict=True)
    profile = args.profile.resolve(strict=True)
    manifest = (bundle / 'bundle.json').read_bytes()
    if json.loads(manifest)['schema'] != 1:
        raise ValueError('Unsupported bundle schema')
    subprocess.run([str(android / 'gradlew'), ':app:testDebugUnitTest', ':app:assembleDebug',
                    f'-PmatrixBridgeDir={ROOT}', f'-PmatrixBundleDir={bundle}',
                    f'-PmatrixProfileApk={profile}', '--console=plain'],
                   cwd=android, check=True)
    apk = android / 'app/build/outputs/apk/debug/app-debug.apk'
    with zipfile.ZipFile(apk) as output:
        if output.read('assets/matrix-bridge/bundle.json') != manifest:
            raise ValueError('Packaged bundle differs from the requested bundle')
        for name, expected in json.loads(manifest)['files'].items():
            data = output.read('assets/matrix-bridge/' + name)
            if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
                raise ValueError('Packaged bundle member differs: ' + name)
        if output.read('assets/matrix-profile-vd.apk') != profile.read_bytes():
            raise ValueError('Packaged profile differs from the signed profile APK')
    signer_hash=signer(apk)
    if signer(profile)!=signer_hash:
        raise ValueError('Profile and Lab APK signing certificates differ')
    print(json.dumps({'apk': str(apk), 'bundleSha256': hashlib.sha256(manifest).hexdigest(),
                      'profileSha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
                      'signerSha256': signer_hash,
                      'installed': False, 'published': False}))


if __name__ == '__main__':
    main()
