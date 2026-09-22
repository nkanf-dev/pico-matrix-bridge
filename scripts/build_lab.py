#!/usr/bin/env python3
"""Build the explicitly opted-in local Lab integration; never installs or publishes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    args = parser.parse_args()
    android = args.lab.resolve(strict=True) / 'apps/android'
    bundle = args.bundle.resolve(strict=True)
    manifest = (bundle / 'bundle.json').read_bytes()
    if json.loads(manifest)['schema'] != 1:
        raise ValueError('Unsupported bundle schema')
    subprocess.run([str(android / 'gradlew'), ':app:testDebugUnitTest', ':app:assembleDebug',
                    f'-PmatrixBridgeDir={ROOT}', f'-PmatrixBundleDir={bundle}', '--console=plain'],
                   cwd=android, check=True)
    apk = android / 'app/build/outputs/apk/debug/app-debug.apk'
    with zipfile.ZipFile(apk) as output:
        if output.read('assets/matrix-bridge/bundle.json') != manifest:
            raise ValueError('Packaged bundle differs from the requested bundle')
        for name, expected in json.loads(manifest)['files'].items():
            data = output.read('assets/matrix-bridge/' + name)
            if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
                raise ValueError('Packaged bundle member differs: ' + name)
    print(json.dumps({'apk': str(apk), 'bundleSha256': hashlib.sha256(manifest).hexdigest(),
                      'installed': False, 'published': False}))


if __name__ == '__main__':
    main()
