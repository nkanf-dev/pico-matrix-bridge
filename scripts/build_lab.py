#!/usr/bin/env python3
"""Build the explicitly opted-in local Lab integration; never installs or publishes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile
from profile_signing import OFFICIAL_CERTIFICATE, apk_signer, certificate_sha256

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--profiles-dir', required=True, type=Path, help='directory of signed matrix-profile-<key>.apk files')
    parser.add_argument('--development-profile-certificate', type=Path,
                        help='local debug build only: use a contributor-owned profile signing certificate')
    args = parser.parse_args()
    android = args.lab.resolve(strict=True) / 'apps/android'
    bundle = args.bundle.resolve(strict=True)
    profiles_dir = args.profiles_dir.resolve(strict=True)
    profiles = sorted(p for p in profiles_dir.iterdir() if p.is_file() and re.fullmatch(r'matrix-profile-[a-z][a-z0-9_]{0,63}\.apk',p.name))
    if not profiles:raise ValueError('No signed profiles found')
    certificate = args.development_profile_certificate or OFFICIAL_CERTIFICATE
    trusted_signer = certificate_sha256(certificate)
    for profile in profiles:
        if apk_signer(profile) != trusted_signer:
            raise ValueError('Profile signer differs from the trusted publisher: ' + profile.name)
    manifest = (bundle / 'bundle.json').read_bytes()
    if json.loads(manifest)['schema'] != 1:
        raise ValueError('Unsupported bundle schema')
    subprocess.run([str(android / 'gradlew'), ':app:testDebugUnitTest', ':app:assembleDebug',
                    f'-PmatrixBridgeDir={ROOT}', f'-PmatrixBundleDir={bundle}',
                    f'-PmatrixProfileDir={profiles_dir}',
                    f'-PmatrixProfileSignerSha256={trusted_signer}', '--console=plain'],
                   cwd=android, check=True)
    apk = android / 'app/build/outputs/apk/debug/app-debug.apk'
    with zipfile.ZipFile(apk) as output:
        if output.read('assets/matrix-bridge/bundle.json') != manifest:
            raise ValueError('Packaged bundle differs from the requested bundle')
        for name, expected in json.loads(manifest)['files'].items():
            data = output.read('assets/matrix-bridge/' + name)
            if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
                raise ValueError('Packaged bundle member differs: ' + name)
        packaged={name.removeprefix('assets/') for name in output.namelist() if re.fullmatch(r'assets/matrix-profile-[a-z][a-z0-9_]{0,63}\.apk',name)}
        if packaged!={p.name for p in profiles}:raise ValueError('Packaged profile set differs from requested profiles')
        for profile in profiles:
            if output.read('assets/'+profile.name)!=profile.read_bytes():
                raise ValueError('Packaged profile differs: '+profile.name)
    signer_hash=apk_signer(apk)
    if signer_hash==trusted_signer:
        raise ValueError('Lab and profile publisher must use separate signing identities')
    print(json.dumps({'apk': str(apk), 'bundleSha256': hashlib.sha256(manifest).hexdigest(),
                      'profileSha256': {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in profiles},
                      'labSignerSha256': signer_hash, 'profileSignerSha256': trusted_signer,
                      'installed': False, 'published': False}))


if __name__ == '__main__':
    main()
