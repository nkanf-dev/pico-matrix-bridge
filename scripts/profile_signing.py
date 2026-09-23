"""Public profile publisher identity checks; private keys stay outside the repository."""
import hashlib
import os
from pathlib import Path
import re
import ssl
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_CERTIFICATE = ROOT / 'profiles/signing/profile-publisher.pem'


def certificate_sha256(path=OFFICIAL_CERTIFICATE):
    pem = Path(path).read_text()
    if pem.count('-----BEGIN CERTIFICATE-----') != 1 or pem.count('-----END CERTIFICATE-----') != 1:
        raise ValueError('Expected one profile publisher certificate')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def parse_signer_sha256(output):
    digests = {match.lower() for match in re.findall(
        r'^(?:Signer #\d+|V\d+ Signer:) certificate SHA-256 digest: ([0-9a-fA-F]{64})$',
        output, re.MULTILINE)}
    if len(digests) != 1:
        raise ValueError(f'Cannot establish a unique APK signer from apksigner output: {output!r}')
    return digests.pop()


def apk_signer(path):
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '')
    binaries = sorted((sdk / 'build-tools').glob('*/apksigner'), reverse=True)
    if not binaries:
        raise ValueError('ANDROID_HOME must provide Android build-tools/apksigner')
    result = subprocess.run([str(binaries[0]), 'verify', '--print-certs', str(path)],
                            check=True, capture_output=True, text=True)
    return parse_signer_sha256(result.stdout)
