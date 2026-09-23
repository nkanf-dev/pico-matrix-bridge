from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from profile_signing import parse_signer_sha256


class ProfileSigningTest(unittest.TestCase):
    def test_apksigner_versions_report_the_same_signer(self):
        digest = 'a' * 64
        self.assertEqual(digest, parse_signer_sha256(
            f'Signer #1 certificate SHA-256 digest: {digest.upper()}\n'))
        self.assertEqual(digest, parse_signer_sha256(
            f'V2 Signer: certificate SHA-256 digest: {digest}\n'
            f'V3 Signer: certificate SHA-256 digest: {digest}\n'))

    def test_multiple_signers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unique APK signer'):
            parse_signer_sha256(
                f'V2 Signer: certificate SHA-256 digest: {"a" * 64}\n'
                f'V3 Signer: certificate SHA-256 digest: {"b" * 64}\n')
