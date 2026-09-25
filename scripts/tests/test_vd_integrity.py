"""Opt-in regression against the retained, licensed research sample.

VD_RESEARCH_ROOT points to matrix/analysis/vd-static-2026-09-22.
MATRIX_VD_PROFILE and MATRIX_VD_APK select a different pinned sample.
The sample is never copied into the repository or loaded as executable code.
"""
import importlib.util
import json
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('VD_RESEARCH_ROOT'), 'requires retained VD research sample')
class IntegrityRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global adapter
        spec = importlib.util.spec_from_file_location('vd_reference', ROOT/'profiles/vd/scripts/reference.py')
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        cls.research = Path(os.environ['VD_RESEARCH_ROOT'])
        cls.profile = json.loads(Path(os.environ.get('MATRIX_VD_PROFILE',ROOT/'profiles/vd/client-1.34.22.0-research.json')).read_text())
        cls.rule = cls.profile['managedLoaderIntegrity']
        cls.image = (cls.research/'managed'/cls.rule['assembly']).read_bytes()
        import zipfile
        cls.apk = Path(os.environ.get('MATRIX_VD_APK',cls.research.parents[1]/'artifacts/virtual-desktop-pico-1.34.22.0.apk'))
        with zipfile.ZipFile(cls.apk) as apk:
            cls.loader = apk.read(cls.rule['library'])
            cls.store = apk.read(cls.profile['managedSigner']['entry'])
        cls.routed = adapter.route_loader(cls.loader, cls.profile['libraries'][cls.rule['library']],cls.profile['outputPackage'])

    def test_embedded_route_is_own_package_and_rejects_overflow(self):
        self.assertEqual(len(self.loader),len(self.routed))
        self.assertNotIn(b'com.bytedance.pico.matrix\0',self.routed)
        self.assertIn(self.profile['outputPackage'].encode()+b'\0',self.routed)
        with self.assertRaises(ValueError):
            adapter.route_loader(self.loader,self.profile['libraries'][self.rule['library']],'org.example.'+'a'*100)

    def test_routing_changes_the_hash_that_original_managed_code_checks(self):
        import base64, hashlib
        original = base64.b64encode(hashlib.md5(self.loader).digest()).decode()
        routed = base64.b64encode(hashlib.md5(self.routed).digest()).decode()
        self.assertEqual(original, self.rule['expectedMd5Base64'])
        self.assertNotEqual(original, routed)
        patched, receipt = adapter.patch_loader_assembly(self.image, self.loader, self.routed, self.rule)
        self.assertEqual(receipt['adaptedMd5Base64'], routed)
        self.assertEqual(len(patched), len(self.image))

    def test_changed_input_and_unrouted_library_are_rejected(self):
        for image, library in ((self.image[:-1]+bytes([self.image[-1]^1]), self.routed),
                               (self.image, self.loader), (self.image, self.routed+b'\0')):
            with self.subTest(image_length=len(image), library_length=len(library)):
                with self.assertRaises(ValueError):
                    adapter.patch_loader_assembly(image, self.loader, library, self.rule)

    def test_both_patches_preserve_code_and_all_unrelated_assemblies(self):
        cert = (self.research/'adapted-signer.der').read_bytes()
        result, receipt = adapter.patch_store(self.store, cert, self.profile['managedSigner'], self.rule,
                                             self.loader, self.routed, self.profile['managedSignerHashes'])
        self.assertEqual(receipt['unchangedAssemblyCount'], 182)
        self.assertTrue(receipt['controlFlowUnchanged'])
        self.assertTrue(receipt['onlyIntegrityConstantsChanged'])
        self.assertEqual({p['assembly'] for p in receipt['patches']},
                         {'Pico.Platform.dll', 'VirtualDesktop.Android.dll', 'VirtualDesktop.Mobile.dll'})
        again, _ = adapter.patch_store(self.store, cert, self.profile['managedSigner'], self.rule,
                                      self.loader, self.routed, self.profile['managedSignerHashes'])
        self.assertEqual(result, again)

    def test_all_delayed_signer_checks_use_actual_certificate_hashes(self):
        import dnfile
        original = dnfile.dnPE(str(self.research/'managed/VirtualDesktop.Android.dll'))
        cert = bytes.fromhex(original.net.user_strings.get(1).value)
        self.assertEqual(adapter.certificate_hashes(cert), {'java':1778352252, 'x509':-1386013078})
        actual = (self.research/'adapted-signer.der').read_bytes()
        hashes = adapter.certificate_hashes(actual)
        rule = self.profile['managedSignerHashes']
        _, receipt = adapter.patch_signer_hashes((self.research/'managed'/rule['assembly']).read_bytes(), actual, rule)
        self.assertEqual(len(receipt['constants']), 4)
        for change in receipt['constants']:
            value = hashes[change['hash']]
            if change['type'].endswith('UserSettings'): value = adapter.signed32(value - 22)
            self.assertEqual(change['after'], value)

    def test_aot_changes_only_six_constant_operands_and_preserves_every_branch(self):
        import zipfile, struct
        from elftools.elf.elffile import ELFFile
        import io
        rule = self.profile['aotSignerHashes']
        with zipfile.ZipFile(self.apk) as apk:
            aot = apk.read(rule['entry'])
        actual = (self.research/'adapted-signer.der').read_bytes()
        patched, receipt = adapter.patch_aot_signer_hashes(aot, actual, rule)
        self.assertEqual(len(aot),len(patched))
        self.assertEqual(receipt['instructionCount'],6)
        section = ELFFile(io.BytesIO(aot)).get_section_by_name('.text')
        expected_offsets = set()
        for comparison in rule['comparisons']:
            value=0
            for name, shift in [('low',0),('high',16)]:
                offset=section['sh_offset']+int(comparison[name],16)-section['sh_addr']
                before, after = struct.unpack_from('<I',aot,offset)[0], struct.unpack_from('<I',patched,offset)[0]
                self.assertEqual(before & ~0x1fffe0,after & ~0x1fffe0)
                value |= ((after >> 5) & 65535) << shift
                expected_offsets.update(range(offset,offset+4))
            self.assertEqual(adapter.signed32(value),adapter.certificate_hashes(actual)[comparison['hash']])
        self.assertTrue(all(a==b or i in expected_offsets for i,(a,b) in enumerate(zip(aot,patched))))
        import dnfile
        original = dnfile.dnPE(str(self.research/'managed/VirtualDesktop.Android.dll'))
        original_cert = bytes.fromhex(original.net.user_strings.get(1).value)
        unchanged, _ = adapter.patch_aot_signer_hashes(aot, original_cert, rule)
        self.assertEqual(unchanged,aot)
        with self.assertRaises(ValueError):
            adapter.patch_aot_signer_hashes(aot+b'\0',actual,rule)
        shifted=json.loads(json.dumps(rule));shifted['comparisons'][0]['low']=hex(int(rule['comparisons'][0]['low'],16)-4)
        with self.assertRaises(ValueError):
            adapter.patch_aot_signer_hashes(aot,actual,shifted)


if __name__ == '__main__':
    unittest.main()
