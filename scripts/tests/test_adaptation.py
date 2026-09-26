"""No licensed binary is required for boundary tests; replay is opt-in."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/adaptation'))
import policy
DEPS = all(importlib.util.find_spec(m) for m in ('capstone', 'dnfile', 'dncil', 'elftools', 'lz4'))


class CommitPolicy(unittest.TestCase):
    def test_only_relocation_fields_may_change(self):
        old = json.loads((ROOT / 'profiles/vd/client-1.34.22.0-research.json').read_text())
        new = json.loads((ROOT / 'profiles/vd/client-1.34.22.0-10709-research.json').read_text())
        self.assertEqual(policy.invariant_profile(old), policy.invariant_profile(new))
        for key in ('outputPackage', 'recipe', 'package'):
            changed = copy.deepcopy(new); changed[key] = 'untrusted'
            self.assertNotEqual(policy.invariant_profile(old), policy.invariant_profile(changed))
        renamed = copy.deepcopy(new)
        renamed['managedSignerHashes']['methods'][2]['method'] = '<GetHasValidIdentityAsync>b__475_0'
        renamed['aotSignerHashes']['comparisons'][2]['method'] = 'UserSettings::<GetHasValidIdentityAsync>b__475_0'
        self.assertEqual(policy.invariant_profile(old), policy.invariant_profile(renamed))
        renamed['managedSignerHashes']['methods'][2]['method'] = 'AlwaysTrue'
        self.assertNotEqual(policy.invariant_profile(old), policy.invariant_profile(renamed))
        changed = copy.deepcopy(new)
        changed['managedSignerHashes']['methods'][0]['count'] = 0
        self.assertNotEqual(policy.invariant_profile(old), policy.invariant_profile(changed))

    def test_stale_and_unverified_results_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'report.json').write_text(json.dumps({'baseCommit': 'a', 'previousInputSha256': 'x', 'state': 'review-required'}))
            with self.assertRaisesRegex(ValueError, 'Stale'):
                policy.validate_bundle(path, {'inputSha256': 'x'}, {}, 'b')
            with self.assertRaisesRegex(ValueError, 'Unverified'):
                policy.validate_bundle(path, {'inputSha256': 'x'}, {}, 'a')

    def test_unchanged_cannot_smuggle_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'report.json').write_text(json.dumps({'baseCommit': 'a', 'previousInputSha256': 'x', 'inputSha256': 'x', 'state': 'unchanged'}))
            self.assertIsNone(policy.validate_bundle(path, {'inputSha256': 'x'}, {}, 'a'))
            (path / 'payload.sh').write_text('bad')
            with self.assertRaises(ValueError):
                policy.validate_bundle(path, {'inputSha256': 'x'}, {}, 'a')


@unittest.skipUnless(DEPS, 'requires pinned adaptation dependencies')
class NativeLocator(unittest.TestCase):
    def setUp(self):
        import analysis
        self.module = analysis
        self.rule = {'expected': 1778352252, 'low': '0x1000', 'high': '0x1004', 'compare': '0x1008'}
        words = [0xd503201f] * 40
        words[12:15] = [0x52800008 | ((self.rule['expected'] & 65535) << 5),
                        0x72a00008 | ((self.rule['expected'] >> 16) << 5), 0x6b08001f]
        self.code = struct.pack('<40I', *words)

    def test_context_not_nearest_offset(self):
        found = self.module.candidates(self.code, 0x8000, self.rule)
        self.assertEqual([x['low'] for x in found], ['0x8030'])
        doubled = self.module.candidates(self.code * 2, 0x8000, self.rule)
        self.assertEqual(len(doubled), 2)
        self.assertEqual(doubled[0]['contextSha256'], doubled[1]['contextSha256'])

    def test_modified_comparison_is_not_a_candidate(self):
        changed = bytearray(self.code); struct.pack_into('<I', changed, 56, 0x6b09001f)
        self.assertEqual(self.module.candidates(changed, 0x8000, self.rule), [])

    def test_gate_branch_polarity_changes_fingerprint(self):
        changed = bytearray(self.code); struct.pack_into('<I', changed, 60, 0x54000041)
        self.assertNotEqual(self.module.candidates(changed, 0x8000, self.rule)[0]['contextSha256'],
                            self.module.candidates(self.code, 0x8000, self.rule)[0]['contextSha256'])


@unittest.skipUnless(DEPS and os.environ.get('VD_REPLAY_OLD_APK') and os.environ.get('VD_REPLAY_NEW_APK'), 'requires two retained VD inputs')
class HistoricalReplay(unittest.TestCase):
    def test_10703_to_10709_matches_reviewed_recipe(self):
        from analysis import baseline, derive
        old = json.loads((ROOT / 'profiles/vd/client-1.34.22.0-research.json').read_text())
        proof = baseline(Path(os.environ['VD_REPLAY_OLD_APK']), old)
        source, recipe = derive(Path(os.environ['VD_REPLAY_NEW_APK']), old, proof, 10709, '1.34.22.0')
        self.assertEqual(source, json.loads((ROOT / 'profiles/vd/client-1.34.22.0-10709-research.json').read_text()))
        current = json.loads((ROOT / 'profiles/vd/recipe.json').read_text())
        self.assertEqual(recipe['store'], current['store']); self.assertEqual(recipe['aot'], current['aot'])
        proof['gates'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Managed gate changed'):
            derive(Path(os.environ['VD_REPLAY_NEW_APK']), old, proof, 10709, '1.34.22.0')

    def test_compiler_callback_rename_requires_identical_unique_body(self):
        from analysis import derive, fingerprint
        old = json.loads((ROOT / 'profiles/vd/client-1.34.22.0-10709-research.json').read_text())
        proof = json.loads((ROOT / 'profiles/vd/adaptation-baseline.json').read_text())
        actual = old['managedSignerHashes']['methods'][2]['method']
        previous = '<GetHasValidIdentityAsync>b__473_0'
        old['managedSignerHashes']['methods'][2]['method'] = previous
        old['aotSignerHashes']['comparisons'][2]['method'] = 'UserSettings::' + previous
        proof['profileSha256'] = fingerprint(old)
        proof['gates'][-1]['method'] = previous
        proof['native'][-1]['method'] = 'UserSettings::' + previous
        mapping = [{'oldMethod': previous, 'newMethod': actual}]
        source, recipe = derive(Path(os.environ['VD_REPLAY_NEW_APK']), old, proof, 10709, '1.34.22.0', mapping)
        self.assertEqual(source, json.loads((ROOT / 'profiles/vd/client-1.34.22.0-10709-research.json').read_text()))
        mapping[0]['newMethod'] = 'AlwaysTrue'
        with self.assertRaisesRegex(ValueError, 'Only compiler-numbered'):
            derive(Path(os.environ['VD_REPLAY_NEW_APK']), old, proof, 10709, '1.34.22.0', mapping)


if __name__ == '__main__':
    unittest.main()
