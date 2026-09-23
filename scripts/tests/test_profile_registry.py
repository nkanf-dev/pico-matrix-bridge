import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from profile_registry import validate


class ProfileRegistryTest(unittest.TestCase):
    def test_duplicate_match_rule_is_rejected_before_profile_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for key,matcher,priority in [('generic','*',0),('vd','VirtualDesktop.Android',100)]:
                (root/f'{key}.json').write_text(json.dumps({'schema':1,'profileKey':key,
                    'packageMatcher':matcher,'priority':priority}))
            self.assertEqual({'generic','vd'},set(validate(root)))
            (root/'other.json').write_text(json.dumps({'schema':1,'profileKey':'other',
                'packageMatcher':'VirtualDesktop.Android','priority':100}))
            with self.assertRaisesRegex(ValueError,'Ambiguous profile match rule'):
                validate(root)

