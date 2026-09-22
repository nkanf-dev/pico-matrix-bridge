import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from contracts import compare
from assemble_bootstrap import patch_native

class MaintenanceTests(unittest.TestCase):
    def test_native_routing_preserves_length_and_class_names(self):
        data=b'\x7fELFpadding\0com.bytedance.pico.matrix\0com.bytedance.pico.matrix.server.ServerBrokerJni\0'
        patched,count=patch_native(data)
        self.assertEqual(count,1);self.assertEqual(len(patched),len(data))
        self.assertIn(b'org.picomatrix.bridge\0',patched)
        self.assertIn(b'com.bytedance.pico.matrix.server.ServerBrokerJni\0',patched)
        self.assertRaises(ValueError,patch_native,b'not elf')

    def test_matching_wire_contract_is_not_runtime_validation(self):
        old={'source':{'sha256':'a'},'contracts':{'commands':{'GET':1},'messages':{'Message':[{'tag':1,'adapter':'STRING'}]}},'entrypoints':{},'libraries':['old']}
        new=copy.deepcopy(old);new['source']['sha256']='b';new['libraries']=['new']
        result=compare(old,new)
        self.assertTrue(result['declarationsEqual']);self.assertFalse(result['nativeLibrariesEqual']);self.assertTrue(result['requiresDeviceValidation'])
        new['contracts']['messages']['Message'][0]['adapter']='INT32'
        self.assertFalse(compare(old,new)['declarationsEqual'])
        new=copy.deepcopy(old);new['contracts']['commands']['GET']=2
        self.assertFalse(compare(old,new)['declarationsEqual'])

if __name__=='__main__': unittest.main()
