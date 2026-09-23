import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from contracts import compare

class MaintenanceTests(unittest.TestCase):
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
