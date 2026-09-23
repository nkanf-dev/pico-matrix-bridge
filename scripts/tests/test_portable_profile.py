"""Opt-in differential regression; keeps the large original APK in place.

Set MATRIX_PORTABLE_RESEARCH to a durable output directory, MATRIX_VD_APK to the
pinned original, and MATRIX_TEST_CERT to the public DER certificate. No key is read.
"""
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[2]

@unittest.skipUnless(os.environ.get('MATRIX_PORTABLE_RESEARCH'),'requires retained pinned sample')
class PortableProfileRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        sys.path.insert(0,str(ROOT/'profiles/vd/scripts'))
        import reference
        from compile import compile_recipe
        cls.source=reference
        cls.apk=Path(os.environ['MATRIX_VD_APK']);cls.certificate=Path(os.environ['MATRIX_TEST_CERT']).read_bytes()
        cls.work=Path(os.environ['MATRIX_PORTABLE_RESEARCH']);cls.work.mkdir(parents=True,exist_ok=True)
        cls.profile=json.loads((ROOT/'profiles/vd/client-1.34.22.0-research.json').read_text())
        cls.recipe=compile_recipe(cls.apk,cls.profile)
        cls.recipe_path=cls.work/'vd-recipe.json';cls.recipe_path.write_text(json.dumps(cls.recipe,indent=2)+'\n')
        subprocess.run([str(ROOT/'tools/build/install/tools/bin/tools'),'apply-vd-recipe',str(cls.apk),str(cls.recipe_path),os.environ['MATRIX_TEST_CERT'],str(cls.work/'java')],check=True)

    def test_native_outputs_are_byte_identical_to_proven_python(self):
        p=self.profile
        with zipfile.ZipFile(self.apk) as apk:
            loader=apk.read(p['managedLoaderIntegrity']['library'])
            aot=apk.read(p['aotSignerHashes']['entry'])
        expected_loader=self.source.route_loader(loader,p['libraries'][p['managedLoaderIntegrity']['library']],p['outputPackage'])
        expected_aot,_=self.source.patch_aot_signer_hashes(aot,self.certificate,p['aotSignerHashes'])
        self.assertEqual(expected_loader,(self.work/'java/loader.so').read_bytes())
        self.assertEqual(expected_aot,(self.work/'java/mobile-aot.so').read_bytes())

    @staticmethod
    def assemblies(blob):
        import lz4.block
        from elftools.elf.elffile import ELFFile
        store=ELFFile(io.BytesIO(blob)).get_section_by_name('payload').data()
        _,_,count,_,index_size=struct.unpack_from('<5I',store);desc=20+index_size;pos=desc+count*28;result={}
        for n in range(count):
            size,=struct.unpack_from('<I',store,pos);pos+=4;name=store[pos:pos+size].decode();pos+=size
            _,start,length,*_=struct.unpack_from('<7I',store,desc+n*28)
            compressed=store[start:start+length];magic,_,uncompressed=struct.unpack_from('<3I',compressed)
            result[name]=lz4.block.decompress(compressed[12:],uncompressed_size=uncompressed) if magic==0x5a4c4158 else compressed
        return result

    def test_every_managed_assembly_matches_python_including_unchanged_182(self):
        p=self.profile
        with zipfile.ZipFile(self.apk) as apk:
            store=apk.read(p['managedSigner']['entry']);loader=apk.read(p['managedLoaderIntegrity']['library'])
        routed=(self.work/'java/loader.so').read_bytes()
        expected,receipt=self.source.patch_store(store,self.certificate,p['managedSigner'],p['managedLoaderIntegrity'],loader,routed,p['managedSignerHashes'])
        actual=(self.work/'java/managed-store.so').read_bytes()
        old=self.assemblies(store);reference=self.assemblies(expected);prepared=self.assemblies(actual)
        self.assertEqual(reference.keys(),prepared.keys());self.assertEqual(len(prepared),185)
        changed={name for name in old if old[name]!=prepared[name]}
        self.assertEqual(changed,{p[key]['assembly'] for key in ['managedSigner','managedLoaderIntegrity','managedSignerHashes']})
        for name in prepared:
            with self.subTest(assembly=name):self.assertEqual(reference[name],prepared[name])
        receipt.update(portableStoreSha256=self.source.digest(actual),pythonStoreSha256=self.source.digest(expected),all185AssembliesEqual=True,
                       certificateSha256=self.source.digest(self.certificate))
        (self.work/'differential-evidence.json').write_text(json.dumps(receipt,indent=2)+'\n')

if __name__=='__main__':unittest.main()
