#!/usr/bin/env python3
"""Compile metadata-selected VD integrity operands to a checked portable recipe.

Only pinned inputs are accepted. No APKs, assemblies, accounts or signing keys
are included in the result. The original checks and instruction layout remain.
"""
import argparse
import io
import json
from pathlib import Path
import struct
import zipfile
import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes
from dncil.clr.token import StringToken
from elftools.elf.elffile import ELFFile
import lz4.block
import adapt_vd as source


def method(pe, rule):
    rows = [m.row for t in pe.net.mdtables.TypeDef
            if f'{t.TypeNamespace}.{t.TypeName}' == rule['type']
            for m in t.MethodList if str(m.row.Name) == rule['method']]
    source.checked(len(rows) == 1, 'Ambiguous metadata method')
    return rows[0], CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(rows[0].Rva)))


def string_patch(image, rule, predicate, kind):
    pe = dnfile.dnPE(data=image)
    _, body = method(pe, rule)
    matches = [i.operand.value & 0xffffff for i in body.instructions
               if i.opcode.name == 'ldstr' and isinstance(i.operand, StringToken)
               and predicate(pe.net.user_strings.get(i.operand.value & 0xffffff).value)]
    source.checked(len(matches) == 1, 'Ambiguous integrity string')
    at = pe.net.user_strings.file_offset + matches[0]
    size, prefix = source.unpack_int(image, at)
    return dict(offset=at, expectedHex=image[at:at+size+prefix].hex(), kind=kind)


def compile_recipe(apk, profile):
    source.checked(profile['recipe'] == 'vd-embedded-v5', 'Unsupported source recipe')
    source.checked(isinstance(profile.get('versionCode'), int) and profile['versionCode'] > 0
                   and isinstance(profile.get('appVersion'), str) and profile['appVersion'], 'Missing application version metadata')
    source.checked(source.file_digest(apk) == profile['inputSha256'], 'Input differs from pinned VD sample')
    with zipfile.ZipFile(apk) as original:
        blob = original.read(profile['managedSigner']['entry'])
        source.checked(source.digest(blob) == profile['managedSigner']['sha256'], 'Store hash changed')
        elf = ELFFile(io.BytesIO(blob)); payload = elf.get_section_by_name('payload'); store = payload.data()
        magic, version, count, index_count, index_size = struct.unpack_from('<5I', store)
        source.checked(magic == 0x41424158 and version == int(profile['managedSigner']['storeVersion'], 16)
                       and count < 4096 and index_size == index_count*12, 'Store format changed')
        desc = 20+index_size; names_at = desc+count*28; entries = []
        for n in range(count):
            length, = struct.unpack_from('<I', store, names_at); names_at += 4
            name = store[names_at:names_at+length].decode(); names_at += length
            entries.append((name, n, struct.unpack_from('<7I', store, desc+n*28)))
        rules = {profile[k]['assembly']: (k, profile[k]) for k in ['managedSigner','managedLoaderIntegrity','managedSignerHashes']}
        assemblies = []; certificate = None
        for name, n, (_, start, length, *_) in entries:
            if name not in rules: continue
            key, rule = rules[name]
            magic, mapping, size = struct.unpack_from('<3I',store,start)
            source.checked(magic == 0x5a4c4158 and 0 < size < 16*1024*1024, 'Compression changed')
            image = lz4.block.decompress(store[start+12:start+length],uncompressed_size=size)
            source.checked(source.digest(image) == rule['assemblySha256'], 'Assembly changed')
            if key == 'managedSigner':
                def is_certificate(value):
                    try: return source.digest(bytes.fromhex(value)) == rule['originalCertificateSha256']
                    except ValueError: return False
                patch = string_patch(image,rule,is_certificate,'certificate')
                old=bytes.fromhex(patch['expectedHex']); size,prefix=source.unpack_int(old,0)
                certificate=bytes.fromhex(old[prefix:prefix+size-1].decode('utf-16le'))
                patches=[patch]
            elif key == 'managedLoaderIntegrity':
                patches=[string_patch(image,rule,lambda value:value==rule['expectedMd5Base64'],'loaderMd5')]
            else:
                patches=[]; pe=dnfile.dnPE(data=image)
                for selector in rule['methods']:
                    row,body=method(pe,selector)
                    old=source.signed32(rule['originalJavaHash' if selector['hash']=='java' else 'originalX509Hash']-selector['subtract'])
                    candidates=[i for i in body.instructions if i.opcode.name=='ldc.i4' and i.operand==old]
                    source.checked(len(candidates)==selector['count'],'Signer operand changed')
                    for instruction in candidates:
                        at=pe.get_offset_from_rva(row.Rva)+instruction.offset+1
                        patches.append(dict(offset=at,expectedHex=image[at:at+4].hex(),kind='hash32',hash=selector['hash'],subtract=selector['subtract'],opcodeOffset=at-1,opcode=0x20))
            assemblies.append(dict(name=name,descriptorOffset=desc+n*28,start=start,compressedSize=length,uncompressedSize=len(image),sha256=source.digest(image),patches=patches))
        source.checked(len(assemblies)==3 and certificate is not None,'Missing assemblies')
        loader_rule=profile['managedLoaderIntegrity'];loader=original.read(loader_rule['library'])
        routed=source.route_loader(loader,profile['libraries'][loader_rule['library']],profile['outputPackage'])
        # Run the original structural validator over all method calls, operands,
        # metadata identities, store extents and exception tables before export.
        source.patch_store(blob,certificate,profile['managedSigner'],loader_rule,loader,routed,profile['managedSignerHashes'])
        aot_rule=profile['aotSignerHashes'];aot=original.read(aot_rule['entry'])
        source.patch_aot_signer_hashes(aot,certificate,aot_rule)
        text=ELFFile(io.BytesIO(aot)).get_section_by_name('.text'); comparisons=[]
        for rule in aot_rule['comparisons']:
            item={**rule}
            for key in ['low','high','compare']: item[key]=text['sh_offset']+int(rule[key],16)-text['sh_addr']
            comparisons.append(item)
        profile=dict(profile)
        profile['appId']='3cd8ad26e891e5c2ac8beeba35588f8f'
        profile['launchActivity']='md59102214312e19799944a61bf7bc2f23e.VrActivity'
        profile['label']='Virtual Desktop · Matrix Bridge'
        profile['account']={'agwKey':'N6HCMSN3Gy45UEZNBo72hxiEnk5BMvKM'}
        return dict(schema=1,kind='checked-integrity-operands',profile=profile,
            store=dict(entry=profile['managedSigner']['entry'],sha256=source.digest(blob),payloadOffset=payload['sh_offset'],payloadSize=len(store),sectionTableOffset=elf['e_shoff'],payloadSectionIndex=next(i for i,s in enumerate(elf.iter_sections()) if s.name=='payload'),assemblies=assemblies),
            aot=dict(entry=aot_rule['entry'],sha256=source.digest(aot),comparisons=comparisons))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--profile',type=Path,default=source.ROOT/'profiles/clients/vd-1.34.22.0-research.json');a=p.parse_args()
    recipe=compile_recipe(a.input,json.loads(a.profile.read_text()))
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(recipe,indent=2)+'\n')
    print(json.dumps({'recipe':str(a.output),'sha256':source.file_digest(a.output),'assemblies':len(recipe['store']['assemblies'])}))

if __name__=='__main__':main()
