#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["dnfile==0.18.0", "dncil==1.0.2", "lz4==4.4.5", "pyelftools==0.33"]
# ///
"""Reproduce the VD research adaptation from a pinned original and local signing key.

Updates existing signer and loader comparisons to the copy's actual artifacts.
Preserves comparisons and control flow; changes only integrity constants, never
account/entitlement results. Retains the original AOT execution and synchronizes
the same actual-signer constants in both IL and the pinned native comparisons.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import zipfile

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes
from dncil.clr.token import StringToken
from elftools.elf.elffile import ELFFile
import lz4.block

ROOT = Path(__file__).resolve().parents[3]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def checked(condition, message):
    if not condition:
        raise ValueError(message)

def unpack_int(data, at):
    first = data[at]
    if first < 0x80:
        return first, 1
    if first < 0xc0:
        return ((first & 0x3f) << 8) | data[at + 1], 2
    if first < 0xe0:
        return ((first & 0x1f) << 24) | int.from_bytes(data[at + 1:at + 4], 'big'), 4
    raise ValueError('invalid ECMA-335 compressed integer')

def pack_int(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x8000).to_bytes(2, 'big')
    checked(value < 0x20000000, 'oversized metadata string')
    return (value | 0xc0000000).to_bytes(4, 'big')

def patch_assembly(image, certificate, rule):
    checked(digest(image) == rule['assemblySha256'], 'VD managed assembly changed')
    pe = dnfile.dnPE(data=image)
    checked(not pe.net.struct.Flags & 8, 'strong-name signed managed assembly needs separate analysis')
    methods = [m.row for t in pe.net.mdtables.TypeDef
               if f'{t.TypeNamespace}.{t.TypeName}' == rule['type']
               for m in t.MethodList if str(m.row.Name) == rule['method']]
    checked(len(methods) == 1, 'VD entry method is missing or ambiguous')
    method = methods[0]
    body = CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(method.Rva)))
    candidates = []
    for instruction in body.instructions:
        token = instruction.operand
        if instruction.opcode.name != 'ldstr' or not isinstance(token, StringToken):
            continue
        index = token.value & 0xffffff
        value = pe.net.user_strings.get(index).value
        try:
            original = bytes.fromhex(value)
        except ValueError:
            continue
        if digest(original) == rule['originalCertificateSha256']:
            candidates.append((index, instruction.offset - body.header_size))
    checked(len(candidates) == 1, 'VD signer comparison literal changed or is ambiguous')
    index, il_offset = candidates[0]
    at = pe.net.user_strings.file_offset + index
    old_size, prefix = unpack_int(image, at)
    new_data = certificate.hex().encode('utf-16le') + b'\0'
    new_entry = pack_int(len(new_data)) + new_data
    checked(len(new_entry) <= prefix + old_size, 'new certificate cannot fit without relocating metadata')
    updated = bytearray(image)
    updated[at:at + prefix + old_size] = new_entry.ljust(prefix + old_size, b'\0')
    result = bytes(updated)
    reread = dnfile.dnPE(data=result)
    checked(reread.net.user_strings.get(index).value == certificate.hex(), 'signer literal failed round trip')
    # Tokens, assembly identity, MVID, method code, and all other bytes retain their positions.
    checked(image[:at] == result[:at] and image[at + prefix + old_size:] == result[at + prefix + old_size:],
            'unexpected managed change outside signer literal')
    for original_method, new_method in zip(pe.net.mdtables.MethodDef, reread.net.mdtables.MethodDef, strict=True):
        checked(original_method.Rva == new_method.Rva, 'method address moved')
        if original_method.Rva:
            old = CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(original_method.Rva)))
            new = CilMethodBody(CilMethodBodyReaderBytes(reread.get_data(new_method.Rva)))
            checked(old.raw_bytes == new.raw_bytes, 'IL or exception table changed')
    return result, dict(stringToken=f'0x{0x70000000 + index:08x}', ilOffset=il_offset,
                        before=digest(image), after=digest(result),
                        originalCertificateSha256=rule['originalCertificateSha256'],
                        adaptedCertificateSha256=digest(certificate))

def patch_loader_assembly(image, original_loader, routed_loader, rule):
    checked(digest(image) == rule['assemblySha256'], 'Pico.Platform assembly changed')
    checked(len(original_loader) == len(routed_loader) == rule['expectedBytes'], 'loader size changed')
    before_hash = base64.b64encode(hashlib.md5(original_loader).digest()).decode()
    after_hash = base64.b64encode(hashlib.md5(routed_loader).digest()).decode()
    checked(before_hash == rule['expectedMd5Base64'], 'original loader does not match managed expectation')
    checked(before_hash != after_hash, 'loader routing did not change its hash')
    pe = dnfile.dnPE(data=image)
    checked(not pe.net.struct.Flags & 8, 'strong-name signed managed assembly needs separate analysis')
    methods = [m.row for t in pe.net.mdtables.TypeDef
               if f'{t.TypeNamespace}.{t.TypeName}' == rule['type']
               for m in t.MethodList if str(m.row.Name) == rule['method']]
    checked(len(methods) == 1, 'platform initializer is missing or ambiguous')
    body = CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(methods[0].Rva)))
    candidates, calls, strings = [], set(), []
    for ins in body.instructions:
        token = ins.operand
        if ins.opcode.name == 'ldstr' and isinstance(token, StringToken):
            index = token.value & 0xffffff
            value = pe.net.user_strings.get(index).value
            strings.append(value)
            if value == before_hash:
                candidates.append((index, ins.offset - body.header_size))
        if ins.opcode.name in ('call', 'callvirt') and token.value >> 24 == 0x0a:
            row = pe.net.mdtables.MemberRef.rows[(token.value & 0xffffff) - 1]
            owner = row.Class.row
            if hasattr(owner, 'TypeName'):
                calls.add(f'{owner.TypeNamespace}.{owner.TypeName}::{row.Name}')
    checked({'System.IO.File::OpenRead', 'System.Security.Cryptography.MD5::Create',
             'System.Security.Cryptography.HashAlgorithm::ComputeHash', 'System.Convert::ToBase64String',
             'System.String::op_Inequality'} <= calls, 'loader verification structure changed')
    checked(Path(rule['library']).name in strings, 'initializer hashes a different file')
    checked(sum(i.opcode.name == 'ldc.i4' and i.operand == rule['expectedBytes'] for i in body.instructions) == 2,
            'loader size checks changed')
    checked(len(candidates) == 1, 'loader hash literal missing or ambiguous')
    index, il_offset = candidates[0]
    at = pe.net.user_strings.file_offset + index
    old_size, prefix = unpack_int(image, at)
    new_data = after_hash.encode('utf-16le') + b'\0'
    new_entry = pack_int(len(new_data)) + new_data
    checked(len(new_entry) == prefix + old_size, 'hash literal changed length')
    result = image[:at] + new_entry + image[at + prefix + old_size:]
    reread = dnfile.dnPE(data=result)
    checked(reread.net.user_strings.get(index).value == after_hash, 'loader hash failed round trip')
    for old, new in zip(pe.net.mdtables.MethodDef, reread.net.mdtables.MethodDef, strict=True):
        checked(old.Rva == new.Rva, 'method address moved')
        if old.Rva:
            checked(CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(old.Rva))).raw_bytes ==
                    CilMethodBody(CilMethodBodyReaderBytes(reread.get_data(new.Rva))).raw_bytes,
                    'IL or exception table changed')
    return result, dict(stringToken=f'0x{0x70000000 + index:08x}', ilOffset=il_offset,
                        before=digest(image), after=digest(result), originalMd5Base64=before_hash,
                        adaptedMd5Base64=after_hash, loaderBytes=len(routed_loader),
                        library=rule['library'], adaptedLibrarySha256=digest(routed_loader))

def route_loader(image, rule, package='org.picomatrix.bridge'):
    checked(digest(image) == rule['sha256'], 'native loader changed')
    original, target = b'com.bytedance.pico.matrix\0', package.encode('ascii')+b'\0'
    checked(len(target)<=len(original), 'native package route does not fit')
    checked(image.startswith(b'\x7fELF'), 'native loader is not ELF')
    checked(image.count(original) == rule['replacements'] == 1, 'native routing count changed')
    return image.replace(original, target.ljust(len(original), b'\0'))

def signed32(value):
    return (value + (1 << 31)) % (1 << 32) - (1 << 31)

def certificate_hashes(certificate):
    # Android Signature.hashCode uses Arrays.hashCode(byte[]), with signed bytes.
    java = 1
    for byte in certificate:
        java = signed32(31 * java + (byte if byte < 128 else byte - 256))
    # X509Certificate.GetHashCode uses the first four SHA-1 thumbprint bytes.
    return dict(java=java, x509=int.from_bytes(hashlib.sha1(certificate).digest()[:4], 'big', signed=True))

def patch_aot_signer_hashes(image, certificate, rule):
    checked(digest(image) == rule['sha256'], 'AOT image differs from pinned profile')
    elf = ELFFile(io.BytesIO(image))
    checked(elf['e_machine'] == 'EM_AARCH64' and elf.little_endian and rule['architecture'] == 'aarch64',
            'unsupported AOT architecture')
    section = elf.get_section_by_name('.text')
    checked(section is not None, 'AOT text section missing')
    def offset(address):
        address = int(address, 16)
        checked(address % 4 == 0 and section['sh_addr'] <= address <= section['sh_addr'] + section['sh_size'] - 4,
                'comparison outside AOT text')
        return section['sh_offset'] + address - section['sh_addr']
    hashes = certificate_hashes(certificate)
    result, constants, touched = bytearray(image), [], set()
    checked(len(rule['comparisons']) == 3, 'expected three native signer comparisons')
    for comparison in rule['comparisons']:
        low, high, cmp = (offset(comparison[k]) for k in ('low', 'high', 'compare'))
        expected = comparison['expected'] & 0xffffffff
        replacement = hashes[comparison['hash']] & 0xffffffff
        # MOVZ W8,#lo ; MOVK W8,#hi,LSL#16 ; CMP W0,W8.
        # LLVM folds the UserSettings subtraction into this comparison and
        # merges the two identical Keyboard checks into one native comparison.
        checked(struct.unpack_from('<I', image, cmp)[0] == 0x6b08001f, 'native comparison changed')
        for at, opcode, shift in ((low, 0x52800008, 0), (high, 0x72a00008, 16)):
            checked(at not in touched, 'overlapping native constants')
            touched.add(at)
            before = opcode | (((expected >> shift) & 0xffff) << 5)
            checked(struct.unpack_from('<I', image, at)[0] == before, 'native signer constant changed')
            after = opcode | (((replacement >> shift) & 0xffff) << 5)
            struct.pack_into('<I', result, at, after)
        constants.append({**comparison, 'replacement': signed32(replacement)})
    allowed = {offset + byte for offset in touched for byte in range(4)}
    checked(all(a == b or i in allowed for i, (a, b) in enumerate(zip(image, result))),
            'unrelated AOT bytes changed')
    return bytes(result), dict(entry=rule['entry'], originalSha256=digest(image), sha256=digest(result),
                               controlFlowUnchanged=True, constants=constants, instructionCount=6)

def patch_signer_hashes(image, certificate, rule):
    checked(digest(image) == rule['assemblySha256'], 'mobile assembly changed')
    pe = dnfile.dnPE(data=image)
    checked(not pe.net.struct.Flags & 8, 'strong-name signed assembly needs separate analysis')
    hashes = certificate_hashes(certificate)
    originals = dict(java=rule['originalJavaHash'], x509=rule['originalX509Hash'])
    result = bytearray(image)
    changes = []
    allowed_bytes = set()
    for selector in rule['methods']:
        methods = [m.row for t in pe.net.mdtables.TypeDef
                   if f'{t.TypeNamespace}.{t.TypeName}' == selector['type']
                   for m in t.MethodList if str(m.row.Name) == selector['method']]
        checked(len(methods) == 1, 'signer hash method missing or ambiguous')
        method = methods[0]
        body = CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(method.Rva)))
        calls = set()
        for ins in body.instructions:
            token = ins.operand
            if ins.opcode.name in ('call', 'callvirt') and token.value >> 24 == 0x0a:
                row = pe.net.mdtables.MemberRef.rows[(token.value & 0xffffff) - 1]
                owner = row.Class.row
                if hasattr(owner, 'TypeName'):
                    calls.add(f'{owner.TypeNamespace}.{owner.TypeName}::{row.Name}')
        checked(set(selector['requiredCalls']) <= calls, 'signer hash source changed')
        subtract = selector['subtract']
        if subtract:
            checked(any(i.opcode.name == 'ldc.i4.s' and i.operand == subtract and
                        body.instructions[n + 1].opcode.name == 'sub'
                        for n, i in enumerate(body.instructions[:-1])), 'signer hash adjustment changed')
        old = signed32(originals[selector['hash']] - subtract)
        new = signed32(hashes[selector['hash']] - subtract)
        candidates = [i for i in body.instructions if i.opcode.name == 'ldc.i4' and i.operand == old]
        checked(len(candidates) == selector['count'], 'signer hash constant count changed')
        for ins in candidates:
            # dncil's offset includes the method header; only the four-byte operand changes.
            at = pe.get_offset_from_rva(method.Rva) + ins.offset + 1
            checked(image[at-1] == 0x20 and struct.unpack_from('<i', image, at)[0] == old,
                    'signer hash operand location does not match IL')
            struct.pack_into('<i', result, at, new)
            allowed_bytes.update(range(at, at+4))
            changes.append(dict(type=selector['type'], method=selector['method'],
                                ilOffset=ins.offset-body.header_size, before=old, after=new, hash=selector['hash']))
    checked(all(a == b or n in allowed_bytes for n, (a,b) in enumerate(zip(image, result, strict=True))),
            'unexpected change outside signer hash operands')
    reread = dnfile.dnPE(data=bytes(result))
    for before, after in zip(pe.net.mdtables.MethodDef, reread.net.mdtables.MethodDef, strict=True):
        checked(before.Rva == after.Rva, 'method address moved')
        if before.Rva:
            a = CilMethodBody(CilMethodBodyReaderBytes(pe.get_data(before.Rva)))
            b = CilMethodBody(CilMethodBodyReaderBytes(reread.get_data(after.Rva)))
            checked(len(a.raw_bytes) == len(b.raw_bytes) and a.header_size == b.header_size, 'method layout changed')
            checked(a.raw_bytes[:a.header_size] == b.raw_bytes[:b.header_size], 'method header changed')
            for x,y in zip(a.instructions,b.instructions,strict=True):
                checked(x.offset == y.offset and x.opcode == y.opcode, 'control flow or opcode changed')
                operand_at = pe.get_offset_from_rva(before.Rva) + x.offset + 1
                if operand_at not in allowed_bytes:
                    checked(x.get_bytes() == y.get_bytes(), 'unrelated instruction changed')
            end = a.header_size + a.code_size
            checked(a.raw_bytes[end:] == b.raw_bytes[end:], 'exception table changed')
    return bytes(result), dict(before=digest(image), after=digest(result), constants=changes,
                              ilUnchanged=False, controlFlowUnchanged=True, onlyIntegrityConstantsChanged=True)

def patch_store(blob, certificate, rule, loader_rule, original_loader, routed_loader, hashes_rule):
    checked(digest(blob) == rule['sha256'], 'VD assembly store changed')
    elf = ELFFile(io.BytesIO(blob))
    section = elf.get_section_by_name('payload')
    checked(section is not None, 'managed ELF has no payload')
    store = section.data()
    magic, version, count, index_count, index_size = struct.unpack_from('<5I', store)
    checked(magic == 0x41424158 and version == int(rule['storeVersion'], 16), 'unsupported store format')
    checked(0 < count < 4096 and index_size == index_count * 12, 'unexpected store index')
    descriptor_start = 20 + index_size
    entries = [struct.unpack_from('<7I', store, descriptor_start + n * 28) for n in range(count)]
    pos = descriptor_start + count * 28
    matches = []
    for number, entry in enumerate(entries):
        length, = struct.unpack_from('<I', store, pos)
        pos += 4
        checked(0 < length < 256 and pos + length <= len(store), 'invalid assembly name')
        name = store[pos:pos + length].decode('utf-8')
        pos += length
        if name in (rule['assembly'], loader_rule['assembly'], hashes_rule['assembly']):
            matches.append((name, number, entry))
    checked(len(matches) == 3 and len({m[0] for m in matches}) == 3, 'managed target assembly missing or repeated')
    result = bytearray(blob)
    base = section['sh_offset']
    extension = bytearray()
    evidence = []
    extents = []
    for name, number, (_, start, size, *_) in matches:
        checked(pos <= start and start + size <= len(store), 'invalid assembly extent')
        compressed = store[start:start + size]
        magic, mapping, original_size = struct.unpack_from('<3I', compressed)
        checked(magic == 0x5a4c4158 and 0 < original_size < 16 * 1024 * 1024, 'unexpected compression header')
        assembly = lz4.block.decompress(compressed[12:], uncompressed_size=original_size)
        if name == rule['assembly']:
            modified, item = patch_assembly(assembly, certificate, rule)
        elif name == loader_rule['assembly']:
            modified, item = patch_loader_assembly(assembly, original_loader, routed_loader, loader_rule)
        else:
            modified, item = patch_signer_hashes(assembly, certificate, hashes_rule)
        new_data = compressed[:12] + lz4.block.compress(modified, mode='high_compression', compression=12, store_size=False)
        checked(lz4.block.decompress(new_data[12:], uncompressed_size=original_size) == modified, 'compression round trip failed')
        if len(new_data) <= size:
            result[base + start:base + start + size] = new_data.ljust(size, b'\0')
            updated_start = start
        else:
            updated_start = len(store) + len(extension)
            extension.extend(new_data.ljust((len(new_data) + 7) & ~7, b'\0'))
        struct.pack_into('<II', result, base + descriptor_start + number * 28 + 4, updated_start, len(new_data))
        extents.append((updated_start, new_data))
        item.update(assembly=name, descriptorIndex=number, originalCompressedBytes=size, compressedBytes=len(new_data))
        evidence.append(item)
    if extension:
        # Mono's store payload is not loadable. Preserve all unrelated extents.
        end = base + len(store)
        checked(elf.elfclass == 64 and elf.little_endian and elf['e_shentsize'] == 64,
                'unsupported ELF wrapper')
        checked(elf['e_shoff'] >= end and elf['e_phoff'] < base, 'unexpected ELF table layout')
        checked(all(s['p_offset'] + s['p_filesz'] <= base for s in elf.iter_segments()),
                'payload overlaps a loadable segment')
        sections = list(elf.iter_sections())
        checked(all(s.name == 'payload' or s['sh_offset'] < base for s in sections),
                'additional sections follow the payload')
        result[end:end] = extension
        new_table = elf['e_shoff'] + len(extension)
        struct.pack_into('<Q', result, 40, new_table)
        payload_index = next(i for i, s in enumerate(sections) if s.name == 'payload')
        struct.pack_into('<Q', result, new_table + payload_index * 64 + 32, len(store) + len(extension))
    reread = ELFFile(io.BytesIO(result)).get_section_by_name('payload').data()
    for start, data in extents:
        checked(reread[start:start + len(data)] == data, 'ELF payload failed round trip')
    for i, entry in enumerate(entries):
        if i not in {m[1] for m in matches}:
            _, begin, length, *_ = entry
            checked(reread[begin:begin + length] == store[begin:begin + length], 'unrelated assembly changed')
    return bytes(result), dict(patches=evidence, ilUnchanged=False, controlFlowUnchanged=True,
                              onlyIntegrityConstantsChanged=True, metadataIdentityUnchanged=True,
                              otherAssembliesUnchanged=True, unchangedAssemblyCount=count-len(matches),
                              storeGrowthBytes=len(result)-len(blob))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--profile', type=Path, default=ROOT / 'profiles/vd/client-1.34.22.0-research.json')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--build-tools', required=True, type=Path)
    parser.add_argument('--research-debug-key', action='store_true', required=True)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--matrix', type=Path, required=True)
    parser.add_argument('--provisioner-package', default='org.picomatrix.bridge')
    args = parser.parse_args()
    source, output = args.input.resolve(strict=True), args.output.resolve()
    checked(source != output and not output.exists(), 'output must be a new file')
    profile = json.loads(args.profile.read_text())
    checked(profile['recipe'] == 'vd-embedded-v5', 'unsupported VD recipe')
    checked(file_digest(source) == profile['inputSha256'], 'input differs from VD profile')
    work = output.parent / (output.stem + '.work')
    checked(not work.exists(), 'work directory already exists; preserve or review the previous attempt')
    work.mkdir(parents=True)
    cert_path = work / 'signer.der'
    key = Path.home() / '.android/debug.keystore'
    subprocess.run(['keytool', '-exportcert', '-keystore', str(key), '-alias', 'androiddebugkey',
                    '-storepass', 'android', '-file', str(cert_path)], check=True)
    certificate = cert_path.read_bytes()
    with zipfile.ZipFile(source) as apk:
        blob = apk.read(profile['managedSigner']['entry'])
        original_loader = apk.read(profile['managedLoaderIntegrity']['library'])
        aot, aot_evidence = patch_aot_signer_hashes(apk.read(profile['aotSignerHashes']['entry']),
                                                  certificate, profile['aotSignerHashes'])
    routed_loader = route_loader(original_loader, profile['libraries'][profile['managedLoaderIntegrity']['library']], profile['outputPackage'])
    patched, evidence = patch_store(blob, certificate, profile['managedSigner'], profile['managedLoaderIntegrity'], original_loader, routed_loader, profile['managedSignerHashes'])
    patched_path = work / 'managed-store.so'
    patched_path.write_bytes(patched)
    evidence.update(inputSha256=profile['inputSha256'], path=str(patched_path), sha256=digest(patched))
    aot_path = work / 'mobile-aot.so'
    aot_path.write_bytes(aot)
    aot_evidence['path'] = str(aot_path)
    evidence['aotSignerHashes'] = aot_evidence
    from embedded_payload import prepare
    evidence['embedded']=prepare(source,args.matrix.resolve(strict=True),work,profile,certificate,args.provisioner_package)
    preparation = work / 'managed-preparation.json'
    preparation.write_text(json.dumps(evidence, indent=2) + '\n')
    if args.prepare_only:
        print(json.dumps(evidence, indent=2))
        return
    tool = ROOT / 'tools/build/install/tools/bin/tools'
    checked(tool.exists(), 'run ./gradlew :tools:installDist first')
    unsigned = work / 'unsigned.apk'
    subprocess.run([str(tool), 'adapt-vd-research', str(source), str(unsigned),
                    str(args.profile.resolve()), str(preparation)], check=True,
                   env={**os.environ, 'JAVA_OPTS': '-Xmx1g'})
    subprocess.run([str(args.build_tools / 'zipalign'), '-P', '16', '-f', '4', str(unsigned), str(output)], check=True)
    unsigned.unlink()
    subprocess.run([str(args.build_tools / 'apksigner'), 'sign', '--ks', str(key), '--ks-key-alias', 'androiddebugkey',
                    '--ks-pass', 'pass:android', '--key-pass', 'pass:android', str(output)], check=True)
    verified = subprocess.check_output([str(args.build_tools / 'apksigner'), 'verify', '--print-certs', str(output)], text=True)
    checked(f'Signer #1 certificate SHA-256 digest: {digest(certificate)}' in verified, 'APK signer differs from prepared comparison')
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(output) as adapted:
        before = {x.filename: (x.CRC, x.file_size) for x in original.infolist()}
        after = {x.filename: (x.CRC, x.file_size) for x in adapted.infolist()}
        changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
        expected = {'AndroidManifest.xml', profile['managedSigner']['entry'], profile['aotSignerHashes']['entry'], *profile['libraries'].keys()}
        checked({x for x in changed if not x.startswith('META-INF/')} == expected, 'unexpected APK changes')
        removed = sorted(before.keys() - after.keys())
        checked(not {x for x in removed if not x.startswith('META-INF/')}, 'unexpected APK removals')
        added={x for x in after.keys() - before.keys() if not x.startswith('META-INF/')}
        checked(added==set(evidence['embedded']['additions']), 'unexpected APK additions')
        for name,item in evidence['embedded']['additions'].items():
            checked(digest(adapted.read(name))==item['sha256'], 'embedded entry differs: '+name)
        checked(len(adapted.namelist()) == len(set(adapted.namelist())), 'duplicate APK entries')
        checked(digest(adapted.read(profile['managedSigner']['entry'])) == digest(patched), 'packaged managed store differs')
        checked(adapted.read(profile['managedLoaderIntegrity']['library']) == routed_loader, 'packaged loader differs from managed hash')
        checked(adapted.read(profile['aotSignerHashes']['entry']) == aot, 'packaged AOT differs from prepared comparisons')
    result = dict(profile=profile['id'], inputSha256=profile['inputSha256'], output=str(output),
                  outputSha256=file_digest(output), signerSha256=digest(certificate), bytes=output.stat().st_size,
                  changedEntries=changed, removedEntries=removed, addedEntries=sorted(added), managed=evidence, installed=False, functionalValidation=False)
    output.with_suffix('.apk.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'managed'}, indent=2))

if __name__ == '__main__':
    main()
