"""Relocate VD operands using structural evidence without executing APK contents."""
import copy
import base64
import difflib
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

import dnfile
from dncil.clr.token import Token, StringToken
from elftools.elf.elffile import ELFFile
import lz4.block
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'profiles/vd/scripts'))
import reference
from compile import compile_recipe, method

KEYS = ('managedSigner', 'managedLoaderIntegrity', 'managedSignerHashes')
MAX_ENTRY = 64 * 1024 * 1024
CALLBACK = re.compile(r'^<GetHasValidIdentityAsync>b__[0-9]+_[0-9]+$')


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def read_entry(archive, name):
    checked(archive.getinfo(name).file_size <= MAX_ENTRY, 'APK entry exceeds analysis budget')
    return archive.read(name)


def unpack_store(blob):
    elf = ELFFile(io.BytesIO(blob))
    checked(elf.elfclass == 64 and elf.little_endian, 'Store ELF layout changed')
    payload = elf.get_section_by_name('payload')
    checked(payload is not None, 'Store payload missing')
    store = payload.data()
    magic, version, count, index_count, index_size = struct.unpack_from('<5I', store)
    checked(magic == 0x41424158 and version == 0x80010002 and 0 < count < 4096
            and index_size == index_count * 12, 'Store format changed')
    desc = 20 + index_size
    pos = desc + count * 28
    result = {}
    for n in range(count):
        size, = struct.unpack_from('<I', store, pos)
        pos += 4
        checked(0 < size < 1024 and pos + size <= len(store), 'Invalid assembly name')
        name = store[pos:pos + size].decode()
        pos += size
        checked(name not in result, 'Duplicate assembly')
        _, start, length, *_ = struct.unpack_from('<7I', store, desc + n * 28)
        checked(length >= 12 and start + length <= len(store), 'Invalid assembly extent')
        result[name] = store[start:start + length]
    return result


def decompress(data):
    magic, _, size = struct.unpack_from('<3I', data)
    if magic != 0x5a4c4158:
        return data
    checked(0 < size <= 16 * 1024 * 1024, 'Assembly exceeds analysis budget')
    return lz4.block.decompress(data[12:], uncompressed_size=size)


def row_identity(pe, row, depth=0):
    checked(depth < 24, 'Metadata reference nesting exceeds budget')
    def identity(value):
        return row_identity(pe, value, depth + 1)
    kind = type(row).__name__
    if kind == 'TypeDefRow':
        parents = [n.EnclosingClass.row for n in pe.net.mdtables.NestedClass or [] if n.NestedClass.row is row]
        return [kind, str(row.TypeNamespace), str(row.TypeName), identity(parents[0]) if parents else None]
    if kind == 'TypeRefRow':
        return [kind, str(row.TypeNamespace), str(row.TypeName), identity(row.ResolutionScope.row)]
    if kind == 'AssemblyRefRow':
        return [kind, str(row.Name), row.MajorVersion, row.MinorVersion, row.BuildNumber,
                row.RevisionNumber, row.PublicKey.value.hex()]
    if kind == 'ModuleRow':
        return [kind, str(row.Name)]
    if kind in ('TypeSpecRow', 'StandAloneSigRow'):
        return [kind, row.Signature.value.hex()]
    if kind == 'MemberRefRow':
        return [kind, identity(row.Class.row), str(row.Name), row.Signature.value.hex()]
    if kind in ('MethodDefRow', 'FieldRow'):
        field = 'MethodList' if kind == 'MethodDefRow' else 'FieldList'
        owner = next(t for t in pe.net.mdtables.TypeDef if any(x.row is row for x in getattr(t, field)))
        return [kind, identity(owner), str(row.Name), row.Signature.value.hex()]
    if kind == 'MethodSpecRow':
        return [kind, identity(row.Method.row), row.Instantiation.value.hex()]
    raise ValueError('Unresolved metadata kind: ' + kind)


def operand_identity(pe, operand):
    if isinstance(operand, StringToken):
        # Preserve equality without publishing certificate literals or app strings.
        return ['string-sha256', digest(pe.net.user_strings.get(operand.value & 0xffffff).value.encode())]
    if isinstance(operand, Token):
        return row_identity(pe, pe.net.mdtables.tables[operand.value >> 24].rows[(operand.value & 0xffffff) - 1])
    return str(operand)


def managed_gate(image, selector):
    pe = dnfile.dnPE(data=image)
    row, body = method(pe, selector)
    eh = []
    for h in body.exception_handlers:
        eh.append({k: operand_identity(pe, getattr(h, k)) for k in
                   ('exception_type', 'try_start', 'try_end', 'handler_start', 'handler_end', 'filter_start', 'catch_type')})
    value = {'signature': row.Signature.value.hex(), 'maxStack': body.max_stack,
             'flags': str(body.flags), 'locals': operand_identity(pe, body.local_var_sig_tok),
             'instructions': [(i.offset, i.opcode.name, operand_identity(pe, i.operand)) for i in body.instructions],
             'handlers': eh}
    return {'sha256': fingerprint(value), 'token': f'0x{0x06000000 + pe.net.mdtables.MethodDef.rows.index(row) + 1:08x}',
            'instructionCount': len(body.instructions)}


def text_section(data):
    elf = ELFFile(io.BytesIO(data))
    checked(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64', 'AOT architecture changed')
    section = elf.get_section_by_name('.text')
    checked(section is not None, 'AOT text missing')
    return section.data(), section['sh_addr']


def native_context(code, base, address):
    """22 instructions: retain registers, virtual slots, constants and branch deltas.

    Only PC-relative page addresses, their literal-load offsets and direct call
    destinations are normalized. This is a checked pattern, not a proof of whole
    program equivalence. Unknown code shape is deliberately not auto-approved.
    """
    start = address - base - 48
    checked(start >= 0 and start + 88 <= len(code), 'Truncated native context')
    instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code[start:start + 88], address - 48))
    checked(len(instructions) == 22, 'Undecodable native context')
    pages = set()
    result = []
    for ins in instructions:
        op = ins.op_str
        if ins.mnemonic == 'adrp':
            pages.add(op.split(',')[0])
            op = op.split(',')[0] + ', <page>'
        elif ins.mnemonic == 'bl':
            op = '<direct-call>'
        elif ins.mnemonic in ('b', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz') or ins.mnemonic.startswith('b.'):
            op = re.sub(r'#0x([0-9a-f]+)$', lambda m: '<relative:' + str(int(m[1], 16) - address) + '>', op)
        else:
            for register in tuple(pages):
                if ins.mnemonic.startswith(('ldr', 'ldur')) and f'[{register}, #' in op:
                    op = re.sub(r'(\[' + register + r', )#(?:0x[0-9a-f]+|[0-9]+)(\])', r'\1<page-offset>\2', op)
                # The destination overwrites a known page register; no later mask.
                if op.split(',')[0] == register:
                    pages.remove(register)
        result.append([ins.mnemonic, op])
    return result


def candidates(code, base, rule):
    low_word = 0x52800008 | ((rule['expected'] & 0xffff) << 5)
    high_word = 0x72a00008 | (((rule['expected'] >> 16) & 0xffff) << 5)
    dh = int(rule['high'], 16) - int(rule['low'], 16)
    dc = int(rule['compare'], 16) - int(rule['low'], 16)
    matches = []
    for at in range(48, len(code) - max(dc + 4, 40), 4):
        if (struct.unpack_from('<I', code, at)[0] == low_word
                and struct.unpack_from('<I', code, at + dh)[0] == high_word
                and struct.unpack_from('<I', code, at + dc)[0] == 0x6b08001f):
            matches.append({'low': hex(base + at), 'high': hex(base + at + dh),
                            'compare': hex(base + at + dc),
                            'contextSha256': fingerprint(native_context(code, base, base + at))})
    return matches


def locate_native(code, base, rule, anchor):
    """Prefer exact context, otherwise require one clearly better structural match."""
    found = candidates(code, base, rule)
    exact = [item for item in found if item['contextSha256'] == anchor['contextSha256']]
    if len(exact) == 1:
        return exact[0]
    checked(not exact, 'Native context is ambiguous: ' + rule['method'])
    previous = anchor.get('context')
    checked(isinstance(previous, list) and len(previous) == 22, 'Native comparison has no reference context: ' + rule['method'])
    scores = []
    for item in found:
        context = native_context(code, base, int(item['low'], 16))
        score = difflib.SequenceMatcher(None, [tuple(i) for i in previous],
                                        [tuple(i) for i in context], autojunk=False).ratio()
        scores.append((score, item))
    scores.sort(key=lambda entry: entry[0], reverse=True)
    checked(bool(scores) and scores[0][0] >= 0.55 and
            (len(scores) == 1 or scores[0][0] - scores[1][0] >= 0.20),
            'Native comparison changed or ambiguous: ' + rule['method'])
    return scores[0][1]


def callback_candidates(image, selector):
    """Only compiler-numbered identity callbacks, in the same declaring type."""
    pe = dnfile.dnPE(data=image)
    names = [str(m.row.Name) for t in pe.net.mdtables.TypeDef
             if f'{t.TypeNamespace}.{t.TypeName}' == selector['type']
             for m in t.MethodList if CALLBACK.fullmatch(str(m.row.Name))]
    checked(len(names) <= 16, 'Too many identity callback candidates')
    return [{'method': name, **managed_gate(image, dict(selector, method=name))} for name in names]


def sample(apk, profile, tolerate_missing=False):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        checked(len(names) == len(set(names)) and len(names) < 10000, 'Duplicate or excessive APK entries')
        blob = read_entry(archive, profile['managedSigner']['entry'])
        packed = unpack_store(blob)
        images = {profile[k]['assembly']: decompress(packed[profile[k]['assembly']]) for k in KEYS}
        loader = read_entry(archive, profile['managedLoaderIntegrity']['library'])
        aot = read_entry(archive, profile['aotSignerHashes']['entry'])
        # DEX and resources contain the Java routing/activity half of this recipe.
        stable = {name: digest(read_entry(archive, name)) for name in sorted(names)
                  if re.fullmatch(r'classes(?:[2-9][0-9]*)?\.dex', name) or name == 'resources.arsc'}
    checked(stable and 'classes.dex' in stable, 'DEX missing')
    gates = []
    for key in KEYS:
        rule = profile[key]
        for selector in rule.get('methods', [rule]):
            gate = {'assembly': rule['assembly'], 'type': selector['type'], 'method': selector['method']}
            try:
                gate.update(managed_gate(images[rule['assembly']], selector))
            except ValueError:
                if not tolerate_missing:
                    raise
                gate['missing'] = True
                if CALLBACK.fullmatch(selector['method']):
                    gate['candidates'] = callback_candidates(images[rule['assembly']], selector)
            gates.append(gate)
    return blob, images, loader, aot, stable, gates, len(packed)


def baseline(apk, profile):
    checked(reference.file_digest(apk) == profile['inputSha256'], 'Baseline APK hash mismatch')
    compile_recipe(apk, profile)
    _, _, _, aot, stable, gates, count = sample(apk, profile)
    code, base = text_section(aot)
    native = []
    for rule in profile['aotSignerHashes']['comparisons']:
        context = fingerprint(native_context(code, base, int(rule['low'], 16)))
        checked(sum(c['contextSha256'] == context for c in candidates(code, base, rule)) == 1,
                'Baseline native anchor is not unique')
        native.append({'method': rule['method'], 'contextSha256': context,
                       'context': native_context(code, base, int(rule['low'], 16))})
    with Path(apk).open('rb') as stream:
        md5 = hashlib.file_digest(stream, 'md5').hexdigest()
    return {'schema': 1, 'inputSha256': profile['inputSha256'], 'apkMd5': md5, 'apkBytes': Path(apk).stat().st_size, 'profileSha256': fingerprint(profile),
            'assemblyCount': count, 'stableEntries': stable, 'gates': gates, 'native': native}


def derive(apk, profile, proof, version_code, version_name, renames=None):
    checked(proof['schema'] == 1 and proof['profileSha256'] == fingerprint(profile)
            and proof['inputSha256'] == profile['inputSha256'], 'Baseline does not belong to profile')
    effective = copy.deepcopy(profile)
    checked(isinstance(renames or [], list) and len(renames or []) <= 1, 'Too many managed mappings')
    for rename in renames or []:
        checked(set(rename) == {'oldMethod', 'newMethod'} and CALLBACK.fullmatch(rename['oldMethod'])
                and CALLBACK.fullmatch(rename['newMethod']) and rename['oldMethod'] != rename['newMethod'],
                'Only compiler-numbered identity callbacks may be renamed')
        rules = [r for r in effective['managedSignerHashes']['methods'] if r['method'] == rename['oldMethod']]
        checked(len(rules) == 1 and rules[0]['type'] == 'VirtualDesktop.Mobile.UserSettings', 'Unknown managed mapping')
        rules[0]['method'] = rename['newMethod']
        original = 'UserSettings::' + rename['oldMethod']
        native = [r for r in effective['aotSignerHashes']['comparisons'] if r['method'] == original]
        checked(len(native) == 1, 'Managed mapping has no native counterpart')
        native[0]['method'] = 'UserSettings::' + rename['newMethod']
    blob, images, loader, aot, stable, gates, count = sample(apk, effective, tolerate_missing=True)
    for gate in gates:
        if not gate.get('missing'):
            continue
        options = gate.get('candidates', [])
        checked(CALLBACK.fullmatch(gate['method']) and len(options) == 1,
                'Managed method changed or ambiguous: ' + gate['type'] + '::' + gate['method'])
        old_method, new_method = gate['method'], options[0]['method']
        for selector in effective['managedSignerHashes']['methods']:
            if selector['type'] == gate['type'] and selector['method'] == old_method:
                selector['method'] = new_method
        for rule in effective['aotSignerHashes']['comparisons']:
            if rule['method'] == 'UserSettings::' + old_method:
                rule['method'] = 'UserSettings::' + new_method
        gate.clear()
        gate.update(assembly=effective['managedSignerHashes']['assembly'], type='VirtualDesktop.Mobile.UserSettings',
                    **options[0])
    for rename in renames or []:
        selector = next(r for r in effective['managedSignerHashes']['methods'] if r['method'] == rename['newMethod'])
        expected = next(g for g in proof['gates'] if g['type'] == selector['type'] and g['method'] == rename['oldMethod'])
        options = callback_candidates(images[effective['managedSignerHashes']['assembly']], selector)
        matches = [r for r in options if r['sha256'] == expected['sha256']]
        checked((len(options) == 1 and options[0]['method'] == rename['newMethod']) or
                (len(matches) == 1 and matches[0]['method'] == rename['newMethod']), 'Managed mapping is ambiguous')
    checked(len(gates) == len(proof['gates']), 'Managed gate set changed')
    checked(all(not gate.get('missing') for gate in gates), 'Managed gate missing')
    result = copy.deepcopy(effective)
    result.update(id=f'vd-{version_name}-{version_code}-arm64-research', versionCode=version_code,
                  appVersion=version_name, inputSha256=reference.file_digest(apk))
    result['managedSigner']['sha256'] = digest(blob)
    loader_name = result['managedLoaderIntegrity']['library']
    result['libraries'][loader_name]['sha256'] = digest(loader)
    result['managedLoaderIntegrity']['expectedBytes'] = len(loader)
    result['managedLoaderIntegrity']['expectedMd5Base64'] = base64.b64encode(hashlib.md5(loader).digest()).decode()
    for key in KEYS:
        result[key]['assemblySha256'] = digest(images[result[key]['assembly']])
    result['aotSignerHashes']['sha256'] = digest(aot)
    code, base = text_section(aot)
    used = set()
    for old, anchor, rule in zip(profile['aotSignerHashes']['comparisons'], proof['native'], result['aotSignerHashes']['comparisons']):
        checked(anchor['method'] == old['method'], 'Native baseline order changed')
        match = locate_native(code, base, old, anchor)
        checked(match['low'] not in used, 'Native anchors overlap')
        used.add(match['low'])
        for key in ('low', 'high', 'compare'):
            rule[key] = match[key]
        selector = next(g for g in gates if g['type'].split('.')[-1] + '::' + g['method'] == rule['method'])
        rule['methodToken'] = selector['token']
    recipe = compile_recipe(apk, result)
    return result, recipe
