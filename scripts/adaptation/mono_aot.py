"""Resolve ARM64 Mono AOT method ranges from managed MethodDef tokens."""
import bisect
import io
import struct
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def decode_call_table(data, address, text_start, text_end):
    """Decode four-byte AArch64 branch entries; unavailable entries map to None."""
    if len(data) % 4:
        raise ValueError('Incomplete Mono call table')
    targets = []
    for offset in range(0, len(data), 4):
        word, = struct.unpack_from('<I', data, offset)
        if word & 0x7c000000 != 0x14000000:
            targets.append(None)
            continue
        delta = word & 0x03ffffff
        if delta & 0x02000000:
            delta -= 0x04000000
        target = address + offset + delta * 4
        targets.append(target if text_start <= target < text_end else None)
    return targets


def method_ranges(image, tokens):
    """Return token-to-range mappings for supported Mono AOT files, else {}.

    The table format is defined by MonoAotFileInfo; LLVM-only or unfamiliar
    layouts fall back to the existing context-based locator.
    """
    try:
        elf = ELFFile(io.BytesIO(image))
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            return {}
        dynsym, reloc, text = (elf.get_section_by_name(n) for n in ('.dynsym', '.rela.dyn', '.text'))
        if not dynsym or not reloc or not text:
            return {}
        symbols = [s for s in dynsym.iter_symbols() if s.name == 'mono_aot_file_info']
        if len(symbols) != 1:
            return {}
        info = symbols[0]['st_value']

        def read(address, length):
            sections = [s for s in elf.iter_sections() if s['sh_addr'] <= address and
                        address + length <= s['sh_addr'] + s['sh_size'] and s['sh_type'] != 'SHT_NOBITS']
            if len(sections) != 1:
                raise ValueError('AOT address outside file-backed section')
            section = sections[0]
            offset = section['sh_offset'] + address - section['sh_addr']
            return image[offset:offset + length]

        raw = read(info, 0x18c)
        version, = struct.unpack_from('<I', raw, 0)
        count, = struct.unpack_from('<I', raw, 0x154)
        stride, = struct.unpack_from('<I', raw, 0x188)
        if version not in (186, 187) or stride != 4 or not 0 < count <= 100000:
            return {}
        relocations = {r['r_offset'] - info: r['r_addend'] for r in reloc.iter_relocations()
                       if info <= r['r_offset'] < info + 0x48 and r['r_info_type'] == 1027}
        llvm_get_method = relocations.get(0x18, struct.unpack_from('<Q', raw, 0x18)[0])
        table = relocations.get(0x40, struct.unpack_from('<Q', raw, 0x40)[0])
        if llvm_get_method or not table:
            return {}
        start, end = text['sh_addr'], text['sh_addr'] + text['sh_size']
        targets = decode_call_table(read(table, count * stride), table, start, end)
        boundaries = sorted(set(target for target in targets if target is not None))
        result = {}
        for token in tokens:
            value = int(token, 16)
            index = (value & 0xffffff) - 1
            if value >> 24 != 6 or not 0 <= index < len(targets) or targets[index] is None:
                continue
            method_start = targets[index]
            next_index = bisect.bisect_right(boundaries, method_start)
            method_end = boundaries[next_index] if next_index < len(boundaries) else end
            if method_start < method_end:
                result[token] = (method_start, method_end)
        return result
    except (ELFError, KeyError, IndexError, ValueError, TypeError, struct.error):
        return {}
