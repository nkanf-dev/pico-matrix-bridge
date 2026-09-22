#!/usr/bin/env python3
"""Build an optional VD UI probe from pinned public Mono exports (no NDK needed).

Uses an existing Clang and ELF lld. Link stubs are the connected device's libc,
libdl and liblog, copied once to the durable research directory. Never publishes.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[2]
MONO_SHA = '4b099c3835e9566342c1b399b9161b63e926d0f524e51624ae2b5072916fb5bc'

def run(*args):
    subprocess.run([str(a) for a in args], check=True, cwd=ROOT)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--research',type=Path,required=True)
    p.add_argument('--clang',type=Path,required=True)
    p.add_argument('--lld',type=Path,required=True)
    p.add_argument('--matrix',type=Path)
    p.add_argument('--build-tools',type=Path)
    p.add_argument('--output',type=Path)
    p.add_argument('--embedded',action='store_true',help='Build the debug runtime for embedding, without a companion APK')
    p.add_argument('--serial',help='Explicitly install the research companion and restart VD')
    a=p.parse_args()
    if a.embedded and a.serial:p.error('--embedded does not install or restart applications')
    if not a.embedded and not all((a.matrix,a.build_tools,a.output)):p.error('Companion output requires --matrix, --build-tools and --output')
    native=a.research/'native';link=native/'probe-link';link.mkdir(exist_ok=True)
    mono=native/'libmonosgen-2.0.so'
    if hashlib.sha256(mono.read_bytes()).hexdigest()!=MONO_SHA:raise ValueError('Unknown Mono runtime')
    source=ROOT/'scripts/research/managed_ui_probe.c'
    with mono.open('rb') as f:
        elf=ELFFile(f);note=elf.get_section_by_name('.note.gnu.build-id')
        symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
        lines=[f'static const unsigned long probe_build_id_offset={note["sh_addr"]};',
               'static const unsigned char probe_build_id[]={'+','.join(map(str,note.data()))+'};']
        for name in sorted(set(re.findall(r'LOAD\((mono_\w+)\)',source.read_text()))):
            lines.append(f'static const unsigned long probe_export_{name}={symbols[name]};')
        header=link/'mono_exports.h';header.write_text('\n'.join(lines)+'\n')
    for name in ['libc.so','libdl.so','liblog.so']:
        if not (link/name).exists():
            if not a.serial:raise ValueError('Provide device link stubs or --serial')
            run('adb','-s',a.serial,'pull','/system/lib64/'+name,link/name)
    obj=link/'managed_ui_probe.o'
    # JNI table declarations come from the installed JDK, not handwritten slots.
    java_home=Path(subprocess.check_output(['/usr/libexec/java_home'],text=True).strip())
    headers=link/'jni-headers';headers.mkdir(exist_ok=True)
    (headers/'stdio.h').write_text('/* JNI declarations use no stdio symbols. */\n')
    resource=Path(subprocess.check_output([str(a.clang),'-print-resource-dir'],text=True).strip())
    target=ROOT/'runtime/src/debug/jniLibs/arm64-v8a/libmatrixdiag.so';target.parent.mkdir(parents=True,exist_ok=True)
    run(a.clang,'--target=aarch64-linux-android29','-nostdinc','-fno-builtin','-fPIC','-fno-stack-protector','-mno-outline-atomics',
        '-O2','-Wall','-Wextra','-Werror','-I',headers,'-I',resource/'include',
        '-I',java_home/'include','-I',java_home/'include/darwin','-include',header,'-c',source,'-o',obj)
    run(a.lld,'-flavor','gnu','-shared','-soname','libmatrixdiag.so','-z','max-page-size=16384','-z','defs',
        '-L',link,'-lc','-ldl','-llog',obj,'-o',target)
    run(ROOT/'gradlew',':runtime:assembleDebug','--console=plain')
    probe={'monoSha256':MONO_SHA,'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
           'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
           'scope':'fixed numeric UI snapshots, isolated EGL texture read and bounded metadata-only connection exception stacks'}
    if a.embedded:
        (native/'embedded-probe-build.json').write_text(json.dumps(probe,indent=2)+'\n')
        print(json.dumps(probe));return
    spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'scripts/assemble_bootstrap.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    result=module.assemble(ROOT/'runtime/build/outputs/apk/debug/runtime-debug.apk',a.matrix,a.output,a.build_tools,True,ROOT/'profiles/matrix-global-6.3.4.json')
    result['probe']=probe
    a.output.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
    if a.serial:
        run('adb','-s',a.serial,'install','-r',a.output)
        for cmd in [['start','-n','org.picomatrix.bridge/.MainActivity'],['force-stop','org.picomatrix.bridge.vd'],
                    ['start','-n','org.picomatrix.bridge.vd/md59102214312e19799944a61bf7bc2f23e.VrActivity']]:
            run('adb','-s',a.serial,'shell','am',*cmd)
    print(json.dumps({'output':str(a.output),'sha256':result['outputSha256']}))

if __name__=='__main__':main()
