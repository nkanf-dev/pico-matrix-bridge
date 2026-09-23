#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["dnfile==0.18.0", "dncil==1.0.2", "lz4==4.4.5", "pyelftools==0.33"]
# ///
"""Build a private, account-free compatibility bundle; never signs or installs.

Run :tools:installDist :runtime:assembleRelease :embedded-bootstrap:assembleRelease
first. Output belongs in ignored local storage and contains licensed vendor code.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile
from elftools.elf.elffile import ELFFile

ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def build(args):
    out=args.output.resolve()
    if out.exists():raise ValueError('Bundle output must be new; preserve previous build')
    matrix_profile=ROOT/'protocol/baselines/matrix-global-6.3.4.json'
    matrix=json.loads(matrix_profile.read_text())
    if sha(args.matrix)!=matrix['source']['sha256']:raise ValueError('Matrix input differs from pinned profile')
    variant='debug' if args.research_diagnostics else 'release'
    def artifact(module):
        folder=ROOT/module/f'build/outputs/apk/{variant}'
        options=[folder/f'{module}-{variant}-unsigned.apk',folder/f'{module}-{variant}.apk']
        return next((p for p in options if p.is_file()),options[0])
    runtime=artifact('runtime');bootstrap=artifact('embedded-bootstrap')
    for path in [runtime,bootstrap]:
        if not path.is_file():raise ValueError(f'Build {variant} artifact first: {path}')
    stage=out.with_name(out.name+'.building')
    if stage.exists():raise ValueError('Bundle staging path already exists')
    stage.mkdir(parents=True)
    try:
        dex=stage/'dex-work'
        subprocess.run([str(ROOT/'tools/build/install/tools/bin/tools'),'prepare-embedded-dex',str(bootstrap),str(runtime),str(args.matrix.resolve()),str(args.client.resolve()),str(dex)],check=True)
        dex_evidence=json.loads((dex/'dex-evidence.json').read_text())
        shutil.copyfile(dex/'bootstrap.dex',stage/'bootstrap.dex')
        native=[]
        with zipfile.ZipFile(runtime) as bridge,zipfile.ZipFile(args.matrix) as vendor,zipfile.ZipFile(stage/'matrix-runtime-template.zip','w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as output:
            def write(name,data):
                item=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                item.compress_type=zipfile.ZIP_DEFLATED
                output.writestr(item,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
            diagnostic='lib/arm64-v8a/libmatrixdiag.so'
            if diagnostic in bridge.namelist() and not args.research_diagnostics:raise ValueError('Release runtime contains research diagnostics')
            names=sorted((n for n in bridge.namelist() if re.fullmatch(r'classes\d*\.dex',n)),key=lambda n:1 if n=='classes.dex' else int(n[7:-4]))
            for i,name in enumerate(names,1):write('classes.dex' if i==1 else f'classes{i}.dex',bridge.read(name))
            for i,name in enumerate(dex_evidence['vendorDex'],len(names)+1):write(f'classes{i}.dex',(dex/name).read_bytes())
            libraries={'libplatformsdk.so','libvolcenginertc.so'}
            system={'liblog.so','libm.so','libdl.so','libc.so','libOpenSLES.so','libEGL.so','libGLESv1_CM.so','libGLESv2.so','libandroid.so'}
            for name in sorted(libraries):
                entry='lib/arm64-v8a/'+name;data=vendor.read(entry)
                elf=ELFFile(io.BytesIO(data));needed={t.needed for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED'}
                if not needed<=system|libraries:raise ValueError('Unknown Matrix native dependency: '+name)
                write(entry,data);native.append({'entry':entry,'sha256':hashlib.sha256(data).hexdigest(),'replacements':data.count(b'com.bytedance.pico.matrix\0'),'needed':sorted(needed)})
            if args.research_diagnostics and diagnostic in bridge.namelist():
                data=bridge.read(diagnostic);write(diagnostic,data);native.append({'entry':diagnostic,'sha256':hashlib.sha256(data).hexdigest(),'replacements':0,'researchDiagnostic':True})
        shutil.copyfile(matrix_profile,stage/'matrix-runtime-profile.json')
        shutil.rmtree(dex)
        manifest={'schema':1,'runtime':'matrix-runtime-template.zip','bootstrap':'bootstrap.dex','matrixProfile':'matrix-runtime-profile.json',
                  'variant':variant,'researchDiagnostics':args.research_diagnostics,'native':native,'bootstrapClasses':dex_evidence['bootstrapClasses'],
                  'sources':{'matrixSha256':sha(args.matrix),'runtimeSha256':sha(runtime),'bootstrapSha256':sha(bootstrap)},
                  'files':{p.name:{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(stage.iterdir()) if p.is_file()}}
        (stage/'bundle.json').write_text(json.dumps(manifest,indent=2)+'\n')
        stage.rename(out)
        print(json.dumps({'bundle':str(out),'manifestSha256':sha(out/'bundle.json'),'variant':variant,'researchDiagnostics':args.research_diagnostics,'files':len(manifest['files'])}))
    except Exception:
        shutil.rmtree(stage);raise

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--matrix',required=True,type=Path);p.add_argument('--client',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--research-diagnostics',action='store_true');build(p.parse_args())

if __name__=='__main__':main()
