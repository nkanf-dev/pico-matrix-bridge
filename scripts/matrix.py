#!/usr/bin/env python3
"""Reusable maintainer entry point. Samples and reports stay in explicit durable paths."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from contracts import profile, compare, canonical, generate_java

ROOT=Path(__file__).resolve().parents[1]
TOOL=ROOT/'tools/build/install/tools/bin/tools'

def inspect(source,output):
    source=source.resolve(strict=True); output=output.absolute()
    if output.resolve()==source or (output.exists() and os.path.samefile(source,output)):
        raise ValueError('output cannot replace original')
    subprocess.run([str(ROOT/'gradlew'),':tools:installDist','--console=plain','-q'],cwd=ROOT,check=True)
    subprocess.run([str(TOOL),'inspect',str(source),str(output)],cwd=ROOT,check=True)
    return json.loads(output.read_text())

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    for command in ('inspect','profile'):
        s=sub.add_parser(command);s.add_argument('apk',type=Path);s.add_argument('--output',type=Path,required=True)
    d=sub.add_parser('compare');d.add_argument('old',type=Path);d.add_argument('new',type=Path);d.add_argument('--output',type=Path,required=True)
    sub.add_parser('check-generated')
    a=p.parse_args()
    if a.command=='check-generated':
        baseline=json.loads((ROOT/'protocol/baselines/matrix-global-6.3.4.json').read_text())
        expected=generate_java(baseline)
        actual=(ROOT/'protocol/src/main/java/org/picomatrix/bridge/protocol/MatrixContract.java').read_text()
        if expected!=actual: raise ValueError('generated constants differ from extracted baseline')
        print('Generated runtime constants match the extracted baseline.');return
    if a.command=='inspect': inspect(a.apk,a.output);return
    if a.command=='profile':
        # Small metadata report sits next to the durable profile; never copy or extract the APK.
        inspection=a.output.with_suffix('.inspection.json')
        if inspection.resolve()==a.output.resolve(): raise ValueError('distinct inspection output required')
        result=profile(inspect(a.apk,inspection))
        if a.output.resolve()==a.apk.resolve() or (a.output.exists() and os.path.samefile(a.apk,a.output)):
            raise ValueError('output cannot replace original')
    else: result=compare(json.loads(a.old.read_text()),json.loads(a.new.read_text()))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'output':str(a.output),'command':a.command}))

if __name__=='__main__': main()
