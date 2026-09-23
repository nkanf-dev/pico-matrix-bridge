#!/usr/bin/env python3
"""Package the generic native Matrix adapter as a separately signed APK."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from profile_registry import load
from profile_signing import OFFICIAL_CERTIFICATE, apk_signer, certificate_sha256

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'profiles/generic/recipe.json')
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--variant',choices=['debug','release'],default='debug')
    parser.add_argument('--development-profile-certificate',type=Path,
                        help='local build only: verify a contributor-owned profile signing certificate')
    parser.add_argument('--built-at',help='UTC build time, for example 2026-09-23T12:34:56Z; defaults to current UTC second')
    args=parser.parse_args()
    built_at=(datetime.strptime(args.built_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
              if args.built_at else datetime.now(timezone.utc).replace(microsecond=0))
    version_name=built_at.strftime('%Y-%m-%dT%H:%M:%SZ')
    version_code=int(built_at.timestamp())
    if version_code<1 or version_code>2100000000:raise ValueError('profile build time is outside Android versionCode range')
    signing=('PICO_PROFILE_KEYSTORE','PICO_PROFILE_KEY_ALIAS','PICO_PROFILE_STORE_PASSWORD','PICO_PROFILE_KEY_PASSWORD')
    if args.variant=='release' and not all(os.environ.get(name) for name in signing):
        raise ValueError('Release profile requires all PICO_PROFILE signing variables')
    recipe=json.loads(args.source.read_text())
    if recipe['schema']!=1:raise ValueError('Wrong generic Matrix recipe')
    definition=load('generic')
    if definition['packageMatcher']!='*':raise ValueError('Generic profile must match all packages')
    recipe['profileApi']=1
    recipe['entryClass']='org.picomatrix.bridge.adapter.GenericMatrixProfile'
    recipe['profile']={'profileKey':definition['profileKey'],'packageMatcher':definition['packageMatcher'],
                       'priority':definition['priority'],'package':'*','outputPackage':'*',
                       'profileVersionCode':version_code}
    recipe['profileVersionUtc']=version_name
    recipe['profileVersionCode']=version_code
    output=args.output.resolve()
    if output.exists():raise ValueError('Profile output must be new; preserve previous build')
    output.mkdir(parents=True)
    try:
        prepared=output/'profile.json'
        prepared.write_text(json.dumps(recipe,sort_keys=True,separators=(',',':'))+'\n')
        subprocess.run([str(ROOT/'gradlew'),':profile-generic:assemble'+args.variant.title(),
                        f'-PgenericRecipeFile={prepared}',f'-PgenericProfileVersionCode={version_code}',
                        f'-PgenericProfileVersionName={version_name}',
                        '--console=plain'],cwd=ROOT,check=True)
        apk=ROOT/'profiles/generic/apk/build/outputs/apk'/args.variant/f'profile-generic-{args.variant}.apk'
        if not apk.is_file():raise ValueError('Profile APK build is missing')
        if args.variant=='release' and apk_signer(apk)!=certificate_sha256(args.development_profile_certificate or OFFICIAL_CERTIFICATE):
            raise ValueError('Profile APK signer differs from the trusted publisher certificate')
        target=output/'matrix-profile-generic.apk';shutil.copyfile(apk,target)
        print(json.dumps({'profile':str(target),'versionCode':version_code,'versionName':version_name,'sha256':digest(target),
                          'signed':True,'installed':False,'published':False}))
    except Exception:
        shutil.rmtree(output)
        raise

if __name__=='__main__':main()
