#!/usr/bin/env python3
"""Assemble a local research bootstrap using supplied, verified vendor APKs.

Does not alter/install original apps. No vendor binary belongs in source control.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = b"com.bytedance.pico.matrix\0"
COMPANION = b"org.picomatrix.bridge\0"

def patch_native(data):
    count = data.count(ORIGINAL)
    if not data.startswith(b"\x7fELF"):
        raise ValueError("not an ELF library")
    return data.replace(ORIGINAL, COMPANION.ljust(len(ORIGINAL), b"\0")), count

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def signature(name):
    upper = name.upper()
    return upper.startswith("META-INF/") and (upper.endswith((".RSA", ".DSA", ".EC", ".SF")) or upper == "META-INF/MANIFEST.MF")

def assemble(base, vendor, out, sdk, runtime, profile):
    unsigned = out.with_suffix(".unsigned.apk")
    aligned = out.with_suffix(".aligned.apk")
    changes = []
    try:
        with zipfile.ZipFile(base) as host, zipfile.ZipFile(vendor) as original, zipfile.ZipFile(unsigned,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=1) as target:
            if runtime:
                target.writestr("assets/matrix-runtime-profile.json",profile.read_bytes())
            count = 0
            for info in host.infolist():
                if signature(info.filename): continue
                if re.fullmatch(r"classes\d*\.dex", info.filename): count += 1
                with host.open(info) as src, target.open(info,"w") as dst: shutil.copyfileobj(src,dst,1024*1024)
            for info in original.infolist():
                name = info.filename
                if runtime and re.fullmatch(r"classes\d*\.dex",name):
                    count += 1
                    with original.open(info) as src, target.open(f"classes{count}.dex","w") as dst: shutil.copyfileobj(src,dst,1024*1024)
                    changes.append({"source":name,"output":f"classes{count}.dex","operation":"include vendor dependency dex after bridge classes"})
                elif (runtime and name.startswith("lib/arm64-v8a/") and name.endswith(".so")) or (not runtime and name=="lib/arm64-v8a/libpxrplatformloader4j.so"):
                    with original.open(info) as stream:
                        data=stream.read(128*1024*1024+1)
                    if len(data)>128*1024*1024: raise ValueError("native entry too large")
                    patched,n=patch_native(data)
                    target.writestr(name,patched,compress_type=zipfile.ZIP_STORED)
                    changes.append({"source":name,"operation":"native package routing" if n else "include dependency","replacements":n,"originalSha256":hashlib.sha256(data).hexdigest(),"outputSha256":hashlib.sha256(patched).hexdigest()})
            target.writestr("assets/matrix-bridge-bootstrap.json", json.dumps({"schemaVersion":1,"researchBootstrap":True,"vendorSha256":sha(vendor),"changes":changes}))
        subprocess.run([str(sdk/"zipalign"),"-P","16","-f","4",str(unsigned),str(aligned)],check=True)
        unsigned.unlink()
        subprocess.run([str(sdk/"apksigner"),"sign","--ks",str(Path.home()/".android/debug.keystore"),"--ks-key-alias","androiddebugkey","--ks-pass","pass:android","--key-pass","pass:android","--out",str(out),str(aligned)],check=True)
        subprocess.run([str(sdk/"apksigner"),"verify",str(out)],check=True)
        return {"input":str(vendor),"inputSha256":sha(vendor),"output":str(out),"outputSha256":sha(out),"bytes":out.stat().st_size,"changes":changes,"status":"signed research bootstrap; not account compatibility proof"}
    finally:
        unsigned.unlink(missing_ok=True); aligned.unlink(missing_ok=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,required=True);p.add_argument("--client",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--build-tools",type=Path,required=True)
    p.add_argument("--profile",type=Path,required=True)
    a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=True)
    profile=json.loads(a.profile.read_text())
    if profile["source"]["sha256"]!=sha(a.matrix): raise ValueError("profile does not match Matrix original")
    for source in [a.matrix,a.client]: subprocess.run([str(a.build_tools/"apksigner"),"verify",str(source)],check=True)
    results=[]
    for module,vendor in [("runtime",a.matrix),("probe",a.client)]:
        out=a.output_dir/f"matrix-{module}-bootstrap.apk"
        if out.resolve() in [a.matrix.resolve(),a.client.resolve()]: raise ValueError("cannot overwrite original")
        results.append(assemble(ROOT/module/f"build/outputs/apk/debug/{module}-debug.apk",vendor,out,a.build_tools,module=="runtime",a.profile))
    (a.output_dir/"assembly.json").write_text(json.dumps(results,indent=2)+"\n")
    print(json.dumps([{k:v for k,v in r.items() if k!="changes"} for r in results],indent=2))

if __name__=="__main__": main()
