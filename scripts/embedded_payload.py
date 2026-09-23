"""Prepare the pinned, account-free VD embedded payload. No device or credentials."""
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile
from elftools.elf.elffile import ELFFile

ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def prepare(source, vendor, work, profile, certificate, provisioner):
    matrix_profile=ROOT/'protocol/baselines/matrix-global-6.3.4.json'
    matrix=json.loads(matrix_profile.read_text())
    if sha(vendor)!=matrix['source']['sha256']:raise ValueError('Unknown Matrix payload source')
    runtime=ROOT/'runtime/build/outputs/apk/debug/runtime-debug.apk'
    bootstrap=ROOT/'embedded-bootstrap/build/outputs/apk/debug/embedded-bootstrap-debug.apk'
    dex=work/'embedded-dex'
    subprocess.run([str(ROOT/'tools/build/install/tools/bin/tools'),'prepare-embedded-dex',str(bootstrap),str(runtime),str(vendor),str(source),str(dex)],check=True)
    evidence=json.loads((dex/'dex-evidence.json').read_text())
    payload=work/'matrix-runtime.zip';libraries={};routes=[]
    with zipfile.ZipFile(runtime) as bridge,zipfile.ZipFile(vendor) as matrix_zip,zipfile.ZipFile(payload,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as output:
        names=sorted(n for n in bridge.namelist() if re.fullmatch(r'classes\d*\.dex',n))
        for i,name in enumerate(names,1): output.writestr('classes.dex' if i==1 else f'classes{i}.dex',bridge.read(name))
        for i,name in enumerate(evidence['vendorDex'],len(names)+1):output.writestr(f'classes{i}.dex',(dex/name).read_bytes())
        # Static DT_NEEDED closure: these are the only non-system libraries in
        # the observed platform driver path. Additional features need a profile update.
        native=['libplatformsdk.so','libvolcenginertc.so']
        system={'liblog.so','libm.so','libdl.so','libc.so','libOpenSLES.so','libEGL.so','libGLESv1_CM.so','libGLESv2.so','libandroid.so'}
        for name in native:
            data=matrix_zip.read('lib/arm64-v8a/'+name)
            elf=ELFFile(io.BytesIO(data));needed={t.needed for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED'}
            if not needed<=system|set(native):raise ValueError('New native dependency: '+name)
            old=b'com.bytedance.pico.matrix\0';new=profile['outputPackage'].encode()+b'\0'
            if len(new)>len(old):raise ValueError('Native embedded identity is too long')
            count=data.count(old);data=data.replace(old,new.ljust(len(old),b'\0'))
            routes.append({'entry':name,'packageRoutes':count,'needed':sorted(needed)})
            output.writestr('lib/arm64-v8a/'+name,data);libraries[name]=hashlib.sha256(data).hexdigest()
        # Diagnostics are opt-in research code; no external runtime service.
        diag='lib/arm64-v8a/libmatrixdiag.so'
        if diag in bridge.namelist():
            data=bridge.read(diag);output.writestr(diag,data);libraries['libmatrixdiag.so']=hashlib.sha256(data).hexdigest()
    config={'schema':1,'package':profile['outputPackage'],'appId':'3cd8ad26e891e5c2ac8beeba35588f8f',
            'launchActivity':'md59102214312e19799944a61bf7bc2f23e.VrActivity',
            'payloadSha256':sha(payload),'libraries':libraries,'provisionerPackage':provisioner,
            'provisionerSignerSha256':hashlib.sha256(certificate).hexdigest()}
    config_path=work/'matrix-embedded.json';config_path.write_text(json.dumps(config,indent=2)+'\n')
    with zipfile.ZipFile(source) as client:original_dex=[n for n in client.namelist() if re.fullmatch(r'classes\d*\.dex',n)]
    expected={'classes.dex'}|{f'classes{i}.dex' for i in range(2,len(original_dex)+1)}
    if set(original_dex)!=expected:raise ValueError('Non-contiguous target DEX entries')
    additions={f'classes{len(original_dex)+1}.dex':dex/'bootstrap.dex','assets/matrix-runtime.zip':payload,
               'assets/matrix-embedded.json':config_path,'assets/matrix-runtime-profile.json':matrix_profile}
    return {'config':config,'dex':evidence,'native':routes,'vendorSha256':sha(vendor),
            'runtimeSha256':sha(runtime),'bootstrapSha256':sha(bootstrap),
            'additions':{name:{'path':str(path),'sha256':sha(path),'bytes':path.stat().st_size} for name,path in additions.items()}}
