#!/usr/bin/env python3
"""Observe, acquire once, check and stage a VD profile. Never signs or pushes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

from analysis import (ROOT, KEYS, baseline, candidates, checked, derive, fingerprint,
                      native_context, sample, text_section)
from agent import run_agent

TARGET_ID = '3540'
MAX_APK = 2 * 1024**3


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def tool(name):
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '')
    paths = sorted((sdk / 'build-tools').glob('*/' + name), reverse=True)
    checked(bool(paths), 'Android build tool is missing: ' + name)
    return str(paths[0])


def identity(apk, profile):
    text = subprocess.run([tool('aapt'), 'dump', 'badging', str(apk)], capture_output=True, text=True, check=True).stdout
    match = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", text, re.M)
    checked(match and match[1] == profile['package'], 'Wrong APK package')
    checked(re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z._-]{0,63}', match[3]), 'Unsupported version name')
    signatures = subprocess.run([tool('apksigner'), 'verify', '--print-certs', str(apk)],
                                 capture_output=True, text=True, check=True).stdout
    certificates = re.findall(r'^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-f]{64})$', signatures, re.M)
    checked(certificates == [profile['managedSigner']['originalCertificateSha256']], 'APK publisher changed')
    return int(match[2]), match[3]


def observed():
    from pico_store_lab.client import PicoStoreClient
    from pico_store_lab.protocol import StoreTarget, PicoAuth
    raw = os.environ.get('PICO_AUTH_JSON')
    checked(bool(raw), 'PICO_AUTH_JSON is missing')
    client = PicoStoreClient()
    target = StoreTarget(TARGET_ID, 'VirtualDesktop.Android', 'Virtual Desktop')
    item = client.download_info(target, PicoAuth(**json.loads(raw)))
    return client, target, item


def acquire(client, target, version, apk):
    from pico_store_lab.protocol import PicoAuth
    raw = os.environ.get('PICO_AUTH_JSON')
    checked(bool(raw), 'PICO_AUTH_JSON is missing; renew the PICO session in the vd-adaptation environment')
    auth = PicoAuth(**json.loads(raw))
    # No automatic purchase or entitlement mutation.
    info = client.download_info(target, auth)
    checked(info.version_code == version and 0 < info.size <= MAX_APK, 'Download metadata changed or exceeds 2 GiB')
    # Do not log the signed URL, response body, account ID or cookies.
    md5 = hashlib.md5()
    written = 0
    try:
        with urllib.request.urlopen(info.url, timeout=60) as response, apk.open('xb') as out:
            while chunk := response.read(1024 * 1024):
                written += len(chunk)
                checked(written <= info.size and written <= MAX_APK, 'Download exceeds declared size')
                md5.update(chunk)
                out.write(chunk)
        checked(written == info.size and md5.hexdigest() == info.md5, 'Downloaded APK checksum/size mismatch')
    except Exception:
        apk.unlink(missing_ok=True)
        raise RuntimeError('Official APK download failed; session, ownership or transport needs attention') from None
    return info


def diagnostic(apk, profile, proof, reason):
    result = {'index': {'ids': ['failure', 'baseline'], 'purpose': 'Read evidence, diagnose uncertainty; do not bypass checks'},
              'failure': {'reason': reason}, 'baseline': proof}
    try:
        _, _, _, aot, _, gates, _ = sample(apk, profile, tolerate_missing=True)
        result['managed'] = gates
        code, base = text_section(aot)
        native = []
        for rule in profile['aotSignerHashes']['comparisons']:
            found = candidates(code, base, rule)
            native.append({'method': rule['method'], 'candidates': [dict(c, context=native_context(code, base, int(c['low'], 16))) for c in found[:8]]})
        result['native'] = native
        result['index']['ids'] += ['managed', 'native']
        missing = [g for g in gates if g.get('missing') and g.get('candidates')]
        if missing:
            result['callback-mapping'] = [{
                'oldMethod': g['method'], 'type': g['type'],
                'expectedSha256': next(b['sha256'] for b in proof['gates'] if b['type'] == g['type'] and b['method'] == g['method']),
                'candidates': g['candidates']} for g in missing]
            result['index'] = {'ids': ['callback-mapping'], 'task': 'Propose managedMappings only for a unique equal fingerprint. The trusted validator will recheck all native and managed gates independently.'}
    except Exception:
        result['failure']['extraction'] = 'Partial evidence only; do not infer equivalence'
    return result


def verify_candidate(apk, profile, recipe, work):
    """Compile again, then compare Python and actual JVM execution on the sample."""
    from analysis import compile_recipe
    checked(compile_recipe(apk, profile) == recipe, 'Candidate recipe changed after analysis')
    cert = work / 'publisher.der'
    shutil.copyfile(ROOT / 'scripts/tests/fixtures/vd-test-signer.der', cert)
    profile_path = work / 'source.json'
    dump(profile_path, profile)
    managed = work / 'managed'
    managed.mkdir()
    _, images, *_ = sample(apk, profile)
    for name, image in images.items():
        (managed / name).write_bytes(image)
    shutil.copyfile(cert, work / 'adapted-signer.der')
    env = dict(os.environ, MATRIX_VD_APK=str(apk), MATRIX_VD_PROFILE=str(profile_path),
               MATRIX_TEST_CERT=str(cert), MATRIX_PORTABLE_RESEARCH=str(work / 'differential'),
               VD_RESEARCH_ROOT=str(work))
    for pattern in ('test_vd_integrity.py', 'test_portable_profile.py'):
        subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT / 'scripts/tests'), '-p', pattern, '-v'],
                       cwd=ROOT, env=env, check=True)
    return json.loads((work / 'differential/differential-evidence.json').read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, help='Existing sample, read in place')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--force-agent', action='store_true')
    parser.add_argument('--recheck-current', action='store_true')
    args = parser.parse_args()
    checked(not args.work.exists() and not args.output.exists(), 'Output/work directory must be new')
    args.work = args.work.resolve(); args.output = args.output.resolve()
    args.work.mkdir(parents=True)
    args.output.mkdir(parents=True)
    recipe_path = ROOT / 'profiles/vd/recipe.json'
    current = json.loads(recipe_path.read_text())
    default_source = ROOT / 'profiles/vd' / f"client-{current['profile']['appVersion']}-{current['profile']['versionCode']}-research.json"
    profile = json.loads((args.source or default_source).read_text())
    proof = json.loads((args.baseline or ROOT / 'profiles/vd/adaptation-baseline.json').read_text())
    report = {'schema': 1, 'state': 'observing', 'baseCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'previousInputSha256': profile['inputSha256'], 'agentUsed': False}
    downloaded = None
    try:
        apk = args.apk.resolve(strict=True) if args.apk else None
        if apk is None:
            client, target, item = observed()
            report['observedVersionCode'] = item.version_code
            report['observedMetadata'] = {'versionCode': item.version_code, 'md5': item.md5, 'bytes': item.size}
            if (item.version_code == profile['versionCode'] and item.md5 == proof['apkMd5']
                    and item.size == proof['apkBytes'] and not args.recheck_current):
                report.update(state='unchanged', inputSha256=profile['inputSha256'])
                return
            checked(item.version_code >= profile['versionCode'], 'Store reports an older build; manual review required')
            downloaded = args.work / 'sample.apk'
            report['state'] = 'acquiring'
            acquire(client, target, item.version_code, downloaded)
            apk = downloaded
        print('Checking APK package and publisher', flush=True)
        version, name = identity(apk, profile)
        report.update(state='analyzing', observedVersionCode=version)
        checked(version >= profile['versionCode'], 'Refusing version downgrade')
        print('Relocating checked profile operands', flush=True)
        try:
            proposed, recipe = derive(apk, profile, proof, version, name)
        except ValueError as error:
            report.update(state='review-required', reason=str(error))
            accepted = False
            if os.environ.get('MIKUMIKU_API_KEY'):
                report['agentUsed'] = True
                report['agent'] = run_agent(diagnostic(apk, profile, proof, str(error)), args.work / 'agent')
                mappings = report['agent'].get('managedMappings', [])
                if mappings:
                    try:
                        # The model's disposition and raw addresses confer no authority.
                        proposed, recipe = derive(apk, profile, proof, version, name, mappings)
                        accepted = True
                        report.update(state='analyzing', agentMappingVerified=True)
                        report.pop('reason', None)
                    except ValueError:
                        report['candidateRejected'] = True
            if not accepted:
                raise RuntimeError('Build requires review; the current profile remains unchanged') from None
        if args.force_agent and not report['agentUsed']:
            evidence = diagnostic(apk, profile, proof, 'Deterministic validation passed; independent diagnostic replay')
            report['agentUsed'] = True
            report['agent'] = run_agent(evidence, args.work / 'agent')
            # Agent approval is not a gate. Recompute using the untouched sample and trusted rules.
            checked(derive(apk, profile, proof, version, name) == (proposed, recipe), 'Non-deterministic candidate')
        report['state'] = 'validating'
        print('Running reference and JVM differential checks', flush=True)
        differential = verify_candidate(apk, proposed, recipe, args.work)
        next_baseline = baseline(apk, proposed)
        report.update(state='verified', inputSha256=proposed['inputSha256'], versionCode=version,
                      recipeSha256=fingerprint(recipe), sourceSha256=fingerprint(proposed), baselineSha256=fingerprint(next_baseline),
                      allAssembliesEqual=differential['all185AssembliesEqual'],
                      onlyIntegrityConstantsChanged=differential['onlyIntegrityConstantsChanged'])
        dump(args.output / 'source.json', proposed)
        dump(args.output / 'recipe.json', recipe)
        dump(args.output / 'baseline.json', next_baseline)
    except Exception as error:
        if report['state'] != 'review-required':
            report.update(failedStage=report['state'], state='failed', reason=type(error).__name__ + ': operation failed at named stage')
        raise
    finally:
        dump(args.output / 'report.json', report)
        print(json.dumps({k: report[k] for k in ('state', 'observedVersionCode', 'agentUsed') if k in report}))
        # No raw application, extracted assemblies or provider logs become CI artifacts.
        shutil.rmtree(args.work)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # SDK exceptions may include account response URLs. Only print trusted error types.
        print('Adaptation stopped: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
