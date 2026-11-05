"""Standard-library-only commit boundary, independent of the model/runtime."""
import copy
import hashlib
import json
import re
from pathlib import Path


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 256 * 1024, 'Invalid data artifact')
    return json.loads(path.read_text())


def invariant_profile(profile):
    p = copy.deepcopy(profile)
    for key in ('id', 'versionCode', 'appVersion', 'inputSha256'):
        p.pop(key)
    p['managedSigner'].pop('sha256')
    p['managedSigner'].pop('originalCertificateSha256')
    for key in ('managedSigner', 'managedLoaderIntegrity', 'managedSignerHashes'):
        p[key].pop('assemblySha256')
    for rule in p['libraries'].values():
        rule.pop('sha256')
    p['managedLoaderIntegrity'].pop('expectedBytes')
    p['managedLoaderIntegrity'].pop('expectedMd5Base64')
    p['managedSignerHashes'].pop('originalJavaHash')
    p['managedSignerHashes'].pop('originalX509Hash')
    callback = r'<GetHasValidIdentityAsync>b__[0-9]+_[0-9]+'
    for selector in p['managedSignerHashes']['methods']:
        if selector['type'] == 'VirtualDesktop.Mobile.UserSettings' and re.fullmatch(callback, selector['method']):
            selector['method'] = '<identity-callback>'
    p['aotSignerHashes'].pop('sha256')
    for rule in p['aotSignerHashes']['comparisons']:
        if re.fullmatch('UserSettings::' + callback, rule['method']):
            rule['method'] = 'UserSettings::<identity-callback>'
        for key in ('low', 'high', 'compare', 'methodToken', 'expected'):
            rule.pop(key)
    return p


def validate_bundle(directory, old, previous_baseline, commit):
    report = read_json(directory / 'report.json')
    require(report['baseCommit'] == commit, 'Stale analysis; retry against current main')
    require(report['previousInputSha256'] == old['inputSha256'], 'Analysis baseline mismatch')
    files = {p.name for p in directory.iterdir()}
    if report['state'] == 'unchanged':
        require(files == {'report.json'} and report['inputSha256'] == old['inputSha256'], 'Invalid unchanged result')
        return None
    require(report['state'] == 'verified' and files == {'source.json', 'recipe.json', 'baseline.json', 'report.json'}, 'Unverified or unexpected artifact')
    source = read_json(directory / 'source.json')
    recipe = read_json(directory / 'recipe.json')
    proof = read_json(directory / 'baseline.json')
    require(invariant_profile(source) == invariant_profile(old), 'Adaptation policy changed')
    require(type(source['versionCode']) is int and old['versionCode'] <= source['versionCode'] <= 2147483647, 'Version downgrade')
    require(re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z._-]{0,63}', source['appVersion']), 'Invalid version name')
    require(source['id'] == f"vd-{source['appVersion']}-{source['versionCode']}-arm64-research", 'Invalid profile ID')
    require(re.fullmatch(r'[0-9a-f]{64}', source['managedSigner']['originalCertificateSha256']) is not None,
            'Invalid APK signer digest')
    require(report['inputSha256'] == source['inputSha256'] and re.fullmatch('[0-9a-f]{64}', source['inputSha256']), 'Input hash mismatch')
    require(report['allAssembliesEqual'] is True and report['onlyIntegrityConstantsChanged'] is True, 'Differential verification missing')
    for name, value in [('source', source), ('recipe', recipe), ('baseline', proof)]:
        require(report[name + 'Sha256'] == fingerprint(value), 'Artifact digest mismatch: ' + name)
    require(recipe['schema'] == 1 and recipe['kind'] == 'checked-integrity-operands', 'Unknown recipe')
    require(all(recipe['profile'].get(k) == v for k, v in source.items()), 'Recipe source mismatch')
    require(proof['inputSha256'] == source['inputSha256'] and proof['profileSha256'] == fingerprint(source), 'Next baseline mismatch')
    require(proof['schema'] == previous_baseline['schema'], 'Unknown baseline schema')
    require(len(proof['gates']) == len(previous_baseline['gates']), 'Gate count changed')
    for a, b in zip(proof['gates'], previous_baseline['gates']):
        require(a['assembly'] == b['assembly'] and a['type'] == b['type'], 'Managed gate identity changed')
        if a['method'] != b['method']:
            require(a['type'] == 'VirtualDesktop.Mobile.UserSettings' and
                    all(re.fullmatch(r'<GetHasValidIdentityAsync>b__[0-9]+_[0-9]+', g['method']) for g in (a, b)), 'Invalid gate rename')
    require(len(proof['native']) == len(previous_baseline['native']), 'Native gate count changed')
    for a, b in zip(proof['native'], previous_baseline['native']):
        require(re.fullmatch(r'[0-9a-f]{64}', a['contextSha256']) is not None, 'Invalid native context')
        require(isinstance(a.get('context'), list) and len(a['context']) == 22 and
                fingerprint(a['context']) == a['contextSha256'], 'Native context digest mismatch')
        if a['method'] != b['method']:
            require(all(re.fullmatch(r'UserSettings::<GetHasValidIdentityAsync>b__[0-9]+_[0-9]+', g['method']) for g in (a, b)), 'Invalid native gate rename')
    for rule in source['aotSignerHashes']['comparisons']:
        key = {'java': 'originalJavaHash', 'x509': 'originalX509Hash'}.get(rule['hash'])
        require(key is not None and type(source['managedSignerHashes'][key]) is int and
                rule['expected'] == source['managedSignerHashes'][key], 'Inconsistent signer constants')
        values = [int(rule[k], 16) for k in ('low', 'high', 'compare')]
        require(all(0 < v < 64 * 1024 * 1024 and v % 4 == 0 for v in values) and values == sorted(set(values)), 'Invalid AOT addresses')
    return source, recipe, proof
