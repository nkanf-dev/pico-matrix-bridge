#!/usr/bin/env python3
"""Copy existing local credentials to CI without printing or writing cleartext files."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from dataclasses import asdict
from pico_store_lab.credentials import load


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='nkanf-dev/pico-matrix-bridge')
    parser.add_argument('--models', type=Path, default=Path.home() / '.omp/agent/models.yml')
    args = parser.parse_args()
    try:
        models = json.loads(args.models.read_text())
    except json.JSONDecodeError:
        raise SystemExit('Use a JSON-formatted OMP models.yml or pass --models with its JSON export') from None
    provider = models['providers']['mikumiku-openai']
    if provider['baseUrl'].rstrip('/') != 'https://newapi.mikumiku.love/v1' or provider['api'] != 'openai-completions':
        raise SystemExit('Provider endpoint/protocol differs from the reviewed CI configuration')
    key = provider['apiKey']
    if key.startswith('!'):
        raise SystemExit('Shell-based secret resolvers are not executed by this helper')
    key = os.environ.get(key, key)
    for name, value in [('MIKUMIKU_API_KEY', key), ('PICO_AUTH_JSON', json.dumps(asdict(load())))]:
        subprocess.run(['gh', 'secret', 'set', name, '--repo', args.repo, '--env', 'vd-adaptation'],
                       input=value.encode(), check=True, stdout=subprocess.DEVNULL)
    print('Updated the two encrypted vd-adaptation environment secrets.')


if __name__ == '__main__':
    main()
