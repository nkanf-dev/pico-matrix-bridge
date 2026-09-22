#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/matrix.py check-generated
python3 -m unittest discover -s scripts/tests -v
./gradlew --console=plain :tools:test :tools:installDist :adapter-core:test :protocol:test :installer-core:test :account-android:testDebugUnitTest :installer-android:testDebugUnitTest :runtime:assembleRelease :runtime:assembleDebugAndroidTest :embedded-bootstrap:assembleRelease :probe:assembleDebug :installer-android:lintDebug
