#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/matrix.py check-generated
python3 scripts/profile_registry.py
python3 -m unittest discover -s scripts/tests -v
profile_tests=()
for manifest in profiles/*/manifest.json; do
  key="$(basename "$(dirname "$manifest")")"
  profile_tests+=(":profile-$key-code:test")
done
./gradlew --console=plain :tools:test :tools:installDist :adapter-core:test "${profile_tests[@]}" :protocol:test :installer-core:test :account-android:testDebugUnitTest :installer-android:testDebugUnitTest :runtime:assembleRelease :embedded-bootstrap:assembleRelease :installer-android:lintDebug
python3 scripts/check_android_json_api.py --android-jar "${ANDROID_HOME:-$ANDROID_SDK_ROOT}/platforms/android-35/android.jar" adapter-core/build/classes/java/main profiles/*/code/build/classes/java/main
