# Generic APK preparation and application profiles

`adapter-core` is the application-neutral Java 17 preparation engine. It inspects
an original APK, builds an embedded Matrix runtime, writes an unsigned adapted
copy, and verifies that unrelated ZIP entries were preserved. It never reads a
signing key, opens a network connection or installs an APK. `installer-android`
verifies/signs the prepared copy and owns Android PackageInstaller.

An `ApplicationProfile` supplies its own package/version metadata, verifies
application-specific inputs, generates replacement entries and checks the
result. The core passes it to the generic APK writer. The first implementation
is `profile-vd-code`, which owns the entire Virtual Desktop managed-store,
loader and AOT adaptation. No VD package name, assembly, offset or recipe is
compiled into `adapter-core`.

```java
ApplicationProfile profile = /* verified by the Android host */;
AdapterEngine.Inspection inspection = AdapterEngine.inspect(original, bundleDir, profile);
AdapterEngine.Result result = AdapterEngine.prepare(original, bundleDir, unsignedOutput,
    targetCertificate.getEncoded(), hostPackage, hostCertificateSha256, profile);
```

The matching package may try a profile despite a source APK hash or app version
mismatch. The profile must still verify every targeted native image, managed
assembly and patch operand before any prepared copy can be installed. Unknown
managed Matrix dependencies and unresolved DEX routing require analysis.

## Independent profile APK

`profile-vd-code` is packaged by `profile-vd` as an APK containing DEX plus
`assets/profile.json`. The APK is **not installed**. `ProfileStore` verifies its
APK signature against the installed Lab signer, APK package, API version,
metadata and monotonic profile version, then loads its classes from a private
read-only file. Its active pointer changes atomically; a failed update retains
the previous verified profile. Profile code runs with Lab permissions, so only
an authorized Lab signing key may sign a release profile.

The runtime bundle is built separately and does not contain a VD recipe:

```sh
./gradlew :tools:installDist :runtime:assembleRelease :embedded-bootstrap:assembleRelease
uv run scripts/build_bundle.py --matrix /absolute/path/matrix.apk \
  --client /absolute/path/verified-client.apk --output /absolute/analysis/runtime-bundle
uv run scripts/build_vd_profile.py --client /absolute/path/virtual-desktop.apk \
  --output /absolute/analysis/profile-vd
python3 scripts/build_lab.py --lab /absolute/path/pico-store \
  --bundle /absolute/analysis/runtime-bundle \
  --profile /absolute/analysis/profile-vd/matrix-profile-vd.apk
```

The client input to `build_bundle.py` checks bootstrap DEX collisions but is
not packaged or listed as a runtime dependency. `build_vd_profile.py` compiles
its checked recipe and builds the signed profile. Debug builds use the same
standard Android debug key as Lab. Release builds require the four
`PICO_ANDROID_*` signing variables used for the Lab release. The build time in
UTC sets APK versionCode, versionName and profile metadata together; pass
`--built-at YYYY-MM-DDTHH:MM:SSZ` to reproduce a build. Keep original APKs and
outputs in durable research storage outside Git.

Lab fetches the highest `vd-profile-YYYYMMDDTHHMMSSZ` GitHub release from the
Bridge repository. Attach exactly `matrix-profile-vd.apk` with a SHA-256 digest.
The URL, digest, package, API version and signer are checked before activation.
Releasing a new signed profile does not require a Lab APK release.

## Verification

`./scripts/verify.sh` runs the Bridge suite. The opt-in differential regression
compares all 185 VD managed assemblies and loader/AOT bytes with the original
Python adaptation. `tools prepare-portable INPUT BUNDLE OUTPUT CERT_DER
HOST_PACKAGE HOST_CERT_SHA256 PROFILE_JSON` runs full preparation with the
separate profile recipe. A successful local build or byte-level regression is
not a headset installation or streaming test.
