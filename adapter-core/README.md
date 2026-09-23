# Generic APK preparation and application profiles

`adapter-core` is the application-neutral Java 17 preparation engine. It inspects
an original APK, builds an embedded Matrix runtime, writes an unsigned adapted
copy, and verifies that unrelated ZIP entries were preserved. It never reads a
signing key, opens a network connection or installs an APK. `installer-android`
verifies/signs the prepared copy and owns Android PackageInstaller.

Each `ApplicationProfile` supplies its package matcher, priority, version
metadata, input checks, replacement entries and output checks. The core selects
from a list and passes one implementation to the shared APK writer.
`profiles/vd/code` owns the Virtual Desktop managed-store, loader and AOT
adaptation; `profiles/generic/code` owns the checked native Matrix path. No
application package name, assembly, offset or recipe is compiled into
`adapter-core`.

```java
List<ApplicationProfile> profiles = /* verified by the Android host */;
AdapterEngine.Inspection inspection = AdapterEngine.inspect(original, bundleDir, profiles);
AdapterEngine.Result result = AdapterEngine.prepare(original, bundleDir, unsignedOutput,
    targetCertificate.getEncoded(), hostPackage, hostCertificateSha256, profiles);
```

The matching package may try a profile despite a source APK hash or app version
mismatch. The profile must still verify every targeted native image, managed
assembly and patch operand before any prepared copy can be installed. Unknown
managed Matrix dependencies and unresolved DEX routing require analysis.

## Independent profile APK

Each implementation is packaged as an APK containing DEX plus
`assets/profile.json`. The APK is **not installed**. `ProfileStore` verifies its
APK signature against the pinned profile publisher certificate, APK package, API version,
metadata and monotonic profile version, then loads its classes from a private
read-only file. Its active pointer changes atomically; a failed update retains
the previous verified profile. Profile code runs with Lab permissions, so only
the profile publisher key is kept separate from the Lab signing key.

The runtime bundle is built separately and does not contain a VD recipe:

```sh
./gradlew :tools:installDist :runtime:assembleRelease :embedded-bootstrap:assembleRelease
uv run scripts/build_bundle.py --matrix /absolute/path/matrix.apk \
  --client /absolute/path/verified-client.apk --output /absolute/analysis/runtime-bundle
uv run profiles/vd/scripts/build.py --client /absolute/path/virtual-desktop.apk \
  --output /absolute/analysis/profile-vd
python3 scripts/build_profile.py --key generic --output /absolute/analysis/profile-generic
mkdir -p /absolute/analysis/profiles
cp /absolute/analysis/profile-{vd,generic}/matrix-profile-*.apk /absolute/analysis/profiles/
python3 scripts/build_lab.py --lab /absolute/path/pico-store \
  --bundle /absolute/analysis/runtime-bundle \
  --profiles-dir /absolute/analysis/profiles
```

The client input to `build_bundle.py` checks bootstrap DEX collisions but is
not packaged or listed as a runtime dependency. The VD profile build script compiles
its checked recipe and builds the signed profile. Debug builds use the
standard Android debug key. Release builds require the four
`PICO_PROFILE_*` signing variables. The build time in
UTC sets APK versionCode, versionName and profile metadata together; pass
`--built-at YYYY-MM-DDTHH:MM:SSZ` to reproduce a build. Keep original APKs and
outputs in durable research storage outside Git.

Lab discovers `<key>-profile-YYYYMMDDTHHMMSSZ` GitHub releases from the Bridge
repository. Attach exactly `matrix-profile-<key>.apk` with a SHA-256 digest.
The URL, digest, package, API version and signer are checked before activation.
Releasing a new signed profile does not require a Lab APK release.
The Lab build rejects profiles with the same package matcher and priority.

## Verification

`./scripts/verify.sh` runs the Bridge suite. The opt-in differential regression
compares all 185 VD managed assemblies and loader/AOT bytes with the original
Python adaptation. `tools prepare-portable INPUT BUNDLE OUTPUT CERT_DER
HOST_PACKAGE HOST_CERT_SHA256 VD_RECIPE_JSON [GENERIC_RECIPE_JSON]` runs full
preparation with profile recipes. A successful local build or byte-level regression is
not a headset installation or streaming test.
