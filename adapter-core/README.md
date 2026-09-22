# Portable APK preparation

`org.picomatrix.bridge.adapter.AdapterEngine` is a Java 17 library using APIs
available on Android 29. It never opens a network connection, reads a signing key,
starts a process, or installs an APK. The host signs its unsigned result with the
same certificate it supplied, verifies that signature, and owns PackageInstaller.

```java
AdapterEngine.Inspection inspection = AdapterEngine.inspect(original, bundleDir);
AdapterEngine.Result result = AdapterEngine.prepare(
    original, bundleDir, unsignedOutput,
    targetCertificate.getEncoded(), hostPackage, hostCertificateSha256);
```

Both methods accept `Path`; `File` overloads are also available. All result fields
are public and final. `Inspection` exposes `route`, original `packageName`,
`profileId`, `appId`, `reason`, `inputSha256`, `matrixDetected`, and Android
long `versionCode`. `supportsProfile(bundleDir, packageName, versionCode)` reads
only the pinned profile metadata for a package/version badge before download;
actual preparation still checks the original APK hash. `Result` exposes `output`,
`requiresSigning`, `inputSha256`, `outputSha256`, `profileId`, `appId`, target
`packageName`, and `targetSignerSha256`. PASSTHROUGH returns the original with
`requiresSigning=false`; it must retain its original signature. ANALYSIS_REQUIRED
throws before writing output. PROFILE and GENERIC produce an atomic new copy.

Ordinary APKs without Matrix references, including Unity applications, retain their
original install path. Unknown managed runtimes with Matrix dependencies require
analysis. Known VD inputs require the exact source hash and never fall through when their
version changes. The separate generic path admits a literal unambiguous app ID,
a known native Matrix loader hash, no DEX routing references and no managed
runtime. Bootstrap class collisions, missing launchers, shared UIDs, conflicting
bundle identities and unknown dependencies fail closed. The original remains
unchanged. ZIP entries are aligned to 4 bytes, with native libraries at 16 KiB.

## Build the private bundle

```sh
./gradlew :tools:installDist :runtime:assembleRelease :embedded-bootstrap:assembleRelease
python scripts/build_bundle.py \
  --matrix /absolute/path/pico-global-matrix-6.3.4.apk \
  --client /absolute/path/virtual-desktop-pico-1.34.22.0.apk \
  --output /absolute/ignored/path/compatibility-bundle
```

Use the pinned Python dependencies declared in `scripts/build_bundle.py` (or the
existing research venv). The output must be new. `bundle.json` pins every included
file by bytes and SHA-256: `vd-recipe.json`, `bootstrap.dex`,
`matrix-runtime-template.zip`, and `matrix-runtime-profile.json`. Vendor APKs are
read in place, never copied into the bundle or repository. Vendor DEX is filtered
once at build time; runtime bytecode and the small bootstrap remain separate.
Native Matrix package routing happens during preparation so the bundle can also
serve the generic path. A release runtime is mandatory by default;
`--research-diagnostics` explicitly selects a debug research bundle.

The bundle carries executable vendor dependencies and must remain private in the
host's trusted app assets/storage. Its hashes detect incomplete or mixed inputs;
they are not a remote trust/signature mechanism. It contains no user session,
cookies, grants, private keys or diagnostic probe by default. `account.agwKey` is
a fixed vendor protocol constant, not an account credential. The account module still obtains and verifies genuine server grants.

## Checked VD profile compilation

`compile_vd_profile.py` resolves the original metadata-selected methods/strings,
validates their calls, IL, native instruction operands and store extents using the
existing research implementation, and emits only hashes and compact offset
recipes. The portable engine checks the full original store/assembly/AOT hashes
and every expected operand before replacement. It derives the certificate string,
Java signature hash, X509 hash and routed-loader MD5 from actual inputs. It changes
no comparison/branch opcodes, metadata identity, method layout or entitlement
result. LZ4 uses its pure Java implementation; no native helper is required.

Target signing identity and host provisioning identity are separate. The target
certificate controls all application integrity comparisons and
`targetSignerSha256`; `provisionerPackage`/`provisionerSignerSha256` identify the
host permitted to hand off a genuine per-application grant. Generic target names
fit the pinned native route slot; hosts must compare the installed target
configuration's `originalPackage` and `appId` before updating an existing generic
target, in addition to checking its signer, to reject truncated-name collisions. An oversized target
certificate fails instead of relocating metadata.

## Verification

Source-only: `./gradlew :adapter-core:test :tools:test`. Tests cover checked
operands, metadata capacity, actual signer algorithms, known-version mismatch,
generic route admission, ambiguous identities and damaged bundle files.

The retained-sample differential test is opt-in:

```sh
MATRIX_PORTABLE_RESEARCH=/absolute/durable/analysis/output \
MATRIX_VD_APK=/absolute/path/virtual-desktop-pico-1.34.22.0.apk \
MATRIX_TEST_CERT=/absolute/path/public-signer.der \
python -m unittest scripts/tests/test_portable_profile.py -v
```

It compares all 185 decompressed managed assemblies and native loader/AOT bytes
against the original Python pipeline; it requires no private key or device.
`tools prepare-portable INPUT BUNDLE OUTPUT CERT_DER HOST_PACKAGE HOST_CERT_SHA256`
is the desktop entry point to the same engine used by Android. External
`apksigner`/`zipalign -c -P 16 4` are useful offline validation tools, not runtime
dependencies.
