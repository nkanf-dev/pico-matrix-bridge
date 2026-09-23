# Contributing profiles

Profiles live in `profiles/manifests/`, `profile-<key>-code/`, and `profile-<key>/`. A profile owns its application-specific matching and adaptation code; the bridge provides shared detection, APK preparation, installation, and recovery.

1. Open an issue with the app package name, version, headset model, and the behavior to support. Do not upload proprietary APKs, account credentials, or signing keys.
2. Add a manifest with a unique key, package matcher, and priority. Use the `generic` profile for shared PICO account integration; add a specific profile when an app needs its own changes.
3. Keep the application recipe and code inside the profile. Include a reproducible test or fixture that checks the matching rule and the changed behavior. Run `./scripts/verify.sh` before submitting a pull request.
4. For local integration, sign profiles with a key you control and pass its public certificate to `build_generic_profile.py` or `build_vd_profile.py` with `--development-profile-certificate`. Pass the same certificate to `build_lab.py`. Never commit a private key or a built APK.
5. Submit a pull request describing the app versions you checked and what the profile changes. Use Conventional Commits for commits.

Maintainers review the source and run the `Publish signed profile` GitHub Actions workflow on `main`. The workflow uses the `profile-publishing` environment, whose secrets contain the dedicated profile publisher key. It verifies the source, signs the selected profile, publishes a timestamped GitHub Release, and checks the uploaded APK digest. Contributors do not need the publisher key. Lab trusts the public publisher certificate in `profiles/signing/profile-publisher.pem` and can update profiles without replacing the Lab APK.
