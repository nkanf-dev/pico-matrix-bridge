# 开发与检查

环境：JDK 17、Python 3.12+、Android SDK platform 35 和 build-tools 36.0.0；Lab 另需 platform 37。通过 `JAVA_HOME` 和 `ANDROID_HOME` 指向本机环境。

## 源码检查

```sh
./scripts/verify.sh
```

该命令检查生成协议、JVM/Python 单元测试、Android 库和运行时构建及安装器 lint。CI 运行同一命令。需要样本的回归通过下方环境变量启用。

## 构建兼容 bundle 和 Lab

原始 APK 保留在研究目录的 `artifacts/` 中，输出放同级 `analysis/`，无需复制原包。使用空的新输出路径；已有目录不会覆盖。

```sh
./gradlew :tools:installDist :runtime:assembleRelease :embedded-bootstrap:assembleRelease
uv run scripts/build_bundle.py --matrix /absolute/research/artifacts/pico-global-matrix-6.3.4.apk --client /absolute/research/artifacts/virtual-desktop-pico-1.34.22.0.apk --output /absolute/research/analysis/build-001/compatibility-bundle
uv run scripts/build_vd_profile.py --client /absolute/research/artifacts/virtual-desktop-pico-1.34.22.0.apk --output /absolute/research/analysis/build-001/profile-vd
python3 scripts/build_lab.py --lab /absolute/source/pico-store --bundle /absolute/research/analysis/build-001/compatibility-bundle --profile /absolute/research/analysis/build-001/profile-vd/matrix-profile-vd.apk
```

两个构建脚本的 Python 依赖已在脚本元数据中固定版本。bundle 默认使用 release runtime，不包含 VD recipe、诊断探针、账号或签名私钥。它包含供应代码，只在本地研究目录保存；不要提交 Git 或上传 CI artifact。profile APK 带有完整 VD 适配代码和 recipe，调试版使用 Lab 的默认调试签名；发布版必须使用同一组 `PICO_ANDROID_*` 发布签名变量。profile 版本使用构建时的 UTC 秒：APK versionCode 为 Unix 秒，versionName 和内嵌元数据为 ISO UTC 时间。重现构建可指定 `--built-at 2026-09-23T12:34:56Z`。

`build_lab.py` 编译并检查 Lab 集成版，不安装设备。对应原始 Gradle 命令：

```sh
cd /absolute/source/pico-store/apps/android
./gradlew :app:testDebugUnitTest :app:assembleDebug -PmatrixBridgeDir=/absolute/source/pico-matrix-bridge -PmatrixBundleDir=/absolute/research/analysis/build-001/compatibility-bundle -PmatrixProfileApk=/absolute/research/analysis/build-001/profile-vd/matrix-profile-vd.apk
```

去掉三个属性即可检查普通 Lab。两种构建共用输出目录，每次以最后一次构建为准。`build_lab.py` 会读取产物并验证打包的 bundle、profile 与 Lab 签名确实匹配输入。Lab 设置中的 VD profile 更新单独查找 Bridge 仓库的 `vd-profile-YYYYMMDDTHHMMSSZ` release；签名 profile 可独立替换，不需要更新 Lab APK。

## 样本回归

使用研究 Python 环境或先安装 `build_bundle.py` 中列出的固定依赖：

```sh
VD_RESEARCH_ROOT=/absolute/research/analysis/vd-static-2026-09-22 python3 -m unittest discover -s scripts/tests -p test_vd_integrity.py -v
MATRIX_PORTABLE_RESEARCH=/absolute/research/analysis/build-001/differential MATRIX_VD_APK=/absolute/research/artifacts/virtual-desktop-pico-1.34.22.0.apk MATRIX_TEST_CERT=/absolute/research/analysis/target-public-cert.der python3 -m unittest discover -s scripts/tests -p test_portable_profile.py -v
```

第二组逐项对照 Python 研究适配和可移植引擎：185 个托管程序集、SDK loader 与 AOT 镜像。只需要公开证书，不读取私钥。完整 APK 的签名与对齐可以使用 Android SDK 的 `apksigner verify` 和 `zipalign -c -P 16 4` 检查。
