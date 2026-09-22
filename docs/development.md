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
python3 scripts/build_lab.py --lab /absolute/source/pico-store --bundle /absolute/research/analysis/build-001/compatibility-bundle
```

`build_bundle.py` 的 Python 依赖已在脚本元数据中固定版本，`uv run` 可建立隔离环境。bundle 默认使用 release runtime，不包含诊断探针、账号或签名私钥。它包含供应代码，只在本地研究目录保存；不要提交 Git 或上传 CI artifact。

`build_lab.py` 编译并检查 Lab 集成版，不安装设备。对应原始 Gradle 命令：

```sh
cd /absolute/source/pico-store/apps/android
./gradlew :app:testDebugUnitTest :app:assembleDebug -PmatrixBridgeDir=/absolute/source/pico-matrix-bridge -PmatrixBundleDir=/absolute/research/analysis/build-001/compatibility-bundle
```

去掉两个属性即可检查普通 Lab。两种构建共用输出目录，每次以最后一次构建为准。`build_lab.py` 会读取产物并验证打包的 bundle 清单及内容确实匹配输入。

## 样本回归

使用研究 Python 环境或先安装 `build_bundle.py` 中列出的固定依赖：

```sh
VD_RESEARCH_ROOT=/absolute/research/analysis/vd-static-2026-09-22 python3 -m unittest discover -s scripts/tests -p test_vd_integrity.py -v
MATRIX_PORTABLE_RESEARCH=/absolute/research/analysis/build-001/differential MATRIX_VD_APK=/absolute/research/artifacts/virtual-desktop-pico-1.34.22.0.apk MATRIX_TEST_CERT=/absolute/research/analysis/target-public-cert.der python3 -m unittest discover -s scripts/tests -p test_portable_profile.py -v
```

第二组逐项对照 Python 研究适配和可移植引擎：185 个托管程序集、SDK loader 与 AOT 镜像。只需要公开证书，不读取私钥。完整 APK 的签名与对齐可以使用 Android SDK 的 `apksigner verify` 和 `zipalign -c -P 16 4` 检查。
