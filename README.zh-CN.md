![PICO Matrix Bridge](assets/brand/banner.svg)

# PICO Matrix Bridge

[![源码检查](https://github.com/nkanf-dev/pico-matrix-bridge/actions/workflows/check.yml/badge.svg)](https://github.com/nkanf-dev/pico-matrix-bridge/actions/workflows/check.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-b33921.svg)](LICENSE)

[English](README.md) · [PICO Store Lab](https://github.com/nkanf-dev/pico-store-lab) · [接入指南](docs/integration.md)

在国区 PICO 头显上，用自己的国际区账号使用支持的应用，无需切换头显地区，也无需 root。

Matrix Bridge 为使用 PICO Platform SDK 的应用提供兼容支持。安装时自动准备应用副本，将兼容组件放进应用，打开后即可使用自己的账号。

## 配合 PICO Store Lab 使用

Android 集成将应用适配和账号接入放进下载、安装流程：

1. 在 PICO Store Lab 登录你的 PICO 国际区账号。
2. 选择应用并下载。
3. 出现提示时选择适配版，再确认安装。已有适配规则的应用，可以直接在详情页选择适配版。
4. 打开应用，继续使用刚才登录的账号；也可以在应用内登录。

集成版的构建方法见 [开发与构建](docs/development.md)。付费应用需要使用已购买该应用的账号。

## 应用支持

**Virtual Desktop for PICO 1.34.22.0** 已有独立适配规则，支持安装、账号登录和连接电脑桌面。

其他应用会自动检测。不依赖 Matrix 的应用照常安装；识别到 Matrix 接入时，可以选择通用 profile 适配，也可以安装原版。需要特殊处理的应用使用更具体的 profile。遇到应用兼容问题，可以在 issue 中提供应用名称、版本、头显型号和具体表现。

## 构建与接入

需要 JDK 17、Python 3.12+ 和 Android SDK。

```sh
./scripts/verify.sh
```

构建兼容组件和集成版 Lab APK，请阅读 [开发与构建](docs/development.md)。接入其他 Android 安装器，请阅读 [宿主接入](docs/integration.md)。

| 组件 | 用途 |
|---|---|
| `adapter-core` | 在 Android 或 JVM 上检测应用、准备兼容安装包 |
| `account-android` | 登录账号，并将账号交接给已安装的应用 |
| `installer-android` | 为应用副本签名、安装，并恢复中断的任务 |
| `embedded-bootstrap` 和 `runtime` | 在目标应用内运行兼容组件 |
| `tools`、`scripts` 和 `profiles` | 提取协议、维护应用适配 |

## 维护应用支持

[维护指南](docs/maintenance.md) 包含协议更新、应用适配规则和可重复构建流程。规则记录原始版本与处理方式，应用更新后可以沿用同一套构建流程。

## 许可

项目源码使用 [MIT 许可](LICENSE)。第三方应用和依赖沿用各自的许可。
