# 维护应用与协议支持

应用适配规则与协议基线分别放在 `profiles/clients/` 和 `profiles/`。更新应用时维护对应 profile；Matrix 协议变化时重新提取基线。两条路径共用检测、构建和安装组件。

## 1. 取得并检查输入

原始 APK 放在工作目录的 `artifacts/`，提取结果和构建输出放在 `analysis/`。记录来源、版本和 SHA-256，工具直接读取原包，无需复制或完整解压。

```sh
python3 scripts/matrix.py inspect /absolute/work/artifacts/client.apk --output /absolute/work/analysis/client-inspection.json
python3 scripts/matrix.py profile /absolute/work/artifacts/matrix.apk --output /absolute/work/analysis/matrix-profile.json
python3 scripts/matrix.py compare profiles/matrix-global-6.3.4.json /absolute/work/analysis/matrix-profile.json --output /absolute/work/analysis/profile-diff.json
```

提取器直接读取 DEX 的 WireField、命令常量和枚举，同时记录 Manifest、SDK 入口和原生库哈希。重复字段、矛盾命令、重复 ZIP 项、解析失败或处理中的输入变化会终止任务。

## 2. 更新协议基线

先比较字段编号、类型、重复字段、命令、驱动和原生依赖。更新基线后重新生成协议常量：

```sh
python3 scripts/contracts.py extract /absolute/work/analysis/matrix-inspection.json profiles/matrix-global-6.3.4.json --java protocol/src/main/java/org/picomatrix/bridge/protocol/MatrixContract.java
python3 scripts/matrix.py check-generated
```

运行时原生依赖、账号协议参数和 bootstrap 类也属于版本输入。`build_bundle.py` 对照固定基线和依赖闭包构建，未匹配的输入会被拒绝。

## 3. 更新应用规则

VD profile 固定原始 APK、程序集、方法、字符串和原生指令的身份。`compile_vd_profile.py` 根据原始元数据定位，生成包含原始字节校验的 recipe；`adapter-core` 在 Android/JVM 上执行 recipe，并使用本次实际目标签名证书计算替换值。比较指令、分支和无关程序集保持不变。

客户端更新时，先静态定位变化，再调整 profile 并执行差分回归。已知应用若原包哈希不匹配，会要求更新 profile，不会自动切换到通用适配。通用路径独立处理已识别的 native Matrix 接入，要求明确的应用标识、入口和 loader 身份。

## 4. 构建与检查

按 [开发说明](development.md) 生成 bundle 并构建 Lab。bundle 清单记录各文件哈希、输入 APK 身份和 runtime/bootstrap 版本；release 构建默认不带诊断探针。所有输出先写入同级工作目录，完成后原子落盘。

```sh
./scripts/verify.sh
```

样本回归逐项比较 185 个托管程序集、native loader 和 AOT 镜像，命令见开发说明。每次保留原始样本、当前 bundle、必要的回退产物及小型构建收据；完成后移除临时 APK 副本。

## 5. 维护安装与账号流程

安装器为每个任务记录目标包、版本、签名、APK 哈希和系统 session。重启后从实际安装结果恢复；已有其他签名或不同来源的应用时保留原应用并报告冲突。安装后的账号交接使用目标实际身份，失败时应用仍可正常打开登录。接口与状态见 [Android 宿主接入](integration.md)。
