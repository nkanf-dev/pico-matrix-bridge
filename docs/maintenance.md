# 维护应用与协议支持

应用适配规则与协议基线分别放在 `profiles/clients/` 和 `profiles/`。每个 profile 在 `profiles/manifests/<key>.json` 声明匹配规则与优先级。更新应用时维护对应 profile；Matrix 协议变化时重新提取基线。两条路径共用检测、构建和安装组件。

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

VD profile 固定原始 APK、程序集、方法、字符串和原生指令的身份。`compile_vd_profile.py` 根据原始元数据定位，生成包含原始字节校验的 recipe；`profile-vd-code` 执行完整 VD 适配，`adapter-core` 只提供通用检查、runtime 嵌入与 APK 写入。profile APK 同时装入 VD 代码和 recipe，使用本次实际目标签名证书计算替换值。比较指令、分支和无关程序集保持不变。

客户端更新时，先静态定位变化，再调整 profile 并执行差分回归。Lab 可让用户对已知应用的新版本显式尝试现有 profile；整包哈希与版本差异本身不阻止尝试，但目标程序集、AOT 镜像、原生库和补丁操作数仍必须与 recipe 匹配。不匹配会在安装前失败，并保留原始下载及现有应用。通用 native Matrix 适配也由独立的 `generic` profile 提供，要求明确的应用标识、入口和 loader 身份。profile 按优先级、包名匹配精度、精确版本依次选择；`*` 通用 profile 的优先级最低。Lab 集成构建会拒绝两个 profile 使用相同的包名匹配规则和优先级。

## 4. 构建与检查

按 [开发说明](development.md) 分别生成通用 runtime bundle 和各个签名 profile APK，再构建 Lab。`scripts/profile_registry.py` 会在源码检查和构建 profile 时拒绝重复匹配规则；Lab 集成构建也会核对实际打包 APK。bundle 清单记录 runtime/bootstrap 身份，应用 recipe 留在 profile。release 构建默认不带诊断探针。每个 profile 使用更新的 UTC 秒，在 Bridge 仓库创建 `<key>-profile-YYYYMMDDTHHMMSSZ` release 并附上 `matrix-profile-<key>.apk`；Lab 下载后校验哈希与 Lab 同签名再切换，失败保留已验证版本。新增社区 profile 可独立提交清单、代码与检查样本，经维护者审查和同签名构建后发布；Lab 按 key 自动发现。

```sh
./scripts/verify.sh
```

样本回归逐项比较 185 个托管程序集、native loader 和 AOT 镜像，命令见开发说明。每次保留原始样本、当前 bundle、必要的回退产物及小型构建收据；完成后移除临时 APK 副本。

## 5. 维护安装与账号流程

安装器为每个任务记录目标包、版本、签名、APK 哈希和系统 session。重启后从实际安装结果恢复；已有其他签名或不同来源的应用时保留原应用并报告冲突。安装后的账号交接使用目标实际身份，失败时应用仍可正常打开登录。接口与状态见 [Android 宿主接入](integration.md)。
