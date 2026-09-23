# Android 宿主接入

PICO Store Lab 负责目录、购买、下载和安装入口。Matrix Bridge 提供共用账号、应用检测、适配和安装结果处理。目标应用仍调用原有 PICO Platform / Matrix SDK；兼容运行时嵌入目标应用，随目标进程运行。

```text
Lab 登录 / 恢复账号
  → 取得应用并校验下载
  → 检查 APK
      ├─ 普通应用：保留原包与签名
      ├─ 已知应用：精确版本使用 profile；其他版本可显式尝试
      ├─ 可识别的通用 Matrix 接入：使用通用适配
      └─ 未支持或有歧义：保留下载，提示更新支持
  → 准备副本并签名
  → Android 安装确认和实际结果
  → 核对已安装 APK → 首次安装时交接该应用的账号授权
```

## 组件

| 模块 | 职责 |
|---|---|
| `adapter-core` | JVM/Android 共用检测和 APK 准备引擎，无网络、设备或桌面命令依赖 |
| `account-android` | Passport 登录、会话迁移、目标应用授权和安装后交接 |
| `installer-android` | Android Keystore 签名、PackageInstaller、结果收据和恢复 |
| `embedded-bootstrap` / `runtime` | 应用内启动、登录、Matrix SDK 路由和授权续期 |
| `tools` / `scripts` | 协议提取、profile 编译、bundle 构建和离线检查 |

## 宿主调用

在工作线程运行网络请求和 APK 准备。先将兼容 bundle 作为宿主 assets 中的 `matrix-bridge/` 目录提供。`AssetBundle.open` 校验并展开到应用私有目录，`MatrixInstaller` 处理下载完成的原包：

```java
MatrixAccount account = new MatrixAccount(context);
account.sendCode(email);
account.login(email, code);

MatrixInstaller installer = new MatrixInstaller(context);
AutoCloseable subscription = installer.observe(status -> updateUi(status.code));
installer.reconcile();
File bundle = AssetBundle.open(context, "matrix-bridge");
AdapterEngine.Inspection result = AdapterEngine.inspect(downloadedApk, bundle);
// 宿主根据检测结果和用户选择指定安装方式。
installer.prepareAndInstall(downloadedApk, bundle, MatrixInstaller.Mode.ADAPTED);
// 界面销毁时 subscription.close()；安装结果由 manifest receiver 接收。
```

`Mode.ORIGINAL` 安装保留签名的原包；`Mode.ADAPTED` 要求检测结果可进入适配准备，否则停止并返回原因。两参数的 `prepareAndInstall` 保留自动路由方式。详情页可用 `AdapterEngine.supportsProfile(bundle, packageName, versionCode)` 查询精确版本支持，用 `canAttemptProfile(bundle, packageName)` 显示其他版本的尝试入口。尝试时逐项验证补丁输入；不兼容就保留下载和已安装副本，不自动改装原版。下载后以 `inspect` 的结果为准。检测记录应按原包名和版本保存，在用户暂不安装时也予以保留。

观察回调不保证在 UI 线程。Activity 重建后重新订阅并调用 `reconcile()`。`prepareAndInstall` 返回表示已提交系统安装，不表示应用已装好。正式结果来自 `InstallationStatus`：

| 状态 | 含义 |
|---|---|
| `checking` / `preparing` / `verifying` | 检查和准备中 |
| `awaiting_install` | 等待系统确认或安装结果 |
| `verifying_install` | 安装完成，正在核对实际安装内容 |
| `account_setup` | 安装已完成，正在交接账号 |
| `installed` | 安装及所需账号交接完成 |
| `installed_login_required` | 安装成功，打开应用登录即可 |
| `cancelled` / `failed` | 系统取消或准备/安装失败 |

收据保存任务、系统 session、目标包、版本、签名和 APK 哈希。恢复时逐项核对已安装文件；还存在的已封存 session 会重新提交回调，恢复丢失的确认流程。中断的未封存 session 被放弃，原下载保留。安装后账号交接失败不会被报告为安装失败；宿主可调用 `retryAccount(id)` 重试。

## 账号与签名

Lab 的旧加密会话只迁移一次：先导入并确认新会话，再标记迁移完成，最后移除旧副本。退出先关闭旧会话迁移入口，避免旧数据恢复登录。Store SDK 的目录、购买和下载能力不变；每次需登录的 Store 请求读取当前共享会话，避免账号授权刷新后继续使用旧令牌。

每台设备上的安装器使用稳定的 Android Keystore 密钥为应用副本签名。目标签名与安装器签名是两个独立身份：前者用于适配和账号授权，后者用于目标的受限交接入口。更换或清除宿主后丢失签名密钥时，已有副本更新会明确报签名冲突，不自动卸载。

账号材料不会参与 APK 准备。首次安装完成后，宿主为已核实的目标取得真实应用授权，经包名、签名和一次性 challenge 交接。覆盖更新保留应用内原有账号，不重新交接宿主账号。目标只保存自己的应用授权，独立运行和续期；没有可用账号时显示应用内登录。

## Lab 开发构建

Lab 使用显式 Gradle composite build；未设置属性的构建继续使用现有独立账号和安装实现，无需访问本私有仓库。集成命令见 [开发说明](development.md)。
