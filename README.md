# d9000_root — vivo Pad 2 免解 BL 锁临时 root（DirtyFrag / CVE-2026-43284）

针对 **vivo Pad 2（PA2373 / DPD2221，天玑 9000 / mt6983，Android 15）** 的提权研究仓库。
核心交付物是 `dist/DirtyFrag-fixed-C.apk`：对上游 DirtyFrag v1.16 内嵌内核模块做了
vermagic / modversions 修复的重打包版本，在本设备上实测获得内核级临时 root
（KernelSU-Next LKM 模式），**无需解锁 BL、无需刷机、重启即复原**。

> 本仓库是研究记录 + 修复产物，不是通用 root 工具。载荷与精确内核构建绑定，
> 换设备、换内核版本都不要直接用，请先读文档。

## 设备与漏洞

| 项 | 值 |
|---|---|
| 设备 | vivo Pad 2，型号 PA2373，代号 DPD2221 |
| SoC | 联发科天玑 9000（mt6983） |
| 系统 | Android 15（OriginOS），安全补丁 2026-05-01，SELinux Enforcing |
| 内核 | `5.10.233-android12-9-gb05bf6af18d3-dirty`（GKI android12-5.10 KMI） |
| 漏洞 | CVE-2026-43284（DirtyFrag）：xfrm ESP 对共享 skb frag 的页缓存原地解密写，确定性逻辑漏洞 |
| 备选链 | CVE-2026-43499（GhostLock，futex/rtmutex-PI 栈 UAF）：设备必然受影响但未投入，原因见 [docs/technical-writeup.md](docs/technical-writeup.md) |

公开分析认为 DirtyFrag 的触发路径依赖 UDP `MSG_SPLICE_PAGES`（6.5 才引入）、
5.10 内核可能不可用——**本设备（5.10.233）实测可用**，该顾虑被实证排除。

## 成果（实测）

- 上游 DirtyFrag v1.16 在本设备首跑卡在 ko 加载（约 10 秒超时）。逆向定位：内嵌 ko 的
  vermagic 写死作者自建内核字符串、`__versions` 段为空，叠加 vivo 内核 vermagic flags
  含定制 token，导致 `finit_module` 失败。
- 核对 v5.10 `kernel/module.c` 语义后明确：带 `__versions` 段时 vermagic 的 release 部分
  不参与比较；CRC 缺失只是 warn-once 放行，**CRC 填错才是硬失败**。
- 据此重铸三个变体做对照实验（详见 [docs/technical-writeup.md](docs/technical-writeup.md)）：

| 变体 | vermagic flags | CRC | 实测结果 |
|---|---|---|---|
| A | 标准 GKI | 11 条 GKI CRC | 半成功：App 显示成功但 KernelSU 未安装（未实锤，见文档"未解问题"） |
| B | 含 `vivo` token | 11 条 GKI CRC | 失败（证明 vivo -dirty 树至少一个符号 CRC 偏离 GKI） |
| **C** | 含 `vivo` token | 空 | **完整成功：KernelSU-Next 激活，LKM (GKI2) 模式，Tracepoint hook，root 可用** |

- root 为临时性：重启失效，重跑 C 版即可恢复；App 内可开 Autorun。

## 快速开始

### 设备要求（硬性）

- 同型号（PA2373 / DPD2221）且内核版本**精确**为
  `5.10.233-android12-9-gb05bf6af18d3-dirty`（`adb shell cat /proc/version` 核对）。
- 载荷绑死该内核构建：CRC、vermagic、符号布局均针对它。其他设备/版本请按
  [docs/reproduction.md](docs/reproduction.md) 重新制作，不要直接刷本仓库的 APK。

### 安装（含 vivo adb 拦截绕过）

vivo 会拦截 `adb install`（报 `INSTALL_FAILED_ABORTED: User rejected permissions`），
且 `adb push` 到设备的 APK 会静默消失。实测可用的绕过方法：

```bash
# 1. 通过 shell stdin 管道写入（base64 中转，push 直传会被静默删除）
base64 -w0 DirtyFrag-fixed-C.apk | adb shell 'base64 -d > /data/local/tmp/df.apk'
# 2. 拷贝到用户可见目录
adb shell 'cp /data/local/tmp/df.apk /sdcard/Download/df.apk'
# 3. 在设备上用文件管理器手动安装
```

同样方法安装 KernelSU-Next（官方 release，见下"上游原件校验"）。

### 使用

1. 打开 DirtyFrag，按界面执行 exploit；成功后打开 KernelSU-Next 确认 LKM 已激活。
2. root 在重启后消失，重跑 C 版恢复；App 内可开 Autorun 实现开机自动执行。

### 风险

- **临时 root**：重启即失效，这是特性也是保护。
- **DirtyFrag 会污染页缓存**：被写过的文件页缓存与磁盘内容不一致，使用后建议重启清理，
  不要在不重启的情况下做系统更新等依赖文件一致性的操作。
- **OTA 可能封洞**：厂商合入补丁后本方法即失效；升级前自行权衡。
- 变体 A 的"半成功"现象原因未实锤（见技术文档），如遇到请按文档排查。

## 仓库结构

```
dist/                  可用构建（C 版为主交付物）+ SHA256SUMS；variants/ 为 A/B 对照版
docs/                  technical-writeup.md（完整技术文档）、reproduction.md（复现指南）、
                       ota-api-notes.md（vivo OTA 接口逆向情报）
tools/                 四个管线脚本：extract_kos / reforge_ko / embed_ko / repack_apk
analysis/              取证与逆向材料：report.md、ko/（8 个原始 ko）、反汇编、symvers、
                       reforged/（重铸 ko 与 lib）、kernel_ref/（内核源码参考片段）
_local/                不入库：上游原件、keystore、固件逆向废料、设备私有 blob
```

## 上游原件校验（本仓库不含这些文件）

| 文件 | sha256 | 来源 |
|---|---|---|
| DirtyFrag-v1.16.apk | `fb0f8e253a0d3c15f01e489922c9a42baef5dd9ce7b61cac8ec0660cfde445d3` | [mitschud/DirtyFrag](https://github.com/mitschud/DirtyFrag) releases |
| KernelSU_Next_v3.4.2_33355-release.apk | `774a5511f7034a4930e881114e202319cbdc34c5aaaa5c7c6b6d2902364e4c58` | [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next) releases |

本仓库重打包构建（自签名）的校验值见 [dist/SHA256SUMS](dist/SHA256SUMS)。

## 签名说明

重打包 APK 使用自签名 keystore（`dfroot.keystore`，口令 `dfroot123`），**keystore 不入库**。
重新生成方法见 [docs/reproduction.md](docs/reproduction.md)。注意：更换签名后，
已安装的 KernelSU 需要重新授权（APK 签名是授权依据之一）。

## 许可证与再分发声明

- 上游 [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot) 采用 **GPL-2.0**
  （本仓库 `LICENSE` 即上游同一文件全文）。
- [mitschud/DirtyFrag](https://github.com/mitschud/DirtyFrag) 是 DFRoot 的 fork，
  仓库内**未附带 LICENSE 文件**；本项目以其上游 DFRoot 的 GPL-2.0 为准。
- `dist/` 内的 APK 是对 DirtyFrag v1.16 **二进制修改后的再分发**，属 GPL-2.0 衍生作品，
  按 GPL-2.0 第 2(a) 条要求，修改内容已显著记录：见
  [docs/technical-writeup.md](docs/technical-writeup.md) §3–§6（ko vermagic flags 增加
  `vivo` token、`__versions` 处理，2026-10-25）。对应源码即上游仓库 + 本仓库 `tools/`
  管线脚本与文档。
- 本仓库原创部分（`tools/` 脚本、`docs/` 文档、`analysis/` 取证材料）同样以 **GPL-2.0** 发布。

## 致谢

- [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)：原始 DFRoot（GPL-2.0）
- [mitschud/DirtyFrag](https://github.com/mitschud/DirtyFrag)：加固 fork（v1.16），本项目 APK 的直接修改对象
- [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)：CVE-2026-43284 原始发现与 PoC
- [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)：SU 管理器
- GKI 构建与符号表：[ci.android.com](https://ci.android.com)（android12-5.10, build 16466987）

## 免责声明

本项目仅供安全研究与自有设备测试使用。提权操作会使设备暂时处于弱保护状态，
可能被恶意应用利用；DirtyFrag 的页缓存污染若使用不当可能影响系统稳定性。
作者不对任何数据丢失、设备损坏或保修失效负责。请勿将本项目用于未经授权的设备。
