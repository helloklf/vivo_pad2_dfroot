# vivo Pad 2（DPD2221）DirtyFrag 提权全程技术记录

本文是本仓库的主文档，按时间线完整记录从漏洞评估到修复成功的过程。
约定：**【实测】** = 在目标设备上验证过；**【推断】** = 有证据支撑但未直接验证；
**【未实锤】** = 尚无充分证据，如实存疑。

- 目标设备：vivo Pad 2（型号 PA2373，代号 DPD2221，联发科天玑 9000 / mt6983）
- 系统：Android 15（OriginOS），安全补丁 2026-05-01，SELinux Enforcing
- 内核：`5.10.233-android12-9-gb05bf6af18d3-dirty`（GKI android12-5.10 KMI）
- 目标：免解 BL 锁提权
- 完整逆向细节见 [../analysis/report.md](../analysis/report.md)，本文侧重过程与结论

## 1. 背景与漏洞链评估

候选两条链，评估后只投入了一条。

### 1.1 GhostLock（CVE-2026-43499）—— 评估后放弃

futex/rtmutex-PI 栈 UAF。5.10.261 才修复，本设备内核 5.10.233 **必然受影响**。
但作为 exploit 链的工程代价过高，全部有实证依据：

- `CONFIG_PANIC_ON_OOPS=y`【实测，`/proc/config.gz`】：UAF 类漏洞试错即重启，
  没有灰度调试空间；
- 无 BTF【实测】：结构偏移需要 boot.img 反汇编确定；
- `CONFIG_STATIC_USERMODEHELPER=y`【实测】：UMH 类后利用路径受限；
- **boot.img 无法免费获得**【实测，详见 [ota-api-notes.md](ota-api-notes.md)】：
  设备分区直读被 SELinux 拒绝；vivo OTA 接口参数走 native 加密（`jvq_param`）无法从
  PC 伪造；免费公开渠道无该版本全量包，只有付费站 ONFIX 有。

结论：作为备选保留，未投入。

### 1.2 DirtyFrag（CVE-2026-43284）—— 采用

xfrm ESP 对共享 skb frag 的页缓存原地解密写，是确定性逻辑漏洞而非竞争/UAF，
不触发 oops，`PANIC_ON_OOPS` 不构成障碍。

公开分析认为其触发路径依赖 UDP `MSG_SPLICE_PAGES`（6.5 才引入），5.10 内核可能不可用。
**本设备（5.10.233）实测可用**【实测】——该顾虑被实证排除，特此记录，
对同样在 5.10 GKI 上评估此漏洞的人有参考价值。

## 2. 工具链与首跑

工具：mitschud/DirtyFrag v1.16（[diabl0w/DFRoot](https://github.com/diabl0w/DFRoot) 的加固 fork）
+ KernelSU-Next v3.4.2。

**vivo 安装拦截**【实测】：`adb install` 被系统拦截
（`INSTALL_FAILED_ABORTED: User rejected permissions`）；`adb push` 到设备的 APK 会
静默消失。绕过方法：shell stdin 管道写入正常——

```bash
base64 -w0 file.apk | adb shell 'base64 -d > /data/local/tmp/x.apk'
adb shell 'cp /data/local/tmp/x.apk /sdcard/Download/x.apk'   # 再手动安装
```

**首跑结果**【实测】：

1. KMI 正确识别为 android12-5.10；
2. 页缓存补丁全部成功：`crash_dump64 → splicehelper`、
   `libbinderdebug.so → dfroot.ko`、`libc++.so` trampoline + shellcode；
3. init hook 触发成功（日志出现 `libc++: loading custom module`）；
4. **卡在 ko 加载**，App 约 10 秒后打印 `timeout: ERROR - check logcat & dmesg`。

日志里出现了 `/dev/df` 对应的提示、没有出现 `/dev/dfm0` 对应的
`kernel module: launching bootstrap`。由回报机制（见 report.md §4）可知：
shellcode 已在 init 进程里执行并（大概率）已 execve insmod，但 **ko 的 init_module
没有被执行**——失败点精确定位在 `/vendor/bin/insmod /vendor/lib64/libbinderdebug.so`
这一次 `finit_module` 调用本身。

## 3. 逆向发现

完整细节见 [../analysis/report.md](../analysis/report.md)，此处列关键结论：

1. `libdfroot.so` 内嵌 8 个 ko，按 KMI 选择；android12-5.10 用第 0 个
   （`analysis/ko/dfroot_0.ko`，13976 字节）【实测，反汇编 + 描述符表核对】。
2. ko_0 的 vermagic 写死为 `5.10.252-dirty SMP preempt mod_unload modversions aarch64`
   ——作者自建内核的字符串，任何零售设备都不可能精确匹配【实测】。
3. ko_0 的 `__versions` 段存在但 sh_size=0（**0 条 CRC**），却引用 11 个内核导出符号
   （10 个未定义符号 + 隐式的 `module_layout`）【实测】。
4. **`libdfroot.so` 对 ko 只做 memcpy，没有任何运行时修补**——不修 vermagic、不填 CRC，
   原样写入目标文件【实测，反汇编 0x1e8e8–0x1e924 逐指令核实】。对照：shellcode 安装路径
   反而有运行时地址修补（`bfxil` 编 `adr` 立即数），ko 没有等价处理。
5. 设备内核配置【实测，`/proc/config.gz`】：`CONFIG_MODVERSIONS=y`、
   无 `MODULE_SIG`（不需要签名，好事）、无 `MODULE_FORCE_LOAD`（不能强塞）。

由此形成第一版判断：vermagic release 不匹配是第一道坎，空 `__versions` 必然 EINVAL。
**这个判断后来被证明是错的**，见下一节。

## 4. 转折：核对 v5.10 kernel/module.c 的真实语义

第一版修复方案"必须同时修 vermagic + 补 11 条真实 CRC"是基于经验直觉。
动手前核对 torvalds/linux v5.10 tag 的 `kernel/module.c`（GKI 同逻辑），
推翻了两个中间结论：

1. **vermagic 的 release 部分不参与比较（当 ko 带 `__versions` 段时）。**
   `same_magic()`：`has_crcs`（`__versions` 段存在即真，与条目数无关）为真时，
   双方字符串都 `+= strcspn(s, " ")` 跳过第一个空格前的 release，**只比较 flags 部分**。
   即 `5.10.252-dirty` vs `5.10.233-android12-9-...-dirty` 根本不会被 strcmp；
   参与比较的只有 `SMP preempt mod_unload modversions aarch64`。
   → 原始 ko_0 在标准 GKI flags 的内核上本可通过 vermagic 检查——这也正是 DFRoot
   对其他设备有效的原因。
2. **5.10 容忍 ko 缺少 CRC 条目。** `check_version()`：符号在 ko 的 `__versions` 里
   查不到时 `pr_warn_once("no symbol version for %s")` 后 **放行**；只有"名字在表里
   但 CRC 不等"（`disagrees about version`）才硬失败 -EINVAL。
   → 空 `__versions` 可加载，**填错的 CRC 才是硬失败**。

嫌疑顺序因此完全重排：

1. **vivo 定制 vermagic token**【推断】：若 vivo 内核 flags 含定制 token
   （如 `... modversions vivo aarch64`，参照 vivo S20 的已知前科，KernelSU-Next PR #174），
   flags 部分 strcmp 失败 → -ENOEXEC，症状与观测完全吻合；
2. vivo mkp / SELinux 对 init→vendor_modprobe exec 域转换或 finit_module 的拦截【未实锤】；
3. ~~release 字符串不匹配~~、~~空 `__versions`~~——均已排除。

这个转折的直接工程价值：**最可能成功的修复不是"补全 CRC"，而是"只修 flags、CRC 留空"**——
既绕开 vermagic 检查，又规避 vivo `-dirty` 树可能改过符号接口导致的 CRC 偏差风险。

## 5. GKI CRC 取证

为制作带 CRC 的对照变体（也为了给"vivo 树是否偏离 GKI"提供判据），从
[ci.android.com](https://ci.android.com) 下载官方 GKI android12-5.10 构建
（build 16466987，android12-5.10-2026-04_r4）的 `vmlinux.symvers`。

**KMI 冻结实证**【实测】：取相隔约 20 个月的三个 build（2024-08_r15、2025-02_r6、
2026-04_r4）的 symvers 全量比对，7226 个共有符号 CRC **零差异**——KMI android12-9
冻结，任一时间点的官方 symvers 均可代表该 KMI。

提取本项目需要的 11 个符号 CRC：

| 符号 | CRC |
|---|---|
| module_layout | 0x7c24b32d |
| snprintf | 0x656e4a6e |
| register_kprobe | 0xc502eb6d |
| printk | 0xc5850110 |
| unregister_kprobe | 0x18b23dc5 |
| memset | 0xdcb764ad |
| arm64_const_caps_ready | 0x14b89635 |
| cpu_hwcap_keys | 0xec2fc692 |
| cpu_hwcaps | 0x8b9f70c7 |
| __stack_chk_fail | 0x98a9d10c |
| __stack_chk_guard | 0x8f678b07 |

三份 symvers 原件在 `analysis/vmlinux*.symvers`。

## 6. 三变体实验矩阵

用 `tools/reforge_ko.py`（改 vermagic / 填 CRC）+ `tools/embed_ko.py`（嵌回 libdfroot.so）
+ `tools/repack_apk.py`（重打包）制作三个变体，包名 `df.root` 不变，自签名
`dfroot.keystore`（口令 `dfroot123`，keystore 不入库）：

| 变体 | vermagic flags | __versions | 设计意图 | 实测结果 |
|---|---|---|---|---|
| A | 标准 GKI（无 vivo token） | 11 条 GKI CRC | 对照组 | **半成功**：App 显示成功但 KernelSU 未安装【未实锤，见 §7】 |
| B | 含 `vivo` token | 11 条 GKI CRC | 测 token + CRC | **直接失败**：证明 vivo -dirty 树至少一个符号 CRC 偏离 GKI【实测】 |
| C | 含 `vivo` token | 空（0 条） | 最可能成功：只修 flags，规避 CRC 偏差 | **完整成功**【实测】 |

C 版成功后的状态【实测】：KernelSU-Next 激活，LKM (GKI2) 模式，Tracepoint hook，
root 可用。重铸的 ko 与 lib 在 `analysis/reforged/`，APK 在 `dist/`（C）与
`dist/variants/`（A、B）。

实验矩阵的信息量值得展开：

- **C 成功**同时证明两件事：vivo 内核 vermagic flags 确实带 `vivo` token
  （否则 B 的 flags 不会比 A 更匹配——结合 B 失败于 CRC 阶段可知 B 已过了 vermagic 关）；
  且空 `__versions` 被容忍，与 module.c 源码语义一致。
- **B 失败**排除了"vivo 树与 GKI 在这 11 个符号上 CRC 一致"的可能：B 已修对 flags，
  唯一新增的失败面就是 CRC 比对，因此至少一个符号 CRC 偏离 GKI【推断，逻辑链完整】。
  这也解释了为什么上游"原样 ko + 空 CRC"的设计在 stock GKI 设备上可行、在本设备
  必须修 flags。

## 7. 结论与未解问题

### 已确证的结论

- DirtyFrag（CVE-2026-43284）在 5.10 GKI（android12-5.10 KMI）上可用【实测】，
  公开分析中"依赖 6.5 的 MSG_SPLICE_PAGES"的顾虑不成立。
- 本设备内核 vermagic flags 为 `SMP preempt mod_unload modversions vivo aarch64`
  【推断，由 B/C 行为差 + vivo 前科支撑，dmesg 取证待做】。
- vivo -dirty 树的符号 CRC 至少一个偏离 GKI 官方 symvers【推断，由 B 失败支撑】。
- 修复公式：**vermagic flags 加 `vivo` token + `__versions` 留空**，即 dist/ 的 C 版。

### 未解问题（如实记录）

1. **变体 A 的半成功**：App 显示成功但 KSU 未安装。疑似 ksud late-load 未完成
   （OriginOS 出厂 `kptr_restrict=2` 有此类前科，KernelSU-Next PR #174），或与 vivo
   内核 vermagic 校验行为有关——**未实锤**。
2. adb shell 的 root 授权尚未逐一验证。
3. dmesg 取证未做：拿到 root 后应 `dmesg | grep -i vermagic` 实锤内核期望的 vermagic
   真实长相，替代 §6 的推断。
4. boot.img 导出留档未做（拿到 root 后可 `dd` 分区，配合
   [ota-api-notes.md](ota-api-notes.md) 的方法留档）。

### 现状与维护

- root 为临时性，重启失效，重跑 DirtyFrag（C 版）恢复；App 内可开 Autorun。
- OTA 升级可能封洞；DirtyFrag 污染页缓存，使用后建议重启清理。

## 8. vivo 坑位清单

本设备上确认存在或需注意的厂商定制防线：

- **mkp.ko（MediaTek Kernel Protection）**：EL2 stage-2 只读保护 + cred 快照比对，
  MiCode 有开源 demo 实现可参考。本链未触发其拦截【实测：C 版成功即证】，
  但改做其他后利用（如直接改内核文本）时需评估。
- **vr.ko（vivo 反 root）**：给 app 派生 task 打标记，持 euid 0 即在 sys_exit 杀掉。
  本设备上 DFRoot 链的执行体是 init→vendor_modprobe，不受影响【实测】；
  但 **app 申请 root 后进程被秒杀的话就是它**——排查方向已明确。
- **sec.ko**：无公开资料，行为未知【未实锤】。
- **安装/推送拦截**：`adb install` 拒绝、`adb push` 的 APK 静默消失；shell stdin
  管道写入可绕过【实测，见 §2】。
- **OTA 接口加密**：参数整体走 native `libvivoseckey.so` 加密（`jvq_param`），
  PC 无法伪造请求，详见 [ota-api-notes.md](ota-api-notes.md)【实测】。
- **设备分区 SELinux 拒读**：boot 等分区 shell uid 不可读，固件取证只能走 OTA 包
  或 root 之后【实测】。
- **`kptr_restrict=2`**：OriginOS 出厂值，与 KSU 生态的已知兼容问题相关（PR #174）。
