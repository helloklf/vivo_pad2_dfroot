# DFRoot LKM 加载失败逆向分析报告

- 目标设备：vivo Pad 2（mt6983），内核 `5.10.233-android12-9-gb05bf6af18d3-dirty`（GKI android12-5.10）
- 样本：`analysis/extracted/df/lib/arm64-v8a/libdfroot.so`（DirtyFrag v1.16，122024 字节）
- 分析环境：Windows + Git Bash + python3.7 + NDK 25.1 llvm-objdump + capstone 5.0.1（venv 未入库，未装额外 NDK）
- 设备侧只做只读 adb 操作（`cat /proc/version`、`/proc/config.gz`、`ls` 等），无任何写操作

## 产出物索引

| 文件 | 说明 |
|---|---|
| `analysis/ko/dfroot_0.ko` … `dfroot_7.ko` | 从 libdfroot.so 提取的 8 个内核模块（ET_REL） |
| `analysis/dfroot_0.disasm.txt` | android12-5.10 目标 ko 的完整反汇编（含重定位注解） |
| `analysis/libdfroot.disasm.txt` | libdfroot.so `.text` 完整反汇编 |
| `analysis/shellcode.bin` / `analysis/shellcode.disasm.txt` | 464 字节 stage1 shellcode 及反汇编 |
| `tools/extract_kos.py` / `ko_detail.py` / `find_xrefs.py` / `decode_refs.py` | 提取/解析/xref 脚本 |

---

## 1. 8 个内嵌 ko 的提取结果

libdfroot.so 的 `.rodata` 内嵌 8 个连续 ET_REL（ko）+ 1 个 ET_EXEC（splicehelper，1408 字节 @0x18858）。
提取脚本 `tools/extract_kos.py`（按 ELF header 的 `e_shoff + e_shnum*64` 定边界）：

| # | libdfroot.so 内偏移 | 大小 | vermagic |
|---|---|---|---|
| 0 | 5248 (0x1480) | 13976 | `5.10.252-dirty SMP preempt mod_unload modversions aarch64` |
| 1 | 19224 (0x4b18) | 12904 | `5.10.245 SMP preempt mod_unload modversions aarch64` |
| 2 | 32128 (0x7d80) | 13144 | `5.15.202-android13-5.15.202_r00-dirty SMP preempt mod_unload modversions aarch64` |
| 3 | 45272 (0xb0d8) | 13144 | `5.15.202-dirty SMP preempt mod_unload modversions aarch64` |
| 4 | 58416 (0xe430) | 9880 | `6.1.166-dirty SMP preempt mod_unload modversions aarch64` |
| 5 | 68296 (0x10ac8) | 10328 | `6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64` |
| 6 | 78624 (0x13320) | 11024 | `6.12.76-4k SMP preempt mod_unload modversions aarch64` |
| 7 | 89648 (0x15e30) | 10792 | `6.18.32-4k-g47cc22554442-dirty SMP preempt mod_unload modversions aarch64` |

**android12-5.10 用的是 `analysis/ko/dfroot_0.ko`。** 证据：libdfroot.so `.data.rel.ro` 里有一张 ko 描述符表
（`{android_ver, major, minor, ko_start, ko_end}`，32 字节/条，指针经 `.rela.dyn` 重定位）。
按 uname 解析出的 major=5/minor=10 + android=12 命中描述符 @0x24df8 → `ko=[0x1480, 0x4b18)` = ko_0
（选择逻辑见 `libdfroot.disasm.txt` 0x1e7f8–0x1e8ac：`cmp w1,#5` → `cmp w2,#10` → `cmp w3,#13; csel`）。
日志里的 "dfroot.ko (13984 bytes)" 也吻合：13976 对齐到 16 = 13984（0x1e8cc `add x23,x20,#15; and ...,#~15`）。

## 2. ko_0（dfroot_0.ko）分析

### 2.1 vermagic 与 modversions

- `.modinfo`（ko 内偏移 6900，123 字节）：
  `name=dfroot`，`vermagic=5.10.252-dirty SMP preempt mod_unload modversions aarch64`
- **`__versions` 段存在但 sh_size=0 —— 0 条 CRC**（ko 内偏移 7024）。
- 未定义符号（需内核导出并过 CRC 校验）共 10 个：
  `snprintf, register_kprobe, printk, unregister_kprobe, arm64_const_caps_ready, cpu_hwcap_keys, cpu_hwcaps, __stack_chk_fail, __stack_chk_guard, memset`
  （加载时还会隐式校验 `module_layout` 的 CRC）

设备侧实测（只读）：`zcat /proc/config.gz` 确认
`CONFIG_MODVERSIONS=y`、`# CONFIG_MODULE_FORCE_LOAD is not set`、`# CONFIG_MODULE_SIG is not set`、
`CONFIG_KALLSYMS_ALL=y`、`CONFIG_KPROBES=y`。
设备 vermagic 期望值为
**`5.10.233-android12-9-gb05bf6af18d3-dirty SMP preempt mod_unload modversions aarch64`**。

### 2.2 init_module 行为（832 字节，逐段核实）

1. `snprintf` 拼命令到 .bss：`"touch /dev/dfm0; exec %s"`，`%s` = `/data/user_de/0/df.root/bootstrap`
2. `register_kprobe("kallsyms_lookup_name")` → 读 `kp.addr` → 立即 `unregister_kprobe`。
   **这就是 5.7+ 的惯例拿法**：`kallsyms_lookup_name` 自 5.7 起不再 `EXPORT_SYMBOL`，但在
   `CONFIG_KALLSYMS_ALL=y`（本机确认=y）下仍在 kallsyms 表里，`register_kprobe` 按名字解析不受影响。
   **所以在 5.10.233 上这一步能成，不是失败点。**
3. 用拿到的函数指针依次解析：`aarch64_insn_patch_text`（找不到→printk→返回 -EINVAL）、
   `module_kallsyms_lookup_name`（存 .bss+0x200，用于解析厂商 ko 里的符号）、
   `kern_path` / `invalidate_inode_pages2` / `path_put`。
4. `kern_path("/apex/com.android.runtime/bin/crash_dump64", 1, &path)` + `invalidate_inode_pages2` +
   `path_put` —— 清掉 crash_dump64 的页缓存（让前面 patch 过的页缓存失效，恢复证据）。
5. 解析 `selinux_state`，**直接写 0 到 enforcing 字段**（"selinux_state permissive"）。
6. 用 `module_kallsyms_lookup_name` 找 `oplus_exe_block_ret_handler` / `oplus_root_check_post_handler`，
   用 `kallsyms_lookup_name` 找 `task_defex_enforce` / `task_defex_user_exec`，
   找到就 `patch_fn_ret_zero`（经 `aarch64_insn_patch_text` 把目标函数改成 `mov w0,#0; ret`）。
   这些都是三星 defex / OPPO 的符号，vivo 上找不到，走 "not found, skipping" 分支，**良性跳过**。
7. `call_usermodehelper_setup("/system/bin/sh", argv={sh,-c,"touch /dev/dfm0; exec .../bootstrap"}, envp={PATH=/system/bin})`
   → `call_usermodehelper_exec(info, UMH_WAIT_EXEC=1)`。
8. **init 必然返回错误码**：所有失败分支返回 `-EINVAL(-22)`，成功路径返回 `-ENODEV(-19)`（0x334 `mov w0,#-19`）。
   这是故意的隐身设计：返回错误 → 内核卸载并释放模块、不留 lsmod/sysfs 痕迹，但副作用
   （SELinux permissive、函数补丁、usermodehelper 已启动）保留。

**结论：init 里没有会挂死的逻辑**；唯一等待是 `UMH_WAIT_EXEC`（只等到 exec，不等退出），是毫秒级。
insmod 因 init 返回 -ENODEV 而报错退出，但 `/dev/dfm0` 已经被 touch —— 这正是回报机制的第一环。

### 2.3 回报机制

ko 本身不直接通信，而是 `touch /dev/dfm0` 作为"ko 已加载"标记，随后 bootstrap 依次 touch
`/dev/dfm1`…`/dev/dfm6`（进度）/ `/dev/dfme0-2`（错误）/ `/dev/dfmw0-1`（警告）。

## 3. libdfroot.so 的运行时修补逻辑（重点结论：什么都不改）

ko 的选取→写入路径（`libdfroot.disasm.txt` 0x1e8ac–0x1e924）：

```
0x1e8ac  ldp w1,w2,[x20]; ldr w3,[x20,#8]      ; 描述符 {android,major,minor}
0x1e8b4  printf("Using KMI: android%d-%d.%d")  ; 日志里的 "Using KMI: android12-5.10"
0x1e8c0  ldp x19,x8,[x20,#16]; x20 = end-start ; ko 指针/大小
0x1e8d4  calloc(round16(size))
0x1e8e8  memcpy(buf, ko_start, size)           ; ★ 原样拷贝
0x1e8f4  printf("patch: %s <- dfroot.ko (%zu bytes)")
0x1e914  write_via_dirtyfrag(path, buf, len, 0, 1)  ; 0x1ed60
0x1e920  free(buf)
```

`memcpy` 之后到写文件之间**没有任何对 ko 缓冲区的修改** —— 没有 vermagic 改写、没有 CRC 填充。
写入函数 0x1ed60 是 DirtyFrag 的写原语（`socket/bind/connect/pipe/vmsplice/splice`，UDP 回环 + 页缓存篡改，
`patch_file_cbc` AES-CBC 按 16 字节块处理），对 ko、shellcode、splicehelper 通用，同样不改内容。
目标文件按 `access()` 顺序三选一：`/vendor/lib64/libbinderdebug.so` → `libstagefrighthw.so` →
`libstagefright_aidl_bufferpool2.so`（本机命中第一个，与日志一致）。

对照：shellcode 安装路径（0x1e954–0x1e9a4）反而**有**运行时修补 —— 0x1eb00–0x1eb18 用 `bfxil` 把
"shellcode 在 libc++.so code cave 里的运行时地址" 编进 `adr` 指令立即数（因为 shellcode 要在别的进程里跑）。
ko 没有等价处理，因为 ko 是被 `/vendor/bin/insmod` **从文件**加载的。

## 4. shellcode（464 字节，stage1）与 10 秒超时

shellcode 嵌在 libdfroot.so `.data`（文件偏移 0x1d290，长度字段在 0x1d460=464），结构 =
字符串块（0x00–0x87：`/dev/df`、`u:r:vendor_modprobe:s0`、`/proc/self/attr/exec`、
`/vendor/bin/insmod`、`/vendor/lib64/libbinderdebug.so`）+ 代码（0x90 起，见 `analysis/shellcode.disasm.txt`）。
它被 patch 进 `/system/lib64/libc++.so` 的 code cave， trampoline（16 字节）装在
`_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`（ostream sentry 构造函数）入口。

代码逻辑（`svc` 号均为 arm64 原生 syscall）：

1. `getuid()`（174）≠ 0 → 恢复寄存器直接返回 —— 只在 root 进程里动作
2. `gettid()`（178）≠ 1 → 返回 —— **只在 PID 1（init）里动作**（init 是 C++ 程序，日志走 iostream，
   必然触发 sentry 构造）
3. `openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC)` —— **创建第一个标记**（失败则放弃）
4. `clone(CLONE_CHILD_SETTID|SIGCHLD)` 双重 fork 脱离 init 上下文
5. 子进程：`openat("/proc/self/attr/exec", O_WRONLY)` → `write("u:r:vendor_modprobe:s0", 23)`
   —— 设置 exec 域转换
6. `execve("/vendor/bin/insmod", {"/vendor/bin/insmod", "/vendor/lib64/libbinderdebug.so", NULL}, NULL)`
   —— 以 **vendor_modprobe 域**执行 insmod（该域被 SELinux 策略允许从 /vendor 加载模块）
7. 失败兜底 `exit(1)`

App 侧的等待循环（0x1ec04–0x1eca8）：每 10ms `usleep(10000)` + 轮询 13 项标记表
（`.data.rel.ro` @0x24cc0，24 字节/项 `{path, msg, code}`，见下），计数到 9990 即超时，
打印 `timeout: ERROR - check logcat & dmesg`（0x1953d）→ ≈10 秒，与观测的 9.3s 吻合。

| 标记文件 | code | 出现时打印 |
|---|---|---|
| /dev/df | -1 | `libc++: loading custom module` |
| /dev/dfm0 | -1 | `kernel module: launching bootstrap` |
| /dev/dfm1,2,3,4,5 | -1 | bootstrap 各进度 |
| /dev/dfme0,1,2 | 1 | bootstrap/ksud 错误 |
| /dev/dfmw0,1 | -1 | 警告 |
| /dev/dfm6 | 0 | `ksud start: SUCCESS`（成功终点） |

**超时定位**：日志里出现了 `libc++: loading custom module` 而没有 `kernel module: launching bootstrap`，
说明：libc++ hook 已在 init 里执行、shellcode 已创建 `/dev/df`、（大概率）已 execve insmod，
但 **ko 没能完成加载**（ko init 的第一步就是 touch /dev/dfm0，只要模块进到 init 就会立刻出现）。
即失败点在 **`/vendor/bin/insmod /vendor/lib64/libbinderdebug.so` 这一次 finit_module**，而不是
bootstrap、ksud 或 exploit 写文件阶段。

## 5. 结论与修复

### 5.1 最可能的失败原因（按确定性排序）

**① vermagic 不匹配 —— 必然发生，是第一道坎。**
ko_0 vermagic 写死为 `5.10.252-dirty ...`，设备是 `5.10.233-android12-9-gb05bf6af18d3-dirty ...`。
libdfroot.so 对 ko 只做原样 memcpy（§3），8 个内嵌 ko 的 release 全是作者自建内核的字符串
（`-dirty` 后缀），任何零售设备都不可能精确匹配。insmod → finit_module →
`check_modstruct_version()` 失败，dmesg 应有：

```
dfroot: version magic '5.10.252-dirty SMP preempt mod_unload modversions aarch64' should be
'5.10.233-android12-9-gb05bf6af18d3-dirty SMP preempt mod_unload modversions aarch64'
```

insmod 返回 EINVAL，stderr 输出丢失（shellcode fork 后无人收集），App 侧唯一表象就是 10 秒超时。

**② 即使修好 vermagic，还有 CRC 这一关 —— 同样必然失败。**
ko 的 `__versions` 段 size=0（0 条 CRC），而设备 `CONFIG_MODVERSIONS=y` 且无 `MODULE_FORCE_LOAD`。
`check_version()` 对 11 个符号（10 个未定义符号 + `module_layout`）全部查不到版本记录 →
`dfroot: no symbol version for module_layout` → EINVAL。**只修 vermagic 重打包 APK 不够。**

**③ mkp/SELinux —— 次要风险，目前还轮不到它。**
vendor_modprobe 域转换（写 `/proc/self/attr/exec` + execve）若被 vivo 策略拒绝会导致 execve 失败，
效果同样是超时；MTK mkp（内核内置，不在 /vendor/lib/modules 里）也可能在内核侧拦模块加载或检测
`aarch64_insn_patch_text` 的文本改写。但 ①② 已经足以解释失败，且 ①② 不修，③ 无法验证。
排查 ③ 的方法：修好 ①② 后若仍超时，用 `adb logcat -b events | grep avc` 看 avc denied，
或检查 /dev/dfm0 是否出现而 dfm1 不出现（=ko 加载成功但 bootstrap 没起来）。

kallsyms 取址方式（register_kprobe 按名解析）在本机配置下可行（§2.2），**不是**失败原因；
init 返回 -ENODEV 是设计行为，**也不是**失败原因。

### 5.2 可行修复方案

核心：**必须同时修 vermagic + 补 11 条真实 CRC，二者缺一不可**（MODULE_SIG=n 不需要签名，好事）。

1. **拿 CRC（关键步骤）**。`/proc/kallsyms` 没有 CRC；本机 adb shell 读 `/vendor/lib/modules/*.ko`
   被 SELinux 拒绝（实测 Permission denied），on-device 拿不到。可行来源：
   - **vivo 全量 OTA 包**（你已有 `firmware/ota_api_notes.md` 的 OTA API 调研）：解开 vendor.img
     里的 `/vendor/lib/modules/*.ko`（固件里读不受 SELinux 限制），解析其 `__versions` 段
     （每条 `struct mod_version_info` = `crc(4) + name(60)`），收集 `module_layout, snprintf, printk,
     memset, __stack_chk_fail, __stack_chk_guard` 等常见符号的 CRC —— 这些是 genksyms 对内核源码算的，
     厂商 ko 与 dfroot.ko 通用。
   - `register_kprobe / unregister_kprobe / arm64_const_caps_ready / cpu_hwcap_keys / cpu_hwcaps`
     厂商 ko 大概率没引用（实测设备上 202 个 ko 无一含 `register_kprobe` 字符串）。这些要从
     OTA 包 boot.img 的内核 Image 提取：vmlinux-to-elf 恢复 kallsyms 拿到 `__ksymtab_<name>` 地址
     与 `__start___kcrctab`，`__kcrctab[index_of_ksymtab_entry]` 即该符号 CRC（ksymtab 与 kcrctab
     同序）。5.10 的 ksymtab 条目是 3×4 字节相对偏移格式。
   - 注意必须用 **同一 build 指纹**（`DPD2221_A_15.2.13.0.W10`，cmdline 实测）的固件，
     CRC 跨版本无效。
2. **重写 dfroot_0.ko 的 ELF**（python 即可，不需要源码）：
   - `.modinfo`：vermagic 记录换成
     `vermagic=5.10.233-android12-9-gb05bf6af18d3-dirty SMP preempt mod_unload modversions aarch64`
     （83 字符 vs 原 55，段内无足够 slack：.modinfo 结束于 7023，下一节 7024 就开始，
     需把新 .modinfo 挪到文件尾追加区并改 sh_offset/sh_size）；
   - `__versions`：写入 11×64=704 字节（crc 小端 + 60 字节名字），改 sh_offset 指向追加区、
     sh_size=704；
   - 校验：改完用 `llvm-readelf -S -s`  sanity check，用 modpost 的 check 逻辑人工过一遍。
3. **重新嵌回 libdfroot.so / 重打包 APK**：
   - 新 ko 会比 13976 大（+704 CRC +28 vermagic ≈ 14700+）。ko_0 的槽位紧挨着 ko_1（19224），
     必须整体后移后续 8 个 blob，并同步更新 `.data.rel.ro` 描述符表（0x24e08/0x24e10 是 ko_0 的
     start/end）以及 `.rela.dyn` 里所有指向这些 blob 的 addend（0x24e28–0x24ef0、0x25090/0x25098
     等，都是 R_AARCH64_RELATIVE 的 addend，直接改 addend 数值即可）；
   - 重打包后 APK 需重新签名（apksigner），与原包签名不同则先卸载旧版再装；
   - libdfroot.so 在 APK 里通常不压缩存储，注意保持 `zipalign -P` 页对齐，否则 lib 无法直接
     mmap 加载。
4. **验证方法（dmesg 不可读的条件下）**：修复后重跑，观察 App 日志是否出现
   `kernel module: launching bootstrap`（=/dev/dfm0 出现 = ko init 已执行）。若仍停在
   `libc++: loading custom module`，按优先级查：
   - `adb logcat -b events | grep -i avc`（vendor_modprobe 域转换/执行被拒）；
   - 用 shell 权限 `ls -l /dev/df*` 确认标记停在哪个；
   - CRC 对错的最快判定：故意把某条 CRC 改错 vs 改对各打一包，行为无变化说明根本没走到
     CRC 校验（即 vermagic 还没修对或 execve 就失败了）。

### 5.3 一个更省事的替代路线

既然 exploit 已经具备任意文件页缓存写能力，可以不改 ko，而是让 shellcode 阶段不 exec insmod，
改为直接 `init_module()`（arm64 syscall 175）内存加载**预先修好 vermagic+CRC 的 ko 映像**（shellcode 读
/vendor/lib64/libbinderdebug.so 到内存再调 syscall）—— 但 464 字节的 stage1 装不下这些逻辑，
且仍绕不开 CRC。工作量并不比 §5.2 小，不推荐。

---

## 附：关键证据速查

- ko_0 vermagic 字符串在 libdfroot.so 文件偏移 **0x2fac**（ko_0 内偏移 6956，`.modinfo` @6900 size=123）
- ko_0 `__versions` 段头：sh_offset=7024, **sh_size=0**（10 个 undef 符号清单见 §2.1）
- ko_0 init_module 返回码：失败 `-22`，成功 `-19`（0x18c / 0x334）
- ko 选择描述符表：`.data.rel.ro` @0x24df8（android12-5.10 → [0x1480,0x4b18)）
- ko 写入代码：0x1e8e8 memcpy → 0x1e914 write，中间无修改
- shellcode：文件偏移 0x1d290，464 字节；insmod execve 在 sc+0x188
- 超时循环：usleep(10ms)×999 ≈ 10s（0x1ec04–0x1eca8，w24=9990）
- 设备实测：`/proc/config.gz` → MODVERSIONS=y / FORCE_LOAD=n / SIG=n / KALLSYMS_ALL=y / KPROBES=y；
  `/vendor/bin/insmod` 存在（→ toybox_vendor）；SELinux Enforcing；
  build 指纹 `DPD2221_A_15.2.13.0.W10`

---

# 勘误与修复进展（2026-10-25 第二轮）

## 勘误：5.10 内核的 vermagic/CRC 校验语义与本报告 §5.1 的两处错误

核对 v5.10 内核源码 `kernel/module.c`（torvalds/linux v5.10 tag，GKI 同逻辑）后，修正 §5.1：

1. **vermagic 的 release 部分根本不参与比较（当 ko 带 __versions 段时）。**
   `same_magic()`（module.c:1371）：`has_crcs`（=`__versions` 段存在，与段内条目数无关）为真时，
   双方字符串都 `+= strcspn(s, " ")` 跳过第一个空格前的 release，只比较 flags 部分。
   即 `5.10.252-dirty` vs `5.10.233-android12-9-gb05bf6af18d3-dirty` **不会被比较**；
   参与 strcmp 的只有 `SMP preempt mod_unload modversions aarch64`。
   → 原报告"vermagic release 不匹配是第一道坎"**错误**；原始 ko_0 在标准 GKI flags 下本可通过 vermagic 检查。
2. **5.10 容忍 ko 缺少 CRC 条目。** `check_version()`（module.c:1333）：符号在 ko 的 `__versions`
   里查不到时 `pr_warn_once("no symbol version for %s")` 后 **return 1（放行）**；
   只有"名字在表里但 CRC 不等"（`disagrees about version`）才 return 0 → -EINVAL。
   → 原报告"空 __versions 必然 EINVAL"**错误**；空表可加载，**填错的 CRC 才是硬失败**。

由此推论：原始 ko_0 在 stock GKI flags 内核上理应能加载（这也正是 DFRoot 对其他设备有效的原因）。
本机失败的嫌疑顺序重排为：

1. **vivo 定制 vermagic token**（如 `... modversions vivo aarch64`，参照 vivo S20 实例）——
   flags 部分 strcmp 失败 → -ENOEXEC，症状完全吻合；
2. vivo mkp / SELinux 对 `init→vendor_modprobe` exec 域转换或 finit_module 的拦截（ko 无关）；
3. ~~release 字符串不匹配~~（已排除）；~~空 __versions~~（已排除）。

## 修复产物（D:/Android/d9000_root/patched/）

CRC 来源：ci.android.com GKI 构建 `kernel_aarch64` 的 `vmlinux.symvers`
（android12-5.10-2026-04_r4, build 16466987；另与 2024-08_r15 / 2025-02_r6 两版 symvers 全量比对，
7226 个共有符号 CRC 完全一致 —— KMI android12-9 冻结实证）。

| 变体 | vermagic | __versions | 用途 |
|---|---|---|---|
| A | `5.10.233-...-dirty SMP preempt mod_unload modversions aarch64` | 11 条 GKI CRC | 对照组（flags 同原始 ko，仅多 CRC） |
| B | `... modversions vivo aarch64` | 11 条 GKI CRC | 测试 vivo token + CRC |
| C | `... modversions vivo aarch64` | 空（0 条） | **最可能成功**：只修 flags，规避 vivo -dirty 树 CRC 偏差风险 |

注意：带 __versions 段时 release 部分仍被忽略，三个变体里的 release 字符串仅作标识。
ko 嵌入方式：重铸 ko 放在 libdfroot.so 偏移 0x1480（覆盖 android13-5.10 用 ko_1 的头部 856 字节，
本设备不选择该 KMI，无影响），描述符 end 的 `.rela.dyn` addend 已同步（0x4b18 → 0x1480+size）。
其余 6 个 ko / splicehelper / 全部字符串 / .text 未动。

重铸/嵌入/打包脚本（可参数化快速再出包）：
`tools/reforge_ko.py`（vermagic + symvers 参数）、`tools/embed_ko.py`、`tools/repack_apk.py`。

## 仍不确定项

- 本机 vermagic 是否真带 vivo token —— 无 root 无法直接读内核 VERMAGIC_STRING；
  A/B/C 依次测试即可二分定位（C 成 → 确认 token；全败 → 查 mkp/SELinux）。
- vivo -dirty 树是否改过这 11 个符号的接口（影响 A/B 的 CRC 有效性；C 不受影响）。
- mkp 对 `aarch64_insn_patch_text` 写内核文本的检测、SELinux 对 vendor_modprobe 域转换的策略
  —— ko 加载成功（出现 /dev/dfm0）后才是下一关。
