# 复现指南：从原版 DirtyFrag APK 重新做出 C 版

本文描述如何从上游原版 `DirtyFrag-v1.16.apk` 出发，完整复现本仓库的
`dist/DirtyFrag-fixed-C.apk`。所有命令在 Windows + Git Bash 下验证过
（Linux/macOS 同理，路径分隔符相应调整）。

## 1. 工具链依赖

| 工具 | 用途 | 备注 |
|---|---|---|
| python3（≥3.6） | 运行 tools/ 四个脚本 | 只用了标准库（struct/zipfile/os/sys） |
| `unzip` / `zipinfo` | 解出 APK 内的 libdfroot.so | — |
| Android SDK build-tools | `zipalign`、`apksigner` | 重打包后对齐与签名 |
| JDK `keytool` | 生成自签名 keystore | — |
| `sha256sum` | 校验 | Git Bash 自带 |
| NDK `llvm-objdump` / `llvm-readelf` + capstone | （可选）逆向核对 | 仅复现构建不需要 |

## 2. 准备输入文件

1. 从 [mitschud/DirtyFrag releases](https://github.com/mitschud/DirtyFrag/releases) 下载
   `DirtyFrag-v1.16.apk`，校验：
   `sha256 = fb0f8e253a0d3c15f01e489922c9a42baef5dd9ce7b61cac8ec0660cfde445d3`
2. 解出目标库到约定路径：

```bash
mkdir -p analysis/extracted/df/lib/arm64-v8a
unzip -p DirtyFrag-v1.16.apk lib/arm64-v8a/libdfroot.so \
  > analysis/extracted/df/lib/arm64-v8a/libdfroot.so
# （可选）libbootstrap.so 同样方法解出，供分析用
```

3. （仅做带 CRC 的 A/B 变体需要）下载 GKI `vmlinux.symvers`：
   [ci.android.com](https://ci.android.com) → 分支 `aosp_kernel_android12-5.10` →
   构建目标 `kernel_aarch64`，任取 android12-9 KMI 的构建（本仓库用 build 16466987，
   android12-5.10-2026-04_r4），在 Artifacts 里下载 `vmlinux.symvers`。
   KMI 冻结已实证（2024-08 / 2025-02 / 2026-04 三版 7226 个共有符号 CRC 零差异，
   见 [technical-writeup.md](technical-writeup.md) §5），任一构建均可。
   做 C 版不需要此文件。

## 3. 四个管线脚本

脚本都在 `tools/`，头部有中文用法注释，均在仓库根目录执行。

### 3.1 extract_kos.py —— 提取内嵌 ko

```bash
python3 tools/extract_kos.py
```

- 输入：`analysis/extracted/df/lib/arm64-v8a/libdfroot.so`
- 输出：`analysis/ko/dfroot_0.ko … dfroot_7.ko`，并打印各 ko 的 vermagic、
  `__versions` 条目数、段清单。
- android12-5.10 目标是 `dfroot_0.ko`。

### 3.2 reforge_ko.py —— 重铸 ko（核心步骤）

```bash
python3 tools/reforge_ko.py <输入.ko> <输出.ko> <vermagic字符串> <symvers文件|->
```

- 替换 `.modinfo` 里的 vermagic 记录（新数据放文件尾追加区，只改两个段头，
  其余字节原样保留）；按 symvers 填 11 条 CRC，或传 `-` 使 `__versions` 留空；
  输出补齐到 16 字节对齐。
- **C 版（本仓库主交付物）**——flags 加 `vivo` token、CRC 留空：

```bash
python3 tools/reforge_ko.py analysis/ko/dfroot_0.ko dfroot_C.ko \
  "5.10.233-android12-9-gb05bf6af18d3-dirty SMP preempt mod_unload modversions vivo aarch64" -
```

- 对照：A 版 flags 不含 `vivo`、传 symvers 文件；B 版 flags 含 `vivo`、传 symvers 文件。
- 原理（为什么 C 能成功而"补全 CRC"反而是错的方向）见
  [technical-writeup.md](technical-writeup.md) §4–§6：带 `__versions` 段时 vermagic
  release 不参与比较；CRC 缺失只 warn-once 放行，填错才硬失败。
- 换设备/换内核时，vermagic 的 release 部分改为目标 `uname -r`，flags 部分按目标
  内核实际情况（可用变体矩阵二分，方法同本仓库 A/B/C 实验）。

### 3.3 embed_ko.py —— 嵌回 libdfroot.so

```bash
python3 tools/embed_ko.py analysis/extracted/df/lib/arm64-v8a/libdfroot.so \
  dfroot_C.ko libdfroot_C.so
```

- 把重铸 ko 写到 libdfroot.so 偏移 0x1480 的槽位（覆盖 android13-5.10 用 ko_1 的头部，
  android12 设备不选该 KMI，无影响），并同步修正 `.rela.dyn` 中 ko_0 描述符
  end 指针的 addend。
- 约束：ko 大小 16 字节对齐、不超过 blob 区容量（约 14.9KB）。脚本内有断言。

### 3.4 repack_apk.py —— 重打包 APK

```bash
python3 tools/repack_apk.py DirtyFrag-v1.16.apk libdfroot_C.so DirtyFrag-fixed-C.apk
```

- 只替换 `lib/arm64-v8a/libdfroot.so`，其余条目逐字节保留、压缩方式不变。
- 包名 `df.root` 不变；已装原版需先卸载（签名不同）。

## 4. 对齐与签名

重打包后必须重新签名。keystore 不入库，自行重新生成：

```bash
# 生成自签名 keystore（alias/口令与本仓库一致；换口令自行记住）
keytool -genkeypair -v -keystore dfroot.keystore -alias dfroot \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass dfroot123 -keypass dfroot123 \
  -dname "CN=dfroot"

# 对齐（lib 为页对齐存储，保持 -P 分页对齐，否则无法直接 mmap 加载）
zipalign -P 4 -f 4 DirtyFrag-fixed-C.apk DirtyFrag-fixed-C.aligned.apk

# 签名（会同时生成 .idsig）
apksigner sign --ks dfroot.keystore --ks-pass pass:dfroot123 \
  --out DirtyFrag-fixed-C.apk DirtyFrag-fixed-C.aligned.apk
apksigner verify --print-certs DirtyFrag-fixed-C.apk
```

> **注意**：更换签名（重新生成 keystore 即更换）后，KernelSU-Next 需要重新授权——
> APK 签名是其授权依据之一。本仓库 `dist/` 构建的签名证书指纹取证材料在
> `analysis/cert_ours.pem`（对照 `analysis/cert_official.pem` 为上游官方签名）。

## 5. 安装与验证

vivo 拦截 `adb install` 且 `adb push` 的 APK 会静默消失，用 shell stdin 管道绕过：

```bash
base64 -w0 DirtyFrag-fixed-C.apk | adb shell 'base64 -d > /data/local/tmp/df.apk'
adb shell 'cp /data/local/tmp/df.apk /sdcard/Download/df.apk'
# 设备上手动安装；KernelSU-Next 同样方法安装
```

验证清单：

1. App 日志出现 `ksud start: SUCCESS`（对应 `/dev/dfm6` 标记，机制见
   [../analysis/report.md](../analysis/report.md) §4）；
2. KernelSU-Next 显示 LKM (GKI2) 模式已激活；
3. 逐变体对照实验方法：同一设备依次安装 A/B/C，行为差异即结论（见
   [technical-writeup.md](technical-writeup.md) §6）。

## 6. 中间产物对照

本仓库保留了每一步的中间产物，可直接比对：

- `analysis/ko/dfroot_0.ko`：原始提取的 ko（步骤 3.1 输出）
- `analysis/reforged/dfroot_{A,B,C}.ko`：重铸后的 ko（步骤 3.2 输出）
- `analysis/reforged/libdfroot_{A,B,C}.so`：嵌入后的 lib（步骤 3.3 输出）
- `dist/DirtyFrag-fixed-C.apk`、`dist/variants/DirtyFrag-fixed-{A,B}.apk`：最终 APK
- `dist/SHA256SUMS`：全部构建的 sha256
