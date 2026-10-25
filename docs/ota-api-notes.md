# vivo DPD2221 (Pad 2 / PA2373) 固件获取情报

目标版本：DPD2221B_A_15.2.13.0.W10（设备当前正在运行，slot _a，内核 5.10.233-android12-9，2026-05-20 编译）

## 结论
未拿到 boot.img。设备分区直读被 SELinux 拒绝；官方 OTA 接口参数整体加密（native lib），无法从 PC 复现；免费公开渠道无该版本全量包。付费站 ONFIX 有精确版本（见下）。

## 设备直读测试（只读，无写入）
- `dd if=/dev/block/by-name/boot_a` / `/dev/block/sdc38` → Permission denied（shell uid=2000，Enforcing，boot_block_device 不可读）。boot_b 同理。
- /proc/kallsyms、/proc/sys/kernel/kptr_restrict → Permission denied。
- /data/ota_package、/data/vivo-updater、/cache → Permission denied。
- /sdcard/Download/upgrade/ 为空（无残留 OTA 包）。

## OTA API（逆向自 /system/app/Updater/Updater.apk，备份在 _local/firmware_work/Updater.apk（未入库））
- 主机：`https://sysupgrade.vivo.com.cn`（备用 st-sysupgrade.vivo.com.cn）
- 检测接口：`GET /vgc/v2/getVgcAndPatch.do?...`，另有 `/vgc/v2/canUpgradeMd.do`
- 明文参数（HttpUtils.getBaseCommonUrl/getBaseUrl + 0x3a2578 处方法）：
  model=DPD2221 & dModel= & snp=<ro.vendor.vivo.serialno，空则默认A0000000000000A> & s_n=<SN后5位> &
  dType=tablet & version=<model>_<ro.product.customize.bbk>_<hwVer>_<swVer>（如 DPD2221_N_DPD2221MA_15.2.13.0.W10.V000L1）&
  public_model=PA2373 & cy=CN-ZH & cu=NULL & vgcSwVer=<ro.vgc.cust.version=15.2.1> & vgcCu &
  hwVer=DPD2221MA & swVer=<ro.vivo.product.version.incremental> & language=zh_CN &
  upversion & dlrequest=0 & downloadType & isPacakgeActive & timeToUptouch & httpsSupport=1 & isTrialVersion & retry=0 &
  timeStamp=<ms> & nonce=<uuid> & hwFingerprint=<UpgradeSecurityHelper.getFingerprintWithDownload，疑似 TEE/vcode 签名>
- **关键障碍**：上述参数经 `SecurityUtils.encryptUrlParams` → `com.vivo.seckeysdk.SecurityKeyCipher.aesEncrypt`（native `libvivoseckey.so`）加密后以 `jvq_param=<base64>` 发送。未带有效 jvq_param 的请求一律返回 `{"message":"无更新","retcode":210}`（试过数十种明文参数组合均如此）。
- SDK 初始化串（getSecurityKeyCipher）：`SecurityKeyCipher.getInstance(ctx, "AAAAdQAAAAAHnRn6AAEAAAAEDmZvckNvbnN0cnVjdG9yD2NvbS5iYmsudXBkYXRlchBTamhJaWZUVmVwcjhBSmM4BUNsb3NlK3sicHJvdGVjdGlvblRocmVhZE1vZGUiOjAsInNlY3VyaXR5TW9kZSI6MH0A")`，内含 app key `SjhIifTVepr8AJc8`，securityMode=0（软件模式）。理论上可逆 libvivoseckey.so 复现，工作量大。
- 触发设备自查（`am broadcast -a new.com.bbk.updater.action.AUTO_CHECK`、启动 com.bbk.updater/.ui.UpdateActivity）可行，但 release 版 logcat 无 URL 日志，结果写在私有目录，无法读取。

## 官方全量包 CDN
- 形式：`https://sysupwrdl.vivo.com.cn/upgrade/official/officialFiles/<PKG>-update-full_<epoch秒>.zip`
  （实证：S9 包 PD2072_A_5.19.2-update-full_1675325465.zip 可 206 分段下载；不带时间戳 404）
- 后端 = 阿里云 OSS bucket `storage-vivo.oss-cn-beijing.aliyuncs.com`，列目录 AccessDenied。
- 目标文件名应为 `DPD2221_A_15.2.13.0.W10.V000L1-update-full_<epoch>.zip`（ONFIX 页面文件名无时间戳；真实 CDN 文件名需要时间戳，无法猜测/枚举）。
- CDN 支持 Range（curl -r 分段可行），拿到 URL 后可只分段下载 payload.bin 头部+索引再按需取 boot 分区段。

## 付费渠道（ONFIX，可精确买到）
- 卡刷包（OTA 全量包）：https://onfix.cn/rom/1055855 — DPD2221_A_15.2.13.0.W10.V000L1-update-full.zip，6781 MB（123网盘+备用直链，付费）
- 上一版：https://onfix.cn/rom/1051713 — DPD2221_A_15.2.12.0.W10.V000L1（内核可能不同，不推荐）
- 更早：14.1.7.31（rom/1055475、1055854）、13.0.12.51、13.0.11.11 线刷包等

## 若拿到全量包后的提取方法
1. vivo MTK A/B 全量包 zip 内含 payload.bin + payload_properties.txt（如无 payload.bin 则直接含 boot.img）。
2. `curl -r` 分段下载 zip 尾部 EOCD+central directory → 解析出 payload.bin 的偏移/压缩段，分段拉取 payload.bin。
3. payload.bin 头部（magic CrAU）+ manifest 在文件头，分区数据段偏移从 manifest 解析；只需下载 boot 分区对应的 data 段（boot.img 约 64MB），用 payload-dumper-go / 自写脚本按 install_operations 重组。
4. 校验：zip 内 META-INF/com/android/metadata 与 payload_properties.txt 的 sha256；boot.img 头应为 ANDROID! magic。

## 其它
- GitHub 无 DPD2221/PA2373 相关仓库；无公开 boot.img 分享。
- vivo 官网 CN 固件下载页已下线（/upgrade/index 跳转首页）；全球站 upgradePackageHome 无此机型。
- _local/firmware_work/ 下保留（未入库）：Updater.apk、dexdis.py/dexscan.py/dis_method.py（自写 DEX 工具）、httputils_all.txt 等逆向中间产物。
