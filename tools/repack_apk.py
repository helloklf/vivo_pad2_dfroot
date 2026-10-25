#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 【用法】python3 tools/repack_apk.py <原APK> <新libdfroot.so> <输出APK>
# 【作用】替换 APK 内 lib/arm64-v8a/libdfroot.so，其余条目逐字节保留、
#         压缩方式保持不变。输出 APK 之后还需 zipalign + apksigner 签名
#         （见 docs/reproduction.md）。
# repack_apk.py - replace lib/arm64-v8a/libdfroot.so inside the APK,
# preserving every other entry byte-for-byte and its compression type.
import zipfile, shutil, sys

SRC_APK, NEW_LIB, DST_APK = sys.argv[1], sys.argv[2], sys.argv[3]
TARGET = 'lib/arm64-v8a/libdfroot.so'

zin = zipfile.ZipFile(SRC_APK, 'r')
zout = zipfile.ZipFile(DST_APK, 'w', zipfile.ZIP_DEFLATED)
for item in zin.infolist():
    data = zin.read(item.filename)
    if item.filename == TARGET:
        data = open(NEW_LIB, 'rb').read()
        print(f"replaced {TARGET}: {item.file_size} -> {len(data)} bytes")
    # preserve original per-entry compression
    zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
    zi.compress_type = item.compress_type
    zi.external_attr = item.external_attr
    zout.writestr(zi, data)
zout.close(); zin.close()
print("wrote", DST_APK)
