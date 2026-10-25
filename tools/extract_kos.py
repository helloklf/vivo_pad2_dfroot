#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 【用法】在仓库根目录执行：python3 tools/extract_kos.py
# 【作用】从 libdfroot.so 提取内嵌的 8 个内核模块（ET_REL ELF）到 analysis/ko/，
#         并打印每个 ko 的 vermagic、__versions（modversions CRC）条目数、段与符号信息。
# 【输入】analysis/extracted/df/lib/arm64-v8a/libdfroot.so（从 DirtyFrag APK 解出）
# 【输出】analysis/ko/dfroot_0.ko … dfroot_7.ko
# Extract the 8 embedded kernel modules (ET_REL ELF) from libdfroot.so
# and dump key metadata: vermagic, __versions (modversions CRC), sections, symbols.
import struct, os, sys

SRC = 'analysis/extracted/df/lib/arm64-v8a/libdfroot.so'
OUT = 'analysis/ko'
os.makedirs(OUT, exist_ok=True)

data = open(SRC, 'rb').read()
KO_OFFS = [5248, 19224, 32128, 45272, 58416, 68296, 78624, 89648]
ENDS    = KO_OFFS[1:] + [100440]  # next blob start = end

def parse_sections(blob):
    e_shoff = struct.unpack('<Q', blob[40:48])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', blob[58:64])
    secs = []
    for i in range(e_shnum):
        sh = blob[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
        name, typ, flags, addr, off, size = struct.unpack('<IIQQQQ', sh[:40])
        link, entsize = struct.unpack('<IxxxxQ', sh[40:40+16]) if False else (struct.unpack('<I', sh[40:44])[0], struct.unpack('<Q', sh[56:64])[0])
        secs.append({'name_off': name, 'type': typ, 'off': off, 'size': size, 'entsize': entsize, 'link': link})
    strtab = secs[e_shstrndx]
    strs = blob[strtab['off']:strtab['off']+strtab['size']]
    for s in secs:
        no = s['name_off']
        end = strs.find(b'\0', no)
        s['name'] = strs[no:end].decode('ascii', 'replace')
    return secs

def get_str(blob, secs, name):
    for s in secs:
        if s['name'] == name:
            return blob[s['off']:s['off']+s['size']]
    return None

report = []
for idx, (o, end) in enumerate(zip(KO_OFFS, ENDS)):
    blob = data[o:end]
    # trim trailing padding beyond ELF end (shoff + shnum*shentsize)
    e_shoff = struct.unpack('<Q', blob[40:48])[0]
    e_shentsize, e_shnum = struct.unpack('<HH', blob[58:62])
    elf_end = e_shoff + e_shnum*e_shentsize
    ko = blob[:elf_end]
    path = os.path.join(OUT, f'dfroot_{idx}.ko')
    open(path, 'wb').write(ko)
    secs = parse_sections(ko)
    modinfo = get_str(ko, secs, '.modinfo') or b''
    vermagic = b''
    for rec in modinfo.split(b'\0'):
        if rec.startswith(b'vermagic='):
            vermagic = rec[len(b'vermagic='):]
    has_versions = any(s['name'] == '__versions' for s in secs)
    nvers = 0
    if has_versions:
        for s in secs:
            if s['name'] == '__versions':
                nvers = s['size'] // 64  # struct mod_version_info = crc(4)+name(60)
    secnames = [s['name'] for s in secs]
    report.append((idx, o, len(ko), vermagic.decode('ascii','replace'),
                   has_versions, nvers, path, secnames))
    print(f"[{idx}] off={o} size={len(ko)} vermagic={vermagic.decode()!r} "
          f"modversions={has_versions} ({nvers} CRCs) -> {path}")
    print(f"     sections: {secnames}")

print()
print("Device kernel: 5.10.233-android12-9-gb05bf6af18d3-dirty")
