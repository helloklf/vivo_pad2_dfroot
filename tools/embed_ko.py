#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 【用法】python3 tools/embed_ko.py <libdfroot.so> <重铸后的.ko> <输出.so>
# 【作用】把重铸后的 ko 嵌回 libdfroot.so 的 0x1480 槽位（覆盖 android13-5.10 用
#         ko_1 的头部，本设备不选该 KMI，无影响），并同步修正 .rela.dyn 里
#         ko_0 描述符 end 指针的 addend（0x4b18 -> 0x1480+size）。
# 【注意】ko 大小必须 16 字节对齐且不超过 blob 区容量（约 14.9KB 可用）。
# embed_ko.py - re-embed a reforged dfroot ko into libdfroot.so
#
# Layout facts (from analysis):
#   - ko_0 blob starts at file offset == vaddr 0x1480 (inside .rodata)
#   - ko_0 descriptor: .data.rel.ro @0x24df8 = {12,5,10}, start/end come from
#     .rela.dyn R_AARCH64_RELATIVE addends at r_offset 0x24e08 (start=0x1480)
#     and 0x24e10 (end=0x4b18)
#   - blob area [0x1480, 0x18dd8) is 31064 bytes; new ko (<= ~14.9k) fits
#     without moving ko_2..ko_7, splicehelper or any string; it overwrites the
#     head of ko_1 (android13-5.10 variant, never selected on android12).
#   - the app writes round16(end-start) bytes to the device file; our ko is
#     already 16-byte aligned in size.
#
# Usage: embed_ko.py <libdfroot.so> <new.ko> <out.so>
import struct, sys

LIB_IN, KO, LIB_OUT = sys.argv[1], sys.argv[2], sys.argv[3]
KO_VADDR = 0x1480
DESC_END_RELA_OFFSET = 0x24e10   # r_offset of ko_0 'end' addend in .rela.dyn

lib = bytearray(open(LIB_IN, 'rb').read())
ko = open(KO, 'rb').read()
assert len(ko) % 16 == 0, "ko must be 16-byte aligned"
assert KO_VADDR + len(ko) <= 0x18dd8, "ko too big for blob area"

# parse sections to find .rela.dyn
e_shoff = struct.unpack('<Q', lib[40:48])[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', lib[58:64])
secs = []
for i in range(e_shnum):
    sh = lib[e_shoff+i*e_shentsize : e_shoff+(i+1)*e_shentsize]
    name, typ, flags, addr, off, size = struct.unpack('<IIQQQQ', sh[:40])
    secs.append(dict(name_off=name, off=off, size=size, addr=addr))
st = secs[e_shstrndx]
strs = bytes(lib[st['off']:st['off']+st['size']])
for s in secs:
    s['name'] = strs[s['name_off']:strs.find(b'\0', s['name_off'])].decode()
rela = next(s for s in secs if s['name'] == '.rela.dyn')

# patch blob
lib[KO_VADDR:KO_VADDR+len(ko)] = ko

# fix descriptor end addend
patched = False
for i in range(rela['size']//24):
    fo = rela['off'] + i*24
    r_off, r_info, r_add = struct.unpack('<QQq', lib[fo:fo+24])
    if r_off == DESC_END_RELA_OFFSET:
        assert r_add == 0x4b18, f"unexpected old end {r_add:#x}"
        struct.pack_into('<q', lib, fo+16, KO_VADDR + len(ko))
        print(f"rela @file {fo:#x}: end 0x4b18 -> {KO_VADDR+len(ko):#x}")
        patched = True
assert patched, "descriptor end rela entry not found"

open(LIB_OUT, 'wb').write(lib)
print(f"wrote {LIB_OUT}: ko {len(ko)} bytes embedded at {KO_VADDR:#x}")
