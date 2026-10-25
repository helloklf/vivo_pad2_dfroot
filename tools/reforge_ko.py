#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 【用法】python3 tools/reforge_ko.py <输入.ko> <输出.ko> <vermagic字符串> <symvers文件|->
#         symvers 传 '-' 表示 __versions 留空（5.10 内核容忍缺 CRC 条目）。
# 【作用】重铸 dfroot_0.ko：替换 .modinfo 里的 vermagic 记录（数据挪到文件尾追加区），
#         可选按 vmlinux.symvers 填入 11 条 CRC；只改两个段头，其余字节原样保留。
# 【示例】python3 tools/reforge_ko.py analysis/ko/dfroot_0.ko dfroot_C.ko \
#           "5.10.233-android12-9-gb05bf6af18d3-dirty SMP preempt mod_unload modversions vivo aarch64" -
# reforge_ko.py - parameterised reforge of dfroot_0.ko for vivo Pad 2
# (5.10.233-android12-9-gb05bf6af18d3-dirty)
#
# What it does:
#   1. replaces the vermagic record in .modinfo (data moved to appended tail)
#   2. optionally fills __versions with modversion_info entries
#      (5.10 layout: u64 crc (LE, low 4 bytes) + char name[56] = 64 bytes/entry)
#   3. pads the ko to a 16-byte multiple (the DirtyFrag writer rounds up to 16)
#
# Only two section headers are modified (sh_offset/sh_size); all other bytes
# of the original ko are preserved verbatim.
#
# Usage: reforge_ko.py <in.ko> <out.ko> <vermagic_string> <symvers.txt|->
#   symvers file format: "0xcrc<TAB>name<TAB>..." lines (vmlinux.symvers);
#   pass '-' to leave __versions EMPTY (5.10 tolerates missing entries).
import struct, sys, os

KO_IN, KO_OUT, NEW_VERMAGIC, SYMVERS = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

# symbols the kernel checks: all SHN_UNDEF symbols of the ko + module_layout
NEED = ['module_layout', 'snprintf', 'register_kprobe', 'printk',
        'unregister_kprobe', 'arm64_const_caps_ready', 'cpu_hwcap_keys',
        'cpu_hwcaps', '__stack_chk_fail', '__stack_chk_guard', 'memset']

def parse_sections(b):
    e_shoff = struct.unpack('<Q', b[40:48])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', b[58:64])
    secs = []
    for i in range(e_shnum):
        sh = bytearray(b[e_shoff+i*e_shentsize : e_shoff+(i+1)*e_shentsize])
        name, typ, flags, addr, off, size = struct.unpack('<IIQQQQ', sh[:40])
        secs.append(dict(idx=i, hdr=sh, name_off=name, off=off, size=size))
    st = secs[e_shstrndx]
    strs = bytes(b[st['off']:st['off']+st['size']])
    for s in secs:
        e = strs.find(b'\0', s['name_off'])
        s['name'] = strs[s['name_off']:e].decode()
    return secs, e_shoff, e_shentsize

ko = bytearray(open(KO_IN, 'rb').read())
secs, e_shoff, e_shentsize = parse_sections(ko)
byname = {s['name']: s for s in secs}

# sanity: confirm undefined symbol set matches NEED
sym = byname['.symtab']
strt = secs[next(s['idx'] for s in secs if s['idx'] ==
                 struct.unpack('<I', sym['hdr'][40:44])[0])]
strdata = bytes(ko[strt['off']:strt['off']+strt['size']])
undef = []
for i in range(sym['size']//24):
    e = ko[sym['off']+i*24 : sym['off']+i*24+24]
    st_name, st_info, st_other, st_shndx = struct.unpack('<IBBH', e[:8])
    if st_shndx == 0 and st_name:
        end = strdata.find(b'\0', st_name)
        undef.append(strdata[st_name:end].decode())
missing = [u for u in undef if u not in NEED]
assert not missing, f"unexpected undefined symbols: {missing}"
print("undef symbols:", undef)

# ---- build new .modinfo ----
mi = byname['.modinfo']
modinfo = bytearray(ko[mi['off']:mi['off']+mi['size']])
records = modinfo.split(b'\0')
new_records = []
for r in records:
    if r.startswith(b'vermagic='):
        r = b'vermagic=' + NEW_VERMAGIC.encode()
    if r:
        new_records.append(r)
new_modinfo = b'\0'.join(new_records) + b'\0'
print(f".modinfo: {mi['size']} -> {len(new_modinfo)} bytes")
print("new vermagic:", NEW_VERMAGIC)

# ---- build __versions ----
if SYMVERS == '-':
    vers = b''
    print("__versions: left EMPTY (0 entries)")
else:
    crcmap = {}
    for ln in open(SYMVERS, encoding='utf-8', errors='replace'):
        p = ln.rstrip('\n').split('\t')
        if len(p) >= 2:
            crcmap[p[1]] = int(p[0], 16)
    ent = bytearray()
    for name in NEED:
        crc = crcmap[name]  # KeyError -> abort, we want all 11
        assert len(name) < 56
        ent += struct.pack('<Q', crc) + name.encode().ljust(56, b'\0')
        print(f"  crc {crc:#010x}  {name}")
    vers = bytes(ent)
    print(f"__versions: {len(NEED)} entries, {len(vers)} bytes")

# ---- append data after the section headers ----
tail = bytearray()          # appended beyond EOF
def append_aligned(blob, align=8):
    pad = (- (len(ko) + len(tail))) % align
    tail.extend(b'\0' * pad)
    off = len(ko) + len(tail)
    tail.extend(blob)
    return off

def set_sh(sec, off, size):
    struct.pack_into('<Q', sec['hdr'], 24, off)   # sh_offset
    struct.pack_into('<Q', sec['hdr'], 32, size)  # sh_size
    ko[e_shoff + sec['idx']*e_shentsize :
       e_shoff + sec['idx']*e_shentsize + e_shentsize] = sec['hdr']

if vers:
    voff = append_aligned(vers, 8)
    set_sh(byname['__versions'], voff, len(vers))
moff = append_aligned(new_modinfo, 1)
set_sh(byname['.modinfo'], moff, len(new_modinfo))

ko.extend(tail)
# pad to 16-byte multiple (writer rounds up anyway; keep it clean)
ko.extend(b'\0' * ((-len(ko)) % 16))
open(KO_OUT, 'wb').write(ko)
print(f"wrote {KO_OUT}: {len(ko)} bytes (orig 13976)")
