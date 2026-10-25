#!/usr/bin/env python3
# 1) decode ko descriptor table in .data.rel.ro using .rela.dyn
# 2) resolve ALL adrp+add string refs in .text and dump (addr -> string)
import struct, re

so = open('dirtyfrag/extracted/df/lib/arm64-v8a/libdfroot.so','rb').read()

# --- sections ---
e_shoff = struct.unpack('<Q', so[40:48])[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', so[58:64])
secs = []
for i in range(e_shnum):
    sh = so[e_shoff+i*e_shentsize:e_shoff+(i+1)*e_shentsize]
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack('<IIQQQQIIQQ', sh)
    secs.append(dict(no=name, type=typ, addr=addr, off=off, size=size, link=link))
strs = secs[e_shstrndx]
sd = so[strs['off']:strs['off']+strs['size']]
for s in secs:
    s['name'] = sd[s['no']:sd.find(b'\0', s['no'])].decode()

def sec(n): return next(s for s in secs if s['name']==n)

# --- relocations: vaddr -> target vaddr ---
rela = sec('.rela.dyn')
rel = {}
for i in range(rela['size']//24):
    off, info, addend = struct.unpack('<QQq', so[rela['off']+i*24:rela['off']+i*24+24])
    rel[off] = addend

def deref(vaddr, drsec):  # read 8 bytes at vaddr from a section, apply reloc
    foff = drsec['off'] + (vaddr - drsec['addr'])
    if vaddr in rel: return rel[vaddr]
    return struct.unpack('<Q', so[foff:foff+8])[0]

dr = sec('.data.rel.ro')
print("== ko descriptor table ==")
for base in range(0x24d98, 0x24ef8, 8):
    pass
# descriptors found at 0x24df8 (+32), 0x24e38(+32), 0x24e78, 0x24e98, 0x24eb8, 0x24ed8(3736->0x24e98?)
for va in [0x24df8, 0x24e18, 0x24e38, 0x24e58, 0x24e78, 0x24e98, 0x24eb8, 0x24ed8]:
    major, minor, andr = struct.unpack('<iii', so[dr['off']+va-dr['addr']: dr['off']+va-dr['addr']+12])
    start = deref(va+16, dr); end = deref(va+24, dr)
    # map start/end vaddr (.rodata) to file offset: .rodata addr==off
    vs = so[start+9:start+60].split(b'\0')[0] if start and start < len(so) else b''
    print(f"desc@0x{va:x}: kernel {major}.{minor} android{andr} ko=[0x{start:x},0x{end:x}) size={end-start} vermagic={vs.decode(errors='replace')!r}")

# --- all string refs ---
lines = open('analysis/libdfroot.disasm.txt', encoding='utf-8', errors='replace').read().splitlines()
adrp = {}
out = []
rod = sec('.rodata'); dat = sec('.data')
def readstr(va):
    for s in (rod, dat):
        if s['addr'] <= va < s['addr']+s['size']:
            fo = s['off'] + va - s['addr']
            e = so.find(b'\0', fo)
            st = so[fo:e]
            if all(32 <= c < 127 for c in st) and len(st) >= 4:
                return st.decode()
    return None

for ln in lines:
    m = re.match(r'^\s+([0-9a-f]+):\s+(\S+)(.*)', ln)
    if not m: continue
    addr = int(m.group(1), 16); op = m.group(2); rest = m.group(3)
    if op == 'adrp':
        mm = re.match(r'\s+(\w+),\s+0x([0-9a-f]+)', rest)
        if mm: adrp[mm.group(1)] = int(mm.group(2), 16)
    elif op == 'add':
        mm = re.match(r'\s+(\w+),\s+(\w+),\s+#(0x[0-9a-f]+|\d+)', rest)
        if mm and mm.group(2) in adrp:
            tgt = adrp[mm.group(2)] + int(mm.group(3), 0)
            st = readstr(tgt)
            if st: out.append((addr, tgt, st))
    elif op in ('ldr','ldrb','ldrsw'):
        pass

for a, t, s in out:
    print(f"0x{a:05x} -> 0x{t:05x} {s!r}")
