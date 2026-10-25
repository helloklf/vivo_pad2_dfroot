#!/usr/bin/env python3
# Deep-dive dfroot_0.ko: exact __versions content, undefined symbols, .modinfo, init params
import struct

ko = open('analysis/ko/dfroot_0.ko','rb').read()

e_shoff = struct.unpack('<Q', ko[40:48])[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', ko[58:64])
secs = []
for i in range(e_shnum):
    sh = ko[e_shoff+i*e_shentsize : e_shoff+(i+1)*e_shentsize]
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack('<IIQQQQIIQQ', sh)
    secs.append(dict(name_off=name, type=typ, flags=flags, off=off, size=size,
                     link=link, info=info, entsize=entsize))
strtab = secs[e_shstrndx]
strs = ko[strtab['off']:strtab['off']+strtab['size']]
for s in secs:
    end = strs.find(b'\0', s['name_off'])
    s['name'] = strs[s['name_off']:end].decode()

def sec(name):
    for s in secs:
        if s['name']==name: return s

# 1. exact __versions
v = sec('__versions')
print(f"__versions: off={v['off']} size={v['size']} entsize={v['entsize']} -> {v['size']//64} entries")
vd = ko[v['off']:v['off']+v['size']]
for i in range(v['size']//64):
    crc, = struct.unpack('<I', vd[i*64:i*64+4])
    name = vd[i*64+4:i*64+64].split(b'\0')[0].decode()
    print(f"  [{i}] crc=0x{crc:08x} {name}")

# 2. modinfo
mi = sec('.modinfo')
print("\n.modinfo:")
for rec in ko[mi['off']:mi['off']+mi['size']].split(b'\0'):
    if rec: print("  ", rec.decode())

# 3. symbols: symtab
sym = sec('.symtab'); strt = secs[sym['link']]
strdata = ko[strt['off']:strt['off']+strt['size']]
nsym = sym['size']//24
undef, defined = [], []
for i in range(nsym):
    e = ko[sym['off']+i*24 : sym['off']+i*24+24]
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('<IBBHQQ', e)
    end = strdata.find(b'\0', st_name)
    nm = strdata[st_name:end].decode('ascii','replace')
    if not nm: continue
    if st_shndx == 0: undef.append(nm)
    else: defined.append((nm, st_shndx, st_value, st_size))
print("\nUNDEFINED symbols (need kernel to provide / CRC-checked):")
for u in undef: print("  ", u)
print("\nDEFINED symbols:")
for d in defined: print("  ", d)

# 4. init sections sizes
for n in ('.init.text','.text','.rela.text.patch_fn_ret_zero','.rela.data.dfroot_init.argv'):
    s = sec(n)
    if s: print(f"\n{n}: off={s['off']} size={s['size']} link={s['link']} info={s['info']} entsize={s['entsize']}")
