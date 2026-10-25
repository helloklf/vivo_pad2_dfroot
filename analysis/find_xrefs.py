#!/usr/bin/env python3
# Find xrefs (adrp+add pairs) to key strings in libdfroot.disasm.txt
import re, sys

lines = open('analysis/libdfroot.disasm.txt', encoding='utf-8', errors='replace').read().splitlines()

targets = {
    0x190db: 'Using KMI: android%d-%d.%d',
    0x195cd: 'patch: %s <- dfroot.ko (%zu bytes)',
    0x198b8: 'found ko_target: %s',
    0x1908b: 'libc++: loading custom module',
    0x1953d: 'timeout: ERROR - check logcat & dmesg',
    0x19305: 'Unsupported kernel %d.%d android %d',
    0x190a9: 'bootstrap: ERROR - disable modules failed',
    0x19413: 'bootstrap: starting SU daemon',
    0x19431: 'success',
    0x1974f: 'Cant parse kernel version',
    0x292c4: '/vendor/bin/insmod (.data)',
    0x29298: 'u:r:vendor_modprobe:s0 (.data)',
    0x292af: '/proc/self/attr/exec (.data)',
    0x29290: '/dev/df (.data)',
    0x1c1d:  '/apex/.../crash_dump64',
}

# parse: track adrp reg -> page, then add reg2, reg, #imm
adrp = {}
insts = []
cur_func = ''
for ln in lines:
    m = re.match(r'^([0-9a-f]+) <(.+)>:', ln)
    if m:
        cur_func = m.group(2); adrp = {}
        continue
    m = re.match(r'^\s+([0-9a-f]+):\s+(\S+)(.*)', ln)
    if not m: continue
    addr = int(m.group(1), 16); op = m.group(2); rest = m.group(3)
    insts.append((addr, op, rest, cur_func))
    if op == 'adrp':
        mm = re.match(r'\s+(\w+),\s+0x([0-9a-f]+)', rest)
        if mm: adrp[mm.group(1)] = int(mm.group(2), 16)
    elif op == 'add':
        mm = re.match(r'\s+(\w+),\s+(\w+),\s+#(0x[0-9a-f]+|\d+)', rest)
        if mm and mm.group(2) in adrp:
            tgt = adrp[mm.group(2)] + int(mm.group(3), 0)
            for t, name in targets.items():
                if tgt == t:
                    print(f"xref to {name!r} at text addr 0x{addr:x} in {cur_func}")
                    break

# print all functions discovered
funcs = sorted(set(f for _,_,_,f in insts))
print("\nfunctions:", funcs)
