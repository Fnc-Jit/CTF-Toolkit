#!/usr/bin/env python3
"""
rev.py - CTF reverse engineering helper (ELF/PE static analysis, stdlib + optional capstone)

  info      <file>             header summary: arch, type, entry, PIE, libs, stripped
  sections  <file>              section table with perms and sizes
  symbols   <file>  [--funcs]   symbol table (name, addr, size, type)
  strings   <file>  [--min N] [--flag PFX]   extract printable strings, flags highlighted
  disasm    <file>  [--addr A] [--section .text] [--count N]   disassemble (capstone/objdump)
  func      <file>  <name>      disassemble a single function by symbol name
  entropy   <file>              per-section Shannon entropy (spot packing/encryption)
  diff      <fileA> <fileB>     diff symbol/string sets between two binaries
  hash      <file>              md5/sha1/sha256 + import hash (sorted needed libs)

Disassembly prefers capstone (pip install capstone) and falls back to
objdump/llvm-objdump on PATH; if neither is available it prints a raw hexdump.
"""
import argparse, hashlib, math, os, re, shutil, string, subprocess, sys
from collections import Counter

import elfkit

PERM = {7: "rwx", 5: "r-x", 6: "rw-", 4: "r--", 3: "-wx", 1: "--x", 2: "-w-", 0: "---"}


def load_elf(path):
    try:
        return elfkit.ELF(path)
    except ValueError:
        return None


def is_pe(path):
    with open(path, "rb") as f:
        return f.read(2) == b"MZ"


# ------------------------------------------------------------------ info
def seg_perm(flags):
    return PERM[flags & 7]


def cmd_info(a):
    if is_pe(a.file):
        return pe_info(a.file)
    e = load_elf(a.file)
    if not e:
        return print("[-] not a recognized ELF/PE file")
    print(f"Arch        : {e.machine_name} ({'64-bit' if e.is64 else '32-bit'}, "
          f"{'little' if e.end == '<' else 'big'}-endian)")
    print(f"Type        : {'PIE/shared' if e.pie else 'ET_EXEC (fixed base)'}")
    print(f"Entry point : {e.e_entry:#x}")
    print(f"Stripped    : {e.stripped}")
    print(f"Needed libs : {', '.join(e.needed) or '(static or none)'}")
    print(f"Sections    : {len(e.sections)}   Symbols: {len(e.symbols)}   "
          f"Dynsyms: {len(e.dynsymbols)}")
    interesting = [n for n in ("ptrace", "fork", "mmap", "mprotect", "seccomp", "alarm",
                               "signal", "setuid", "system", "execve", "socket", "connect")
                   if e.find_symbol(n)]
    if interesting:
        print(f"Notable imports: {', '.join(interesting)}")


def pe_info(path):
    with open(path, "rb") as f:
        d = f.read()
    if len(d) < 0x40:
        return print("[-] file too small to be a valid PE")
    import struct
    pe_off = struct.unpack_from("<I", d, 0x3c)[0]
    if pe_off + 24 > len(d) or d[pe_off:pe_off + 4] != b"PE\0\0":
        return print("[-] malformed PE")
    machine, nsec, _, _, _, optsz, chars = struct.unpack_from("<HHIIIHH", d, pe_off + 4)
    mach = {0x14c: "x86", 0x8664: "x86-64", 0xaa64: "ARM64"}.get(machine, hex(machine))
    dll = bool(chars & 0x2000)
    print(f"Arch        : {mach}  ({'DLL' if dll else 'EXE'})")
    print(f"Sections    : {nsec}")
    print("[*] install pefile (pip install pefile) for deeper PE analysis (imports/exports)")


# ------------------------------------------------------------------ sections
def cmd_sections(a):
    e = load_elf(a.file)
    if not e:
        return print("[-] not an ELF file")
    print(f"{'name':<20}{'addr':<14}{'offset':<12}{'size':<10}perm")
    for s in e.sections:
        if not s.name:
            continue
        perm = ""
        for p in e.phdrs:
            if p["type"] == 1 and p["vaddr"] <= s.addr < p["vaddr"] + p["memsz"]:
                perm = seg_perm(p["flags"])
                break
        print(f"{s.name:<20}{hex(s.addr):<14}{hex(s.offset):<12}{hex(s.size):<10}{perm}")


# ------------------------------------------------------------------ symbols
def cmd_symbols(a):
    e = load_elf(a.file)
    if not e:
        return print("[-] not an ELF file")
    syms = e.func_symbols() if a.funcs else (e.symbols + e.dynsymbols)
    seen = set()
    rows = []
    for s in sorted(syms, key=lambda s: s.value):
        if not s.name or s.name in seen:
            continue
        seen.add(s.name)
        rows.append(s)
    if not rows:
        return print("[-] no symbols (binary likely stripped)")
    for s in rows:
        kind = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}.get(s.type, str(s.type))
        print(f"{s.value:#010x}  {kind:<8} {s.name}")


# ------------------------------------------------------------------ strings
PRINTABLE = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")


def extract_strings(data, minlen=4):
    out, cur, start = [], bytearray(), 0
    for i, b in enumerate(data):
        if b in PRINTABLE and b not in (9, 10, 13):
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append((start, cur.decode("latin-1")))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((start, cur.decode("latin-1")))
    return out


URL_RE = re.compile(r"https?://\S+")
PATH_RE = re.compile(r"(/[\w.\-]+)+")
FMT_RE = re.compile(r"%[0-9.*]*[hlLqjzt]{0,2}[diouxXeEfFgGaAcspn%]")


def cmd_strings(a):
    with open(a.file, "rb") as f:
        data = f.read()
    rows = extract_strings(data, a.min)
    flag_rx = re.compile(re.escape(a.flag) + r"\{[^}\n]{1,120}\}", re.I) if a.flag else \
        re.compile(r"(?i)\b[a-z0-9_]*(?:ctf|flag|CTF|FLAG)\{[^}\n]{1,120}\}|"
                   r"(?i)\b(?:HTB|DUCTF|pico|google|hack|THM|CSAW|TCTF|RCTF)\{[^}\n]{1,120}\}")
    for off, s in rows:
        tag = ""
        if flag_rx.search(s):
            tag = "  <<< FLAG"
        elif URL_RE.search(s):
            tag = "  [url]"
        elif "/bin/sh" in s or s in ("sh", "bash"):
            tag = "  [shell]"
        elif FMT_RE.search(s) and len(s) < 40:
            tag = "  [fmt]"
        print(f"{off:#08x}  {s}{tag}")


# ------------------------------------------------------------------ entropy
def shannon(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def cmd_entropy(a):
    e = load_elf(a.file)
    if not e:
        with open(a.file, "rb") as f:
            data = f.read()
        print(f"whole file   entropy={shannon(data):.2f} bits/byte  size={len(data)}")
        return
    print(f"{'section':<20}{'size':<10}entropy  note")
    for s in e.sections:
        if not s.name or s.size == 0:
            continue
        data = e.section_bytes(s.name)
        h = shannon(data)
        note = "PACKED/ENCRYPTED?" if h > 7.2 and s.size > 256 else ""
        print(f"{s.name:<20}{s.size:<10}{h:<9.2f}{note}")


# ------------------------------------------------------------------ hashing
def cmd_hash(a):
    with open(a.file, "rb") as f:
        data = f.read()
    print(f"md5    {hashlib.md5(data).hexdigest()}")
    print(f"sha1   {hashlib.sha1(data).hexdigest()}")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")
    e = load_elf(a.file)
    if e and e.needed:
        imphash = hashlib.md5(",".join(sorted(e.needed)).encode()).hexdigest()
        print(f"libs   {', '.join(sorted(e.needed))}")
        print(f"libhash {imphash}  (not a real impfuzzy/imphash, just a quick fingerprint)")


# ------------------------------------------------------------------ diff
def cmd_diff(a):
    ea, eb = load_elf(a.file1), load_elf(a.file2)
    if not ea or not eb:
        return print("[-] both files must be ELF")
    sa = {s.name for s in ea.symbols + ea.dynsymbols if s.name}
    sb = {s.name for s in eb.symbols + eb.dynsymbols if s.name}
    print(f"symbols only in {a.file1}: {sorted(sa - sb)[:50]}")
    print(f"symbols only in {a.file2}: {sorted(sb - sa)[:50]}")
    with open(a.file1, "rb") as f1, open(a.file2, "rb") as f2:
        stra = {s for _, s in extract_strings(f1.read(), 5)}
        strb = {s for _, s in extract_strings(f2.read(), 5)}
    print(f"strings only in {a.file1}: {sorted(stra - strb)[:30]}")
    print(f"strings only in {a.file2}: {sorted(strb - stra)[:30]}")


# ------------------------------------------------------------------ disassembly
def find_disassembler():
    try:
        import capstone  # noqa
        return "capstone"
    except ImportError:
        pass
    for tool in ("objdump", "llvm-objdump", "gobjdump"):
        if shutil.which(tool):
            return tool
    return None


def cs_disasm(data, addr, is64, machine_name):
    import capstone
    if "x86" in machine_name:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    elif "ARM64" in machine_name or machine_name == "AArch64":
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif machine_name == "ARM":
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        return None
    return [(i.address, i.mnemonic, i.op_str, i.bytes) for i in md.disasm(data, addr)]


def objdump_disasm(tool, path, addr=None, section=None, count=None):
    cmd = [tool, "-d", "--no-show-raw-insn", path]
    if section:
        cmd = [tool, "-d", "-j", section, path]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except Exception as ex:
        return None, str(ex)
    lines = out.splitlines()
    if addr is not None:
        start = None
        for i, l in enumerate(lines):
            if l.strip().startswith(f"{addr:x}:"):
                start = i
                break
        lines = lines[start:] if start is not None else lines
    if count:
        insns = [l for l in lines if ":\t" in l]
        if len(insns) > count:
            cutoff = insns[count]
            idx = lines.index(cutoff)
            lines = lines[:idx]
    return "\n".join(lines), None


def cmd_disasm(a):
    e = load_elf(a.file)
    if not e:
        return print("[-] not an ELF file (PE/raw disasm not supported here)")
    tool = find_disassembler()
    if tool is None:
        print("[-] no disassembler available. Install one of:")
        print("      pip install capstone")
        print("      apt install binutils   # provides objdump")
        print("      brew install binutils  # macOS, provides gobjdump")
        sec = e.section(a.section or ".text")
        if sec:
            print(f"\n[*] raw hexdump of {sec.name} instead:")
            data = e.section_bytes(sec.name)[:256]
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                print(f"{sec.addr + i:#010x}  " + " ".join(f"{b:02x}" for b in chunk))
        return
    if tool == "capstone":
        sec = e.section(a.section or ".text")
        if not sec:
            return print(f"[-] section {a.section or '.text'} not found")
        data = e.section_bytes(sec.name)
        start_addr = sec.addr
        if a.addr is not None:
            skip = a.addr - sec.addr
            if skip < 0 or skip >= len(data):
                return print(f"[-] address {a.addr:#x} not in {sec.name}")
            data, start_addr = data[skip:], a.addr
        insns = cs_disasm(data, start_addr, e.is64, e.machine_name)
        if insns is None:
            return print(f"[-] capstone has no backend for {e.machine_name}")
        for addr, mnem, ops, raw in insns[:a.count or 60]:
            print(f"{addr:#010x}  {mnem} {ops}".rstrip())
    else:
        out, err = objdump_disasm(tool, a.file, a.addr, a.section, a.count)
        if err:
            return print(f"[-] {tool} failed: {err}")
        print(out)


def cmd_func(a):
    e = load_elf(a.file)
    if not e:
        return print("[-] not an ELF file")
    sym = e.find_symbol(a.name)
    if not sym or sym.value == 0:
        return print(f"[-] function {a.name!r} not found (binary may be stripped — try `symbols`)")
    off = e.addr_to_offset(sym.value)
    if off is None:
        return print("[-] could not map symbol address to file offset")
    tool = find_disassembler()
    size = sym.size or 128
    if tool == "capstone":
        data = e.data[off:off + size]
        insns = cs_disasm(data, sym.value, e.is64, e.machine_name)
        if not insns:
            return print("[-] capstone has no backend for this architecture")
        for addr, mnem, ops, raw in insns:
            print(f"{addr:#010x}  {mnem} {ops}".rstrip())
    elif tool:
        out, err = objdump_disasm(tool, a.file, sym.value)
        if err:
            return print(f"[-] {tool} failed: {err}")
        # trim to roughly this function: stop at next blank line after start
        lines, started, buf = out.splitlines(), False, []
        for l in lines:
            if f"<{a.name}>:" in l:
                started = True
            if started:
                buf.append(l)
                if l.strip() == "" and len(buf) > 1:
                    break
        print("\n".join(buf) if buf else out)
    else:
        print("[-] no disassembler available (pip install capstone, or install binutils)")


# ------------------------------------------------------------------ main
def intarg(x):
    return int(x, 0)


def main():
    ap = argparse.ArgumentParser(description="CTF reverse engineering helper",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("info"); p.add_argument("file"); p.set_defaults(fn=cmd_info)
    p = sp.add_parser("sections"); p.add_argument("file"); p.set_defaults(fn=cmd_sections)
    p = sp.add_parser("symbols"); p.add_argument("file"); p.add_argument("--funcs", action="store_true")
    p.set_defaults(fn=cmd_symbols)
    p = sp.add_parser("strings"); p.add_argument("file"); p.add_argument("--min", type=int, default=4)
    p.add_argument("--flag"); p.set_defaults(fn=cmd_strings)
    p = sp.add_parser("entropy"); p.add_argument("file"); p.set_defaults(fn=cmd_entropy)
    p = sp.add_parser("hash"); p.add_argument("file"); p.set_defaults(fn=cmd_hash)
    p = sp.add_parser("diff"); p.add_argument("file1"); p.add_argument("file2"); p.set_defaults(fn=cmd_diff)
    p = sp.add_parser("disasm"); p.add_argument("file"); p.add_argument("--addr", type=intarg)
    p.add_argument("--section", default=".text"); p.add_argument("--count", type=int)
    p.set_defaults(fn=cmd_disasm)
    p = sp.add_parser("func"); p.add_argument("file"); p.add_argument("name"); p.set_defaults(fn=cmd_func)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
