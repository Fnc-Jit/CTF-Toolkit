#!/usr/bin/env python3
"""
pwn.py - CTF binary exploitation helper (static/offline analysis, stdlib + optional capstone)

  checksec   <file>                         NX, PIE, RELRO, canary, stripped, FORTIFY
  pattern create <len>                      de Bruijn cyclic pattern (pwntools-compatible)
  pattern offset <value> [--len N]          find offset of a 4/8-byte value in the pattern
  got        <file>                         GOT/PLT import table (addr -> function)
  rop        <file> [--max N] [--reg rdi]   find ROP gadgets ending in ret (capstone/objdump)
  fmt        <offset> [--param write]       format-string offset cheatsheet for %p / %n style leaks
  unpack     <hex> [--arch amd64]           hex bytes -> int (p64/u64-style, both endians)
  pack       <int> [--arch amd64] [--signed]  int -> hex bytes (p64/p32-style)

This is a static/offline helper (no process interaction, no network sockets, no
payload generation). For live exploitation, scripting, and sending payloads to a
remote target, use pwntools (`pip install pwntools`) — this toolkit is meant to
complement it for the static-analysis side.
"""
import argparse, shutil, string, struct, subprocess, sys

import elfkit

DE_BRUIJN_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits


def load_elf(path):
    """Load ELF or print a friendly error; returns None on failure."""
    try:
        return elfkit.ELF(path)
    except ValueError:
        return None


# ------------------------------------------------------------------ checksec
def checksec(path):
    e = load_elf(path)
    if not e:
        print(f"[-] {path}: not a valid ELF file"); return {}
    out = {}
    out["arch"] = f"{e.machine_name} ({'64' if e.is64 else '32'}-bit)"
    out["pie"] = e.pie
    gnu_stack = next((p for p in e.phdrs if p["type"] == elfkit.PT_GNU_STACK), None)
    out["nx"] = (gnu_stack is not None) and not (gnu_stack["flags"] & 0x1)
    gnu_relro = next((p for p in e.phdrs if p["type"] == elfkit.PT_GNU_RELRO), None)
    bind_now = bool(e.dynflags & 0x8) or bool(e.dynflags1 & 0x1)  # DF_BIND_NOW / DF_1_NOW
    if gnu_relro and bind_now:
        out["relro"] = "Full"
    elif gnu_relro:
        out["relro"] = "Partial"
    else:
        out["relro"] = "None"
    out["canary"] = e.find_symbol("__stack_chk_fail") is not None
    out["stripped"] = e.stripped
    fortified = [s.name for s in e.symbols + e.dynsymbols if s.name.endswith("_chk") and s.name.startswith("__")]
    out["fortify"] = sorted(set(fortified))
    out["static"] = len(e.needed) == 0
    return out


def cmd_checksec(a):
    c = checksec(a.file)
    if not c:
        return
    yn = lambda b, good_true=True: ("YES" if b else "NO") if good_true else ("NO" if b else "YES")
    print(f"{a.file}")
    print(f"  Arch:        {c['arch']}")
    print(f"  Static:      {'YES' if c['static'] else 'NO (dynamic)'}")
    print(f"  PIE:         {'YES' if c['pie'] else 'NO (fixed load address)'}")
    print(f"  NX:          {'YES (stack not executable)' if c['nx'] else 'NO (stack executable!)'}")
    print(f"  RELRO:       {c['relro']}")
    print(f"  Canary:      {'YES' if c['canary'] else 'NO'}")
    print(f"  Stripped:    {'YES' if c['stripped'] else 'NO'}")
    print(f"  FORTIFY:     {', '.join(c['fortify']) if c['fortify'] else 'none detected'}")
    hints = []
    if not c["canary"]:
        hints.append("no canary -> classic stack buffer overflow may directly hijack return address")
    if not c["nx"]:
        hints.append("stack executable -> shellcode-on-stack is viable")
    if not c["pie"]:
        hints.append("no PIE -> addresses are static, no leak needed to call known functions")
    if c["relro"] != "Full":
        hints.append(f"RELRO={c['relro']} -> GOT overwrite may be possible")
    if hints:
        print("  Hints:")
        for h in hints:
            print(f"    - {h}")


# ------------------------------------------------------------------ cyclic pattern (de Bruijn, pwntools-compatible)
def de_bruijn(alphabet, n):
    k = len(alphabet)
    a = [0] * k * n
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return "".join(alphabet[i] for i in seq)


def cyclic(length, n=4):
    seq = de_bruijn(DE_BRUIJN_ALPHABET, n)
    out = (seq * (length // len(seq) + 1))[:length]
    return out


def cyclic_find(value, width=4):
    """Find a value in the de Bruijn sequence. `width` is the byte-width
    of the integer (4 for 32-bit, 8 for 64-bit). The subsequence order
    is always 4 (pwntools-compatible)."""
    n = 4  # de Bruijn order — always 4, same as pwntools
    if isinstance(value, int):
        b = value.to_bytes(width, "little")
        try:
            value = b.decode("ascii")
        except UnicodeDecodeError:
            return -1
    seq = de_bruijn(DE_BRUIJN_ALPHABET, n)
    doubled = seq + seq[: n - 1]
    return doubled.find(value)


def cmd_pattern(a):
    if a.action == "create":
        print(cyclic(a.length))
    else:  # offset
        v = a.value
        width = a.width  # byte width: 4 for 32-bit, 8 for 64-bit
        if v.lower().startswith("0x"):
            off = cyclic_find(int(v, 16), width)
        else:
            off = cyclic_find(v, width)  # literal substring, e.g. a captured register as ASCII
        if off == -1:
            print("[-] not found in pattern (wrong width? try --width 8 for a 64-bit value)")
        else:
            print(f"offset = {off}")


# ------------------------------------------------------------------ GOT/PLT
def cmd_got(a):
    e = load_elf(a.file)
    if not e:
        return print(f"[-] {a.file}: not a valid ELF file")
    entries = e.got_plt()
    if not entries:
        return print("[-] no GOT/PLT relocations found (static binary or no PLT)")
    print(f"{'GOT addr':<14}function")
    for addr, name in sorted(entries):
        print(f"{addr:#010x}  {name}")


# ------------------------------------------------------------------ ROP gadget search
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


RET = 0xC3
X86_64_PREFIXES = set(range(0x40, 0x50))  # REX prefixes, rough heuristic only


def gadgets_capstone(data, base_addr, is64, max_len=6, max_gadgets=400):
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    md.detail = False
    ret_offsets = [i for i in range(len(data)) if data[i] == RET]
    seen, out = set(), []
    for ro in ret_offsets:
        for start in range(max(0, ro - max_len * 4), ro):
            chunk = data[start:ro + 1]
            insns = list(md.disasm(chunk, base_addr + start))
            if not insns or insns[-1].address + insns[-1].size != base_addr + ro + 1:
                continue
            if any(i.mnemonic in ("ret", "retf") for i in insns[:-1]):
                continue
            text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
            if text in seen:
                continue
            seen.add(text)
            out.append((base_addr + start, text))
            if len(out) >= max_gadgets:
                return out
    return out


def gadgets_objdump(tool, path, filt=None, max_gadgets=400):
    try:
        out = subprocess.run([tool, "-d", path], capture_output=True, text=True, timeout=30).stdout
    except Exception as ex:
        return None, str(ex)
    lines = out.splitlines()
    gadgets, cur = [], []
    for l in lines:
        if ":\t" not in l:
            continue
        addr_s, rest = l.split(":\t", 1)
        addr_s = addr_s.strip()
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        mnem = rest.split("\t")[-1].strip() if "\t" in rest else rest.strip()
        cur.append((addr, mnem))
        if mnem.startswith("ret"):
            # emit short windows ending at this ret
            for start in range(max(0, len(cur) - 6), len(cur) - 1):
                window = cur[start:]
                text = "; ".join(m for _, m in window)
                if filt is None or filt in text:
                    gadgets.append((window[0][0], text))
            cur = []
        elif len(cur) > 8:
            cur = cur[-8:]
    # dedupe by text, keep lowest address
    best = {}
    for addr, text in gadgets:
        if text not in best or addr < best[text]:
            best[text] = addr
    ordered = sorted(best.items(), key=lambda kv: kv[1])[:max_gadgets]
    return [(addr, text) for text, addr in ordered], None


def cmd_rop(a):
    e = load_elf(a.file)
    if not e:
        return print(f"[-] {a.file}: not a valid ELF file")
    tool = find_disassembler()
    if tool is None:
        return print("[-] no disassembler available. pip install capstone, or install binutils (objdump).")
    print(f"[*] searching executable segments for gadgets ending in ret...")
    if tool == "capstone" and "x86" in e.machine_name:
        results = []
        for vaddr, data in e.exec_segments():
            results += gadgets_capstone(data, vaddr, e.is64, max_len=a.maxlen)
        results.sort(key=lambda t: t[0])
    else:
        objtool = tool if tool != "capstone" else (shutil.which("objdump") or shutil.which("llvm-objdump"))
        if not objtool:
            return print("[-] capstone has no x86 backend here and objdump isn't installed either")
        results, err = gadgets_objdump(objtool, a.file)
        if err:
            return print(f"[-] {objtool} failed: {err}")
    if a.reg:
        results = [r for r in results if a.reg in r[1]]
    if not results:
        return print("[-] no gadgets found" + (f" matching {a.reg!r}" if a.reg else ""))
    for addr, text in results[: a.max]:
        print(f"{addr:#010x}  {text}")
    print(f"\n[*] {len(results)} gadget(s) found" + (f", showing first {a.max}" if len(results) > a.max else ""))


# ------------------------------------------------------------------ format string helper
def cmd_fmt(a):
    off = a.offset
    print(f"Format-string offset: {off}")
    print(f"  Leak a stack value   : " + "%{}$p".format(off))
    print(f"  Leak as string       : " + "%{}$s".format(off))
    print(f"  Write 4 bytes (%n)   : " + "%{}$n".format(off) + "   (needs the target address on the stack at that slot)")
    print(f"  Write N bytes (%hhn) : " + "%{}$hhn".format(off) + "  (byte-at-a-time write, safer for precise values)")
    print("\nTypical recipe for an arbitrary write (e.g. GOT overwrite):")
    print("  1. place the target address in the payload (padded to reach the right $N slot)")
    print("  2. use %<N>c%{}$hhn / %{}$hn / %{}$n per byte or half-word of the target value".format(off, off, off))
    print("  3. find the exact offset first with the cyclic pattern or incrementing %1$p, %2$p, ... probes")
    print("\nNote: this prints the format-string syntax only; building and sending the actual")
    print("payload bytes is a scripting/exploitation step best done with pwntools' fmtstr_payload().")


# ------------------------------------------------------------------ pack/unpack
ARCHES = {"amd64": ("<Q", 8), "x86_64": ("<Q", 8), "i386": ("<I", 4), "x86": ("<I", 4),
          "arm": ("<I", 4), "aarch64": ("<Q", 8), "arm64": ("<Q", 8)}


def cmd_unpack(a):
    h = a.hex.replace("0x", "").replace(" ", "")
    if len(h) % 2:
        h = "0" + h
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return print(f"[-] {a.hex!r} is not valid hex")
    le = int.from_bytes(b, "little")
    be = int.from_bytes(b, "big")
    print(f"little-endian: {le}  (hex {le:#x})")
    print(f"big-endian   : {be}  (hex {be:#x})")


def cmd_pack(a):
    fmt, size = ARCHES.get(a.arch, ("<Q", 8))
    if a.signed:
        fmt = fmt.replace("Q", "q").replace("I", "i")
    v = struct.pack(fmt, a.value)
    print(f"little-endian hex: {v.hex()}")
    print(f"big-endian hex   : {v[::-1].hex()}")
    print(f"bytes (escaped)  : {v!r}")


# ------------------------------------------------------------------ main
def intarg(x):
    return int(x, 0)


def main():
    ap = argparse.ArgumentParser(description="CTF binary exploitation helper (static analysis)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("checksec"); p.add_argument("file"); p.set_defaults(fn=cmd_checksec)

    p = sp.add_parser("pattern")
    psub = p.add_subparsers(dest="action", required=True)
    pc = psub.add_parser("create"); pc.add_argument("length", type=int, help="number of characters")
    po = psub.add_parser("offset"); po.add_argument("value", help="4/8-byte value (hex or ASCII)")
    po.add_argument("--width", type=int, default=4, choices=[4, 8],
                    help="byte width of the value: 4 (32-bit) or 8 (64-bit)")
    p.set_defaults(fn=cmd_pattern)

    p = sp.add_parser("got"); p.add_argument("file"); p.set_defaults(fn=cmd_got)

    p = sp.add_parser("rop")
    p.add_argument("file")
    p.add_argument("--max", type=int, default=50, help="max gadgets to print")
    p.add_argument("--maxlen", type=int, default=6, help="max instructions per gadget (capstone mode)")
    p.add_argument("--reg", help="only show gadgets mentioning this register, e.g. rdi")
    p.set_defaults(fn=cmd_rop)

    p = sp.add_parser("fmt"); p.add_argument("offset", type=int); p.set_defaults(fn=cmd_fmt)

    p = sp.add_parser("unpack"); p.add_argument("hex"); p.set_defaults(fn=cmd_unpack)
    p = sp.add_parser("pack")
    p.add_argument("value", type=intarg)
    p.add_argument("--arch", default="amd64", choices=sorted(ARCHES))
    p.add_argument("--signed", action="store_true")
    p.set_defaults(fn=cmd_pack)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
