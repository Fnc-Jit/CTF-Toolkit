"""
elfkit.py - minimal pure-stdlib ELF32/ELF64 parser (LE/BE) for re.py / pwn.py.
No external dependencies. Good enough for CTF rev/pwn static analysis.
"""
import struct

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474e551, 0x6474e552
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB, SHT_RELA, SHT_REL, SHT_DYNAMIC = 2, 11, 3, 4, 9, 6
SHF_EXECINSTR, SHF_WRITE, SHF_ALLOC = 0x4, 0x1, 0x2
DT_NEEDED, DT_FLAGS, DT_FLAGS_1, DT_BIND_NOW, DT_SYMTAB, DT_STRTAB, DT_RELA, DT_RELASZ, \
    DT_RELAENT, DT_JMPREL, DT_PLTRELSZ = 1, 30, 0x6ffffffb, 24, 6, 5, 7, 8, 9, 23, 2

STT_FUNC = 2
MACHINES = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0x08: "MIPS",
            0x14: "PowerPC", 0x2b: "SPARC32+", 0xf3: "RISC-V"}


class Sym:
    __slots__ = ("name", "value", "size", "info", "shndx", "bind", "type")

    def __repr__(self):
        return f"Sym({self.name!r}@{self.value:#x} size={self.size} type={self.type})"


class Section:
    __slots__ = ("name", "type", "flags", "addr", "offset", "size", "link", "info", "entsize")

    def __repr__(self):
        return f"Section({self.name!r} addr={self.addr:#x} off={self.offset:#x} size={self.size:#x})"


class Rel:
    __slots__ = ("offset", "sym_idx", "rtype", "addend", "sym_name")


class ELF:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.is64 = d[4] == 2
        self.end = "<" if d[5] == 1 else ">"
        self.osabi = d[7]
        e = self.end
        if self.is64:
            (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
             self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
                e + "HHIQQQIHHHHHH", d, 16)
        else:
            (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
             self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
                e + "HHIIIIIHHHHHH", d, 16)
        self.machine_name = MACHINES.get(self.e_machine, f"0x{self.e_machine:x}")
        self.pie = (self.e_type == 3)  # ET_DYN
        self._parse_phdrs()
        self._parse_shdrs()
        self._parse_dynamic()
        self.symbols = self._parse_symtab(".symtab", ".strtab")
        self.dynsymbols = self._parse_symtab(".dynsym", ".dynstr")
        self.stripped = not any(s.name for s in self.symbols)

    # ---------------------------------------------------------- headers
    def _parse_phdrs(self):
        self.phdrs = []
        d, e = self.data, self.end
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                    struct.unpack_from(e + "IIQQQQQQ", d, off)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                    struct.unpack_from(e + "IIIIIIII", d, off)
            self.phdrs.append(dict(type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr,
                                   filesz=p_filesz, memsz=p_memsz, align=p_align))

    def _parse_shdrs(self):
        self.sections = []
        d, e = self.data, self.end
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.is64:
                vals = struct.unpack_from(e + "IIQQQQIIQQ", d, off)
            else:
                vals = struct.unpack_from(e + "IIIIIIIIII", d, off)
            raw.append(vals)
        if not raw:
            return
        shstr_off = raw[self.e_shstrndx][4]
        shstr_size = raw[self.e_shstrndx][5]
        shstrtab = d[shstr_off:shstr_off + shstr_size]
        for vals in raw:
            name_off, sh_type, flags, addr, offset, size, link, info, align, entsize = vals
            name = shstrtab[name_off:shstrtab.index(b"\0", name_off)].decode("latin-1")
            s = Section()
            s.name, s.type, s.flags, s.addr = name, sh_type, flags, addr
            s.offset, s.size, s.link, s.info, s.entsize = offset, size, link, info, entsize
            self.sections.append(s)
        self.by_name = {s.name: s for s in self.sections}

    def section(self, name):
        return self.by_name.get(name)

    def section_bytes(self, name):
        s = self.section(name)
        if not s or s.type == 8:  # SHT_NOBITS
            return b""
        return self.data[s.offset:s.offset + s.size]

    # ---------------------------------------------------------- dynamic / needed libs
    def _parse_dynamic(self):
        self.needed = []
        self.dynflags = 0
        self.dynflags1 = 0
        dynsec = self.section(".dynamic")
        dynstr = self.section_bytes(".dynstr")
        if not dynsec:
            return
        d, e = self.data, self.end
        entsz = 16 if self.is64 else 8
        fmt = e + ("qQ" if self.is64 else "iI")
        off = dynsec.offset
        n = dynsec.size // entsz
        for i in range(n):
            tag, val = struct.unpack_from(fmt, d, off + i * entsz)
            if tag == 0:
                break
            if tag == DT_NEEDED and dynstr:
                end_ = dynstr.index(b"\0", val)
                self.needed.append(dynstr[val:end_].decode("latin-1"))
            elif tag == DT_FLAGS:
                self.dynflags = val
            elif tag == DT_FLAGS_1:
                self.dynflags1 = val

    # ---------------------------------------------------------- symbols
    def _parse_symtab(self, sec_name, str_name):
        sec = self.section(sec_name)
        strtab = self.section_bytes(str_name)
        out = []
        if not sec or sec.size == 0:
            return out
        d, e = self.data, self.end
        if self.is64:
            entsz, fmt = 24, e + "IBBHQQ"
        else:
            entsz, fmt = 16, e + "IIIBBH"
        n = sec.size // entsz
        for i in range(n):
            off = sec.offset + i * entsz
            if self.is64:
                name_off, info, other, shndx, value, size = struct.unpack_from(fmt, d, off)
            else:
                name_off, value, size, info, other, shndx = struct.unpack_from(fmt, d, off)
            sym = Sym()
            end_ = strtab.index(b"\0", name_off) if name_off < len(strtab) else name_off
            sym.name = strtab[name_off:end_].decode("latin-1", "replace") if strtab else ""
            sym.value, sym.size, sym.info, sym.shndx = value, size, info, shndx
            sym.bind, sym.type = info >> 4, info & 0xf
            out.append(sym)
        return out

    def func_symbols(self):
        seen = {}
        for s in self.symbols + self.dynsymbols:
            if s.name and s.type == STT_FUNC:
                seen[s.name] = s
        return list(seen.values())

    def find_symbol(self, name):
        for s in self.symbols + self.dynsymbols:
            if s.name == name:
                return s
        return None

    # ---------------------------------------------------------- relocations (GOT/PLT)
    def relocations(self, sec_name):
        sec = self.section(sec_name)
        out = []
        if not sec:
            return out
        d, e = self.data, self.end
        rela = sec.type == SHT_RELA
        symsec_idx = sec.link
        # find which symtab this points to by matching section index to by position
        symtab_sec = None
        for idx, s in enumerate(self.sections):
            if idx == symsec_idx:
                symtab_sec = s
                break
        syms = self.dynsymbols if (symtab_sec and symtab_sec.name == ".dynsym") else self.symbols
        if self.is64:
            entsz = 24 if rela else 16
            fmt = e + ("QQq" if rela else "QQ")
        else:
            entsz = 12 if rela else 8
            fmt = e + ("IIi" if rela else "II")
        n = sec.size // entsz
        for i in range(n):
            off = sec.offset + i * entsz
            vals = struct.unpack_from(fmt, d, off)
            r_offset, r_info = vals[0], vals[1]
            addend = vals[2] if rela else 0
            sym_idx = (r_info >> 32) if self.is64 else (r_info >> 8)
            rtype = (r_info & 0xffffffff) if self.is64 else (r_info & 0xff)
            r = Rel()
            r.offset, r.sym_idx, r.rtype, r.addend = r_offset, sym_idx, rtype, addend
            r.sym_name = syms[sym_idx].name if syms and sym_idx < len(syms) else ""
            out.append(r)
        return out

    def got_plt(self):
        """Returns list of (got_addr, imported_symbol_name) from .rela.plt/.rel.plt."""
        rels = self.relocations(".rela.plt") or self.relocations(".rel.plt")
        return [(r.offset, r.sym_name) for r in rels if r.sym_name]

    # ---------------------------------------------------------- executable bytes
    def exec_segments(self):
        """List of (vaddr, bytes) for PT_LOAD segments with PF_X (0x1) set."""
        out = []
        for p in self.phdrs:
            if p["type"] == PT_LOAD and (p["flags"] & 0x1):
                out.append((p["vaddr"], self.data[p["offset"]:p["offset"] + p["filesz"]]))
        return out

    def addr_to_offset(self, vaddr):
        for p in self.phdrs:
            if p["type"] == PT_LOAD and p["vaddr"] <= vaddr < p["vaddr"] + p["filesz"]:
                return p["offset"] + (vaddr - p["vaddr"])
        return None
