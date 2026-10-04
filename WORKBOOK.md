# 🏴 CTF Toolkit Workbook

> Quick-reference command guide, decision flowcharts, and flag-finding playbook for every tool in this toolkit.

---

## 📦 Toolkit at a Glance

| Tool | Category | What it does |
|------|----------|-------------|
| `master.py` | 🔰 Auto | Runs **everything** — file, strings, exiftool, binwalk, zsteg, steghide, foremost, xxd, unzip, LSB |
| `crypto.py` | 🔐 Crypto | Decode chains, classical ciphers, XOR, RSA, hash cracking |
| `rev.py` | ⚙️ Reverse Eng | ELF/PE info, sections, symbols, strings, disassembly, entropy, diff |
| `pwn.py` | 💥 Binary Exploit | checksec, cyclic patterns, GOT/PLT, ROP gadgets, format strings, pack/unpack |
| `elfkit.py` | 📚 Library | Pure-Python ELF parser (used internally by rev.py and pwn.py) |
| `forensics.py` | 🔍 Forensics | File header analysis, metadata, embedded payloads, encoded strings |
| `stego.py` | 🖼️ Steganography | LSB analysis, embedded file carving, steghide/zsteg integration |
| `pcap.py` | 🌐 Network | PCAP/PCAPNG flag scanner — payloads, DNS, ICMP, base64, hex |
| `unpack.py` | 📂 Archives | Safe archive extraction + multi-layer cipher decoding |
| `website.js` | 🌍 Web | Violentmonkey userscript — scans DOM, cookies, storage, comments, headers |

### Install dependencies
```bash
pip install -r requirements.txt   # scapy (pcap), Pillow (forensics/stego), numpy (stego)
# Optional: pip install capstone   (better disassembly in rev.py/pwn.py)
```

---

## 🔰 Step 0: "I Have No Idea What This Is"

**Start here every time.** Run `master.py` to shotgun-blast every analysis technique at the file:

```bash
python3 master.py mystery_file
```

It runs: `file` → `strings` → `exiftool` → `binwalk` → `zsteg` → `steghide` → `foremost` → `xxd` → `unzip` → `LSB`

If `master.py` finds flags, you're done. If not, use the flowchart below to pick the right specialist tool.

---

## 🧭 Decision Flowchart — Which Tool Do I Use?

```
              ┌─────────────────────────────┐
              │  What did you get from the  │
              │  challenge description?     │
              └─────────────┬───────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   📄 A file           🔤 A string         🌐 A URL /
   (binary/img/        (ciphertext/         website
    pcap/archive)       encoded text)
        │                   │                   │
        ▼                   ▼                   ▼
  What type of file?   ┌─ crypto.py        website.js
        │               │  (see §Crypto)    (install as
        │               │                   userscript)
  ┌─────┼─────┬─────┐  │
  ▼     ▼     ▼     ▼  │
 ELF  Image  PCAP  ZIP │
  │     │     │     │   │
  ▼     ▼     ▼     ▼   │
rev.py stego forensics unpack
pwn.py .py    pcap.py  .py
```

### More specifically:

| You have... | First try | Then try |
|------------|-----------|----------|
| An unknown file | `master.py file` | `forensics.py file` |
| An ELF binary | `rev.py info file` → `pwn.py checksec file` | `rev.py strings file` |
| A PE (.exe) binary | `rev.py info file.exe` | `rev.py strings file.exe` |
| An image (PNG/JPG/BMP) | `stego.py image.png` | `forensics.py image.png -e` |
| A PCAP file | `pcap.py capture.pcap` | `pcap.py capture.pcap --loose` |
| A ZIP/TAR/7z archive | `unpack.py archive.zip` | `unpack.py -w wordlist.txt archive.zip` |
| A ciphertext string | `crypto.py auto "ciphertext"` | `crypto.py decode "text"` |
| A hash | `crypto.py hash "e99a18..."` | `crypto.py hash "hash" --wordlist rockyou.txt` |
| An RSA challenge (n, e, c) | `crypto.py rsa --n N --e E --c C` | Add `--online` for factordb |
| A web challenge | Install `website.js` in Violentmonkey | Check page source, cookies, headers |
| A buffer overflow binary | `pwn.py checksec vuln` | `pwn.py rop vuln --reg rdi` |

---

## 🔐 Crypto — `crypto.py`

### Auto-solve (try this first!)
```bash
# Throws everything at the text: decode chains + classical ciphers + XOR
python3 crypto.py auto "ciphertext_here"
python3 crypto.py auto encoded_file.txt
```

### Decode chains (Base64, hex, binary, morse, etc.)
```bash
python3 crypto.py decode "ZmxhZ3tiYXNlNjR9"              # base64
python3 crypto.py decode "666c61677b6865787d"              # hex
python3 crypto.py decode "01000110 01001100 01000001 01000111"  # binary
python3 crypto.py decode "6 12 1 7"                        # A1Z26
python3 crypto.py decode ".- -... -.-."                    # morse
```

### Classical ciphers
```bash
# Caesar / ROT13 / Atbash / Affine / Rail Fence / Vigenère
python3 crypto.py classic "synt{ebg13_jbexf}"

# Vigenère with known key
python3 crypto.py vigenere "ciphertext" --key SECRET

# Vigenère auto-crack (IC + Kasiski)
python3 crypto.py vigenere "long_ciphertext_here"

# Substitution cipher (hill-climbing solver)
python3 crypto.py subst "gsviv rh z uozt rm gsrh hvmgvmxv"
```

### XOR
```bash
# Single-byte XOR brute force (input as hex)
python3 crypto.py xor "242e2325393a2d30"

# Known key XOR
python3 crypto.py xor "hexdata" --key 42

# Crib-based XOR
python3 crypto.py xor "hexdata" --crib "flag{"
```

### RSA
```bash
# Basic RSA: provide n, e, c — auto-tries small-e, Wiener, Fermat, Pollard
python3 crypto.py rsa --n 12345... --e 65537 --c 9876...

# With known factors
python3 crypto.py rsa --n N --e E --c C --p P --q Q

# Online factorization (factordb)
python3 crypto.py rsa --n N --e E --c C --online

# Common modulus attack (same n, two different e values)
python3 crypto.py rsa-common --n N --e1 E1 --e2 E2 --c1 C1 --c2 C2

# Hastad's broadcast attack (same message, multiple (n, c) pairs)
python3 crypto.py rsa-hastad --e 3 --n N1 N2 N3 --c C1 C2 C3
```

### Hash identification & cracking
```bash
python3 crypto.py hash "5d41402abc4b2a76b9719d911017c592"
python3 crypto.py hash "hash_value" --wordlist /path/to/rockyou.txt
```

### Custom flag prefix
```bash
# If the CTF uses a custom prefix like picoCTF{...}
python3 crypto.py auto "ciphertext" --flag picoCTF
```

### 🚩 Where flags hide in crypto challenges
- In the **decoded output** of multi-layer encoding (base64 → hex → base64)
- As the **plaintext** after cracking a Caesar/Vigenère/XOR cipher
- In the **RSA decrypted message** (convert int to bytes)
- In **hash collisions** or cracked hash values

---

## ⚙️ Reverse Engineering — `rev.py`

### First look at a binary
```bash
python3 rev.py info challenge_binary      # arch, PIE, stripped, libs, notable imports
python3 rev.py sections challenge_binary  # section table with permissions
python3 rev.py symbols challenge_binary   # all symbols (name, addr, type)
python3 rev.py symbols challenge_binary --funcs  # functions only
```

### Find flags in strings
```bash
python3 rev.py strings challenge_binary              # all strings (flags auto-highlighted)
python3 rev.py strings challenge_binary --min 8       # longer strings only
python3 rev.py strings challenge_binary --flag HTB    # custom flag prefix
```

### Disassemble
```bash
# Disassemble .text section (needs capstone or objdump)
python3 rev.py disasm challenge_binary
python3 rev.py disasm challenge_binary --section .rodata
python3 rev.py disasm challenge_binary --addr 0x401000 --count 50

# Disassemble a specific function
python3 rev.py func challenge_binary main
python3 rev.py func challenge_binary check_password
```

### Detect packing / encryption
```bash
python3 rev.py entropy challenge_binary
# High entropy (>7.2) in a section → likely packed or encrypted (try UPX, etc.)
```

### Compare two binaries
```bash
python3 rev.py diff original patched   # symbol + string differences
```

### Hash a binary
```bash
python3 rev.py hash challenge_binary   # md5, sha1, sha256 + library fingerprint
```

### 🚩 Where flags hide in RE challenges
- In **plaintext strings** — always run `strings` first!
- In the **comparison logic** of a password check function (disassemble it)
- **XOR'd or encoded** in `.data`/`.rodata` — look for suspicious byte arrays
- In **environment variables** or **command-line arg checks**
- **Packed binaries** — high entropy sections; unpack first (upx -d), then re-analyze

---

## 💥 Binary Exploitation — `pwn.py`

### Security check (always do this first!)
```bash
python3 pwn.py checksec vulnerable_binary
```
Output tells you what's exploitable:
| Result | Meaning | Attack |
|--------|---------|--------|
| NX = NO | Stack is executable | Shellcode on stack |
| Canary = NO | No stack canary | Buffer overflow → overwrite return addr |
| PIE = NO | Fixed addresses | No leak needed, use hardcoded addrs |
| RELRO = Partial/None | GOT is writable | GOT overwrite |

### Find buffer overflow offset
```bash
# 1. Generate a cyclic pattern
python3 pwn.py pattern create 200

# 2. Feed it to the binary, get the crash value (e.g. from EIP/RIP)
# 3. Find the offset
python3 pwn.py pattern offset 0x41416141        # 32-bit value
python3 pwn.py pattern offset 0x4141614141416241 --width 8  # 64-bit value
python3 pwn.py pattern offset Aa5A               # ASCII substring
```

### Find ROP gadgets
```bash
python3 pwn.py rop challenge_binary                # all gadgets (first 50)
python3 pwn.py rop challenge_binary --reg rdi       # pop rdi; ret
python3 pwn.py rop challenge_binary --reg rsi       # pop rsi; ret
python3 pwn.py rop challenge_binary --max 200       # show more
```

### GOT/PLT table
```bash
python3 pwn.py got challenge_binary   # imported functions + GOT addresses
```

### Format string helper
```bash
# If you found a format string vuln at offset 6:
python3 pwn.py fmt 6
# Prints: %6$p (leak), %6$s (string), %6$n (write), %6$hhn (byte write)
```

### Pack / Unpack addresses
```bash
# Convert hex bytes → integer (like u64/u32)
python3 pwn.py unpack "deadbeef"
python3 pwn.py unpack "41 42 43 44 45 46 47 48"

# Convert integer → hex bytes (like p64/p32)
python3 pwn.py pack 0x00401234                     # 64-bit (default)
python3 pwn.py pack 0x08041234 --arch i386          # 32-bit
python3 pwn.py pack -- -1 --arch amd64 --signed     # negative value
```

### 🚩 Where flags hide in pwn challenges
- **Printed by a `win()` function** — redirect execution there
- **In a file** read by the binary after you get a shell (`cat flag.txt`)
- **Returned by the server** after sending the right exploit payload

---

## 🔍 Forensics — `forensics.py`

```bash
python3 forensics.py mystery_file                # full analysis
python3 forensics.py mystery_file -e              # also extract embedded payloads
python3 forensics.py mystery_file -v              # verbose string output
python3 forensics.py mystery_file --loose         # loose flag matching
python3 forensics.py mystery_file -s 8            # min string length = 8
```

**Requires**: `pip install Pillow`

### What it does automatically
1. File magic / header analysis (detects mismatched extensions)
2. EXIF metadata extraction
3. String scanning with flag detection
4. Embedded archive detection
5. Trailing data / appended payload detection
6. Base64/hex encoded content scanning

### 🚩 Where flags hide in forensics challenges
- In **EXIF metadata** (comments, author, GPS coords → decode them)
- In **mismatched file headers** (a .png that's actually a .zip)
- **Appended after EOF** — trailing bytes after the file's real end
- In **embedded archives** — a ZIP inside a JPEG
- **Base64 encoded** in metadata fields

---

## 🖼️ Steganography — `stego.py`

```bash
python3 stego.py secret_image.png                 # full stego analysis
python3 stego.py secret_image.png --lsb-only      # LSB analysis only (zsteg mode)
python3 stego.py secret_image.png --carve-only     # embedded file carving only (binwalk mode)
python3 stego.py secret_image.png -e               # extract carved files
python3 stego.py secret_image.png --steghide-only  # steghide extractor only
python3 stego.py secret_image.png --no-external    # pure Python (skip zsteg/steghide)
python3 stego.py secret_image.png --loose          # loose flag matching
```

**Requires**: `pip install Pillow numpy`

### What it does automatically
1. **LSB steganography** — checks RGB bit planes for hidden text
2. **Embedded file carving** — finds files hidden inside the image (PNG, ZIP, PDF, ELF, etc.)
3. **External tool integration** — calls `zsteg` and `steghide` if installed
4. **Steghide password brute force** — tries common CTF passwords
5. **PNG chunk analysis** — checks for suspicious IDAT/tEXt/zTXt chunks

### 🚩 Where flags hide in stego challenges
- **LSB (least significant bit)** of pixel RGB values
- **Steghide-embedded** in JPEG/BMP/WAV (often with a simple password)
- In **PNG chunks** (tEXt, zTXt, iTXt metadata)
- **Appended after IEND** — extra data after the PNG end marker
- In **color palette manipulation** or **alpha channel**

---

## 🌐 Network / PCAP — `pcap.py`

```bash
python3 pcap.py capture.pcap                       # strict flag scan
python3 pcap.py capture.pcap --loose               # loose matching (any prefix{...})
python3 pcap.py capture.pcap --max-packets 50000   # increase packet limit
```

**Requires**: `pip install scapy`

### What it scans
1. **TCP/UDP payloads** — raw packet data for flag patterns
2. **HTTP requests/responses** — URLs, headers, body content
3. **DNS queries & responses** — domain names, TXT records
4. **ICMP payloads** — data hidden in ping packets
5. **Base64 strings** in payloads → auto-decoded and scanned
6. **Hex runs** in payloads → auto-decoded and scanned

### 🚩 Where flags hide in PCAP challenges
- In **HTTP response bodies** or **POST data**
- In **DNS TXT records** or encoded in queried domain names
- **Base64 encoded** inside packet payloads
- In **ICMP ping data** (exfiltration via ping)
- Split across **multiple packets** (reassemble manually)
- In **FTP/SMTP/telnet** cleartext sessions

---

## 📂 Archives — `unpack.py`

### Basic extraction
```bash
python3 unpack.py archive.zip
python3 unpack.py archive.tar.gz
python3 unpack.py archive.7z
```

### Password-protected archives
```bash
python3 unpack.py -p "secret123" archive.zip            # known password
python3 unpack.py -w /path/to/wordlist.txt archive.zip   # dictionary attack (max 5000 words)
```

### Decode encoded strings (no file needed)
```bash
python3 unpack.py -d "ZmxhZ3ttdWx0aV9sYXllcl9iYXNlNjRfZGVjb2RlZH0="
python3 unpack.py -d "ciphertext" --loose    # loose flag prefix matching
```

### Safety features
- ZipSlip / TarSlip protection (rejects `../` paths, symlinks)
- Per-file 50MB cap, 200MB total cap
- Compression-ratio bomb guard
- Recursive nested archives to depth 3 (configurable with `--max-depth`)
- Auto-decodes: Base64, Base32, Base85, Hex, Caesar, URL-encoding, single-byte XOR

### 🚩 Where flags hide in archive challenges
- In **nested archives** (zip inside zip inside tar…)
- In **password-protected ZIPs** — try `unpack.py -w wordlist.txt`
- **Base64/hex encoded** filenames or file contents
- In **file metadata** within the archive
- **Renamed file extensions** — a .txt that's really a .zip

---

## 🌍 Web Exploitation — `website.js`

### Setup
1. Install [Violentmonkey](https://violentmonkey.github.io/) browser extension
2. Create new userscript → paste contents of `website.js`
3. Set `@match` to your CTF host (e.g., `*://ctf.example.com/*`)
4. Enable and navigate to the challenge page

### What it auto-scans
- **DOM text** — visible and hidden (`display:none`, `visibility:hidden`)
- **HTML comments** (`<!-- flag{...} -->`)
- **Base64 strings** in page source → auto-decoded
- **Cookies and localStorage/sessionStorage**
- **JavaScript source** in `<script>` tags
- **HTTP response headers** (via `GM_xmlhttpRequest`)
- **Inline event handlers** and data attributes

### Toggle loose mode
In the script, set `LOOSE_MODE = true` for custom-prefix challenges:
```js
const LOOSE_MODE = true;  // matches any prefix{...}
```

### 🚩 Where flags hide in web challenges
- In **HTML comments** or **hidden DOM elements**
- In **cookies** or **localStorage**
- In **JavaScript source** (obfuscated or encoded)
- In **HTTP response headers** (custom headers like `X-Flag:`)
- In **robots.txt**, **sitemap.xml**, or **source maps**
- In **API responses** (check network tab)
- **Base64 encoded** in data attributes or script variables

---

## 🔰 Master Scanner — `master.py`

```bash
python3 master.py mystery_file
```

This is the **"I don't know what this is, just find the flag"** tool. It sequentially runs:

| Step | What it does | External tool needed |
|------|-------------|---------------------|
| 1 | `file` — identify file type | file (builtin) |
| 2 | `strings` — extract printable strings + base64 decode | strings (builtin) |
| 3 | `exiftool` — metadata analysis | exiftool |
| 4 | `binwalk` — embedded file detection + auto-extract | binwalk |
| 5 | `zsteg` — PNG/BMP steganography | zsteg (Ruby gem) |
| 6 | `steghide` — JPEG/BMP/WAV stego + password brute | steghide |
| 7 | `foremost` — file carving | foremost |
| 8 | `xxd` — hex dump + raw binary flag search | xxd (builtin) |
| 9 | `unzip` — archive extraction + password brute | unzip (builtin) |
| 10 | `LSB` — manual least-significant-bit check | Pillow (pip) |

At the end, prints a **summary of all flags found** with their sources.

---

## ⚡ Speed Run Cheatsheets

### "I got a random file and 5 minutes"
```bash
python3 master.py file           # shotgun everything
python3 rev.py strings file      # pure-Python string extraction with flag highlight
python3 crypto.py auto "$(cat file)"  # if it looks like encoded text
```

### "I got a crypto challenge"
```bash
python3 crypto.py auto "ciphertext"                          # try everything
python3 crypto.py decode "ciphertext"                        # just encodings
python3 crypto.py rsa --n N --e E --c C --online             # RSA with online factor
```

### "I got a binary to reverse"
```bash
python3 rev.py info binary && python3 rev.py strings binary  # quick recon
python3 rev.py func binary main                              # look at main()
python3 rev.py entropy binary                                # check for packing
```

### "I got a binary to exploit"
```bash
python3 pwn.py checksec binary                               # what's enabled?
python3 pwn.py pattern create 200                            # find overflow offset
python3 pwn.py rop binary --reg rdi                          # find useful gadgets
python3 pwn.py got binary                                    # what can we overwrite?
```

### "I got an image"
```bash
python3 stego.py image.png                                   # full stego analysis
python3 forensics.py image.png -e                            # extract embedded payloads
python3 rev.py strings image.png --flag CTF                  # strings with flag highlight
```

### "I got a network capture"
```bash
python3 pcap.py capture.pcap                                 # strict scan
python3 pcap.py capture.pcap --loose                         # if strict misses it
```

### "I got a ZIP/archive"
```bash
python3 unpack.py archive.zip                                # auto-extract + decode
python3 unpack.py -w passwords.txt archive.zip               # password brute force
python3 unpack.py -d "encoded_string"                        # decode without a file
```

---

## 🧰 External Tools — Install Guide

These are optional but greatly improve the toolkit:

```bash
# Python packages
pip install capstone        # disassembly in rev.py/pwn.py
pip install Pillow          # forensics.py, stego.py image analysis
pip install numpy           # stego.py LSB analysis
pip install scapy           # pcap.py network analysis
pip install pwntools        # live exploitation scripting (complements pwn.py)

# System tools (macOS)
brew install binutils       # objdump/gobjdump for disassembly
brew install exiftool       # metadata extraction
brew install binwalk        # embedded file detection
brew install foremost       # file carving
brew install steghide       # JPEG/WAV steganography

# System tools (Linux)
sudo apt install binutils exiftool binwalk foremost steghide

# Ruby gems
gem install zsteg           # PNG/BMP steganography
```

---

## 📋 Flag Format Reference

Most CTFs use the format `PREFIX{content}`. The toolkit auto-detects these prefixes:

| Prefix | CTF |
|--------|-----|
| `flag{...}` | Generic |
| `CTF{...}` | Generic |
| `picoCTF{...}` | picoCTF |
| `HTB{...}` | Hack The Box |
| `THM{...}` | TryHackMe |
| `DUCTF{...}` | DownUnderCTF |
| `SEKAI{...}` | SekaiCTF |
| `UIUCTF{...}` | UIUCTF |
| `CSAW{...}` | CSAW CTF |
| `kju{...}` | KJU CTF |

Use `--flag PREFIX` or `--loose` to match custom prefixes:
```bash
python3 crypto.py auto "text" --flag myctf
python3 pcap.py capture.pcap --loose
python3 stego.py image.png --loose
```
