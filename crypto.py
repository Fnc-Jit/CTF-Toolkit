#!/usr/bin/env python3
"""
crypto.py - CTF cryptography solver (stdlib only)

  auto        <text|file>   run everything: decode chains + classical ciphers + xor
  decode      <text|file>   recursive encoding decoder (b64/b32/hex/b85/bin/url/dec/morse)
  classic     <text|file>   caesar, atbash, affine, rail fence, vigenere, substitution
  vigenere    <text|file>   [--key K]  crack (IC/Kasiski style) or decrypt with key
  subst       <text|file>   monoalphabetic substitution (hill climbing)
  xor         <hex|file>    [--key K] [--crib flag{]  single/repeating-key xor
  rsa         --n --e --c   [--p --q] [--online]  factor / small-e / wiener / fermat / rho / p-1
  rsa-common  --n --e1 --e2 --c1 --c2
  rsa-hastad  --e 3 --n N1 N2 N3 --c C1 C2 C3
  hash        <hash>        [--wordlist FILE]  identify + dictionary crack

Global: --flag PREFIX (default: any word{...})
"""
import argparse, base64, binascii, hashlib, json, math, os, random, re, string, sys, time
import urllib.parse
from collections import Counter

# ANSI Terminal Colors (matching toolkit convention)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

FLAG_RE = re.compile(r'(?i)\b(?:[a-z0-9_]*ctf|flag|htb|thm|cyber|[a-z0-9_]*hack|csc|inctf|bcactf|dice|uiuctf)\{[^}\n]{3,120}\}')
ALPHA = string.ascii_uppercase

EN_FREQ = dict(zip(ALPHA, [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
    0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758,
    0.978, 2.360, 0.150, 1.974, 0.074]))
COMMON = {"the", "and", "that", "have", "for", "not", "with", "you", "this", "but", "his",
          "from", "they", "are", "was", "were", "flag", "ctf", "is", "to", "of", "in", "it",
          "be", "as", "at", "on", "or", "an", "we", "can", "will", "your", "key", "secret"}

CORPUS = """
it was the best of times it was the worst of times it was the age of wisdom it was the age
of foolishness it was the epoch of belief it was the epoch of incredulity it was the season
of light it was the season of darkness it was the spring of hope it was the winter of despair
we had everything before us we had nothing before us the quick brown fox jumps over the lazy dog
the message was hidden inside the file and nobody could find it without the secret key so we
searched through every part of the network looking for anything that might help us understand
what had happened the attacker had gained access to the server and then moved through the
system quietly collecting information about the users and their passwords before leaving a note
that said you will never find the flag but of course with enough time and effort anyone can
solve this problem because every cipher has a weakness and every weakness can be used to
recover the original text this is the reason why careful analysis of letter frequency and common
words is important when you are trying to break a code with only the encrypted text in your hands
there is nothing more satisfying than watching the plain text appear from random looking letters
when you finally find the correct key and the whole message becomes clear and readable again

people often say that the most important part of any puzzle is knowing where to begin and the
same is true for a challenge in a competition because the first step is always to look at what
you have been given and then to think about how it might have been made the people who write
these problems like to hide a small piece of text inside something larger and they hope that
you will take the time to read it carefully and find out how it works many of the best
solutions come from simple ideas such as trying every possible key or counting how often each
letter appears in the message and comparing the result with what we know about the language
my name is not important but the message that was sent to me on monday morning was very strange
it came from a computer in another country and it asked me to meet them at the old market
before the sun came up so that we could talk about the money that had been taken from the bank
please remember that you should never share your password with anyone and that every program
should check the input that it receives from the user before using it for something important
"""

# ---------------------------------------------------------------- helpers
def load_input(arg):
    """arg is a path or literal text -> str (latin-1 safe)."""
    if arg == "-":
        return sys.stdin.read().strip()
    if os.path.isfile(arg):
        with open(arg, "rb") as f:
            return f.read().decode("latin-1").strip()
    return arg


def find_flags(s, prefix=None):
    rx = re.compile(re.escape(prefix) + r'\{[^}\n]{1,120}\}', re.I) if prefix else FLAG_RE
    return rx.findall(s)


def printable_ratio(s):
    return sum(c in string.printable for c in s) / len(s) if s else 0


def score(text):
    """Higher = more English-like.  Also gives a bonus if a flag pattern is present."""
    if not text:
        return -1e9
    pr = printable_ratio(text) ** 4
    letters = [c for c in text.upper() if c in ALPHA]
    if len(letters) < 3:
        return pr * -50
    n = len(letters)
    cnt = Counter(letters)
    chi = sum((cnt.get(c, 0) - EN_FREQ[c] / 100 * n) ** 2 / (EN_FREQ[c] / 100 * n) for c in ALPHA) / n
    words = re.findall(r"[a-z]+", text.lower())
    wr = sum(w in COMMON for w in words) / max(1, len(words))
    base = pr * 10 - chi + 25 * wr
    # boost result if it already contains a flag pattern
    if FLAG_RE.search(text):
        base += 50
    return base


def show(title, results, prefix, top=3):
    """results: list of (score, label, text)."""
    results = sorted(results, key=lambda r: -r[0])
    print(f"\n{Colors.BOLD}{Colors.BLUE}=== {title} ==={Colors.RESET}")
    for sc, label, txt in results[:top]:
        flags = find_flags(txt, prefix)
        mark = f"  {Colors.GREEN}<<< FLAG{Colors.RESET}" if flags else ""
        print(f"[{sc:7.2f}] {label}: {txt[:200]!r}{mark}")
    # Print flags found in results below the top-N display
    for sc, label, txt in results[top:]:
        for f in find_flags(txt, prefix):
            print(f"{Colors.YELLOW}[flag in {label}]{Colors.RESET} {f}")


# (removed unused egcd_inv wrapper — pow(a, -1, m) used directly)


# ---------------------------------------------------------------- encodings
MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
         "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
         "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
         "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0",
         ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
         "--...": "7", "---..": "8", "----.": "9"}


def _b64(s):
    s = re.sub(r"\s", "", s)
    if len(s) < 4 or not re.fullmatch(r"[A-Za-z0-9+/_-]+=*", s):
        return None
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _b32(s):
    s = re.sub(r"\s", "", s).upper()
    if len(s) < 8 or not re.fullmatch(r"[A-Z2-7]+=*", s):
        return None
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _hex(s):
    s = re.sub(r"(0x|\\x|\s|:)", "", s)
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s)


def _b85(s):
    s = s.strip()
    if len(s) < 5 or re.search(r"\s", s):
        return None
    try:
        return base64.b85decode(s)
    except Exception:
        return None


def _bin(s):
    s = re.sub(r"\s", "", s)
    if len(s) < 8 or len(s) % 8 or not re.fullmatch(r"[01]+", s):
        return None
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def _dec(s):
    parts = re.split(r"[\s,;]+", s.strip())
    if len(parts) < 3 or not all(p.isdigit() and int(p) < 256 for p in parts):
        return None
    return bytes(int(p) for p in parts)


def _url(s):
    if "%" not in s:
        return None
    return urllib.parse.unquote_to_bytes(s)


def _morse(s):
    if not re.fullmatch(r"[.\-/\s|]+", s.strip()) or not re.search(r"[.-]", s):
        return None
    words = re.split(r"\s*[/|]\s*|\s{3,}", s.strip())
    out = " ".join("".join(MORSE.get(c, "?") for c in w.split()) for w in words)
    return out.encode() if "?" not in out else None


def _a1z26(s):
    """A1Z26 cipher: 1=A, 2=B, ... 26=Z.  Accepts comma/space/dash separated numbers."""
    parts = re.split(r"[,\s\-]+", s.strip())
    if len(parts) < 3 or not all(p.isdigit() and 1 <= int(p) <= 26 for p in parts):
        return None
    return "".join(chr(int(p) + 64) for p in parts).encode()


def _bacon(s):
    """Baconian cipher: 5-char groups of A/B (or a/b, 0/1) -> letters."""
    s = re.sub(r"\s", "", s.upper())
    # Normalize: 0->A, 1->B
    s = s.replace("0", "A").replace("1", "B")
    if len(s) < 5 or len(s) % 5 or not re.fullmatch(r"[AB]+", s):
        return None
    BACON_MAP = {f"{i:05b}".replace("0", "A").replace("1", "B"): chr(65 + i) for i in range(26)}
    out = "".join(BACON_MAP.get(s[i:i+5], "?") for i in range(0, len(s), 5))
    return out.encode() if "?" not in out else None


DECODERS = [("base64", _b64), ("base32", _b32), ("hex", _hex), ("base85", _b85),
            ("binary", _bin), ("decimal", _dec), ("url", _url), ("morse", _morse),
            ("a1z26", _a1z26), ("bacon", _bacon)]


def rot_n(s, n):
    out = []
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base + n) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)


def atbash(s):
    return "".join(chr(155 - ord(c)) if c.isupper() else chr(219 - ord(c)) if c.islower() else c for c in s)


def decode_chain(text, prefix=None, max_depth=6):
    leaves, seen = [], set()

    def rec(s, chain, depth):
        if s in seen:
            return
        seen.add(s)
        # cheap transforms evaluated as variants only
        for name, fn in (("rot13", lambda x: rot_n(x, 13)), ("rot47", rot47),
                         ("reverse", lambda x: x[::-1]), ("atbash", atbash)):
            v = fn(s)
            if find_flags(v, prefix):
                leaves.append((100, " > ".join(chain + [name]), v))
        progressed = False
        if depth < max_depth:
            for name, fn in DECODERS:
                try:
                    r = fn(s)
                except Exception:
                    continue
                if not r or r == s.encode("latin-1", "ignore"):
                    continue
                t = r.decode("latin-1")
                if printable_ratio(t) < 0.9:
                    if depth > 0:
                        leaves.append((score(t) - 20, " > ".join(chain + [name]) + " (binary)", t))
                    elif name in ("hex", "base64", "base32", "binary", "decimal"):
                        leaves.append((-5, " > ".join(chain + [name]) + " (binary)", t))
                    continue
                progressed = True
                rec(t, chain + [name], depth + 1)
        if chain and (not progressed or find_flags(s, prefix)):
            leaves.append((100 if find_flags(s, prefix) else score(s), " > ".join(chain), s))

    rec(text.strip(), [], 0)
    return leaves


# ---------------------------------------------------------------- classical ciphers
def caesar_all(ct):
    return [(score(rot_n(ct, k)), f"caesar shift={k}", rot_n(ct, k)) for k in range(1, 26)]


def affine_all(ct):
    out = []
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        ai = pow(a, -1, 26)
        for b in range(26):
            if a == 1 and b == 0:
                continue
            pt = "".join(
                chr((ai * (ord(c) - (65 if c.isupper() else 97) - b)) % 26 + (65 if c.isupper() else 97))
                if c.isalpha() else c for c in ct)
            out.append((score(pt), f"affine a={a} b={b}", pt))
    return out


def rail_decrypt(ct, rails):
    n = len(ct)
    pattern, r, d = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if rails > 1:
            if r == 0:
                d = 1
            elif r == rails - 1:
                d = -1
            r += d
    order = sorted(range(n), key=lambda i: pattern[i])
    out = [""] * n
    for k, i in enumerate(order):
        out[i] = ct[k]
    return "".join(out)


def rail_all(ct):
    return [(score(rail_decrypt(ct, r)), f"railfence rails={r}", rail_decrypt(ct, r))
            for r in range(2, min(15, len(ct) // 2 + 1))]


def vig_dec(ct, key):
    out, j = [], 0
    for c in ct:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base - (ord(key[j % len(key)].upper()) - 65)) % 26 + base))
            j += 1
        else:
            out.append(c)
    return "".join(out)


def best_shift(col):
    best, bs = 0, 1e18
    n = len(col)
    if not n:
        return 0
    cnt = Counter(col)
    for s in range(26):
        chi = 0
        for i, c in enumerate(ALPHA):
            obs = cnt.get(ALPHA[(i + s) % 26], 0)
            exp = EN_FREQ[c] / 100 * n
            chi += (obs - exp) ** 2 / exp
        if chi < bs:
            best, bs = s, chi
    return best


def ic(col):
    n = len(col)
    if n < 2:
        return 0
    return sum(v * (v - 1) for v in Counter(col).values()) / (n * (n - 1))


def vigenere_crack(ct, maxk=20):
    letters = [c for c in ct.upper() if c in ALPHA]
    cands = []
    for k in range(1, min(maxk, len(letters) // 3) + 1):
        cols = ["".join(letters[i::k]) for i in range(k)]
        avg = sum(ic(c) for c in cols) / k
        key = "".join(ALPHA[best_shift(c)] for c in cols)
        cands.append((avg, k, key))
    # prefer shortest key whose IC is near the best
    top = max(c[0] for c in cands) if cands else 0
    good = sorted([c for c in cands if c[0] >= top * 0.85], key=lambda c: c[1])[:3]
    res = []
    for avg, k, key in good:
        pt = vig_dec(ct, key)
        res.append((score(pt), f"vigenere key={key} (len {k}, IC {avg:.3f})", pt))
    return res


# substitution ------------------------------------------------------------
def build_stats(corpus):
    txt = [ALPHA.index(c) for c in corpus.upper() if c in ALPHA]
    big = [[0.5] * 26 for _ in range(26)]
    for a, b in zip(txt, txt[1:]):
        big[a][b] += 1
    return [[math.log(v / sum(row)) for v in row] for row in big]


def solve_substitution(ct, corpus=CORPUS, restarts=40, seed=1):
    random.seed(seed)
    big = build_stats(corpus)
    idx = [ALPHA.index(c) for c in ct.upper() if c in ALPHA]
    if len(idx) < 30:
        return None
    cnt = Counter(idx)
    freq_order = [c for c, _ in cnt.most_common()] + [c for c in range(26) if c not in cnt]
    en_order = [ALPHA.index(c) for c in "ETAOINSHRDLCUMWFGYPBVKJXQZ"]

    def sc(key):
        p = [key[i] for i in idx]
        return sum(big[a][b] for a, b in zip(p, p[1:]))

    best_key, best_sc = None, -1e18
    for r in range(restarts):
        key = [0] * 26
        for c, p in zip(freq_order, en_order):
            key[c] = p
        if r:
            for _ in range(r % 6 * 2 + 2):
                i, j = random.sample(range(26), 2)
                key[i], key[j] = key[j], key[i]
        cur, improved = sc(key), True
        while improved:
            improved = False
            for i in range(26):
                for j in range(i + 1, 26):
                    key[i], key[j] = key[j], key[i]
                    s = sc(key)
                    if s > cur:
                        cur, improved = s, True
                    else:
                        key[i], key[j] = key[j], key[i]
        if cur > best_sc:
            best_key, best_sc = key[:], cur
    # polish: word-aware swaps using corpus vocabulary
    vocab = set(re.findall(r"[a-z]{3,}", corpus.lower()))

    def sc2(key):
        dec = "".join(ALPHA[key[i]] if i is not None else " " for i in full).lower()
        return sc(key) + 3.0 * sum(len(w) for w in re.findall(r"[a-z]+", dec) if w in vocab)

    full = [ALPHA.index(c.upper()) if c.upper() in ALPHA else None for c in ct]
    cur, improved = sc2(best_key), True
    while improved:
        improved = False
        for i in range(26):
            for j in range(i + 1, 26):
                best_key[i], best_key[j] = best_key[j], best_key[i]
                v = sc2(best_key)
                if v > cur:
                    cur, improved = v, True
                else:
                    best_key[i], best_key[j] = best_key[j], best_key[i]
    out = "".join((ALPHA[best_key[ALPHA.index(c.upper())]] if c.upper() in ALPHA else c) if not c.islower()
                  else (ALPHA[best_key[ALPHA.index(c.upper())]].lower() if c.upper() in ALPHA else c)
                  for c in ct)
    mapping = "".join(ALPHA[best_key[i]] for i in range(26))
    return best_sc, mapping, out


def classic_all(ct, prefix):
    res = caesar_all(ct) + affine_all(ct) + rail_all(ct)
    res.append((score(atbash(ct)), "atbash", atbash(ct)))
    r47 = rot47(ct)
    res.append((score(r47), "rot47", r47))
    res += vigenere_crack(ct)
    s = solve_substitution(ct)
    if s:
        res.append((score(s[2]), f"substitution cipher->plain={s[1]}", s[2]))
    return res


# ---------------------------------------------------------------- xor
def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def single_xor(data):
    res = []
    for k in range(256):
        t = xor_bytes(data, bytes([k])).decode("latin-1")
        res.append((score(t), f"xor key=0x{k:02x}", t))
    return res


def repeating_xor(data, maxk=40):
    sizes = []
    for k in range(2, min(maxk, len(data) // 4) + 1):
        blocks = [data[i * k:(i + 1) * k] for i in range(min(8, len(data) // k))]
        d = [hamming(blocks[i], blocks[j]) / k for i in range(len(blocks)) for j in range(i + 1, len(blocks))]
        if d:
            sizes.append((sum(d) / len(d), k))
    res = []
    for _, k in sorted(sizes)[:4]:
        key = bytearray()
        for i in range(k):
            col = data[i::k]
            best = max(range(256), key=lambda b: score(bytes(x ^ b for x in col).decode("latin-1")))
            key.append(best)
        t = xor_bytes(data, bytes(key)).decode("latin-1")
        res.append((score(t), f"xor repeating key={bytes(key)!r}", t))
    return res


def to_bytes(s):
    h = _hex(s)
    if h is not None:
        return h
    try:
        b = _b64(s)
        if b:
            return b
    except Exception:
        pass
    return s.encode("latin-1")


# ---------------------------------------------------------------- RSA
def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def show_pt(m):
    b = long_to_bytes(m)
    print(f"  m = {m}")
    print(f"  plaintext = {b!r}")
    for f in find_flags(b.decode("latin-1")):
        print(f"  FLAG: {f}")


def iroot(x, k):
    if x < 2:
        return x
    lo, hi = 0, 1 << (x.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def is_probable_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def small_primes(limit=200000):
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i, v in enumerate(sieve) if v]


def trial(n):
    for p in small_primes():
        if n % p == 0:
            return p
    return None


def fermat(n, iters=2_000_000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(iters):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b
        a += 1
    return None


def rho(n, limit=20):
    if n % 2 == 0:
        return 2
    t = time.time()
    while time.time() - t < limit:
        c = random.randrange(1, n)
        x = y = random.randrange(0, n)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if time.time() - t > limit:
                return None
        if d != n:
            return d
    return None


def pminus1(n, B=300000):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        if j % 500 == 0:
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d
    d = math.gcd(a - 1, n)
    return d if 1 < d < n else None


def wiener(e, n):
    cf, a, b = [], e, n
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    h1, h2, k1, k2 = 1, 0, 0, 1
    for q in cf:
        h, k = q * h1 + h2, q * k1 + k2
        h2, h1, k2, k1 = h1, h, k1, k
        kg, d = h, k
        if kg == 0 or (e * d - 1) % kg:
            continue
        phi = (e * d - 1) // kg
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            r = math.isqrt(disc)
            if r * r == disc and (s + r) % 2 == 0:
                return (s + r) // 2, (s - r) // 2
    return None


def factordb(n):
    from urllib.request import urlopen, Request
    url = "https://factordb.com/api?query=" + str(n)
    data = json.loads(urlopen(Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=15).read())
    if data.get("status") in ("FF",):
        fs = []
        for p, e in data["factors"]:
            fs += [int(p)] * e
        return fs
    return None


def rsa_with_primes(n, e, c, primes):
    phi = 1
    for p, k in Counter(primes).items():
        phi *= (p - 1) * p ** (k - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n)


def cmd_rsa(a):
    n, e, c = a.n, a.e, a.c
    print(f"{Colors.BOLD}[*] n has {n.bit_length()} bits, e={e}{Colors.RESET}")
    if a.p and a.q:
        print("[+] decrypting with provided p,q")
        return show_pt(rsa_with_primes(n, e, c, [a.p, a.q]))
    if is_probable_prime(n):
        print("[+] n is prime -> phi = n-1")
        return show_pt(rsa_with_primes(n, e, c, [n]))
    # small e, no wraparound
    if e <= 65537 and e < 64:
        for k in range(0, 5000):
            m = iroot(c + k * n, e)
            if m ** e == c + k * n:
                print(f"[+] small-e attack worked (k={k})")
                return show_pt(m)
    steps = [("small primes", trial), ("wiener", None), ("fermat", fermat),
             ("pollard p-1", pminus1), ("pollard rho", rho)]
    for name, fn in steps:
        print(f"[*] trying {name}...")
        if name == "wiener":
            w = wiener(e, n)
            if w:
                p, q = w
                print(f"[+] wiener: p={p}\n             q={q}")
                return show_pt(rsa_with_primes(n, e, c, [p, q]))
            continue
        p = fn(n)
        if p and 1 < p < n:
            q = n // p
            print(f"[+] {name}: p={p}\n             q={q}")
            if is_probable_prime(p) and is_probable_prime(q):
                return show_pt(rsa_with_primes(n, e, c, [p, q]))
            print("    (factors not both prime; trying anyway)")
            return show_pt(rsa_with_primes(n, e, c, [p, q]))
    if a.online:
        print("[*] querying factordb...")
        try:
            fs = factordb(n)
            if fs:
                print(f"[+] factordb: {fs}")
                return show_pt(rsa_with_primes(n, e, c, fs))
            print("[-] factordb: not fully factored")
        except Exception as ex:
            print(f"[-] factordb failed: {ex}")
    print("[-] no attack worked. Try --online, msieve/yafu/cado-nfs, or check for multi-prime / shared primes across keys.")


def cmd_common(a):
    g, x, y = _egcd(a.e1, a.e2)
    if g != 1:
        return print("[-] e1,e2 not coprime")
    n = a.n
    c1 = pow(a.c1, x, n) if x >= 0 else pow(pow(a.c1, -1, n), -x, n)
    c2 = pow(a.c2, y, n) if y >= 0 else pow(pow(a.c2, -1, n), -y, n)
    print("[+] common modulus attack")
    show_pt(c1 * c2 % n)


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def cmd_hastad(a):
    N = 1
    for n in a.n:
        N *= n
    total = 0
    for n, c in zip(a.n, a.c):
        Ni = N // n
        total += c * Ni * pow(Ni, -1, n)
    m = iroot(total % N, a.e)
    if m ** a.e == total % N:
        print("[+] hastad broadcast attack")
        show_pt(m)
    else:
        print("[-] failed (need >= e ciphertexts with coprime moduli, same unpadded message)")


# ---------------------------------------------------------------- hashes
HASH_LEN = {32: ["MD5", "NTLM", "MD4"], 40: ["SHA1"], 56: ["SHA224"], 64: ["SHA256"],
            96: ["SHA384"], 128: ["SHA512"]}
TINY = ["password", "123456", "admin", "letmein", "qwerty", "flag", "secret", "ctf", "root",
        "toor", "password1", "iloveyou", "welcome", "monkey", "dragon", "123456789", "12345678"]


def hashers():
    h = {"md5": lambda b: hashlib.md5(b).hexdigest(), "sha1": lambda b: hashlib.sha1(b).hexdigest(),
         "sha224": lambda b: hashlib.sha224(b).hexdigest(), "sha256": lambda b: hashlib.sha256(b).hexdigest(),
         "sha384": lambda b: hashlib.sha384(b).hexdigest(), "sha512": lambda b: hashlib.sha512(b).hexdigest()}
    try:
        hashlib.new("md4", b"")
        h["ntlm"] = lambda b: hashlib.new("md4", b.decode("latin-1").encode("utf-16le")).hexdigest()
    except Exception:
        pass
    return h


def cmd_hash(a):
    h = a.hash.strip().lower()
    cands = HASH_LEN.get(len(h)) if re.fullmatch(r"[0-9a-f]+", h) else None
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return print("[*] bcrypt - use hashcat -m 3200 / john")
    if h.startswith("$6$"):
        return print("[*] sha512crypt - use hashcat -m 1800 / john")
    if h.startswith("$1$"):
        return print("[*] md5crypt - use hashcat -m 500 / john")
    if not cands:
        return print("[-] unknown hash format")
    print(f"[*] possible types: {', '.join(cands)}")
    path = a.wordlist or next((p for p in ("/usr/share/wordlists/rockyou.txt",
                                           "/usr/share/wordlists/rockyou.txt.gz") if os.path.exists(p)), None)
    words = TINY
    if path and not path.endswith(".gz"):
        words = (l.rstrip("\n") for l in open(path, "r", encoding="latin-1"))
    elif path:
        import gzip
        words = (l.rstrip("\n") for l in gzip.open(path, "rt", encoding="latin-1"))
    algos = {k: v for k, v in hashers().items() if k.upper() in cands}
    t, n = time.time(), 0
    for w in words:
        n += 1
        b = w.encode("latin-1", "ignore")
        for name, fn in algos.items():
            if fn(b) == h:
                return print(f"[+] CRACKED ({name}): {w}  ({n} tries, {time.time() - t:.1f}s)")
    print(f"[-] not found in {n} candidates. Try a bigger wordlist, or hashcat/john with rules.")


# ---------------------------------------------------------------- commands
def cmd_decode(a):
    text = load_input(a.text)
    leaves = decode_chain(text, a.flag)
    if not leaves:
        return print("[-] no encoding layers detected")
    show("Decode chains", leaves, a.flag, top=5)


def cmd_classic(a):
    text = load_input(a.text)
    show("Classical ciphers", classic_all(text, a.flag), a.flag, top=6)


def cmd_vig(a):
    text = load_input(a.text)
    if a.key:
        pt = vig_dec(text, a.key)
        return show("Vigenere (given key)", [(score(pt), f"key={a.key}", pt)], a.flag, 1)
    show("Vigenere", vigenere_crack(text), a.flag, 3)


def cmd_subst(a):
    text = load_input(a.text)
    corpus = open(a.corpus, errors="ignore").read() if a.corpus else CORPUS
    r = solve_substitution(text, corpus)
    if not r:
        return print("[-] ciphertext too short (need ~30+ letters, ideally 150+)")
    print(f"[*] cipher->plain map: {r[1]}\n{r[2]}")


def cmd_xor(a):
    raw = load_input(a.data)
    data = to_bytes(raw)
    res = []
    if a.key:
        key = _hex(a.key) if _hex(a.key) and len(a.key) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", a.key) else a.key.encode()
        t = xor_bytes(data, key).decode("latin-1")
        res.append((score(t), f"xor key={key!r}", t))
    else:
        if a.crib:
            crib = a.crib.encode()
            for off in (0,):
                key = bytes(x ^ y for x, y in zip(data[off:off + len(crib)], crib))
                for kl in range(1, len(key) + 1):
                    k = key[:kl]
                    if kl == len(key) or all(key[i] == k[i % kl] for i in range(len(key))):
                        k = k[off % kl:] + k[:off % kl] if off else k
                        t = xor_bytes(data, k).decode("latin-1")
                        res.append((score(t) + (50 if find_flags(t, a.flag) else 0), f"crib@{off} key={k!r}", t))
                        break
        res += single_xor(data)
        if len(data) > 16:
            res += repeating_xor(data)
    show("XOR", res, a.flag, 5)


def cmd_auto(a):
    text = load_input(a.text)
    print(f"[*] input: {len(text)} chars")
    leaves = decode_chain(text, a.flag)
    if leaves:
        show("Decode chains", leaves, a.flag, 4)
    # re-run classical on best decoded text too
    targets = [text] + [t for sc, l, t in sorted(leaves, key=lambda r: -r[0])[:1] if printable_ratio(t) > 0.95]
    for t in targets:
        if len(re.findall(r"[A-Za-z]", t)) >= 8:
            show("Classical ciphers" + ("" if t is text else " (on best decoded)"), classic_all(t, a.flag), a.flag, 5)
    raw = to_bytes(text)
    if _hex(text) is not None or (_b64(text) if len(text) > 8 else None):
        res = single_xor(raw) + (repeating_xor(raw) if len(raw) > 16 else [])
        show("XOR", res, a.flag, 3)
    if re.fullmatch(r"[0-9a-fA-F]{32,128}", text.strip()) and len(text.strip()) in HASH_LEN:
        print(f"\n[*] looks like a hash: {HASH_LEN[len(text.strip())]} -> run: crypto.py hash {text.strip()}")


def intarg(x):
    return int(x, 0)


def main():
    ap = argparse.ArgumentParser(description="CTF crypto solver", formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument("--flag", help="flag prefix, e.g. picoCTF")
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("auto", cmd_auto), ("decode", cmd_decode), ("classic", cmd_classic), ("subst", cmd_subst),
                     ("vigenere", cmd_vig)):
        p = sp.add_parser(name)
        p.add_argument("text", help="text, file path, or - for stdin")
        if name == "vigenere":
            p.add_argument("--key")
        if name == "subst":
            p.add_argument("--corpus", help="English text file for better stats")
        p.set_defaults(fn=fn)
    p = sp.add_parser("xor")
    p.add_argument("data")
    p.add_argument("--key")
    p.add_argument("--crib", help="known plaintext start, e.g. 'flag{'")
    p.set_defaults(fn=cmd_xor)
    p = sp.add_parser("rsa")
    for k in ("n", "e", "c"):
        p.add_argument(f"--{k}", type=intarg, required=True)
    p.add_argument("--p", type=intarg)
    p.add_argument("--q", type=intarg)
    p.add_argument("--online", action="store_true", help="query factordb.com")
    p.set_defaults(fn=cmd_rsa)
    p = sp.add_parser("rsa-common")
    for k in ("n", "e1", "e2", "c1", "c2"):
        p.add_argument(f"--{k}", type=intarg, required=True)
    p.set_defaults(fn=cmd_common)
    p = sp.add_parser("rsa-hastad")
    p.add_argument("--e", type=intarg, required=True)
    p.add_argument("--n", type=intarg, nargs="+", required=True)
    p.add_argument("--c", type=intarg, nargs="+", required=True)
    p.set_defaults(fn=cmd_hastad)
    p = sp.add_parser("hash")
    p.add_argument("hash")
    p.add_argument("--wordlist")
    p.set_defaults(fn=cmd_hash)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()