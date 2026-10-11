"""Small shared helpers (standard library only)."""
import math
import re
import struct
from datetime import datetime, timedelta, timezone

_EPOCH_1601 = datetime(1601, 1, 1)
_EPOCH_1970 = datetime(1970, 1, 1)
MIN_YEAR, MAX_YEAR = 1995, 2100

u8 = lambda b, o: b[o]
u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
i32 = lambda b, o: struct.unpack_from("<i", b, o)[0]
u64 = lambda b, o: struct.unpack_from("<Q", b, o)[0]


def _fmt(dt):
    if dt.year < MIN_YEAR or dt.year > MAX_YEAR:
        return None
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]


def ft(v):
    """FILETIME (100 ns since 1601, UTC) -> 'YYYY-MM-DD HH:MM:SS.mmm' or None."""
    if not v or v < 0 or v > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _fmt(_EPOCH_1601 + timedelta(microseconds=v // 10))
    except (OverflowError, ValueError):
        return None


def ft_bytes(b, o=0):
    if len(b) < o + 8:
        return None
    return ft(u64(b, o))


def unix(v, scale=1):
    try:
        return _fmt(_EPOCH_1970 + timedelta(seconds=v / scale))
    except (OverflowError, ValueError, OSError):
        return None


def webkit(v):
    """Chrome/WebKit microseconds since 1601."""
    try:
        return _fmt(_EPOCH_1601 + timedelta(microseconds=int(v)))
    except (OverflowError, ValueError, TypeError):
        return None


def systemtime(b, o=0):
    try:
        y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", b, o)
        return _fmt(datetime(y, mo, d, h, mi, s, ms * 1000))
    except (ValueError, struct.error):
        return None


def parse_ts(s):
    """Our stored text time -> datetime (naive, UTC)."""
    if not s:
        return None
    s = s.replace("T", " ").rstrip("Z")
    for f in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:26], f)
        except ValueError:
            pass
    return None


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:23] if dt else None


def shift(ts, **kw):
    d = parse_ts(ts)
    return fmt_dt(d + timedelta(**kw)) if d else None


def utf16z(b, o=0, maxlen=None):
    """Null-terminated UTF-16LE string starting at o."""
    end = len(b) if maxlen is None else min(len(b), o + maxlen)
    p = o
    while p + 1 < end:
        if b[p] == 0 and b[p + 1] == 0:
            break
        p += 2
    return bytes(b[o:p]).decode("utf-16-le", "replace")


def asciiz(b, o=0):
    p = bytes(b).find(b"\0", o)
    return bytes(b[o:p if p >= 0 else len(b)]).decode("latin-1", "replace")


def sid_str(b):
    if len(b) < 8:
        return ""
    rev, cnt = b[0], b[1]
    auth = int.from_bytes(b[2:8], "big")
    subs = [str(u32(b, 8 + 4 * i)) for i in range(cnt) if 12 + 4 * i <= len(b)]
    return "S-%d-%d%s" % (rev, auth, "".join("-" + s for s in subs))


def guid_str(b):
    if len(b) < 16:
        return ""
    a, b1, c = struct.unpack_from("<IHH", b, 0)
    return "{%08X-%04X-%04X-%s-%s}" % (a, b1, c, bytes(b[8:10]).hex().upper(), bytes(b[10:16]).hex().upper())


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for x in data:
        counts[x] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


_RANDOMISH = re.compile(r"^[a-z0-9]{6,}$", re.I)


def looks_random(name):
    """Heuristic: a file stem that looks machine-generated (e.g. 'xK3pqZ9w')."""
    stem = name.rsplit(".", 1)[0]
    if not _RANDOMISH.match(stem) or len(stem) > 40:
        return False
    vowels = sum(c in "aeiouAEIOU" for c in stem)
    digits = sum(c.isdigit() for c in stem)
    mixed = any(c.islower() for c in stem) and any(c.isupper() for c in stem)
    return (vowels / len(stem) < 0.2 and len(stem) >= 7) or (digits >= 3 and mixed) or re.fullmatch(r"[0-9a-f]{16,}", stem, re.I) is not None
