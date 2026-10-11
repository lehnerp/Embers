"""
Windows registry hive (regf) reader, standard library only.

  * keys, values, big-data values, all subkey list types
  * transaction log replay (.LOG1/.LOG2, Windows 8.1+ "HvLE" format)
  * diff between the hive on disk and the hive after replay: changes that were still
    sitting in the logs, i.e. the most recent registry writes before the image was taken
  * keys and values recovered from free cells (deleted keys)
"""
import struct

from util import u16, u32, i32, u64, ft

T_NAMES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BE",
           6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
           10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}


class Key:
    __slots__ = ("hive", "off", "name", "lw", "parent", "nsub", "sublist", "nval", "vallist", "flags")

    @property
    def lastwrite(self):
        return ft(self.lw)


class Value:
    __slots__ = ("name", "type", "raw")

    @property
    def tname(self):
        return T_NAMES.get(self.type, "0x%X" % self.type)

    @property
    def data(self):
        return decode(self.type, self.raw)

    def text(self, limit=400):
        return render(self.type, self.raw, limit)


def decode(t, raw):
    if raw is None:
        return None
    try:
        if t in (1, 2, 6):
            if len(raw) % 2 == 0 and (len(raw) < 2 or raw[1:2] == b"\0" or b"\0\0" in raw):
                s = raw.decode("utf-16-le", "replace")
            else:
                s = raw.decode("latin-1")
            return s.split("\0", 1)[0]
        if t == 4 and len(raw) >= 4:
            return u32(raw, 0)
        if t == 5 and len(raw) >= 4:
            return struct.unpack(">I", raw[:4])[0]
        if t == 11 and len(raw) >= 8:
            return u64(raw, 0)
        if t == 7:
            return [s for s in raw.decode("utf-16-le", "replace").split("\0") if s]
    except Exception:
        pass
    return bytes(raw)


def render(t, raw, limit=400):
    v = decode(t, raw)
    if isinstance(v, bytes):
        h = v[:limit // 2].hex(" ")
        return h + (" …(%d bytes)" % len(v) if len(v) > limit // 2 else "")
    if isinstance(v, list):
        s = " | ".join(v)
    elif isinstance(v, int):
        s = "%d (0x%X)" % (v, v)
    else:
        s = "" if v is None else str(v)
    return s if len(s) <= limit else s[:limit] + "…"


class Hive:
    def __init__(self, data, name=""):
        if data[:4] != b"regf":
            raise ValueError("not a registry hive")
        self.d = data if isinstance(data, (bytes, bytearray)) else bytes(data)
        self.name = name
        self.seq1, self.seq2 = u32(self.d, 4), u32(self.d, 8)
        self.written = ft(u64(self.d, 12))
        self.minor = u32(self.d, 24)
        self.root_off = u32(self.d, 36)
        self.hbins_size = u32(self.d, 40)
        self.embedded_name = self.d[48:112].decode("utf-16-le", "ignore").split("\0")[0]
        self.replayed = 0
        self.notes = []

    @property
    def dirty(self):
        return self.seq1 != self.seq2

    # -------------------------------------------------------------- cells ---
    def key_at(self, off, any_cell=False):
        d = self.d
        p = 4096 + off + 4
        if off in (0, 0xFFFFFFFF) or p + 76 > len(d) or d[p:p + 2] != b"nk":
            return None
        if not any_cell and i32(d, p - 4) > 0:   # free cell
            return None
        k = Key()
        k.hive, k.off = self, off
        k.flags = u16(d, p + 2)
        k.lw = u64(d, p + 4)
        k.parent = u32(d, p + 16)
        k.nsub, k.sublist = u32(d, p + 20), u32(d, p + 28)
        k.nval, k.vallist = u32(d, p + 36), u32(d, p + 40)
        nlen = u16(d, p + 72)
        raw = d[p + 76:p + 76 + nlen]
        k.name = raw.decode("latin-1") if k.flags & 0x20 else raw.decode("utf-16-le", "replace")
        return k

    def root(self):
        return self.key_at(self.root_off)

    def _sub_offsets(self, off, depth=0):
        d = self.d
        p = 4096 + off + 4
        if off in (0, 0xFFFFFFFF) or p + 4 > len(d) or depth > 8:
            return []
        sig, cnt = d[p:p + 2], u16(d, p + 2)
        if sig in (b"lf", b"lh"):
            return [u32(d, p + 4 + 8 * i) for i in range(cnt) if p + 8 + 8 * i <= len(d)]
        if sig == b"li":
            return [u32(d, p + 4 + 4 * i) for i in range(cnt) if p + 8 + 4 * i <= len(d)]
        if sig == b"ri":
            out = []
            for i in range(cnt):
                if p + 8 + 4 * i <= len(d):
                    out += self._sub_offsets(u32(d, p + 4 + 4 * i), depth + 1)
            return out
        return []

    def subkeys(self, k):
        if not k or not k.nsub:
            return []
        out = []
        for o in self._sub_offsets(k.sublist):
            s = self.key_at(o, any_cell=True)
            if s:
                out.append(s)
        return out

    def _value_at(self, off, any_cell=False):
        d = self.d
        p = 4096 + off + 4
        if off in (0, 0xFFFFFFFF) or p + 20 > len(d) or d[p:p + 2] != b"vk":
            return None
        nlen, dsize, doff, typ, flags = u16(d, p + 2), u32(d, p + 4), u32(d, p + 8), u32(d, p + 12), u16(d, p + 16)
        raw = d[p + 20:p + 20 + nlen]
        v = Value()
        v.name = (raw.decode("latin-1") if flags & 1 else raw.decode("utf-16-le", "replace")) if nlen else ""
        v.type = typ
        size = dsize & 0x7FFFFFFF
        if dsize & 0x80000000:
            v.raw = bytes(d[p + 8:p + 8 + min(size, 4)])
        elif size == 0:
            v.raw = b""
        else:
            q = 4096 + doff + 4
            if doff == 0xFFFFFFFF or q > len(d):
                v.raw = None
            elif size > 16344 and self.minor >= 4 and d[q:q + 2] == b"db":
                cnt, lst = u16(d, q + 2), u32(d, q + 4)
                lp = 4096 + lst + 4
                parts = bytearray()
                for i in range(cnt):
                    if lp + 4 * i + 4 > len(d):
                        break
                    seg = 4096 + u32(d, lp + 4 * i) + 4
                    parts += d[seg:seg + min(16344, size - len(parts))]
                v.raw = bytes(parts[:size])
            else:
                v.raw = bytes(d[q:q + size])
        return v

    def values(self, k):
        if not k or not k.nval:
            return []
        d = self.d
        p = 4096 + k.vallist + 4
        out = []
        for i in range(min(k.nval, 100000)):
            if p + 4 * i + 4 > len(d):
                break
            v = self._value_at(u32(d, p + 4 * i), any_cell=True)
            if v:
                out.append(v)
        return out

    # ------------------------------------------------------------ navigate ---
    def get(self, path):
        k = self.root()
        if not path:
            return k
        for part in path.strip("\\").split("\\"):
            lp = part.lower()
            nxt = None
            for s in self.subkeys(k):
                if s.name.lower() == lp:
                    nxt = s
                    break
            if nxt is None:
                return None
            k = nxt
        return k

    def value(self, key_or_path, name, default=None):
        k = self.get(key_or_path) if isinstance(key_or_path, str) else key_or_path
        if not k:
            return default
        ln = name.lower()
        for v in self.values(k):
            if v.name.lower() == ln:
                return v.data
        return default

    def walk(self, start="", max_keys=5_000_000):
        k = self.get(start)
        if not k:
            return
        stack = [(start.strip("\\"), k)]
        seen = set()
        n = 0
        while stack:
            path, key = stack.pop()
            if key.off in seen:
                continue
            seen.add(key.off)
            yield path, key
            n += 1
            if n >= max_keys:
                return
            for s in self.subkeys(key):
                stack.append((path + "\\" + s.name if path else s.name, s))

    def key_path(self, k):
        names, seen = [], set()
        cur = k
        while cur and cur.off != self.root_off and cur.off not in seen and len(names) < 512:
            seen.add(cur.off)
            names.append(cur.name)
            cur = self.key_at(cur.parent, any_cell=True)
        if cur is None:
            names.append("?")
        return "\\".join(reversed(names))

    def control_set(self):
        cur = self.value("Select", "Current")
        return "ControlSet%03d" % cur if isinstance(cur, int) else "ControlSet001"

    # ------------------------------------------------------- deleted keys ---
    def deleted_keys(self, limit=5000):
        """Keys found in free cells: name, last write, best-effort path and values."""
        d = self.d
        end = min(len(d), 4096 + self.hbins_size)
        p, out = 4096, []
        while p < end and len(out) < limit:
            if d[p:p + 4] != b"hbin":
                p += 4096
                continue
            hsize = u32(d, p + 8) or 4096
            q = p + 32
            stop = min(p + hsize, end)
            while q + 8 < stop:
                sz = i32(d, q)
                if sz == 0:
                    break
                if sz > 0 and d[q + 4:q + 6] == b"nk":
                    k = self.key_at(q - 4096, any_cell=True)
                    if k and k.lastwrite and k.name and k.name.isprintable() and len(k.name) < 256:
                        vals = []
                        try:
                            if 0 < k.nval < 200:
                                vals = [(v.name, v.tname, v.text(200)) for v in self.values(k) if v.name.isprintable()]
                        except Exception:
                            vals = []
                        out.append({"path": self.key_path(k), "lastwrite": k.lastwrite, "values": vals})
                q += abs(sz)
            p += hsize
        return out


# ---------------------------------------------------------- log replay ---
def _log_entries(log):
    if not log or log[:4] != b"regf":
        return []
    out, p = [], 512
    while p + 40 <= len(log):
        if log[p:p + 4] != b"HvLE":
            break
        size, seq, hbsize, cnt = u32(log, p + 4), u32(log, p + 12), u32(log, p + 16), u32(log, p + 20)
        if size < 40 or p + size > len(log) or cnt > 100000 or 40 + 8 * cnt > size:
            break
        dp = p + 40 + 8 * cnt
        pages = []
        for i in range(cnt):
            off, sz = u32(log, p + 40 + 8 * i), u32(log, p + 44 + 8 * i)
            pages.append((off, log[dp:dp + sz]))
            dp += sz
        out.append((seq, hbsize, pages))
        p += size
    return out


def replay(primary, logs):
    """Apply transaction logs. Returns (new_bytes, entries_applied, note)."""
    if not logs:
        return primary, 0, ""
    base = bytearray(primary)
    seq2 = u32(base, 8)
    entries = {}
    old_format = False
    for lg in logs:
        if lg and lg[:4] == b"regf" and len(lg) > 512 and lg[512:516] != b"HvLE" and b"DIRT" in lg[:8192]:
            old_format = True
        for e in _log_entries(lg):
            entries.setdefault(e[0], e)
    seqs = sorted(s for s in entries if s >= seq2)
    applied, last = 0, None
    for s in seqs:
        if last is not None and s != last + 1:
            break
        _seq, hbsize, pages = entries[s]
        need = 4096 + hbsize
        if len(base) < need:
            base += b"\0" * (need - len(base))
        for off, data in pages:
            a = 4096 + off
            if a + len(data) > len(base):
                base += b"\0" * (a + len(data) - len(base))
            base[a:a + len(data)] = data
        struct.pack_into("<I", base, 40, max(u32(base, 40), hbsize))
        applied += 1
        last = s
    if applied:
        struct.pack_into("<II", base, 4, last + 1, last + 1)
    note = ""
    if old_format and not applied:
        note = "old-format (pre-8.1) transaction log present, not replayed"
    return bytes(base), applied, note


def diff(old, new, max_items=20000):
    """Compare two versions of the same hive. Returns list of change dicts."""
    idx = {}
    for path, k in old.walk():
        idx[path.lower()] = (k.off, k.lw)
    out, seen = [], set()

    def vals(h, k):
        return {v.name.lower(): v for v in h.values(k)}

    for path, k in new.walk():
        lp = path.lower()
        seen.add(lp)
        o = idx.get(lp)
        if o is None:
            out.append({"kind": "key added", "path": path, "value": "", "old": "", "new": "", "lastwrite": k.lastwrite})
            for v in new.values(k):
                out.append({"kind": "value added", "path": path, "value": v.name or "(default)", "old": "",
                            "new": v.text(), "lastwrite": k.lastwrite})
        elif o[1] != k.lw:
            ok = old.key_at(o[0])
            ov, nv = vals(old, ok), vals(new, k)
            for n, v in nv.items():
                if n not in ov:
                    out.append({"kind": "value added", "path": path, "value": v.name or "(default)", "old": "",
                                "new": v.text(), "lastwrite": k.lastwrite})
                elif ov[n].raw != v.raw or ov[n].type != v.type:
                    out.append({"kind": "value changed", "path": path, "value": v.name or "(default)",
                                "old": ov[n].text(), "new": v.text(), "lastwrite": k.lastwrite})
            for n, v in ov.items():
                if n not in nv:
                    out.append({"kind": "value deleted", "path": path, "value": v.name or "(default)",
                                "old": v.text(), "new": "", "lastwrite": k.lastwrite})
        if len(out) >= max_items:
            break
    for lp, (off, lw) in idx.items():
        if lp not in seen and len(out) < max_items:
            ok = old.key_at(off)
            out.append({"kind": "key deleted", "path": old.key_path(ok) if ok else lp, "value": "", "old": "",
                        "new": "", "lastwrite": ft(lw)})
    return out
