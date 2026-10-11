"""
Read-only NTFS access straight from a volume or disk image, standard library only.

Sources it accepts:
  \\\\.\\F:                  a mounted image's volume (Macrium "Explore image", attached VHD), needs admin
  \\\\.\\PhysicalDrive3      an attached virtual disk (partition picked automatically)
  disk.raw / disk.dd / .img  raw disk or volume images (fixed .vhd works too: it is raw + footer)

Everything is read, nothing is written. Reads are aligned to 4 KiB, which Windows requires for raw devices.
"""
import bisect
import os
import struct

from util import u16, u32, u64, ft

ALIGN = 4096
CHUNK = 8 * 1024 * 1024

USN_REASONS = [
    (0x00000001, "DataOverwrite"), (0x00000002, "DataExtend"), (0x00000004, "DataTruncation"),
    (0x00000010, "NamedDataOverwrite"), (0x00000020, "NamedDataExtend"), (0x00000040, "NamedDataTruncation"),
    (0x00000100, "FileCreate"), (0x00000200, "FileDelete"), (0x00000400, "EaChange"),
    (0x00000800, "SecurityChange"), (0x00001000, "RenameOldName"), (0x00002000, "RenameNewName"),
    (0x00004000, "IndexableChange"), (0x00008000, "BasicInfoChange"), (0x00010000, "HardLinkChange"),
    (0x00020000, "CompressionChange"), (0x00040000, "EncryptionChange"), (0x00080000, "ObjectIdChange"),
    (0x00100000, "ReparsePointChange"), (0x00200000, "StreamChange"), (0x00400000, "TransactedChange"),
    (0x00800000, "IntegrityChange"), (0x80000000, "Close"),
]


def usn_reason_text(r):
    return "|".join(n for b, n in USN_REASONS if r & b)


class Device:
    """Aligned, read-only access to a file or raw device."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb", buffering=0)

    def read(self, off, n):
        if n <= 0:
            return b""
        out = bytearray()
        while n > 0:
            take = min(n, CHUNK)
            a = off - off % ALIGN
            end = off + take
            b = end + (-end) % ALIGN
            self.f.seek(a)
            try:
                data = self.f.read(b - a) or b""
            except OSError:
                data = b""
            piece = data[off - a: off - a + take]
            out += piece
            if len(piece) < take:
                break
            off += take
            n -= take
        return bytes(out)

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


def list_partitions(dev):
    """Return [(index, byte_offset, byte_size, is_ntfs, label)] for a disk; [(0,0,None,True,'volume')] for a bare volume."""
    s0 = dev.read(0, 512)
    if s0[3:11] == b"NTFS    ":
        return [(0, 0, u64(s0, 40) * u16(s0, 11), True, "whole volume")]
    parts = []
    for sector in (512, 4096):
        hdr = dev.read(sector, 512)
        if hdr[:8] == b"EFI PART":
            lba, n, esz = u64(hdr, 72), u32(hdr, 80), u32(hdr, 84)
            tbl = dev.read(lba * sector, n * esz)
            for i in range(n):
                e = tbl[i * esz:(i + 1) * esz]
                if len(e) < 128 or e[:16] == b"\0" * 16:
                    continue
                first, last = u64(e, 32), u64(e, 40)
                name = e[56:128].decode("utf-16-le", "ignore").rstrip("\0")
                parts.append((len(parts), first * sector, (last - first + 1) * sector, name))
            break
    if not parts and s0[510:512] == b"\x55\xaa":
        def mbr(sector_off, ext_base=None, depth=0):
            s = dev.read(sector_off, 512)
            for i in range(4):
                e = s[446 + 16 * i: 462 + 16 * i]
                typ, lba, cnt = e[4], u32(e, 8), u32(e, 12)
                if typ == 0 or cnt == 0:
                    continue
                if typ in (0x05, 0x0F, 0x85):
                    if depth < 32:
                        base = ext_base if ext_base is not None else lba * 512
                        mbr(base + (lba * 512 if ext_base is not None else 0), base, depth + 1)
                    continue
                start = (sector_off if ext_base is not None else 0) + lba * 512
                parts.append((len(parts), start, cnt * 512, "type 0x%02X" % typ))
        mbr(0)
    out = []
    for idx, off, size, name in parts:
        bs = dev.read(off, 512)
        out.append((idx, off, size, bs[3:11] == b"NTFS    ", name))
    return out


def pick_ntfs(dev, index=None):
    parts = list_partitions(dev)
    ntfs = [p for p in parts if p[3]]
    if index is not None:
        for p in parts:
            if p[0] == index:
                return p, parts
        raise ValueError("No partition %s. Found: %s" % (index, parts))
    if not ntfs:
        raise ValueError("No NTFS partition found on %s (partitions: %s)" % (dev.path, parts))
    return max(ntfs, key=lambda p: p[2] or 0), parts


# ------------------------------------------------------------------ records ---
def fixup(buf):
    usa_off, usa_cnt = u16(buf, 4), u16(buf, 6)
    if usa_cnt < 2 or usa_off + 2 * usa_cnt > len(buf):
        return bytes(buf), False
    stride = len(buf) // (usa_cnt - 1)
    if stride not in (512, 1024, 2048, 4096):
        stride = 512
    b = bytearray(buf)
    check = buf[usa_off:usa_off + 2]
    ok = True
    for i in range(1, usa_cnt):
        p = i * stride - 2
        if p + 2 > len(b):
            break
        if b[p:p + 2] != check:
            ok = False
        b[p:p + 2] = buf[usa_off + 2 * i: usa_off + 2 * i + 2]
    return bytes(b), ok


def decode_runs(data, off=0):
    """Runlist -> [(lcn or None for sparse, length_in_clusters)]."""
    runs, lcn, p = [], 0, off
    while p < len(data):
        h = data[p]
        if h == 0:
            break
        ln, lo = h & 0xF, h >> 4
        p += 1
        if ln == 0 or p + ln + lo > len(data):
            break
        length = int.from_bytes(data[p:p + ln], "little")
        p += ln
        if lo:
            lcn += int.from_bytes(data[p:p + lo], "little", signed=True)
            runs.append((lcn, length))
        else:
            runs.append((None, length))
        p += lo
    return runs


class Attr:
    __slots__ = ("type", "name", "nonres", "flags", "content", "runs", "start_vcn", "real_size", "alloc_size", "init_size", "aid")


def parse_attrs(buf):
    out = []
    p = u16(buf, 20)
    while p + 16 <= len(buf):
        t = u32(buf, p)
        if t == 0xFFFFFFFF:
            break
        ln = u32(buf, p + 4)
        if ln < 16 or p + ln > len(buf):
            break
        a = Attr()
        a.type, a.nonres, a.flags, a.aid = t, buf[p + 8], u16(buf, p + 12), u16(buf, p + 14)
        nl, no = buf[p + 9], u16(buf, p + 10)
        a.name = buf[p + no:p + no + 2 * nl].decode("utf-16-le", "replace") if nl else ""
        if not a.nonres:
            clen, coff = u32(buf, p + 16), u16(buf, p + 20)
            a.content = buf[p + coff:p + coff + clen]
            a.runs, a.start_vcn = None, 0
            a.real_size = a.alloc_size = a.init_size = clen
        else:
            a.content = None
            a.start_vcn = u64(buf, p + 16)
            roff = u16(buf, p + 32)
            a.alloc_size, a.real_size, a.init_size = u64(buf, p + 40), u64(buf, p + 48), u64(buf, p + 56)
            a.runs = decode_runs(buf[p:p + ln], roff)
        out.append(a)
        p += ln
    return out


def scan_record(buf):
    """Fast extraction of what the MFT table needs. Returns dict or None."""
    if buf[:4] != b"FILE":
        return None
    buf, ok = fixup(buf)
    flags = u16(buf, 22)
    r = {"seq": u16(buf, 16), "in_use": flags & 1, "is_dir": 1 if flags & 2 else 0,
         "base": u64(buf, 32) & 0xFFFFFFFFFFFF, "torn": not ok, "si": None, "fn": None,
         "size": None, "ads": [], "zone": None, "attrs": 0, "has_al": False, "reparse": False}
    best_ns = 99
    p = u16(buf, 20)
    n = len(buf)
    while p + 16 <= n:
        t = u32(buf, p)
        if t == 0xFFFFFFFF:
            break
        ln = u32(buf, p + 4)
        if ln < 16 or p + ln > n:
            break
        nonres = buf[p + 8]
        if t in (0x10, 0x30) and not nonres:
            coff = u16(buf, p + 20)
            c = p + coff
            if t == 0x10 and c + 36 <= n:
                r["si"] = struct.unpack_from("<4Q", buf, c)
                r["attrs"] = u32(buf, c + 32)
            elif t == 0x30 and c + 66 <= n:
                nlen, ns = buf[c + 64], buf[c + 65]
                rank = {1: 0, 3: 0, 0: 1, 2: 2}.get(ns, 3)
                if rank < best_ns:
                    best_ns = rank
                    parent = u64(buf, c)
                    r["fn"] = (parent & 0xFFFFFFFFFFFF, parent >> 48,
                               buf[c + 66:c + 66 + 2 * nlen].decode("utf-16-le", "replace"),
                               struct.unpack_from("<4Q", buf, c + 8), u64(buf, c + 48))
        elif t == 0x80:
            nl, no = buf[p + 9], u16(buf, p + 10)
            name = buf[p + no:p + no + 2 * nl].decode("utf-16-le", "replace") if nl else ""
            if nonres:
                size = u64(buf, p + 48) if u64(buf, p + 16) == 0 else None
            else:
                size = u32(buf, p + 16)
            if name == "":
                if size is not None:
                    r["size"] = size
            else:
                r["ads"].append((name, size))
                if name == "Zone.Identifier" and not nonres:
                    coff = u16(buf, p + 20)
                    r["zone"] = buf[p + coff:p + coff + u32(buf, p + 16)].decode("latin-1", "replace")
        elif t == 0x20:
            r["has_al"] = True
        elif t == 0xC0:
            r["reparse"] = True
        p += ln
    return r


# ------------------------------------------------------------------ streams ---
class BytesStream:
    def __init__(self, data):
        self.data, self.size = bytes(data), len(data)

    def read(self, off=0, n=None):
        return self.data[off:] if n is None else self.data[off:off + n]

    def iter_alloc(self):
        if self.data:
            yield 0, self.data


def lznt1(buf, out_cap):
    out = bytearray()
    p = 0
    while p + 2 <= len(buf) and len(out) < out_cap:
        hdr = u16(buf, p)
        p += 2
        if hdr == 0:
            break
        size = (hdr & 0xFFF) + 1
        chunk = buf[p:p + size]
        p += size
        if not hdr & 0x8000:
            out += chunk
            continue
        start, q = len(out), 0
        while q < len(chunk):
            flags = chunk[q]
            q += 1
            for bit in range(8):
                if q >= len(chunk):
                    break
                if not flags & (1 << bit):
                    out.append(chunk[q])
                    q += 1
                else:
                    if q + 2 > len(chunk):
                        q = len(chunk)
                        break
                    tok = u16(chunk, q)
                    q += 2
                    pos = len(out) - start - 1
                    lmask, oshift = 0xFFF, 12
                    while pos >= 0x10:
                        lmask >>= 1
                        oshift -= 1
                        pos >>= 1
                    length, offset = (tok & lmask) + 3, (tok >> oshift) + 1
                    if offset > len(out):
                        return bytes(out)
                    for _ in range(length):
                        out.append(out[-offset])
    return bytes(out)


class RunStream:
    def __init__(self, vol, runs, size, compressed=False, cu_size=16):
        self.vol, self.runs, self.size, self.compressed = vol, runs, size, compressed
        self.cu = cu_size
        self.starts, v = [], 0
        for _lcn, ln in runs:
            self.starts.append(v)
            v += ln
        self.nclusters = v
        self._plain = None

    def _read_clusters(self, vcn, count):
        cs = self.vol.cluster
        out = bytearray()
        i = max(0, bisect.bisect_right(self.starts, vcn) - 1)
        while count > 0 and i < len(self.runs):
            lcn, ln = self.runs[i]
            rel = vcn - self.starts[i]
            if rel >= ln:
                i += 1
                continue
            take = min(ln - rel, count)
            if lcn is None:
                out += b"\0" * (take * cs)
            else:
                out += self.vol.read((lcn + rel) * cs, take * cs).ljust(take * cs, b"\0")
            vcn += take
            count -= take
            i += 1
        if count > 0:
            out += b"\0" * (count * cs)
        return bytes(out)

    def _decompress_all(self, cap):
        if self._plain is None:
            cs, out = self.vol.cluster, bytearray()
            for cu_start in range(0, self.nclusters, self.cu):
                real = 0
                for vcn in range(cu_start, min(cu_start + self.cu, self.nclusters)):
                    i = bisect.bisect_right(self.starts, vcn) - 1
                    if i >= 0 and self.runs[i][0] is not None and vcn - self.starts[i] < self.runs[i][1]:
                        real += 1
                if real == self.cu or real == 0:
                    out += self._read_clusters(cu_start, self.cu)
                else:
                    raw = self._read_clusters(cu_start, real)
                    out += lznt1(raw, self.cu * cs).ljust(self.cu * cs, b"\0")
                if len(out) >= min(self.size, cap):
                    break
            self._plain = bytes(out[:self.size])
        return self._plain

    def read(self, off=0, n=None, cap=1 << 30):
        if n is None:
            n = self.size - off
        n = max(0, min(n, self.size - off))
        if self.compressed:
            return self._decompress_all(cap)[off:off + n]
        cs = self.vol.cluster
        first = off // cs
        last = (off + n + cs - 1) // cs
        data = self._read_clusters(first, last - first)
        return data[off - first * cs: off - first * cs + n]

    def iter_alloc(self, chunk_clusters=None):
        """Yield (offset, bytes) for allocated (non-sparse) parts only."""
        cs = self.vol.cluster
        step = chunk_clusters or max(1, CHUNK // cs)
        for (lcn, ln), start in zip(self.runs, self.starts):
            if lcn is None:
                continue
            done = 0
            while done < ln:
                take = min(step, ln - done)
                off = (start + done) * cs
                if off >= self.size:
                    return
                data = self.vol.read((lcn + done) * cs, take * cs)
                yield off, data[:max(0, self.size - off)]
                done += take


# ------------------------------------------------------------------- volume ---
class NtfsVolume:
    def __init__(self, dev, base=0):
        self.dev, self.base = dev, base
        bs = dev.read(base, 512)
        if bs[3:11] != b"NTFS    ":
            raise ValueError("Not an NTFS boot sector at offset %d" % base)
        self.bps = u16(bs, 11)
        spc = bs[13]
        spc = 2 ** (256 - spc) if spc > 0x80 else spc
        self.cluster = self.bps * spc
        self.size = u64(bs, 40) * self.bps
        self.mft_lcn = u64(bs, 48)
        c = struct.unpack_from("<b", bs, 64)[0]
        self.rec_size = 2 ** (-c) if c < 0 else c * self.cluster
        self.serial = "%016X" % u64(bs, 72)
        first = self.read(self.mft_lcn * self.cluster, self.rec_size)
        if first[:4] != b"FILE":
            raise ValueError("$MFT record 0 not found (bad boot sector or encrypted volume, e.g. BitLocker)")
        buf, _ = fixup(first)
        attrs = parse_attrs(buf)
        data = [a for a in attrs if a.type == 0x80 and a.name == "" and a.nonres]
        self.mft = RunStream(self, data[0].runs, data[0].real_size)
        if any(a.type == 0x20 for a in attrs):   # fragmented $MFT: pull remaining runs from extension records
            allattrs = self.attributes(0, buf)
            data = sorted([a for a in allattrs if a.type == 0x80 and a.name == "" and a.nonres], key=lambda a: a.start_vcn)
            runs = []
            for a in data:
                runs += a.runs
            self.mft = RunStream(self, runs, data[0].real_size)
        self.records = self.mft.size // self.rec_size

    def read(self, off, n):
        return self.dev.read(self.base + off, n)

    def read_record(self, n):
        return self.mft.read(n * self.rec_size, self.rec_size)

    def attributes(self, recno, buf=None):
        if buf is None:
            raw = self.read_record(recno)
            if raw[:4] != b"FILE":
                return []
            buf, _ = fixup(raw)
        attrs = parse_attrs(buf)
        al = [a for a in attrs if a.type == 0x20]
        if not al:
            return attrs
        a = al[0]
        content = a.content if not a.nonres else RunStream(self, a.runs, a.real_size).read()
        refs, p = [], 0
        while p + 26 <= len(content):
            ln = u16(content, p + 4)
            if ln == 0:
                break
            ref = u64(content, p + 16) & 0xFFFFFFFFFFFF
            if ref != recno and ref not in refs:
                refs.append(ref)
            p += ln
        out = [x for x in attrs if x.type != 0x20]
        for r in refs:
            raw = self.read_record(r)
            if raw[:4] == b"FILE":
                out += [x for x in parse_attrs(fixup(raw)[0]) if x.type != 0x20]
        return out

    def stream(self, recno, name=""):
        attrs = [a for a in self.attributes(recno) if a.type == 0x80 and a.name == name]
        if not attrs:
            return None
        if not attrs[0].nonres:
            return BytesStream(attrs[0].content)
        attrs.sort(key=lambda a: a.start_vcn)
        runs = []
        for a in attrs:
            runs += a.runs
        first = attrs[0]
        return RunStream(self, runs, first.real_size, compressed=bool(first.flags & 0x0001))

    def iter_records(self):
        """Yield (record_number, raw_bytes) for the whole $MFT, reading large chunks."""
        rs = self.rec_size
        for off, data in self.mft.iter_alloc():
            base = off // rs
            for i in range(len(data) // rs):
                yield base + i, data[i * rs:(i + 1) * rs]


class MftFile:
    """An exported $MFT file (FTK Imager, KAPE, etc.)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            head = f.read(64)
        self.rec_size = u32(head, 28) if head[:4] == b"FILE" and u32(head, 28) in (1024, 4096) else 1024
        self.records = os.path.getsize(path) // self.rec_size

    def iter_records(self):
        rs = self.rec_size
        with open(self.path, "rb") as f:
            n = 0
            while True:
                data = f.read(rs * 4096)
                if not data:
                    break
                for i in range(len(data) // rs):
                    yield n, data[i * rs:(i + 1) * rs]
                    n += 1


# ---------------------------------------------------------------------- USN ---
def parse_usn_block(data, base_off=0):
    """Yield USN records (dict) from a block of $UsnJrnl:$J data."""
    p, n = 0, len(data)
    while p + 60 <= n:
        ln = u32(data, p)
        if ln == 0:
            # zero padding up to the next 4 KiB page, or a hole: jump over long zero runs quickly
            if data[p:p + 64] == b"\0" * 64:
                rest = data[p:].lstrip(b"\0")
                p = (n - len(rest)) & ~7
            else:
                p += 8
            continue
        major = u16(data, p + 4)
        if ln < 60 or ln > 4096 or ln % 8 or p + ln > n or major not in (2, 3):
            p += 8
            continue
        try:
            if major == 2:
                frn, pfrn = u64(data, p + 8), u64(data, p + 16)
                usn, ts, reason = struct.unpack_from("<qQI", data, p + 24)
                attrs = u32(data, p + 52)
                nl, no = u16(data, p + 56), u16(data, p + 58)
                rec, seq = frn & 0xFFFFFFFFFFFF, frn >> 48
                prec, pseq = pfrn & 0xFFFFFFFFFFFF, pfrn >> 48
            else:
                frn_lo, pfrn_lo = u64(data, p + 8), u64(data, p + 24)
                usn, ts, reason = struct.unpack_from("<qQI", data, p + 40)
                attrs = u32(data, p + 68)
                nl, no = u16(data, p + 72), u16(data, p + 74)
                rec, seq = frn_lo & 0xFFFFFFFFFFFF, frn_lo >> 48
                prec, pseq = pfrn_lo & 0xFFFFFFFFFFFF, pfrn_lo >> 48
            name = data[p + no:p + no + nl].decode("utf-16-le", "replace")
            t = ft(ts)
            if t and name:
                yield {"usn": usn, "ts": t, "rec": rec, "seq": seq, "prec": prec, "pseq": pseq,
                       "reason": reason, "attrs": attrs, "name": name, "off": base_off + p}
        except struct.error:
            pass
        p += ln


def iter_usn(stream):
    """stream: object with iter_alloc() (RunStream/BytesStream) or a file path of an exported $J."""
    if isinstance(stream, str):
        with open(stream, "rb") as f:
            off = 0
            carry = b""
            while True:
                data = f.read(CHUNK)
                if not data:
                    break
                if data.count(0) == len(data):
                    off += len(data)
                    continue
                yield from parse_usn_block(data, off)
                off += len(data)
        return
    for off, data in stream.iter_alloc():
        yield from parse_usn_block(data, off)
