"""Build a small synthetic NTFS volume with a ransomware scenario, for testing Embers end to end."""
import struct
import sys
from datetime import datetime, timedelta

CL = 4096
REC = 1024
NREC = 128
MFT_LCN = 4
DATA_START = 64


def ftv(dt):
    return int((dt - datetime(1601, 1, 1)).total_seconds() * 10_000_000)


T0 = datetime(2024, 5, 10, 2, 0, 0)       # encryption starts
BASE = datetime(2023, 1, 15, 9, 30, 12, 345678)


# --------------------------------------------------------------- hive builder ---
class HB:
    def __init__(self):
        self.cells = bytearray(32)          # hbin header space

    def alloc(self, data):
        size = (len(data) + 4 + 7) & ~7
        off = len(self.cells)
        self.cells += struct.pack("<i", -size) + data + b"\0" * (size - 4 - len(data))
        return off

    def patch(self, off, data):
        self.cells[off + 4:off + 4 + len(data)] = data

    def key(self, name, tree, parent, lw):
        nb = name.encode("latin-1")
        off = self.alloc(b"\0" * (76 + len(nb)))
        vals = tree.get("_v", {})
        voffs = []
        for vn, (t, data) in vals.items():
            vnb = vn.encode("latin-1")
            if len(data) <= 4:
                dsz, doff = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\0"))[0]
            else:
                dsz, doff = len(data), self.alloc(data)
            voffs.append(self.alloc(b"vk" + struct.pack("<HIIIHH", len(vnb), dsz, doff, t, 1, 0) + vnb))
        vlist = self.alloc(b"".join(struct.pack("<I", o) for o in voffs)) if voffs else 0xFFFFFFFF
        subs = [(k, v) for k, v in tree.items() if k != "_v"]
        soffs = [self.key(k, v, off, lw) for k, v in subs]
        slist = self.alloc(b"lf" + struct.pack("<H", len(soffs)) + b"".join(struct.pack("<II", o, 0) for o in soffs)) if soffs else 0xFFFFFFFF
        nk = b"nk" + struct.pack("<HQ" + "I" * 15 + "HH", 0x20 if parent else 0x2C, ftv(lw), 0, parent or 0, len(soffs), 0, slist,
                                 0xFFFFFFFF, len(voffs), vlist, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, len(nb), 0) + nb
        self.patch(off, nk)
        return off

    def build(self, tree, lw, seq=5):
        root = self.key("ROOT", tree, None, lw)
        size = (len(self.cells) + 4095) & ~4095
        cells = self.cells + b"\0" * (size - len(self.cells))
        # trailing free cell
        if size > len(self.cells):
            struct.pack_into("<i", cells, len(self.cells), size - len(self.cells))
        cells[0:32] = b"hbin" + struct.pack("<II", 0, size) + b"\0" * 20
        base = bytearray(4096)
        base[0:4] = b"regf"
        struct.pack_into("<IIQIIIIIII", base, 4, seq, seq, ftv(lw), 1, 6, 0, 1, root, size, 1)
        return bytes(base + cells)


def sz(s):
    return (1, (s + "\0").encode("utf-16-le"))


def dw(v):
    return (4, struct.pack("<I", v))


def make_system():
    tree = {"Select": {"_v": {"Current": dw(1)}},
            "ControlSet001": {"Control": {"ComputerName": {"ComputerName": {"_v": {"ComputerName": sz("VICTIM-PC")}}},
                                          "TimeZoneInformation": {"_v": {"TimeZoneKeyName": sz("Central Europe Standard Time"),
                                                                         "ActiveTimeBias": dw(0xFFFFFF88)}},
                                          "Terminal Server": {"_v": {"fDenyTSConnections": dw(0)}}},
                              "Services": {"VSS": {"_v": {"ImagePath": sz(r"%SystemRoot%\System32\vssvc.exe"), "Start": dw(4)}},
                                           "x7kqsvc": {"_v": {"ImagePath": sz(r"C:\Users\Public\x7kq9zp.exe -svc"), "Start": dw(2)}},
                                           "Spooler": {"_v": {"ImagePath": sz(r"%SystemRoot%\System32\spoolsv.exe"), "Start": dw(2)}}}}}
    return HB().build(tree, T0 - timedelta(hours=1))


def make_software(extra=False):
    run = {"_v": {"OneDrive": sz(r"C:\Program Files\OneDrive\OneDrive.exe")}}
    if extra:
        run["_v"]["svchostx"] = sz(r"C:\Users\Public\x7kq9zp.exe -persist")
    tree = {"Microsoft": {"Windows": {"CurrentVersion": {"Run": run}},
                          "Windows NT": {"CurrentVersion": {"_v": {"ProductName": sz("Windows 10 Pro"), "CurrentBuild": sz("19045"),
                                                                   "DisplayVersion": sz("22H2")},
                                                            "ProfileList": {"S-1-5-21-1-2-3-1001": {"_v": {"ProfileImagePath": sz(r"C:\Users\bob")}}}}},
                          "Windows Defender": {"Exclusions": {"Paths": {"_v": {"C:\\": dw(0)}}}}},
            "Policies": {"Microsoft": {"Windows Defender": {"_v": {"DisableAntiSpyware": dw(1)}}}},
            "Classes": {".lockbit": {"_v": {"": sz("lockbit")}}}}
    return HB().build(tree, T0 - timedelta(minutes=25 if extra else 30))


def make_log(primary, newer, seq):
    hb_size = struct.unpack_from("<I", newer, 40)[0]
    pages = newer[4096:4096 + hb_size]
    body = b"HvLE" + struct.pack("<IIIIIQQ", 0, 0, seq, hb_size, 1, 0, 0) + struct.pack("<II", 0, len(pages)) + pages
    total = (len(body) + 511) & ~511
    body = body[:4] + struct.pack("<I", total) + body[8:]
    body += b"\0" * (total - len(body))
    base = bytearray(primary[:512])
    return bytes(base) + body


# --------------------------------------------------------------- evtx builder ---
class BX:
    def __init__(self, start):
        self.b = bytearray()
        self.start = start

    @property
    def pos(self):
        return self.start + len(self.b)

    def name(self, s):
        e = s.encode("utf-16-le")
        self.b += struct.pack("<IHH", 0, 0, len(s)) + e + b"\0\0"

    def open(self, nm, attrs=False):
        p = self.pos
        tok = 0x41 if attrs else 0x01
        hdr = 11 + (4 if attrs else 0)
        self.b += bytes([tok]) + struct.pack("<HII", 0xFFFF, 0, p + hdr) + (struct.pack("<I", 0) if attrs else b"")
        self.name(nm)

    def attr(self, nm, more):
        p = self.pos
        self.b += bytes([0x46 if more else 0x06]) + struct.pack("<I", p + 5)
        self.name(nm)

    def text(self, s):
        self.b += b"\x05\x01" + struct.pack("<H", len(s)) + s.encode("utf-16-le")

    def sub(self, i, t, opt=True):
        self.b += bytes([0x0E if opt else 0x0D]) + struct.pack("<HB", i, t)


def template_body(bx):
    bx.b += b"\x0f\x01\x01\x00"
    bx.open("Event"); bx.b += b"\x02"
    bx.open("System"); bx.b += b"\x02"
    bx.open("Provider", True); bx.attr("Name", False); bx.sub(0, 0x01); bx.b += b"\x03"
    bx.open("EventID"); bx.b += b"\x02"; bx.sub(1, 0x06); bx.b += b"\x04"
    bx.open("TimeCreated", True); bx.attr("SystemTime", False); bx.sub(2, 0x11); bx.b += b"\x03"
    bx.open("EventRecordID"); bx.b += b"\x02"; bx.sub(3, 0x0A); bx.b += b"\x04"
    bx.open("Channel"); bx.b += b"\x02"; bx.sub(4, 0x01); bx.b += b"\x04"
    bx.open("Computer"); bx.b += b"\x02"; bx.sub(5, 0x01); bx.b += b"\x04"
    bx.b += b"\x04"
    bx.open("EventData"); bx.b += b"\x02"
    bx.open("Data", True); bx.attr("Name", False); bx.text("CommandLine"); bx.b += b"\x02"; bx.sub(6, 0x01); bx.b += b"\x04"
    bx.open("Data", True); bx.attr("Name", False); bx.text("NewProcessName"); bx.b += b"\x02"; bx.sub(7, 0x01); bx.b += b"\x04"
    bx.open("Data", True); bx.attr("Name", False); bx.text("SubjectUserName"); bx.b += b"\x02"; bx.sub(8, 0x01); bx.b += b"\x04"
    bx.b += b"\x04"
    bx.b += b"\x04\x00"


def make_evtx(events):
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\0"
    p = 512
    tmpl_off = None
    for i, (eid, ts, cmd, img, user) in enumerate(events, 1):
        bx = BX(p + 24)
        bx.b += b"\x0f\x01\x01\x00"
        tpos = bx.pos
        if tmpl_off is None:
            tmpl_off = tpos + 10
            bx.b += b"\x0c\x01" + struct.pack("<II", 1, tmpl_off)
            body = BX(tmpl_off + 24)
            template_body(body)
            bx.b += struct.pack("<I", 0) + b"\0" * 16 + struct.pack("<I", len(body.b)) + body.b
        else:
            bx.b += b"\x0c\x01" + struct.pack("<II", 1, tmpl_off)
        vals = [("Microsoft-Windows-Security-Auditing\0".encode("utf-16-le")[:-2], 0x01), (struct.pack("<H", eid), 0x06),
                (struct.pack("<Q", ftv(ts)), 0x11), (struct.pack("<Q", i), 0x0A), ("Security".encode("utf-16-le"), 0x01),
                ("VICTIM-PC".encode("utf-16-le"), 0x01), (cmd.encode("utf-16-le"), 0x01), (img.encode("utf-16-le"), 0x01),
                (user.encode("utf-16-le"), 0x01)]
        bx.b += struct.pack("<I", len(vals))
        for v, t in vals:
            bx.b += struct.pack("<HBB", len(v), t, 0)
        for v, t in vals:
            bx.b += v
        bx.b += b"\x00"
        size = 24 + len(bx.b) + 4
        size = (size + 7) & ~7
        rec = b"\x2a\x2a\x00\x00" + struct.pack("<IQQ", size, i, ftv(ts)) + bytes(bx.b)
        rec += b"\0" * (size - 4 - len(rec)) + struct.pack("<I", size)
        chunk[p:p + size] = rec
        p += size
    struct.pack_into("<QQQQIII", chunk, 8, 1, len(events), 1, len(events), 128, p - 0, p)
    hdr = bytearray(4096)
    hdr[0:8] = b"ElfFile\0"
    struct.pack_into("<QQQIHHHH", hdr, 8, 0, 0, len(events) + 1, 128, 1, 3, 4096, 1)
    return bytes(hdr + chunk)


# -------------------------------------------------------------- prefetch v30 ---
def make_pf(exe, runs, files):
    d = bytearray(0x400)
    struct.pack_into("<I4sII", d, 0, 30, b"SCCA", 17, 0)
    d[16:16 + 60] = exe.encode("utf-16-le").ljust(60, b"\0")
    struct.pack_into("<I", d, 76, 0x1234ABCD)
    fn = ("\0".join(files) + "\0").encode("utf-16-le")
    fn_off = 0x400
    struct.pack_into("<IIIIIIIII", d, 84, 0x130, 0, 0, 0, fn_off, len(fn), 0, 0, 0)
    for i, r in enumerate(runs):
        struct.pack_into("<Q", d, 0x80 + 8 * i, ftv(r))
    struct.pack_into("<I", d, 0xD0, len(runs))
    out = bytes(d) + fn
    return out[:12] + struct.pack("<I", len(out)) + out[16:]


# ---------------------------------------------------------------- NTFS builder ---
class Vol:
    def __init__(self, nclusters=2048):
        self.img = bytearray(nclusters * CL)
        self.next = DATA_START
        self.records = {}

    def put(self, data):
        n = (len(data) + CL - 1) // CL
        lcn = self.next
        self.img[lcn * CL:lcn * CL + len(data)] = data
        self.next += max(1, n)
        return lcn, max(1, n)


def runlist(runs):
    out, prev = b"", 0
    for lcn, ln in runs:
        lb = ln.to_bytes(4, "little").rstrip(b"\0") or b"\0"
        if lcn is None:
            out += bytes([len(lb)]) + lb
            continue
        delta = lcn - prev
        ob = delta.to_bytes(4, "little", signed=True)
        while len(ob) > 1 and ((ob[-1] == 0 and ob[-2] < 0x80) or (ob[-1] == 0xFF and ob[-2] >= 0x80)):
            ob = ob[:-1]
        out += bytes([(len(ob) << 4) | len(lb)]) + lb + ob
        prev = lcn
    return out + b"\0"


def attr_res(t, content, name=""):
    nb = name.encode("utf-16-le")
    hdr = 24
    noff = hdr
    coff = (hdr + len(nb) + 7) & ~7
    total = (coff + len(content) + 7) & ~7
    a = bytearray(total)
    struct.pack_into("<IIBBHHHIHBB", a, 0, t, total, 0, len(name), noff, 0, 0, len(content), coff, 0, 0)
    a[noff:noff + len(nb)] = nb
    a[coff:coff + len(content)] = content
    return bytes(a)


def attr_nonres(t, runs, real, name=""):
    nb = name.encode("utf-16-le")
    noff = 64
    rl = runlist(runs)
    roff = (noff + len(nb) + 7) & ~7
    total = (roff + len(rl) + 7) & ~7
    ncl = sum(l for _x, l in runs)
    a = bytearray(total)
    struct.pack_into("<IIBBHHH", a, 0, t, total, 1, len(name), noff, 0, 0)
    struct.pack_into("<QQHHIQQQ", a, 16, 0, ncl - 1, roff, 0, 0, ncl * CL, real, real)
    a[noff:noff + len(nb)] = nb
    a[roff:roff + len(rl)] = rl
    return bytes(a)


def si(c, m=None, e=None, a=None):
    m, e, a = m or c, e or m or c, a or m or c
    return attr_res(0x10, struct.pack("<QQQQI", ftv(c), ftv(m), ftv(e), ftv(a), 0x20) + b"\0" * 44)


def fn(parent, name, c, size=0, pseq=1):
    nb = name.encode("utf-16-le")
    content = struct.pack("<QQQQQQQII", parent | (pseq << 48), ftv(c), ftv(c), ftv(c), ftv(c), size, size, 0x20, 0) + bytes([len(name), 1]) + nb
    return attr_res(0x30, content)


def record(n, attrs, is_dir=False, in_use=True, seq=1):
    r = bytearray(REC)
    body = b"".join(attrs) + struct.pack("<I", 0xFFFFFFFF) + b"\0" * 4
    first = 56
    struct.pack_into("<4sHHQHHHHII", r, 0, b"FILE", 48, 3, 0, seq, 1, first, (1 if in_use else 0) | (2 if is_dir else 0), first + len(body), REC)
    struct.pack_into("<QHHI", r, 32, 0, 0, 0, n)
    r[first:first + len(body)] = body
    usn = b"\x01\x00"
    r[48:50] = usn
    for i in (1, 2):
        p = i * 512 - 2
        r[48 + 2 * i:50 + 2 * i] = r[p:p + 2]
        r[p:p + 2] = usn
    return bytes(r)


def build(out):
    v = Vol()
    recs = {}
    t_old = BASE

    def add(n, parent, name, c, data=None, is_dir=False, m=None, e=None, stream=None, in_use=True):
        attrs = [si(c, m, e), fn(parent, name, c, len(data or b""))]
        if not is_dir:
            if data is not None and len(data) < 600:
                attrs.append(attr_res(0x80, data))
            elif data is not None:
                lcn, ncl = v.put(data)
                attrs.append(attr_nonres(0x80, [(lcn, ncl)], len(data)))
            else:
                attrs.append(attr_res(0x80, b""))
        if stream:
            attrs.append(stream)
        recs[n] = record(n, attrs, is_dir, in_use)

    # metafiles
    recs[0] = record(0, [si(t_old), fn(5, "$MFT", t_old, NREC * REC), attr_nonres(0x80, [(MFT_LCN, NREC * REC // CL)], NREC * REC)])
    add(5, 5, ".", t_old, is_dir=True)
    add(11, 5, "$Extend", t_old, is_dir=True)
    dirs = {20: (5, "Windows"), 21: (20, "System32"), 22: (21, "config"), 23: (21, "winevt"), 24: (23, "Logs"), 25: (20, "Prefetch"),
            26: (5, "Users"), 27: (26, "bob"), 28: (27, "Documents"), 29: (27, "Desktop"), 30: (26, "Public"), 31: (27, "Pictures"),
            32: (27, "Music"), 33: (27, "Videos"), 34: (27, "Downloads"), 35: (20, "System32_x")}
    for n, (p, nm) in dirs.items():
        add(n, p, nm, t_old, is_dir=True)
    system = make_system()
    sw_old, sw_new = make_software(False), make_software(True)
    add(40, 22, "SYSTEM", t_old, system)
    add(41, 22, "SOFTWARE", t_old, sw_old)
    add(42, 22, "SOFTWARE.LOG1", t_old, make_log(sw_old, sw_new, 5))
    evts = [(4624, T0 - timedelta(hours=3), "", "", "bob"),
            (4688, T0 - timedelta(minutes=20), r'"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet', r"C:\Windows\System32\vssadmin.exe", "bob"),
            (4688, T0 - timedelta(minutes=10), r"C:\Users\Public\x7kq9zp.exe -pass 1234", r"C:\Users\Public\x7kq9zp.exe", "bob"),
            (1102, T0 + timedelta(minutes=15), "", "", "bob")]
    add(43, 24, "Security.evtx", t_old, make_evtx(evts))
    payload_c = T0 - timedelta(minutes=12)
    add(44, 30, "x7kq9zp.exe", payload_c, b"MZ" + b"\x90" * 3000)
    files_ref = [r"\VOLUME{01d000000000000-1234}\USERS\PUBLIC\X7KQ9ZP.EXE", r"\VOLUME{01d000000000000-1234}\USERS\BOB\DOCUMENTS\RESTORE-MY-FILES.TXT"]
    add(45, 25, "X7KQ9ZP.EXE-1234ABCD.pf", T0 - timedelta(minutes=10), make_pf("X7KQ9ZP.EXE", [T0 - timedelta(minutes=10)], files_ref))
    note = b"All your files are encrypted by LockBit 3.0!\r\nContact: decryptme@onionmail.org\r\nhttp://lockbitapt2yfbt7lchxejug47kmqvqqxvvjpqkmevv4l3azl3gy6pyd.onion\r\nYour ID: 3A9F11C2BB7E"
    n = 50
    usn_entries = []
    note_dirs = [28, 29, 31, 32, 33, 34, 30]
    for di, d in enumerate([28, 29, 31, 32, 33, 34]):
        for k in range(6):
            t = T0 + timedelta(seconds=di * 60 + k * 7)
            old = "file%d_%d.docx" % (di, k)
            add(n, d, old + ".lockbit", BASE, b"\x8f\x13" * 400, m=t, e=t)
            usn_entries.append((t, n, d, old, 0x1000))
            usn_entries.append((t + timedelta(milliseconds=5), n, d, old + ".lockbit", 0x2000))
            usn_entries.append((t + timedelta(milliseconds=6), n, d, old + ".lockbit", 0x80002000))
            n += 1
    for d in note_dirs:
        t = T0 + timedelta(seconds=3)
        add(n, d, "Restore-My-Files.txt", t, note)
        usn_entries.append((t, n, d, "Restore-My-Files.txt", 0x80000100))
        n += 1
    add(n, 28, "untouched.pdf", BASE, b"%PDF-1.4" * 10)
    n += 1
    # deleted file and a timestomped dll
    add(n, 30, "loader.dll", T0 - timedelta(days=400), b"MZ" * 300, in_use=True)
    recs[n] = recs[n][:]  # SI older than FN below
    recs[n] = record(n, [si(T0 - timedelta(days=400)), fn(30, "loader.dll", T0 - timedelta(minutes=30), 600), attr_res(0x80, b"MZ" * 200)])
    n += 1
    usn_entries.append((T0 + timedelta(minutes=12), 44, 30, "x7kq9zp.exe", 0x80000200))
    # USN journal ($J, sparse at start)
    jbuf = bytearray()
    for i, (t, rec, parent, name, reason) in enumerate(usn_entries):
        nb = name.encode("utf-16-le")
        ln = (60 + len(nb) + 7) & ~7
        r = struct.pack("<IHHQQqQIIII", ln, 2, 0, rec | (1 << 48), parent | (1 << 48), 0x100000 + i * 128, ftv(t), reason, 0, 0, 0x20) + struct.pack("<HH", len(nb), 60) + nb
        jbuf += r + b"\0" * (ln - len(r))
    jbuf += b"\0" * ((-len(jbuf)) % CL)
    lcn, ncl = v.put(bytes(jbuf))
    jattr = attr_nonres(0x80, [(None, 100), (lcn, ncl)], (100 + ncl) * CL, "$J")
    attrs = [si(t_old), fn(11, "$UsnJrnl", t_old), jattr]
    recs[n] = record(n, attrs)
    n += 1
    assert n < NREC, n
    # write MFT
    mft = bytearray(NREC * REC)
    for i, r in recs.items():
        mft[i * REC:(i + 1) * REC] = r
    v.img[MFT_LCN * CL:MFT_LCN * CL + len(mft)] = mft
    bs = bytearray(512)
    bs[0:3] = b"\xeb\x52\x90"
    bs[3:11] = b"NTFS    "
    struct.pack_into("<HB", bs, 11, 512, 8)
    struct.pack_into("<QQQ", bs, 40, len(v.img) // 512, MFT_LCN, 2)
    struct.pack_into("<b", bs, 64, -10)
    struct.pack_into("<b", bs, 68, 1)
    struct.pack_into("<Q", bs, 72, 0xABCDEF0123456789)
    bs[510:512] = b"\x55\xaa"
    v.img[0:512] = bs
    with open(out, "wb") as f:
        f.write(v.img)
    print("wrote", out, len(v.img), "bytes, records", n)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "fixture.raw")
