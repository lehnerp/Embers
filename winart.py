"""
Parsers for Windows execution / user-activity artifacts. Standard library only.

prefetch (Win XP..11, incl. MAM/Xpress-Huffman compression), LNK shortcuts, Recycle Bin $I,
ShimCache (AppCompatCache), scheduled-task XML, and registry-derived artifacts
(Amcache, BAM, UserAssist, RunMRU, services, Run keys, ProfileList, SAM accounts, host facts).
"""
import codecs
import re
import struct
import xml.etree.ElementTree as ET

from util import u16, u32, u64, i32, ft, ft_bytes, utf16z, asciiz, unix

# ---------------------------------------------------------------- Xpress ---
def _xpress_huffman(data, out_size):
    out = bytearray()
    pos = 0
    n = len(data)
    while len(out) < out_size and pos + 256 <= n:
        lengths = []
        for i in range(256):
            v = data[pos + i]
            lengths.append(v & 0xF)
            lengths.append(v >> 4)
        pos += 256
        table = [0] * 32768
        tlen = [0] * 32768
        cur = 0
        for bl in range(1, 16):
            cnt = 1 << (15 - bl)
            for sym in range(512):
                if lengths[sym] == bl:
                    if cur + cnt > 32768:
                        raise ValueError("corrupt Huffman table")
                    for j in range(cur, cur + cnt):
                        table[j] = sym
                        tlen[j] = bl
                    cur += cnt

        def r16(p):
            return data[p] | (data[p + 1] << 8) if p + 1 < n else 0

        nb = (r16(pos) << 16) | r16(pos + 2)
        pos += 4
        extra = 16
        block_end = min(len(out) + 65536, out_size)
        while len(out) < block_end:
            idx = nb >> 17
            sym, bl = table[idx], tlen[idx]
            if bl == 0:
                raise ValueError("bad Huffman symbol")
            nb = (nb << bl) & 0xFFFFFFFF
            extra -= bl
            if extra < 0:
                nb |= r16(pos) << (-extra)
                extra += 16
                pos += 2
            if sym < 256:
                out.append(sym)
                continue
            sym -= 256
            mlen, obits = sym & 15, sym >> 4
            if mlen == 15:
                mlen = data[pos]
                pos += 1
                if mlen == 255:
                    mlen = r16(pos)
                    pos += 2
                    if mlen < 15:
                        raise ValueError("corrupt match length")
                    mlen -= 15
                mlen += 15
            mlen += 3
            moff = ((nb >> (32 - obits)) if obits else 0) + (1 << obits)
            nb = (nb << obits) & 0xFFFFFFFF
            extra -= obits
            if extra < 0:
                nb |= r16(pos) << (-extra)
                extra += 16
                pos += 2
            if moff > len(out):
                raise ValueError("bad match offset")
            for _ in range(mlen):
                out.append(out[-moff])
    return bytes(out[:out_size])


def _win_decompress(data, out_size):
    import ctypes
    ntdll = ctypes.windll.ntdll
    ws1, ws2 = ctypes.c_ulong(), ctypes.c_ulong()
    if ntdll.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(ws1), ctypes.byref(ws2)):
        raise OSError("RtlGetCompressionWorkSpaceSize failed")
    ws = ctypes.create_string_buffer(ws1.value)
    out = ctypes.create_string_buffer(out_size)
    final = ctypes.c_ulong()
    st = ntdll.RtlDecompressBufferEx(4, out, out_size, ctypes.c_char_p(data), len(data), ctypes.byref(final), ws)
    if st:
        raise OSError("RtlDecompressBufferEx 0x%08X" % (st & 0xFFFFFFFF))
    return out.raw[:final.value]


def decompress_mam(raw):
    if raw[:3] != b"MAM":
        return raw
    size = u32(raw, 4)
    body = raw[12:] if raw[3] & 0x80 else raw[8:]
    try:
        return _win_decompress(body, size)
    except Exception:
        return _xpress_huffman(body, size)


# -------------------------------------------------------------- prefetch ---
def parse_prefetch(raw):
    d = decompress_mam(raw)
    if d[4:8] != b"SCCA":
        raise ValueError("not a prefetch file")
    ver = u32(d, 0)
    exe = utf16z(d, 16, 60)
    pf_hash = "%08X" % u32(d, 76)
    fn_off, fn_size = u32(d, 100), u32(d, 104)
    vol_off, vol_cnt = u32(d, 108), u32(d, 112)
    runs = []
    if ver == 17:
        runs, count = [ft(u64(d, 0x78))], u32(d, 0x90)
    elif ver == 23:
        runs, count = [ft(u64(d, 0x80))], u32(d, 0x98)
    else:
        runs = [ft(u64(d, 0x80 + 8 * i)) for i in range(8)]
        metrics = u32(d, 84)
        count = u32(d, 0xD0) if metrics >= 0x130 else u32(d, 0xC8)
        if count == 0 or count > 10_000_000:
            count = u32(d, 0xC8) or u32(d, 0xD0)
    files = [s for s in d[fn_off:fn_off + fn_size].decode("utf-16-le", "replace").split("\0") if s]
    vols = []
    esz = {17: 40, 23: 104, 26: 104}.get(ver, 96)
    for i in range(min(vol_cnt, 32)):
        e = vol_off + i * esz
        if e + 20 > len(d):
            break
        po, pl = u32(d, e), u32(d, e + 4)
        vols.append({"device": d[vol_off + po:vol_off + po + 2 * pl].decode("utf-16-le", "replace"),
                     "created": ft(u64(d, e + 8)), "serial": "%08X" % u32(d, e + 16)})
    exe_path = ""
    for f in files:
        if f.upper().endswith("\\" + exe.upper()):
            exe_path = f
            break
    return {"version": ver, "exe": exe, "hash": pf_hash, "count": count,
            "runs": [r for r in runs if r], "files": files, "volumes": vols, "path": exe_path}


def device_to_path(p):
    """\\VOLUME{...}\\WINDOWS\\X or \\Device\\HarddiskVolume3\\X -> \\Windows\\X (volume prefix dropped)."""
    m = re.match(r"^\\(?:VOLUME\{[^}]*\}|Device\\HarddiskVolume\d+)(\\.*)$", p, re.I)
    return m.group(1) if m else p


# ------------------------------------------------------------------- LNK ---
def parse_lnk(d):
    if len(d) < 76 or u32(d, 0) != 0x4C:
        raise ValueError("not a shortcut")
    flags = u32(d, 20)
    r = {"target_created": ft(u64(d, 28)), "target_accessed": ft(u64(d, 36)), "target_modified": ft(u64(d, 44)),
         "target_size": u32(d, 52), "target": "", "args": "", "workdir": "", "name": "", "relpath": "",
         "volume_serial": "", "drive_type": None, "network": ""}
    p = 76
    if flags & 0x1:
        p += 2 + u16(d, p)
    if flags & 0x2 and p + 28 <= len(d):
        li = p
        size, hsize, lflags = u32(d, li), u32(d, li + 4), u32(d, li + 8)
        vol_off, base_off, net_off, suf_off = u32(d, li + 12), u32(d, li + 16), u32(d, li + 20), u32(d, li + 24)
        if lflags & 1:
            if vol_off and li + vol_off + 16 <= len(d):
                r["drive_type"] = u32(d, li + vol_off + 4)
                r["volume_serial"] = "%08X" % u32(d, li + vol_off + 8)
            if hsize >= 0x24 and u32(d, li + 28):
                r["target"] = utf16z(d, li + u32(d, li + 28))
            elif base_off:
                r["target"] = asciiz(d, li + base_off)
        if lflags & 2 and net_off:
            c = li + net_off
            if c + 12 <= len(d):
                r["network"] = asciiz(d, c + u32(d, c + 8))
                suffix = asciiz(d, li + suf_off) if suf_off else ""
                if not r["target"]:
                    r["target"] = r["network"] + ("\\" + suffix if suffix else "")
        p += size
    uni = flags & 0x80
    for bit, key in ((0x4, "name"), (0x8, "relpath"), (0x10, "workdir"), (0x20, "args"), (0x40, "icon")):
        if flags & bit and p + 2 <= len(d):
            cnt = u16(d, p)
            p += 2
            if uni:
                s = d[p:p + 2 * cnt].decode("utf-16-le", "replace")
                p += 2 * cnt
            else:
                s = d[p:p + cnt].decode("latin-1")
                p += cnt
            if key != "icon":
                r[key] = s
    if not r["target"] and r["relpath"]:
        r["target"] = r["relpath"]
    return r


# ------------------------------------------------------------- recycle $I ---
def parse_recycle_i(d):
    ver = u64(d, 0)
    size, deleted = u64(d, 8), ft(u64(d, 16))
    if ver == 2:
        path = d[28:28 + 2 * u32(d, 24)].decode("utf-16-le", "replace").rstrip("\0")
    else:
        path = utf16z(d, 24, 520)
    return {"version": ver, "size": size, "deleted": deleted, "path": path}


# --------------------------------------------------------------- ShimCache ---
def parse_shimcache(d):
    out = []
    if len(d) < 16:
        return out
    hdr = u32(d, 0)
    if hdr in (0x30, 0x34):
        p = hdr
        pos = 0
        while p + 12 <= len(d) and d[p:p + 4] == b"10ts":
            esize = u32(d, p + 8)
            q = p + 12
            plen = u16(d, q)
            path = d[q + 2:q + 2 + plen].decode("utf-16-le", "replace")
            q += 2 + plen
            mtime = ft(u64(d, q)) if q + 8 <= len(d) else None
            out.append({"pos": pos, "path": path, "modified": mtime})
            pos += 1
            p += 12 + esize
    elif hdr == 0x80 and d[0x80:0x84] in (b"00ts", b"10ts"):
        p = 0x80
        pos = 0
        while p + 12 <= len(d) and d[p:p + 4] in (b"00ts", b"10ts"):
            esize = u32(d, p + 8)
            q = p + 12
            plen = u16(d, q)
            path = d[q + 2:q + 2 + plen].decode("utf-16-le", "replace")
            q += 2 + plen + 8
            mtime = ft(u64(d, q)) if q + 8 <= len(d) else None
            out.append({"pos": pos, "path": path, "modified": mtime})
            pos += 1
            p += 12 + esize
    elif hdr == 0xBADC0FEE:                       # Windows 7 / 2008 R2 x64
        cnt = u32(d, 4)
        for i in range(min(cnt, 4096)):
            e = 128 + 48 * i
            if e + 48 > len(d):
                break
            ln, off = u16(d, e), u64(d, e + 8)
            out.append({"pos": i, "path": d[off:off + ln].decode("utf-16-le", "replace"), "modified": ft(u64(d, e + 16))})
    return out


# ---------------------------------------------------------- scheduled tasks ---
def parse_task_xml(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("utf-16-le", "replace")
    text = re.sub(r"^<\?xml[^>]*\?>", "", text.strip())
    root = ET.fromstring(text)

    def find(el, path):
        for x in el.iter():
            if x.tag.split("}")[-1] == path:
                return x
        return None

    def ftxt(path):
        x = find(root, path)
        return (x.text or "").strip() if x is not None and x.text else ""

    actions = []
    acts = find(root, "Actions")
    if acts is not None:
        for a in acts:
            tag = a.tag.split("}")[-1]
            if tag == "Exec":
                cmd = args = ""
                for c in a:
                    t = c.tag.split("}")[-1]
                    if t == "Command":
                        cmd = (c.text or "").strip()
                    elif t == "Arguments":
                        args = (c.text or "").strip()
                actions.append((cmd + " " + args).strip())
            elif tag == "ComHandler":
                cls = find(a, "ClassId")
                actions.append("COM " + ((cls.text or "") if cls is not None else ""))
            else:
                actions.append(tag)
    triggers = []
    tr = find(root, "Triggers")
    if tr is not None:
        triggers = [t.tag.split("}")[-1] for t in tr]
    return {"uri": ftxt("URI"), "author": ftxt("Author"), "date": ftxt("Date"), "description": ftxt("Description"),
            "actions": actions, "triggers": triggers, "user": ftxt("UserId") or ftxt("GroupId"),
            "runlevel": ftxt("RunLevel"), "hidden": ftxt("Hidden").lower() == "true", "enabled": ftxt("Enabled").lower() != "false"}


# ------------------------------------------------------ registry artifacts ---
def _ver(software, name, default=""):
    return software.value("Microsoft\\Windows NT\\CurrentVersion", name, default) if software else default


def host_info(system, software):
    info = {}
    if system:
        cs = system.control_set()
        info["control_set"] = cs
        info["computer_name"] = system.value(cs + "\\Control\\ComputerName\\ComputerName", "ComputerName", "")
        tz = cs + "\\Control\\TimeZoneInformation"
        info["timezone"] = system.value(tz, "TimeZoneKeyName", "") or system.value(tz, "StandardName", "")
        bias = system.value(tz, "ActiveTimeBias")
        if isinstance(bias, int):
            bias = struct.unpack("<i", struct.pack("<I", bias & 0xFFFFFFFF))[0]
            info["utc_offset_min"] = -bias
        sd = system.value(cs + "\\Control\\Windows", "ShutdownTime")
        if isinstance(sd, bytes):
            info["last_shutdown"] = ft_bytes(sd)
        info["domain"] = system.value(cs + "\\Services\\Tcpip\\Parameters", "Domain", "") or \
            system.value(cs + "\\Services\\Tcpip\\Parameters", "NV Domain", "")
        ips = []
        ifs = system.get(cs + "\\Services\\Tcpip\\Parameters\\Interfaces")
        for k in system.subkeys(ifs):
            for vn in ("DhcpIPAddress", "IPAddress"):
                v = system.value(k, vn)
                for ip in (v if isinstance(v, list) else [v]):
                    if isinstance(ip, str) and ip and ip != "0.0.0.0" and ip not in ips:
                        ips.append(ip)
        info["ips"] = ips
    if software:
        info["product"] = _ver(software, "ProductName")
        info["display_version"] = _ver(software, "DisplayVersion") or _ver(software, "ReleaseId")
        info["build"] = str(_ver(software, "CurrentBuild") or "")
        ubr = _ver(software, "UBR", None)
        if isinstance(ubr, int):
            info["build"] += ".%d" % ubr
        try:
            if int(info["build"].split(".")[0]) >= 22000 and "Windows 10" in (info["product"] or ""):
                info["product"] = info["product"].replace("Windows 10", "Windows 11")
        except ValueError:
            pass
        idate = _ver(software, "InstallDate", None)
        if isinstance(idate, int):
            info["install_date"] = unix(idate)
        info["owner"] = _ver(software, "RegisteredOwner")
    return info


def profiles(software):
    out = {}
    if not software:
        return out
    k = software.get("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    for s in software.subkeys(k):
        path = software.value(s, "ProfileImagePath", "") or ""
        out[s.name] = {"sid": s.name, "path": path, "user": path.rstrip("\\").split("\\")[-1] if path else "",
                       "key_written": s.lastwrite}
    return out


def sam_accounts(sam):
    out = []
    if not sam:
        return out
    names = sam.get("SAM\\Domains\\Account\\Users\\Names")
    rid_names = {}
    for k in sam.subkeys(names):
        for v in sam.values(k):
            if v.name == "":
                rid_names[v.type] = (k.name, k.lastwrite)
    users = sam.get("SAM\\Domains\\Account\\Users")
    for k in sam.subkeys(users):
        if k.name.lower() == "names":
            continue
        try:
            rid = int(k.name, 16)
        except ValueError:
            continue
        f = sam.value(k, "F")
        name, created = rid_names.get(rid, ("RID %d" % rid, None))
        acc = {"rid": rid, "name": name, "created": created}
        if isinstance(f, bytes) and len(f) >= 0x44:
            acc.update({"last_logon": ft(u64(f, 8)), "pwd_set": ft(u64(f, 24)), "last_fail": ft(u64(f, 40)),
                        "disabled": bool(u16(f, 0x38) & 1), "logons": u16(f, 0x42), "fails": u16(f, 0x40)})
        out.append(acc)
    return out


RUN_KEYS = [
    "Microsoft\\Windows\\CurrentVersion\\Run", "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
]


def run_keys(hive, label, prefix=""):
    out = []
    if not hive:
        return out
    for rk in RUN_KEYS:
        k = hive.get(prefix + rk)
        for v in hive.values(k):
            out.append({"kind": "Run key", "location": "%s\\%s%s" % (label, prefix, rk), "name": v.name or "(default)",
                        "value": v.text(1000), "ts": k.lastwrite})
    return out


SERVICE_START = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}


def services(system):
    out = []
    if not system:
        return out
    cs = system.control_set()
    for k in system.subkeys(system.get(cs + "\\Services")):
        img = system.value(k, "ImagePath")
        if img is None:
            continue
        dll = system.value(k.name and system.get(cs + "\\Services\\" + k.name + "\\Parameters") or None, "ServiceDll", "")
        start = system.value(k, "Start")
        out.append({"name": k.name, "display": system.value(k, "DisplayName", "") or "", "image": str(img),
                    "dll": dll or "", "start": SERVICE_START.get(start, start), "type": system.value(k, "Type"),
                    "account": system.value(k, "ObjectName", "") or "", "ts": k.lastwrite})
    return out


def task_cache(software):
    """TaskCache\\Tree entries; a task without SD (security descriptor) is hidden from schtasks / Task Scheduler."""
    out = []
    if not software:
        return out
    base = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"
    tasks = {}
    for k in software.subkeys(software.get(base + "\\Tasks")):
        tasks[k.name.upper()] = k
    for path, k in software.walk(base + "\\Tree"):
        idv = software.value(k, "Id")
        if not idv:
            continue
        names = [v.name for v in software.values(k)]
        t = tasks.get(str(idv).upper())
        actions = ""
        if t:
            a = software.value(t, "Actions")
            if isinstance(a, bytes):
                actions = " ".join(re.findall(r"[\x20-\x7e]{3,}", a.decode("utf-16-le", "ignore")))
        out.append({"path": path[len(base) + 6:], "id": idv, "hidden": "SD" not in names, "ts": k.lastwrite,
                    "actions": actions})
    return out


def amcache(hive):
    out = []
    if not hive:
        return out
    for k in hive.subkeys(hive.get("Root\\InventoryApplicationFile")):
        vals = {v.name: v.data for v in hive.values(k)}
        fid = vals.get("FileId") or ""
        out.append({"path": vals.get("LowerCaseLongPath") or vals.get("Name") or k.name,
                    "sha1": fid[4:] if isinstance(fid, str) and len(fid) == 44 else (fid if isinstance(fid, str) else ""),
                    "name": vals.get("Name") or "", "publisher": vals.get("Publisher") or "",
                    "version": vals.get("Version") or "", "linkdate": vals.get("LinkDate") or "",
                    "size": vals.get("Size"), "os": vals.get("IsOsComponent"), "ts": k.lastwrite})
    if not out:                                     # Windows 7/8 layout
        for vol in hive.subkeys(hive.get("Root\\File")):
            for k in hive.subkeys(vol):
                vals = {v.name: v.data for v in hive.values(k)}
                sha = vals.get("101") or ""
                out.append({"path": vals.get("15") or k.name, "sha1": sha[4:] if isinstance(sha, str) else "",
                            "name": "", "publisher": vals.get("1") or "", "version": "", "linkdate": "",
                            "size": vals.get("6"), "os": None, "ts": k.lastwrite})
    return out


def bam(system):
    out = []
    if not system:
        return out
    cs = system.control_set()
    for base in (cs + "\\Services\\bam\\State\\UserSettings", cs + "\\Services\\bam\\UserSettings"):
        for sk in system.subkeys(system.get(base)):
            for v in system.values(sk):
                if v.type == 3 and v.raw and len(v.raw) >= 8 and v.name not in ("Version", "SequenceNumber"):
                    out.append({"sid": sk.name, "path": device_to_path(v.name), "ts": ft(u64(v.raw, 0))})
    return out


KNOWN_FOLDERS = {
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%", "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%System32%", "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%Windows%",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "%SysWOW64%", "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%CommonPrograms%",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%Programs%", "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%UserPinned%",
}


def userassist(ntuser):
    out = []
    if not ntuser:
        return out
    base = ntuser.get("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    for g in ntuser.subkeys(base):
        cnt = ntuser.get("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\%s\\Count" % g.name)
        for v in ntuser.values(cnt):
            name = codecs.decode(v.name, "rot13")
            for guid, rep in KNOWN_FOLDERS.items():
                if name.upper().startswith(guid):
                    name = rep + name[len(guid):]
            raw = v.raw or b""
            if len(raw) >= 68:
                out.append({"path": name, "count": u32(raw, 4), "focus_ms": u32(raw, 12), "ts": ft(u64(raw, 60))})
            elif len(raw) == 16:
                out.append({"path": name, "count": max(0, u32(raw, 4) - 5), "focus_ms": None, "ts": ft(u64(raw, 8))})
    return [x for x in out if x["ts"] or x["count"]]


def runmru(ntuser):
    k = ntuser.get("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU") if ntuser else None
    if not k:
        return []
    vals = {v.name: v.data for v in ntuser.values(k)}
    order = vals.get("MRUList", "") or ""
    out = []
    for i, ch in enumerate(order):
        cmd = vals.get(ch)
        if isinstance(cmd, str):
            out.append({"cmd": cmd.rstrip("\\1").rstrip("\\"), "rank": i, "ts": k.lastwrite if i == 0 else None})
    return out


def rdp_outbound(ntuser):
    out = []
    if not ntuser:
        return out
    for k in ntuser.subkeys(ntuser.get("Software\\Microsoft\\Terminal Server Client\\Servers")):
        out.append({"host": k.name, "user": ntuser.value(k, "UsernameHint", "") or "", "ts": k.lastwrite})
    return out


def typed_paths(ntuser):
    k = ntuser.get("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths") if ntuser else None
    return [{"path": v.data, "ts": k.lastwrite} for v in ntuser.values(k) if isinstance(v.data, str)] if k else []
