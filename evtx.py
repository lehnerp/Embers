"""
Windows .evtx reader with BinXML decoding (templates and substitutions), standard library only.

Each record is flattened to:
  {"rec": EventRecordID, "ts": TimeCreated (UTC), "eid": EventID, "provider", "channel", "computer",
   "level", "user": Security UserID, "pid", "data": {EventData/UserData field: value}}
"""
import struct

from util import u16, u32, u64, ft, systemtime, sid_str, guid_str

CHUNK = 65536


class _Sub:
    __slots__ = ("idx", "opt")

    def __init__(self, idx, opt):
        self.idx, self.opt = idx, opt


class _El:
    __slots__ = ("name", "attrs", "kids")

    def __init__(self, name):
        self.name, self.attrs, self.kids = name, [], []


class BinXml:
    def __init__(self, chunk):
        self.b = chunk
        self.templates = {}

    def name_at(self, off):
        b = self.b
        n = u16(b, off + 6)
        return b[off + 8:off + 8 + 2 * n].decode("utf-16-le", "replace"), 8 + 2 * n + 2

    # ---------------------------------------------------- token parsing ---
    def parse_fragment(self, p, end=None):
        """Parse a document fragment; returns (list_of_nodes, pos)."""
        b = self.b
        nodes = []
        end = end or len(b)
        while p < end:
            t = b[p]
            if t == 0x00:
                p += 1
                break
            if t == 0x0F:
                p += 4
            elif t == 0x0C:
                el, p = self.parse_template_instance(p)
                nodes.append(el)
            elif t & 0xBF == 0x01:
                el, p = self.parse_element(p)
                nodes.append(el)
            else:
                break
        return nodes, p

    def parse_element(self, p):
        b = self.b
        tok = b[p]
        noff = u32(b, p + 7)
        q = p + 11
        if tok & 0x40:
            q += 4
        name, nlen = self.name_at(noff)
        if noff > p:                            # name stored inline, right inside this tag
            q += nlen
        el = _El(name)
        if tok & 0x40:
            while b[q] & 0xBF == 0x06:
                more = b[q] & 0x40
                aoff = u32(b, q + 1)
                start = q
                q += 5
                aname, alen = self.name_at(aoff)
                if aoff > start:
                    q += alen
                parts, q = self.parse_content(q, attr=True)
                el.attrs.append((aname, parts))
                if not more:
                    break
        t = b[q]
        if t == 0x03:
            return el, q + 1
        if t == 0x02:
            q += 1
            parts, q = self.parse_content(q)
            el.kids = parts
            if q < len(b) and b[q] == 0x04:
                q += 1
            return el, q
        return el, q

    def parse_content(self, q, attr=False):
        b = self.b
        out = []
        while q < len(b):
            t = b[q]
            tt = t & 0xBF
            if tt == 0x05:                      # value text
                vt = b[q + 1]
                if vt == 0x01:
                    n = u16(b, q + 2)
                    out.append(b[q + 4:q + 4 + 2 * n].decode("utf-16-le", "replace"))
                    q += 4 + 2 * n
                else:
                    q += 2
            elif t in (0x0D, 0x0E):              # substitution
                out.append(_Sub(u16(b, q + 1), t == 0x0E))
                q += 4
            elif tt == 0x07:                    # CDATA
                n = u16(b, q + 1)
                out.append(b[q + 3:q + 3 + 2 * n].decode("utf-16-le", "replace"))
                q += 3 + 2 * n
            elif tt == 0x08:                    # char ref
                out.append(chr(u16(b, q + 1)))
                q += 3
            elif tt == 0x09:                    # entity ref
                eoff = u32(b, q + 1)
                nm, ln = self.name_at(eoff)
                if eoff > q:
                    q += ln
                q += 5
                out.append({"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}.get(nm, "&%s;" % nm))
            elif attr:
                break
            elif tt == 0x01:
                el, q = self.parse_element(q)
                out.append(el)
            elif t == 0x0C:
                el, q = self.parse_template_instance(q)
                out.append(el)
            elif t == 0x0A:                     # PI target
                q += 5
            elif t == 0x0B:
                n = u16(b, q + 1)
                q += 3 + 2 * n
            elif t == 0x0F:
                q += 4
            else:                               # 0x04 end element, 0x00 EOF, or attribute
                break
        return out, q

    def parse_template_instance(self, p):
        b = self.b
        toff = u32(b, p + 6)
        q = p + 10
        if toff > p:                            # definition is inline
            q = toff + 24 + u32(b, toff + 20)
        tmpl = self.templates.get(toff)
        if tmpl is None:
            nodes, _ = self.parse_fragment(toff + 24, toff + 24 + u32(b, toff + 20))
            tmpl = nodes[0] if nodes else _El("?")
            self.templates[toff] = tmpl
        n = u32(b, q)
        q += 4
        decl = []
        for i in range(min(n, 4096)):
            decl.append((u16(b, q), b[q + 2]))
            q += 4
        vals = []
        for size, typ in decl:
            vals.append(self.value(q, size, typ))
            q += size
        return self.instantiate(tmpl, vals), q

    # ------------------------------------------------------------ values ---
    def value(self, p, size, typ):
        b = self.b
        d = b[p:p + size]
        try:
            if typ == 0x00:
                return None
            if typ == 0x01:
                return d.decode("utf-16-le", "replace").rstrip("\0")
            if typ == 0x02:
                return d.decode("latin-1").rstrip("\0")
            if typ == 0x21:
                nodes, _ = self.parse_fragment(p, p + size)
                if not nodes:
                    return None
                return nodes[0] if isinstance(nodes[0], dict) else self.instantiate(nodes[0], [])
            if typ == 0x81:
                return ", ".join(s for s in d.decode("utf-16-le", "replace").split("\0") if s)
            fmt = {0x03: "b", 0x04: "B", 0x05: "h", 0x06: "H", 0x07: "i", 0x08: "I", 0x09: "q", 0x0A: "Q",
                   0x0B: "f", 0x0C: "d", 0x0D: "I"}
            base = typ & 0x7F
            if base in fmt:
                sz = struct.calcsize(fmt[base])
                items = [struct.unpack_from("<" + fmt[base], d, i)[0] for i in range(0, len(d) - sz + 1, sz)]
                if base == 0x0D:
                    items = ["true" if x else "false" for x in items]
                return ", ".join(str(x) for x in items) if typ & 0x80 else (items[0] if items else None)
            if base == 0x0E:
                return d.hex()
            if base == 0x0F:
                return ", ".join(guid_str(d[i:i + 16]) for i in range(0, len(d), 16))
            if base == 0x10 or base == 0x15:
                return "0x%x" % int.from_bytes(d[:8], "little") if size >= 8 else "0x%x" % int.from_bytes(d, "little")
            if base == 0x14:
                return ", ".join("0x%x" % u32(d, i) for i in range(0, len(d) - 3, 4))
            if base == 0x11:
                return ft(u64(d, 0)) if len(d) >= 8 else None
            if base == 0x12:
                return systemtime(d, 0)
            if base == 0x13:
                return sid_str(d)
            return d.hex()
        except Exception:
            return d.hex()

    def instantiate(self, node, vals):
        """Return a plain dict tree: {'n': name, 'a': {..}, 'k': [...], 't': text}."""
        def resolve(parts):
            text, kids = [], []
            for x in parts:
                if isinstance(x, str):
                    text.append(x)
                elif isinstance(x, _Sub):
                    v = vals[x.idx] if x.idx < len(vals) else None
                    if isinstance(v, dict):
                        kids.append(v)
                    elif v is not None:
                        text.append(str(v))
                elif isinstance(x, _El):
                    kids.append(build(x))
                elif isinstance(x, dict):
                    kids.append(x)
            return "".join(text), kids

        def build(el):
            attrs = {}
            for an, parts in el.attrs:
                t, _ = resolve(parts)
                attrs[an] = t
            t, kids = resolve(el.kids)
            return {"n": el.name, "a": attrs, "k": kids, "t": t}

        if isinstance(node, dict):
            return node
        return build(node)


def _child(node, name):
    for k in node.get("k", []):
        if k["n"] == name:
            return k
    return None


def _flatten(node, prefix, out, depth=0):
    if depth > 6:
        return
    kids = node.get("k", [])
    if not kids:
        key = prefix or node["n"]
        if key in out:
            i = 2
            while "%s_%d" % (key, i) in out:
                i += 1
            key = "%s_%d" % (key, i)
        out[key] = node.get("t", "")
        return
    for k in kids:
        _flatten(k, k["n"] if not prefix else prefix + "." + k["n"], out, depth + 1)


def flatten_event(root):
    ev = {"eid": None, "provider": "", "channel": "", "computer": "", "level": None, "user": "",
          "pid": None, "ts": None, "rec": None, "data": {}}
    if not root:
        return ev
    sysn = _child(root, "System")
    if sysn:
        for k in sysn["k"]:
            n = k["n"]
            if n == "Provider":
                ev["provider"] = k["a"].get("Name") or k["a"].get("EventSourceName", "")
            elif n == "EventID":
                try:
                    ev["eid"] = int(k["t"])
                except ValueError:
                    ev["eid"] = None
            elif n == "TimeCreated":
                ev["ts"] = k["a"].get("SystemTime")
            elif n == "EventRecordID":
                try:
                    ev["rec"] = int(k["t"])
                except ValueError:
                    pass
            elif n == "Channel":
                ev["channel"] = k["t"]
            elif n == "Computer":
                ev["computer"] = k["t"]
            elif n == "Level":
                try:
                    ev["level"] = int(k["t"])
                except ValueError:
                    pass
            elif n == "Security":
                ev["user"] = k["a"].get("UserID", "")
            elif n == "Execution":
                try:
                    ev["pid"] = int(k["a"].get("ProcessID") or 0)
                except ValueError:
                    pass
    data = {}
    ed = _child(root, "EventData")
    if ed:
        i = 0
        for k in ed["k"]:
            nm = k["a"].get("Name")
            if k["n"] == "Data":
                if not nm:
                    i += 1
                    nm = "Data%d" % i
                data[nm] = k["t"] if not k["k"] else _subtext(k)
            else:
                data[k["n"]] = k["t"] if not k["k"] else _subtext(k)
    ud = _child(root, "UserData")
    if ud:
        for top in ud["k"]:
            _flatten(top, "", data)
    ev["data"] = data
    return ev


def _subtext(node):
    out = {}
    _flatten(node, "", out)
    return "; ".join("%s=%s" % (k, v) for k, v in out.items())


def iter_events(path_or_bytes, max_bytes=None):
    """Yield flattened events. Accepts a path or bytes. Errors inside a record skip that record."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = path_or_bytes
    else:
        with open(path_or_bytes, "rb") as f:
            data = f.read(max_bytes) if max_bytes else f.read()
    if data[:8] != b"ElfFile\0":
        return
    hdr_size = u16(data, 32) or 4096
    off = 4096 if hdr_size <= 4096 else hdr_size
    while off + 512 <= len(data):
        chunk = data[off:off + CHUNK]
        off += CHUNK
        if chunk[:8] != b"ElfChnk\0":
            continue
        bx = BinXml(chunk)
        free = u32(chunk, 48) or CHUNK
        p = 0x200
        while p + 24 < min(free, len(chunk)):
            if chunk[p:p + 4] != b"\x2a\x2a\x00\x00":
                break
            size = u32(chunk, p + 4)
            if size < 28 or p + size > len(chunk):
                break
            rec_id, rec_ts = u64(chunk, p + 8), u64(chunk, p + 16)
            try:
                nodes, _ = bx.parse_fragment(p + 24, p + size - 4)
                ev = flatten_event(nodes[0] if nodes else None)
            except Exception:
                ev = flatten_event(None)
                ev["broken"] = True
            if ev["rec"] is None:
                ev["rec"] = rec_id
            if not ev["ts"]:
                ev["ts"] = ft(rec_ts)
            yield ev
            p += size


def file_info(data):
    """Header facts: dirty flag, record counts, oldest/next record id."""
    if data[:8] != b"ElfFile\0":
        return {}
    return {"first_chunk": u64(data, 8), "last_chunk": u64(data, 16), "next_record": u64(data, 24),
            "chunks": u16(data, 42), "dirty": bool(u32(data, 120) & 1), "full": bool(u32(data, 120) & 2)}
