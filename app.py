"""
Embers: Windows ransomware investigation dashboard (sister of Crumbs).

    python app.py \\\\.\\F:                         # mounted Macrium image volume (run as Administrator)
    python app.py disk.raw --partition 2          # raw / dd / fixed-VHD disk image
    python app.py F:\\ --mft F:\\$MFT.bin            # folder mode (exported $MFT / $J optional)
    python app.py --no-index --db case.db         # just open an existing case
"""
import argparse
import csv
import io
import json
import os
import re
import sqlite3
import threading
import time

from flask import Flask, Response, abort, g, jsonify, request, send_from_directory

import indexer as ix
import ntfs
import regf
from util import entropy, parse_ts, fmt_dt, shift

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
app = Flask(__name__, static_folder=None)
CFG = {"db": "embers.db"}
INDEXER = None
_HIVES = {}
_SRC = {"obj": None, "lock": threading.Lock()}


# ------------------------------------------------------------------ helpers ---
def db():
    if "db" not in g:
        g.db = ix.connect(CFG["db"])
    return g.db


@app.teardown_appcontext
def _close(_e):
    c = g.pop("db", None)
    if c is not None:
        c.close()


def rows(cur):
    return [dict(r) for r in cur.fetchall()]


def arg(name, default=""):
    return (request.args.get(name) or default).strip()


def arg_int(name, default, lo=0, hi=10_000_000):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def tparam(name):
    v = arg(name)
    if not v:
        return None
    v = v.replace("T", " ")
    if len(v) == 16:
        v += ":00"
    return v


def like(s):
    return "%" + s.replace("^", "^^").replace("%", "^%").replace("_", "^_") + "%"


def add_time(where, params, col):
    a, b = tparam("from"), tparam("to")
    if a:
        where.append("%s >= ?" % col)
        params.append(a)
    if b:
        where.append("%s <= ?" % col)
        params.append(b + ".999" if len(b) == 19 else b)


def meta(k, default=None):
    try:
        return ix.get_meta(db(), k, default)
    except sqlite3.Error:
        return default


def source():
    """Lazily (re)open the evidence for on-demand reads (hex view, notes)."""
    with _SRC["lock"]:
        if _SRC["obj"] is None:
            o = meta("options", {}) or {}
            if not o.get("spec"):
                return None
            try:
                s = ix.open_source(o["spec"], o.get("partition"), o.get("mft"), o.get("usn"))
                s.con = ix.connect(CFG["db"])
                _SRC["obj"] = s
            except Exception:
                return None
        return _SRC["obj"]


def bucket_for(a, b):
    da, dbb = parse_ts(a), parse_ts(b)
    if not da or not dbb:
        return "hour", 13
    hours = (dbb - da).total_seconds() / 3600
    if hours <= 6:
        return "minute", 16
    if hours <= 24 * 10:
        return "hour", 13
    return "day", 10


# --------------------------------------------------------------------- pages ---
@app.route("/")
def index_page():
    return send_from_directory(STATIC, "index.html")


@app.route("/static/<path:rel>")
def static_asset(rel):
    return send_from_directory(STATIC, rel)


# -------------------------------------------------------------------- status ---
@app.route("/api/status")
def api_status():
    st = dict(INDEXER.status)
    st["stages_all"] = ix.Indexer.STAGES
    st["source"] = meta("source", {})
    st["indexed_at"] = meta("indexed_at")
    st["errors_saved"] = meta("index_errors", [])
    st["options"] = meta("options", {})
    return jsonify(st)


@app.route("/api/partitions")
def api_partitions():
    spec = arg("source")
    if not spec:
        abort(400)
    if os.path.isdir(spec) and not spec.startswith("\\\\.\\"):
        return jsonify({"kind": "folder", "partitions": []})
    try:
        dev = ntfs.Device(spec)
        parts = ntfs.list_partitions(dev)
        dev.close()
        return jsonify({"kind": "device", "partitions": [{"index": p[0], "offset": p[1], "size": p[2], "ntfs": p[3], "name": p[4]} for p in parts]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/index", methods=["POST"])
def api_index():
    b = request.get_json(force=True) or {}
    spec = (b.get("source") or "").strip()
    if not spec:
        return jsonify({"error": "source required"}), 400
    part = b.get("partition")
    part = int(part) if part not in (None, "", "auto") else None
    with _SRC["lock"]:
        _SRC["obj"] = None
    _HIVES.clear()
    try:
        INDEXER.start(spec, part, b.get("mft") or None, b.get("usn") or None, int(b.get("reg_days") or 60), int(b.get("span_days") or 14))
    except Exception as e:
        return jsonify({"error": str(e)}), 409
    return jsonify({"ok": True})


@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    INDEXER.cancel = True
    return jsonify({"ok": True})


@app.route("/api/reanalyze", methods=["POST"])
def api_reanalyze():
    b = request.get_json(force=True) or {}
    ov = {}
    if b.get("extensions") is not None:
        ov["extensions"] = [e.strip().lstrip(".").lower() for e in b["extensions"] if e.strip()]
    if b.get("window"):
        ov["window"] = {"start": b["window"]["start"].replace("T", " "), "end": b["window"]["end"].replace("T", " "), "basis": "set by analyst"}
    if b.get("span"):
        ov["span"] = {"from": b["span"]["from"].replace("T", " "), "to": b["span"]["to"].replace("T", " ")}
    try:
        INDEXER.reanalyze(ov)
    except Exception as e:
        return jsonify({"error": str(e)}), 409
    return jsonify({"ok": True})


# ------------------------------------------------------------------ overview ---
@app.route("/api/overview")
def api_overview():
    c = db()
    count = lambda sql, *p: c.execute(sql, p).fetchone()[0]
    impact = meta("impact", {}) or {}
    fig = {
        "files": count("SELECT COUNT(*) FROM files"),
        "encrypted": count("SELECT COUNT(*) FROM files WHERE enc=1"),
        "notes": count("SELECT COUNT(*) FROM files WHERE note=1"),
        "events": count("SELECT COUNT(*) FROM events"),
        "usn": count("SELECT COUNT(*) FROM usn"),
        "exec": count("SELECT COUNT(*) FROM exec"),
        "high": count("SELECT COUNT(*) FROM findings WHERE sev='high'"),
        "medium": count("SELECT COUNT(*) FROM findings WHERE sev='medium'"),
        "persist_flagged": count("SELECT COUNT(*) FROM persist WHERE sev IN ('high','medium')"),
        "regchecks": count("SELECT COUNT(*) FROM regchecks WHERE sev IN ('high','medium')"),
        "regchanges": count("SELECT COUNT(*) FROM regchanges WHERE source='transaction log'"),
    }
    cats = rows(c.execute("SELECT cat, sev, COUNT(*) n FROM findings GROUP BY cat, sev ORDER BY n DESC"))
    return jsonify({"host": meta("host", {}), "profiles": meta("profiles", {}), "accounts": meta("accounts", []),
                    "source": meta("source", {}), "impact": {k: impact.get(k) for k in ("chosen", "window", "encrypted", "dirs", "span")},
                    "notes": [{k: n.get(k) for k in ("name", "copies", "dirs", "first", "iocs")} for n in impact.get("notes", [])],
                    "payload": impact.get("payload", [])[:5], "figures": fig, "cats": cats, "story": (meta("story", []) or [])[:150],
                    "evtx": meta("evtx", []), "hives": meta("hives", []), "usn_range": meta("usn_range"),
                    "errors": meta("index_errors", []), "indexed_at": meta("indexed_at")})


# -------------------------------------------------------------------- impact ---
@app.route("/api/impact")
def api_impact():
    c = db()
    impact = meta("impact", {}) or {}
    w = impact.get("window") or {}
    hist, unit = [], "minute"
    if w.get("start"):
        unit, n = bucket_for(shift(w["start"], minutes=-30), shift(w["end"], minutes=30))
        a, b = shift(w["start"], hours=-2), shift(w["end"], hours=2)
        enc = dict(c.execute("SELECT substr(si_e,1,?) k, COUNT(*) FROM files WHERE enc=1 AND si_e BETWEEN ? AND ? GROUP BY k", (n, a, b)).fetchall())
        chosen = impact.get("chosen") or []
        ren = {}
        if chosen:
            q = ",".join("?" * len(chosen))
            ren = dict(c.execute("SELECT substr(ts,1,?) k, COUNT(*) FROM usn WHERE (reason & 8192)<>0 AND ext IN (%s) AND ts BETWEEN ? AND ? GROUP BY k" % q,
                                 [n] + chosen + [a, b]).fetchall())
        notes = dict(c.execute("SELECT substr(si_c,1,?) k, COUNT(*) FROM files WHERE note=1 AND si_c BETWEEN ? AND ? GROUP BY k", (n, a, b)).fetchall())
        keys = sorted(set(enc) | set(ren) | set(notes))
        hist = [{"t": k, "enc": enc.get(k, 0), "usn": ren.get(k, 0), "notes": notes.get(k, 0)} for k in keys]
    dirs = rows(c.execute("""SELECT f.parent, (SELECT path FROM files d WHERE d.rec=f.parent) path, COUNT(*) n, SUM(size) bytes
                             FROM files f WHERE enc=1 GROUP BY f.parent ORDER BY n DESC LIMIT 40"""))
    tops = rows(c.execute("""SELECT CASE WHEN path LIKE '\\Users\\%' THEN '\\Users\\'||substr(substr(path,8),1,instr(substr(path,8),'\\')-1)
                             ELSE substr(path,1,instr(substr(path,2),'\\')) END top, COUNT(*) n FROM files WHERE enc=1 GROUP BY top ORDER BY n DESC LIMIT 20"""))
    types = rows(c.execute("""SELECT lower(CASE WHEN instr(orig,'.')>0 THEN replace(orig, rtrim(orig, replace(orig,'.','')), '') ELSE '' END) t,
                              COUNT(*) n, SUM(size) bytes FROM files WHERE enc=1 GROUP BY t ORDER BY n DESC LIMIT 25"""))
    left = rows(c.execute("""SELECT ext, COUNT(*) n FROM files WHERE enc=0 AND in_use=1 AND is_dir=0 AND parent IN (SELECT DISTINCT parent FROM files WHERE enc=1)
                             AND ext IN ('doc','docx','xls','xlsx','pdf','jpg','png','txt','pptx','zip','csv') GROUP BY ext ORDER BY n DESC LIMIT 12"""))
    sz = c.execute("SELECT SUM(size), MIN(si_e), MAX(si_e) FROM files WHERE enc=1").fetchone()
    return jsonify({"impact": impact, "hist": hist, "unit": unit, "dirs": dirs, "tops": tops, "types": types,
                    "untouched": left, "bytes": sz[0], "first": sz[1], "last": sz[2]})


@app.route("/api/impact/files")
def api_impact_files():
    c = db()
    where, p = ["enc=1"], []
    q = arg("q")
    if q:
        where.append("(path LIKE ? ESCAPE '^' OR orig LIKE ? ESCAPE '^')")
        p += [like(q), like(q)]
    if arg("parent"):
        where.append("parent=?")
        p.append(arg_int("parent", 0))
    if arg("type"):
        where.append("lower(orig) LIKE ?")
        p.append("%." + arg("type").lower())
    off, lim = arg_int("offset", 0), arg_int("limit", 200, 1, 2000)
    sql = "SELECT rec, path, orig, size, si_c, si_m, si_e, fn_c FROM files WHERE %s ORDER BY %s LIMIT ? OFFSET ?" % (
        " AND ".join(where), "si_e" if arg("sort", "time") == "time" else "path")
    total = c.execute("SELECT COUNT(*) FROM files WHERE " + " AND ".join(where), p).fetchone()[0]
    return jsonify({"total": total, "rows": rows(c.execute(sql, p + [lim, off]))})


@app.route("/api/impact/files.csv")
def api_impact_csv():
    c = db()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["path", "original_name", "size", "encrypted_utc(si_entry_modified)", "si_created", "si_modified", "fn_created", "mft_record"])
    for r in c.execute("SELECT path, orig, size, si_e, si_c, si_m, fn_c, rec FROM files WHERE enc=1 ORDER BY si_e"):
        w.writerow(list(r))
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=encrypted_files.csv"})


@app.route("/api/notes")
def api_notes():
    impact = meta("impact", {}) or {}
    c = db()
    out = []
    for n in impact.get("notes", []):
        n = dict(n)
        n["locations"] = [r[0] for r in c.execute("SELECT path FROM files WHERE note=1 AND lower(name)=? ORDER BY si_c LIMIT 200", (n["name"],))]
        out.append(n)
    return jsonify(out)


# ------------------------------------------------------------------ timeline ---
@app.route("/api/timeline")
def api_timeline():
    c = db()
    impact = meta("impact", {}) or {}
    span = impact.get("span") or {}
    where, p = [], []
    a, b = tparam("from") or span.get("from"), tparam("to") or span.get("to")
    if a:
        where.append("ts >= ?")
        p.append(a)
    if b:
        where.append("ts <= ?")
        p.append(b + ".999" if len(b) == 19 else b)
    srcs = [s for s in arg("src").split(",") if s]
    if srcs:
        where.append("src IN (%s)" % ",".join("?" * len(srcs)))
        p += srcs
    q = arg("q")
    if q:
        for term in q.split():
            if term.startswith("-") and len(term) > 1:
                where.append("(text NOT LIKE ? ESCAPE '^' AND kind NOT LIKE ? ESCAPE '^')")
                p += [like(term[1:]), like(term[1:])]
            else:
                where.append("(text LIKE ? ESCAPE '^' OR kind LIKE ? ESCAPE '^')")
                p += [like(term), like(term)]
    if arg("sev"):
        where.append("sev IN ('high','medium')")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    off, lim = arg_int("offset", 0), arg_int("limit", 300, 1, 2000)
    order = "DESC" if arg("order") == "desc" else "ASC"
    data = rows(c.execute("SELECT ts, src, kind, text, ref, sev FROM timeline%s ORDER BY ts %s, id LIMIT ? OFFSET ?" % (w, order), p + [lim, off]))
    out = {"rows": data, "span": span}
    if not off:
        lo, hi = c.execute("SELECT MIN(ts), MAX(ts) FROM timeline" + w, p).fetchone()
        unit, n = bucket_for(lo or a, hi or b)
        hist = rows(c.execute("SELECT substr(ts,1,?) t, src, COUNT(*) n FROM timeline%s GROUP BY t, src ORDER BY t" % w, [n] + p))
        out.update({"hist": hist, "unit": unit, "total": c.execute("SELECT COUNT(*) FROM timeline" + w, p).fetchone()[0],
                    "by_src": rows(c.execute("SELECT src, COUNT(*) n FROM timeline%s GROUP BY src" % w, p))})
    return jsonify(out)


@app.route("/api/ref")
def api_ref():
    """Detail for any row reference used across the UI."""
    c = db()
    ref = arg("ref")
    kind, _, rid = ref.partition(":")
    tables = {"ev": ("events", "id"), "usn": ("usn", "id"), "f": ("files", "rec"), "ex": ("exec", "id"), "pe": ("persist", "id"),
              "rk": ("regkeys", "id"), "rc": ("regchanges", "id"), "ar": ("artifacts", "id"), "fd": ("findings", "id")}
    if kind == "ev" and rid.count(":") == 1:
        fname, rec = rid.split(":")
        r = c.execute("SELECT * FROM events WHERE file=? AND rec=?", (fname, rec)).fetchone()
    elif kind in tables:
        t, col = tables[kind]
        r = c.execute("SELECT * FROM %s WHERE %s=?" % (t, col), (rid,)).fetchone()
    elif kind == "path":
        r = c.execute("SELECT * FROM files WHERE path=? COLLATE NOCASE", (rid.rsplit(":", 1)[0] if re.search(r":\d+$", rid) else rid,)).fetchone()
        kind = "f"
    elif kind in ("exec",):
        r = c.execute("SELECT * FROM exec WHERE path LIKE ? ESCAPE '^' ORDER BY ts LIMIT 1", (like(rid.rsplit("\\", 1)[-1]),)).fetchone()
        kind = "ex"
    else:
        r = None
    if not r:
        return jsonify({"ref": ref, "missing": True})
    d = dict(r)
    if kind == "ev":
        try:
            d["data"] = json.loads(d["data"] or "{}")
        except ValueError:
            pass
    if kind == "ex" and d.get("extra"):
        try:
            d["extra"] = json.loads(d["extra"])
        except ValueError:
            pass
    extra = {}
    if kind == "f":
        extra["usn"] = rows(c.execute("SELECT ts, reasons, path FROM usn WHERE rec=? ORDER BY usn LIMIT 400", (d["rec"],)))
    return jsonify({"ref": ref, "kind": kind, "row": d, "extra": extra})


# ----------------------------------------------------------------- execution ---
@app.route("/api/execution")
def api_execution():
    c = db()
    where, p = ["1=1"], []
    q = arg("q")
    if q:
        where.append("(path LIKE ? ESCAPE '^' OR detail LIKE ? ESCAPE '^' OR sha1 LIKE ? ESCAPE '^')")
        p += [like(q)] * 3
    add_time(where, p, "coalesce(ts,'')") if (arg("from") or arg("to")) else None
    data = rows(c.execute("""SELECT lower(name) k, MAX(name) name, MAX(path) path, MIN(ts) first, MAX(ts) last, COUNT(*) n,
                             group_concat(DISTINCT source) sources, MAX(sha1) sha1, MAX(user) user,
                             group_concat(DISTINCT CASE WHEN source IN ('Security 4688','Sysmon 1','RunMRU') THEN substr(detail,1,300) END) cmds
                             FROM exec WHERE %s GROUP BY lower(name), lower(replace(path,'/','\\')) ORDER BY last DESC LIMIT 5000""" % " AND ".join(where), p))
    from rules import odd_path, tool_hit, scan_text
    from util import looks_random
    for r in data:
        fl = []
        w = odd_path(r["path"] or "")
        if w:
            fl.append(w)
        t = tool_hit(r["path"] or "")
        if t:
            fl.append("tool: " + t[0])
        if looks_random(r["name"] or ""):
            fl.append("random name")
        for h in scan_text(r["cmds"] or ""):
            fl.append(h[3])
        r["flags"] = fl
    return jsonify(data)


@app.route("/api/execution/item")
def api_execution_item():
    c = db()
    name = arg("name").lower()
    return jsonify(rows(c.execute("SELECT * FROM exec WHERE lower(name)=? ORDER BY ts", (name,))))


@app.route("/api/persistence")
def api_persistence():
    c = db()
    where, p = ["1=1"], []
    if arg("kind"):
        where.append("kind=?")
        p.append(arg("kind"))
    if arg("flagged"):
        where.append("(sev IN ('high','medium','low') OR ts >= ?)")
        span = (meta("impact", {}) or {}).get("span") or {}
        p.append(span.get("from") or "9999")
    if arg("q"):
        where.append("(name LIKE ? ESCAPE '^' OR value LIKE ? ESCAPE '^' OR location LIKE ? ESCAPE '^')")
        p += [like(arg("q"))] * 3
    data = rows(c.execute("""SELECT * FROM persist WHERE %s ORDER BY CASE sev WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                             ts DESC LIMIT 3000""" % " AND ".join(where), p))
    kinds = rows(c.execute("SELECT kind, COUNT(*) n, SUM(sev IN ('high','medium')) flagged FROM persist GROUP BY kind ORDER BY n DESC"))
    return jsonify({"rows": data, "kinds": kinds})


# ------------------------------------------------------------------ registry ---
@app.route("/api/registry/checks")
def api_reg_checks():
    c = db()
    return jsonify(rows(c.execute("""SELECT * FROM regchecks ORDER BY CASE sev WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, ts DESC""")))


@app.route("/api/registry/changes")
def api_reg_changes():
    c = db()
    where, p = ["source=?"], [arg("source", "transaction log")]
    if arg("q"):
        where.append("(path LIKE ? ESCAPE '^' OR value LIKE ? ESCAPE '^' OR new LIKE ? ESCAPE '^' OR old LIKE ? ESCAPE '^')")
        p += [like(arg("q"))] * 4
    if arg("hive"):
        where.append("hive=?")
        p.append(arg("hive"))
    add_time(where, p, "ts")
    off = arg_int("offset", 0)
    total = c.execute("SELECT COUNT(*) FROM regchanges WHERE " + " AND ".join(where), p).fetchone()[0]
    data = rows(c.execute("SELECT * FROM regchanges WHERE %s ORDER BY ts DESC LIMIT 500 OFFSET ?" % " AND ".join(where), p + [off]))
    return jsonify({"total": total, "rows": data})


@app.route("/api/registry/recent")
def api_reg_recent():
    c = db()
    where, p = ["1=1"], []
    if arg("q"):
        where.append("path LIKE ? ESCAPE '^'")
        p.append(like(arg("q")))
    if arg("hive"):
        where.append("hive=?")
        p.append(arg("hive"))
    if arg("noise") != "1":
        where.append("""path NOT LIKE '%\\Microsoft\\Windows\\CurrentVersion\\CloudStore%' AND path NOT LIKE '%Microsoft\\Windows NT\\CurrentVersion\\Notifications%'
                        AND path NOT LIKE 'Microsoft\\Windows\\CurrentVersion\\WINEVT%' AND path NOT LIKE '%\\Enum\\%' AND path NOT LIKE '%Microsoft\\Windows\\CurrentVersion\\Diagnostics%'
                        AND path NOT LIKE '%\\Microsoft\\SystemCertificates%' AND path NOT LIKE '%Local Settings\\MuiCache%'""")
    add_time(where, p, "ts")
    off = arg_int("offset", 0)
    total = c.execute("SELECT COUNT(*) FROM regkeys WHERE " + " AND ".join(where), p).fetchone()[0]
    data = rows(c.execute("SELECT * FROM regkeys WHERE %s ORDER BY ts DESC LIMIT 500 OFFSET ?" % " AND ".join(where), p + [off]))
    hives = [r[0] for r in c.execute("SELECT DISTINCT hive FROM regkeys")]
    return jsonify({"total": total, "rows": data, "hives": hives})


def hive_obj(label):
    if label in _HIVES:
        return _HIVES[label]
    for h in meta("hives", []) or []:
        if h["label"] == label and h.get("file"):
            fp = os.path.join(os.path.splitext(CFG["db"])[0] + "_hives", h["file"])
            if os.path.exists(fp):
                with open(fp, "rb") as f:
                    _HIVES[label] = regf.Hive(f.read(), label)
                return _HIVES[label]
    return None


@app.route("/api/registry/hives")
def api_reg_hives():
    return jsonify(meta("hives", []))


@app.route("/api/registry/key")
def api_reg_key():
    h = hive_obj(arg("hive"))
    if not h:
        return jsonify({"error": "hive not available"}), 404
    path = arg("path").strip("\\")
    k = h.get(path)
    if not k:
        return jsonify({"error": "key not found", "path": path}), 404
    subs = sorted(({"name": s.name, "lastwrite": s.lastwrite, "nsub": s.nsub, "nval": s.nval} for s in h.subkeys(k)), key=lambda x: x["name"].lower())
    vals = [{"name": v.name or "(default)", "type": v.tname, "data": v.text(4000), "size": len(v.raw or b"")} for v in h.values(k)]
    return jsonify({"hive": h.name, "path": path, "lastwrite": k.lastwrite, "subkeys": subs, "values": vals})


# -------------------------------------------------------------------- events ---
@app.route("/api/events/stats")
def api_event_stats():
    c = db()
    return jsonify({"channels": rows(c.execute("SELECT channel, COUNT(*) n, MIN(ts) first, MAX(ts) last FROM events GROUP BY channel ORDER BY n DESC")),
                    "ids": rows(c.execute("SELECT channel, eid, COUNT(*) n FROM events GROUP BY channel, eid ORDER BY n DESC LIMIT 400")),
                    "logs": meta("evtx", [])})


@app.route("/api/events")
def api_events():
    c = db()
    where, p = ["1=1"], []
    if arg("channel"):
        where.append("channel=?")
        p.append(arg("channel"))
    if arg("eid"):
        ids = [int(x) for x in re.findall(r"\d+", arg("eid"))]
        if ids:
            where.append("eid IN (%s)" % ",".join("?" * len(ids)))
            p += ids
    if arg("q"):
        for term in arg("q").split():
            where.append("(summary LIKE ? ESCAPE '^' OR data LIKE ? ESCAPE '^')")
            p += [like(term)] * 2
    add_time(where, p, "ts")
    off, lim = arg_int("offset", 0), arg_int("limit", 300, 1, 2000)
    total = c.execute("SELECT COUNT(*) FROM events WHERE " + " AND ".join(where), p).fetchone()[0]
    data = rows(c.execute("SELECT id, ts, channel, provider, eid, rec, user, summary, file FROM events WHERE %s ORDER BY ts %s LIMIT ? OFFSET ?" % (
        " AND ".join(where), "DESC" if arg("order") == "desc" else "ASC"), p + [lim, off]))
    return jsonify({"total": total, "rows": data})


@app.route("/api/logons")
def api_logons():
    c = db()
    where, p = ["channel='Security' AND eid IN (4624,4625,4648)"], []
    add_time(where, p, "ts")
    data = rows(c.execute("""SELECT eid, json_extract(data,'$.TargetDomainName')||'\\'||json_extract(data,'$.TargetUserName') user,
                             json_extract(data,'$.LogonType') type, json_extract(data,'$.IpAddress') ip, json_extract(data,'$.WorkstationName') ws,
                             json_extract(data,'$.AuthenticationPackageName') auth, COUNT(*) n, MIN(ts) first, MAX(ts) last
                             FROM events WHERE %s GROUP BY eid, user, type, ip, ws ORDER BY last DESC LIMIT 2000""" % " AND ".join(where), p))
    data = [r for r in data if not (r["type"] in ("5",) or (r["user"] or "").upper().endswith(("\\SYSTEM", "$", "\\LOCAL SERVICE", "\\NETWORK SERVICE", "\\DWM-1", "\\UMFD-0", "\\UMFD-1")))]
    rdp = rows(c.execute("""SELECT ts, channel, eid, summary FROM events WHERE (channel LIKE '%TerminalServices%' AND eid IN (21,22,24,25,1149))
                            OR (channel='Security' AND eid IN (4778,4779)) ORDER BY ts DESC LIMIT 1000"""))
    from rules import is_public_ip, LOGON_TYPES
    for r in data:
        r["public"] = is_public_ip(r["ip"] or "")
        try:
            r["type_name"] = LOGON_TYPES.get(int(r["type"]), "")
        except (TypeError, ValueError):
            r["type_name"] = ""
    return jsonify({"logons": data, "rdp": rdp})


# ---------------------------------------------------------------- filesystem ---
@app.route("/api/files")
def api_files():
    c = db()
    where, p = ["1=1"], []
    q = arg("q")
    if q:
        where.append("path LIKE ? ESCAPE '^'")
        p.append(like(q))
    if arg("ext"):
        exts = [e.strip().lstrip(".").lower() for e in arg("ext").split(",") if e.strip()]
        where.append("ext IN (%s)" % ",".join("?" * len(exts)))
        p += exts
    field = arg("field", "si_c")
    if field not in ("si_c", "si_m", "si_e", "si_a", "fn_c", "fn_m"):
        field = "si_c"
    add_time(where, p, field)
    flt = arg("filter")
    if flt == "deleted":
        where.append("in_use=0")
    elif flt == "exec":
        where.append("ext IN ('exe','dll','ps1','bat','cmd','scr','vbs','js','hta','msi','sys')")
    elif flt == "timestomp":
        where.append("flags LIKE '%SI<FN%'")
    elif flt == "zone":
        where.append("zone<>''")
    elif flt == "ads":
        where.append("ads<>'' AND ads NOT LIKE 'Zone.Identifier%'")
    elif flt == "notes":
        where.append("note=1")
    elif flt == "encrypted":
        where.append("enc=1")
    if arg("dirs") != "1":
        where.append("is_dir=0")
    off, lim = arg_int("offset", 0), arg_int("limit", 300, 1, 2000)
    order = {"time": field + " DESC", "path": "path", "size": "size DESC"}.get(arg("sort", "time"), field + " DESC")
    total = c.execute("SELECT COUNT(*) FROM files WHERE " + " AND ".join(where), p).fetchone()[0]
    data = rows(c.execute("""SELECT rec, path, size, in_use, is_dir, si_c, si_m, si_e, fn_c, flags, zone, ads, enc, note FROM files
                             WHERE %s ORDER BY %s LIMIT ? OFFSET ?""" % (" AND ".join(where), order), p + [lim, off]))
    return jsonify({"total": total, "rows": data})


@app.route("/api/file")
def api_file():
    c = db()
    rec = arg_int("rec", -1, -1)
    r = c.execute("SELECT * FROM files WHERE rec=?", (rec,)).fetchone()
    if not r:
        abort(404)
    d = dict(r)
    out = {"row": d, "usn": rows(c.execute("SELECT ts, reasons, path FROM usn WHERE rec=? ORDER BY usn LIMIT 500", (rec,)))}
    s = source()
    if s is not None and d["in_use"] and not d["is_dir"] and arg("content") == "1":
        try:
            if isinstance(s, ix.NtfsSource):
                st = s.vol.stream(rec)
                head = st.read(0, 65536) if st else b""
            else:
                head = s.read(d["path"], 65536) or b""
            out["hex"] = head[:1024].hex()
            out["entropy"] = round(entropy(head), 3)
            out["text"] = head[:4096].decode("utf-8", "replace") if head[:1] != b"\0" else ""
        except Exception as e:
            out["content_error"] = str(e)
    return jsonify(out)


@app.route("/api/usn")
def api_usn():
    c = db()
    where, p = ["1=1"], []
    if arg("q"):
        where.append("path LIKE ? ESCAPE '^'")
        p.append(like(arg("q")))
    reason_bits = {"create": 0x100, "delete": 0x200, "rename": 0x3000, "overwrite": 0x1, "extend": 0x2, "truncate": 0x4,
                   "security": 0x800, "basic": 0x8000, "stream": 0x200000}
    if arg("reason") in reason_bits:
        where.append("(reason & ?)<>0")
        p.append(reason_bits[arg("reason")])
    if arg("close") == "1":
        where.append("(reason & 2147483648)<>0")
    add_time(where, p, "ts")
    off, lim = arg_int("offset", 0), arg_int("limit", 300, 1, 2000)
    total = c.execute("SELECT COUNT(*) FROM usn WHERE " + " AND ".join(where), p).fetchone()[0]
    data = rows(c.execute("SELECT id, ts, usn, rec, path, reasons FROM usn WHERE %s ORDER BY usn %s LIMIT ? OFFSET ?" % (
        " AND ".join(where), "DESC" if arg("order") == "desc" else "ASC"), p + [lim, off]))
    return jsonify({"total": total, "rows": data, "range": meta("usn_range")})


# ------------------------------------------------------------------ findings ---
@app.route("/api/findings")
def api_findings():
    c = db()
    where, p = ["1=1"], []
    if arg("sev"):
        where.append("sev=?")
        p.append(arg("sev"))
    if arg("cat"):
        where.append("cat=?")
        p.append(arg("cat"))
    if arg("q"):
        where.append("(title LIKE ? ESCAPE '^' OR detail LIKE ? ESCAPE '^')")
        p += [like(arg("q"))] * 2
    add_time(where, p, "coalesce(ts,'')") if (arg("from") or arg("to")) else None
    data = rows(c.execute("""SELECT * FROM findings WHERE %s ORDER BY CASE sev WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                             ts LIMIT 5000""" % " AND ".join(where), p))
    grouped = rows(c.execute("""SELECT title, sev, cat, COUNT(*) n, MIN(ts) first, MAX(ts) last FROM findings WHERE %s
                                GROUP BY title, sev, cat ORDER BY CASE sev WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, n DESC""" % " AND ".join(where), p))
    return jsonify({"rows": data, "groups": grouped})


@app.route("/api/artifacts")
def api_artifacts():
    c = db()
    where, p = ["1=1"], []
    if arg("kind"):
        where.append("kind=?")
        p.append(arg("kind"))
    if arg("q"):
        where.append("(title LIKE ? ESCAPE '^' OR detail LIKE ? ESCAPE '^')")
        p += [like(arg("q"))] * 2
    off = arg_int("offset", 0)
    total = c.execute("SELECT COUNT(*) FROM artifacts WHERE " + " AND ".join(where), p).fetchone()[0]
    data = rows(c.execute("SELECT id, ts, kind, title, detail, path FROM artifacts WHERE %s ORDER BY ts DESC LIMIT 500 OFFSET ?" % " AND ".join(where), p + [off]))
    kinds = rows(c.execute("SELECT kind, COUNT(*) n FROM artifacts GROUP BY kind ORDER BY n DESC"))
    return jsonify({"total": total, "rows": data, "kinds": kinds})


# ---------------------------------------------------------------------- pins ---
@app.route("/api/pins", methods=["GET", "POST"])
def api_pins():
    c = db()
    if request.method == "POST":
        b = request.get_json(force=True) or {}
        c.execute("INSERT INTO pins(ref,ts,src,title,detail,note,created) VALUES(?,?,?,?,?,?,?)",
                  (b.get("ref", ""), b.get("ts"), b.get("src", ""), (b.get("title") or "")[:500], (b.get("detail") or "")[:4000],
                   b.get("note", ""), time.strftime("%Y-%m-%d %H:%M:%S")))
        c.commit()
        return jsonify({"ok": True})
    return jsonify(rows(c.execute("SELECT * FROM pins ORDER BY coalesce(ts,'9999'), id")))


@app.route("/api/pins/<int:pid>", methods=["PATCH", "DELETE"])
def api_pin(pid):
    c = db()
    if request.method == "DELETE":
        c.execute("DELETE FROM pins WHERE id=?", (pid,))
    else:
        b = request.get_json(force=True) or {}
        c.execute("UPDATE pins SET note=? WHERE id=?", (b.get("note", ""), pid))
    c.commit()
    return jsonify({"ok": True})


@app.route("/api/report.md")
def api_report():
    c = db()
    host = meta("host", {}) or {}
    imp = meta("impact", {}) or {}
    w = imp.get("window") or {}
    L = ["# Ransomware investigation: %s" % (host.get("computer_name") or "host"), "",
         "Generated %s by Embers. All times UTC." % time.strftime("%Y-%m-%d %H:%M"), "", "## Host", ""]
    for k in ("computer_name", "product", "display_version", "build", "domain", "timezone", "ips", "last_shutdown"):
        if host.get(k):
            L.append("- **%s**: %s" % (k.replace("_", " "), host[k] if not isinstance(host[k], list) else ", ".join(host[k])))
    L += ["", "## Impact", ""]
    L.append("- Ransomware extension(s): %s" % (", ".join("." + e for e in imp.get("chosen") or []) or "not identified"))
    L.append("- Encrypted files: %s in %s folders" % (imp.get("encrypted"), imp.get("dirs")))
    if w:
        L.append("- Encryption window: %s → %s (%s)" % (w.get("start"), w.get("end"), w.get("basis")))
    for n in imp.get("notes", []):
        L.append("- Ransom note `%s`: %s copies in %s folders, first %s" % (n["name"], n["copies"], n["dirs"], n["first"]))
        for k, v in (n.get("iocs") or {}).items():
            L.append("  - %s: %s" % (k, ", ".join(v)))
    if imp.get("payload"):
        L += ["", "## Payload candidates", ""]
        for p in imp["payload"][:10]:
            L.append("- `%s` first seen %s, score %s: %s" % (p["path"], p["ts"], p["score"], "; ".join(p["why"])))
    L += ["", "## Key events", "", "| Time (UTC) | Severity | What | Detail |", "|---|---|---|---|"]
    for s in (meta("story", []) or [])[:200]:
        L.append("| %s | %s | %s | %s |" % (s["ts"], s["sev"], s["title"], (s["detail"] or "").replace("|", "\\|").replace("\n", " ")[:300]))
    pins = rows(c.execute("SELECT * FROM pins ORDER BY coalesce(ts,'9999'), id"))
    if pins:
        L += ["", "## Evidence board", ""]
        for p in pins:
            L.append("- **%s** [%s] %s  \n  %s%s" % (p["ts"] or "no time", p["src"], p["title"], (p["detail"] or "")[:600],
                                                    ("  \n  _Note:_ " + p["note"]) if p["note"] else ""))
    L += ["", "## Registry settings of note", ""]
    for r in rows(c.execute("SELECT * FROM regchecks WHERE sev IN ('high','medium') ORDER BY sev")):
        L.append("- [%s] %s: `%s\\%s` %s = %s (written %s)" % (r["sev"], r["title"], r["hive"], r["path"], r["value"], r["data"], r["ts"]))
    return Response("\n".join(L) + "\n", mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=embers_report.md"})


# ---------------------------------------------------------------------- main ---
def main():
    global INDEXER
    ap = argparse.ArgumentParser(description="Embers: Windows ransomware investigation dashboard")
    ap.add_argument("source", nargs="?", help=r"\\.\F: (mounted image volume), \\.\PhysicalDriveN, disk.raw, or a folder")
    ap.add_argument("--partition", type=int, help="partition index (default: largest NTFS)")
    ap.add_argument("--mft", help="folder mode: exported $MFT file")
    ap.add_argument("--usn", help="folder mode: exported $UsnJrnl:$J file")
    ap.add_argument("--db", default="embers.db", help="case database (default embers.db)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--reg-days", type=int, default=60, help="keep registry key write times this many days back (default 60)")
    ap.add_argument("--span-days", type=int, default=14, help="timeline starts this many days before encryption (default 14)")
    ap.add_argument("--no-index", action="store_true", help="open the existing database without re-indexing")
    a = ap.parse_args()
    CFG["db"] = os.path.abspath(a.db)
    con = ix.connect(CFG["db"])
    ix.init_db(con)
    con.close()
    INDEXER = ix.Indexer(CFG["db"])
    if a.source and not a.no_index:
        INDEXER.start(a.source, a.partition, a.mft, a.usn, a.reg_days, a.span_days)
        print("Indexing %s in the background…" % a.source)
    print("Database: %s" % CFG["db"])
    print("Open http://%s:%d" % (a.host, a.port))
    app.run(host=a.host, port=a.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
