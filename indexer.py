"""
Embers indexer: reads a Windows volume (raw NTFS or a mounted/extracted folder), extracts
artifacts into one SQLite database and runs the ransomware analysis on top.
"""
import fnmatch
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import traceback
from collections import Counter, defaultdict

import evtx
import ntfs
import regf
import rules
import winart
from util import ft, parse_ts, fmt_dt, shift, looks_random, entropy

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS files(rec INTEGER PRIMARY KEY, seq INT, parent INT, pseq INT, name TEXT, ext TEXT, path TEXT,
  is_dir INT, in_use INT, size INT, si_c TEXT, si_m TEXT, si_e TEXT, si_a TEXT, fn_c TEXT, fn_m TEXT, fn_e TEXT, fn_a TEXT,
  attrs INT, ads TEXT, zone TEXT, flags TEXT, enc INT DEFAULT 0, note INT DEFAULT 0, orig TEXT);
CREATE TABLE IF NOT EXISTS usn(id INTEGER PRIMARY KEY, usn INT, ts TEXT, rec INT, seq INT, prec INT, name TEXT, ext TEXT,
  path TEXT, reason INT, reasons TEXT, attrs INT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, channel TEXT, provider TEXT, eid INT, rec INT,
  computer TEXT, user TEXT, summary TEXT, data TEXT, file TEXT);
CREATE TABLE IF NOT EXISTS exec(id INTEGER PRIMARY KEY, ts TEXT, source TEXT, path TEXT, name TEXT, detail TEXT,
  user TEXT, sha1 TEXT, extra TEXT);
CREATE TABLE IF NOT EXISTS persist(id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, location TEXT, name TEXT, value TEXT,
  flags TEXT, sev TEXT);
CREATE TABLE IF NOT EXISTS regkeys(id INTEGER PRIMARY KEY, ts TEXT, hive TEXT, path TEXT, nvals INT);
CREATE TABLE IF NOT EXISTS regchanges(id INTEGER PRIMARY KEY, hive TEXT, kind TEXT, path TEXT, value TEXT, old TEXT,
  new TEXT, ts TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS regchecks(id INTEGER PRIMARY KEY, hive TEXT, path TEXT, value TEXT, data TEXT, sev TEXT,
  title TEXT, why TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, title TEXT, detail TEXT, path TEXT, extra TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, ts TEXT, sev TEXT, cat TEXT, title TEXT, detail TEXT,
  source TEXT, ref TEXT, rule TEXT);
CREATE TABLE IF NOT EXISTS timeline(id INTEGER PRIMARY KEY, ts TEXT, src TEXT, kind TEXT, text TEXT, ref TEXT, sev TEXT);
CREATE TABLE IF NOT EXISTS pins(id INTEGER PRIMARY KEY, ref TEXT, ts TEXT, src TEXT, title TEXT, detail TEXT, note TEXT, created TEXT);
"""
INDEXES = """
CREATE INDEX IF NOT EXISTS ix_files_path ON files(path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_files_parent ON files(parent);
CREATE INDEX IF NOT EXISTS ix_files_ext ON files(ext);
CREATE INDEX IF NOT EXISTS ix_files_sic ON files(si_c);
CREATE INDEX IF NOT EXISTS ix_files_sim ON files(si_m);
CREATE INDEX IF NOT EXISTS ix_files_sie ON files(si_e);
CREATE INDEX IF NOT EXISTS ix_files_enc ON files(enc);
CREATE INDEX IF NOT EXISTS ix_usn_ts ON usn(ts);
CREATE INDEX IF NOT EXISTS ix_usn_rec ON usn(rec);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_ev_eid ON events(channel, eid);
CREATE INDEX IF NOT EXISTS ix_exec_ts ON exec(ts);
CREATE INDEX IF NOT EXISTS ix_reg_ts ON regkeys(ts);
CREATE INDEX IF NOT EXISTS ix_tl_ts ON timeline(ts);
CREATE INDEX IF NOT EXISTS ix_tl_src ON timeline(src, ts);
CREATE INDEX IF NOT EXISTS ix_find_ts ON findings(ts);
"""
DATA_TABLES = ["files", "usn", "events", "exec", "persist", "regkeys", "regchanges", "regchecks", "artifacts", "findings", "timeline"]

HIVE_LABEL = {"SYSTEM": "HKLM\\SYSTEM", "SOFTWARE": "HKLM\\SOFTWARE", "SAM": "HKLM\\SAM", "SECURITY": "HKLM\\SECURITY",
              "Amcache": "Amcache.hve"}


def connect(path):
    con = sqlite3.connect(path, timeout=60, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=60000")
    return con


def init_db(con):
    con.executescript(SCHEMA)
    con.executescript(INDEXES)
    con.commit()


def get_meta(con, k, default=None):
    r = con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    if not r:
        return default
    try:
        return json.loads(r[0])
    except (ValueError, TypeError):
        return r[0]


def set_meta(con, k, v):
    con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, json.dumps(v, default=str)))


# =================================================================== sources ===
class NtfsSource:
    kind = "ntfs"

    def __init__(self, spec, partition=None):
        self.spec = spec
        self.dev = ntfs.Device(spec)
        part, self.partitions = ntfs.pick_ntfs(self.dev, partition)
        self.part = part
        self.vol = ntfs.NtfsVolume(self.dev, part[1])
        self.con = None   # set by the indexer after the MFT stage

    def describe(self):
        return {"kind": "raw NTFS", "source": self.spec, "partition": self.part[0], "offset": self.part[1],
                "volume_size": self.vol.size, "cluster": self.vol.cluster, "serial": self.vol.serial,
                "mft_records": self.vol.records,
                "partitions": [{"index": p[0], "offset": p[1], "size": p[2], "ntfs": p[3], "name": p[4]} for p in self.partitions]}

    def mft_records(self):
        return self.vol.iter_records(), self.vol.records

    def usn(self):
        r = self.con.execute("SELECT rec FROM files WHERE parent=11 AND name='$UsnJrnl'").fetchone()
        if not r:
            return None
        st = self.vol.stream(r[0], "$J")
        return ntfs.iter_usn(st) if st else None

    def _rec(self, path):
        r = self.con.execute("SELECT rec FROM files WHERE path=? COLLATE NOCASE AND in_use=1 AND is_dir=0", (path,)).fetchone()
        return r[0] if r else None

    def read(self, path, cap=1 << 30):
        rec = self._rec(path)
        if rec is None:
            return None
        st = self.vol.stream(rec)
        if st is None:
            return b""
        return st.read(0, min(st.size, cap))

    def glob(self, pattern):
        return db_glob(self.con, pattern)

    def under(self, folder):
        like = folder.rstrip("\\").replace("^", "^^").replace("%", "^%").replace("_", "^_") + "\\%"
        return [r[0] for r in self.con.execute(
            "SELECT path FROM files WHERE path LIKE ? ESCAPE '^' AND in_use=1 AND is_dir=0", (like,))]


class FolderSource:
    """A mounted or extracted volume (e.g. Macrium 'Explore image' drive letter). Optional exported $MFT / $J."""
    kind = "folder"

    def __init__(self, root, mft=None, usn=None):
        self.root = os.path.abspath(root)
        self.mft_path, self.usn_path = mft, usn
        self.con = None
        self.use_db_paths = bool(mft)

    def describe(self):
        return {"kind": "folder", "source": self.root, "mft": self.mft_path or "", "usn": self.usn_path or ""}

    def mft_records(self):
        if not self.mft_path:
            return None, 0
        m = ntfs.MftFile(self.mft_path)
        return m.iter_records(), m.records

    def usn(self):
        return ntfs.iter_usn(self.usn_path) if self.usn_path else None

    def _resolve(self, rel):
        cur = self.root
        for p in [x for x in rel.replace("/", "\\").split("\\") if x]:
            cand = os.path.join(cur, p)
            if os.path.exists(cand):
                cur = cand
                continue
            try:
                names = os.listdir(cur)
            except OSError:
                return None
            m = next((n for n in names if n.lower() == p.lower()), None)
            if m is None:
                return None
            cur = os.path.join(cur, m)
        return cur

    def read(self, path, cap=1 << 30):
        fp = self._resolve(path)
        if not fp or not os.path.isfile(fp):
            return None
        try:
            with open(fp, "rb") as f:
                return f.read(cap)
        except OSError:
            return None

    def glob(self, pattern):
        parts = [x for x in pattern.split("\\") if x]
        cur = [("", self.root)]
        for i, seg in enumerate(parts):
            nxt = []
            for rel, real in cur:
                if "*" in seg or "?" in seg:
                    try:
                        names = os.listdir(real)
                    except OSError:
                        continue
                    for n in names:
                        if fnmatch.fnmatch(n.lower(), seg.lower()):
                            nxt.append((rel + "\\" + n, os.path.join(real, n)))
                else:
                    cand = os.path.join(real, seg)
                    if not os.path.exists(cand):
                        try:
                            m = next((n for n in os.listdir(real) if n.lower() == seg.lower()), None)
                        except OSError:
                            m = None
                        if m is None:
                            continue
                        cand = os.path.join(real, m)
                        seg_name = m
                    else:
                        seg_name = seg
                    nxt.append((rel + "\\" + seg_name, cand))
            cur = nxt
        return [rel for rel, real in cur if os.path.isfile(real)]

    def under(self, folder):
        base = self._resolve(folder)
        out = []
        if not base:
            return out
        for dp, _dn, fn in os.walk(base):
            for f in fn:
                full = os.path.join(dp, f)
                out.append(folder.rstrip("\\") + "\\" + os.path.relpath(full, base).replace("/", "\\"))
        return out


def db_glob(con, pattern):
    like = pattern.replace("^", "^^").replace("%", "^%").replace("_", "^_").replace("*", "%").replace("?", "_")
    rx = re.compile("^" + "\\\\".join(re.escape(s).replace("\\*", "[^\\\\]*").replace("\\?", "[^\\\\]")
                                       for s in pattern.split("\\")) + "$", re.I)
    return [r[0] for r in con.execute("SELECT path FROM files WHERE path LIKE ? ESCAPE '^' AND in_use=1 AND is_dir=0", (like,))
            if rx.match(r[0])]


def open_source(spec, partition=None, mft=None, usn=None):
    if os.path.isdir(spec) and not re.match(r"^\\\\\.\\", spec):
        return FolderSource(spec, mft, usn)
    return NtfsSource(spec, partition)


# ================================================================== indexer ===
class Indexer:
    STAGES = ["MFT", "USN journal", "Registry", "Event logs", "Prefetch", "Scheduled tasks", "User artifacts", "Analysis", "Timeline"]

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.thread = None
        self.cancel = False
        self.status = {"running": False, "stage": "", "done": 0, "total": 0, "msg": "", "errors": [], "started": None,
                       "finished": None, "stages": []}

    # ------------------------------------------------------------ control ---
    def start(self, spec, partition=None, mft=None, usn=None, reg_days=60, span_days=14, skip=()):
        if self.thread and self.thread.is_alive():
            raise RuntimeError("indexing already running")
        self.cancel = False
        self.opts = {"spec": spec, "partition": partition, "mft": mft, "usn": usn, "reg_days": reg_days,
                     "span_days": span_days, "skip": list(skip)}
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def reanalyze(self, overrides):
        if self.thread and self.thread.is_alive():
            raise RuntimeError("indexing already running")
        self.cancel = False
        self.thread = threading.Thread(target=self._reanalyze, args=(overrides,), daemon=True)
        self.thread.start()

    def _set(self, stage=None, done=None, total=None, msg=None):
        s = self.status
        if stage is not None:
            s["stage"] = stage
            s["stages"].append({"name": stage, "started": time.time()})
        if done is not None:
            s["done"] = done
        if total is not None:
            s["total"] = total
        if msg is not None:
            s["msg"] = msg

    def _err(self, where, e):
        self.status["errors"].append("%s: %s" % (where, e))
        tb = traceback.format_exc()
        print("! %s: %s\n%s" % (where, e, tb))

    def _run(self):
        s = self.status
        s.update({"running": True, "errors": [], "started": time.time(), "finished": None, "stages": [], "msg": ""})
        con = connect(self.dbpath)
        try:
            init_db(con)
            for t in DATA_TABLES:
                con.execute("DELETE FROM " + t)
            con.execute("DELETE FROM meta WHERE k NOT IN ('overrides')")
            con.commit()
            o = self.opts
            src = open_source(o["spec"], o["partition"], o["mft"], o["usn"])
            src.con = con
            self.src = src
            set_meta(con, "source", src.describe())
            set_meta(con, "options", o)
            con.commit()
            self.hives = {}
            steps = [("MFT", self.stage_mft), ("USN journal", self.stage_usn), ("Registry", self.stage_registry),
                     ("Event logs", self.stage_evtx), ("Prefetch", self.stage_prefetch), ("Scheduled tasks", self.stage_tasks),
                     ("User artifacts", self.stage_user)]
            for name, fn in steps:
                if self.cancel:
                    break
                if name in o.get("skip", []):
                    continue
                self._set(stage=name, done=0, total=0, msg="")
                try:
                    fn(con, src)
                    con.commit()
                except Exception as e:
                    con.rollback()
                    self._err(name, e)
            if not self.cancel:
                self._set(stage="Analysis", done=0, total=0)
                try:
                    analyze(con, src, self, get_meta(con, "overrides", {}) or {})
                    con.commit()
                except Exception as e:
                    con.rollback()
                    self._err("Analysis", e)
                self._set(stage="Timeline")
                try:
                    build_timeline(con)
                    con.commit()
                except Exception as e:
                    con.rollback()
                    self._err("Timeline", e)
            set_meta(con, "index_errors", s["errors"])
            set_meta(con, "indexed_at", time.strftime("%Y-%m-%d %H:%M:%S"))
            con.commit()
        except Exception as e:
            self._err("Indexer", e)
        finally:
            s["running"] = False
            s["finished"] = time.time()
            s["stage"] = "cancelled" if self.cancel else "done"
            con.close()

    def _reanalyze(self, overrides):
        s = self.status
        s.update({"running": True, "errors": [], "started": time.time(), "finished": None, "stages": []})
        con = connect(self.dbpath)
        try:
            set_meta(con, "overrides", overrides)
            src = None
            try:
                o = get_meta(con, "options", {}) or {}
                if o.get("spec"):
                    src = open_source(o["spec"], o.get("partition"), o.get("mft"), o.get("usn"))
                    src.con = con
            except Exception:
                src = None
            self._set(stage="Analysis")
            con.execute("DELETE FROM findings WHERE source='analysis'")
            con.execute("DELETE FROM regchecks WHERE title LIKE 'Ransomware extension%'")
            analyze(con, src, self, overrides)
            con.commit()
            self._set(stage="Timeline")
            build_timeline(con)
            con.commit()
        except Exception as e:
            self._err("Re-analysis", e)
        finally:
            s["running"] = False
            s["finished"] = time.time()
            s["stage"] = "done"
            con.close()

    # =============================================================== stages ===
    def stage_mft(self, con, src):
        it, total = src.mft_records()
        if it is None:
            self.status["msg"] = "no $MFT available (folder mode without --mft): filesystem views will be empty"
            return
        self._set(total=total)
        dirs = {}
        batch = []
        n = 0
        ins = "INSERT OR REPLACE INTO files(rec,seq,parent,pseq,name,ext,is_dir,in_use,size,si_c,si_m,si_e,si_a,fn_c,fn_m,fn_e,fn_a,attrs,ads,zone,flags) " \
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        for recno, raw in it:
            n += 1
            if n % 20000 == 0:
                self._set(done=n)
                if batch:
                    con.executemany(ins, batch)
                    batch = []
                if self.cancel:
                    return
            r = ntfs.scan_record(raw)
            if not r or r["base"] or not r["fn"]:
                continue
            parent, pseq, name, fnt, fnsize = r["fn"]
            si = r["si"] or (0, 0, 0, 0)
            if r["is_dir"]:
                dirs[recno] = (parent, pseq, name, r["seq"])
            ext = name.rsplit(".", 1)[1].lower()[:24] if "." in name[1:] else ""
            flags = []
            if si[0] and fnt[0] and si[0] + 10_000_000 < fnt[0]:
                flags.append("SI<FN")
            if si[0] and si[0] % 10_000_000 == 0 and ext in rules.EXEC_EXT:
                flags.append("whole-second")
            if r["torn"]:
                flags.append("torn")
            zone = ""
            if r["zone"]:
                z = dict(re.findall(r"(\w+)=([^\r\n]*)", r["zone"]))
                zone = "Zone %s %s %s" % (z.get("ZoneId", "?"), z.get("HostUrl", ""), ("ref " + z["ReferrerUrl"]) if z.get("ReferrerUrl") else "")
            ads = ";".join("%s:%s" % (a, b) for a, b in r["ads"])
            size = r["size"] if r["size"] is not None else fnsize
            batch.append((recno, r["seq"], parent, pseq, name, ext, r["is_dir"], r["in_use"], size,
                          ft(si[0]), ft(si[1]), ft(si[2]), ft(si[3]), ft(fnt[0]), ft(fnt[1]), ft(fnt[2]), ft(fnt[3]),
                          r["attrs"], ads, zone.strip(), ",".join(flags)))
        if batch:
            con.executemany(ins, batch)
        self._set(done=n, msg="building paths")
        memo = {5: ""}

        def dpath(rec, depth=0):
            if rec in memo:
                return memo[rec]
            chain, cur = [], rec
            while cur not in memo and cur in dirs and len(chain) < 300:
                chain.append(cur)
                cur = dirs[cur][0]
                if cur in chain:
                    break
            base = memo.get(cur, "\\?" if cur != 5 else "")
            for c in reversed(chain):
                base = base + "\\" + dirs[c][2]
                memo[c] = base
            return memo.get(rec, base)

        def fpath(parent, pseq, name):
            p = dpath(parent)
            d = dirs.get(parent)
            if d and d[3] != pseq and pseq:
                return "\\?" + p + "\\" + name   # parent folder record was reused: path is a best guess
            return p + "\\" + name

        con.create_function("fpath", 3, fpath)
        con.execute("UPDATE files SET path = CASE WHEN rec=5 THEN '\\' ELSE fpath(parent, pseq, name) END")
        self.dirs = dirs
        self.dpath = dpath
        set_meta(con, "mft_count", n)

    def stage_usn(self, con, src):
        it = src.usn()
        if it is None:
            self.status["msg"] = "no $UsnJrnl:$J found"
            return
        dirs = getattr(self, "dirs", {})
        dpath = getattr(self, "dpath", lambda r: "")
        usn_dirs = {}
        batch, n = [], 0
        ins = "INSERT INTO usn(usn,ts,rec,seq,prec,name,ext,path,reason,reasons,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
        for r in it:
            n += 1
            if r["attrs"] & 0x10:
                usn_dirs[r["rec"]] = (r["prec"], r["name"])
            if r["prec"] in dirs or r["prec"] == 5:
                parent = dpath(r["prec"])
            elif r["prec"] in usn_dirs:
                pr, nm = usn_dirs[r["prec"]]
                parent = (dpath(pr) if pr in dirs else "\\?") + "\\" + nm
            else:
                parent = "\\?"
            name = r["name"]
            ext = name.rsplit(".", 1)[1].lower()[:24] if "." in name[1:] else ""
            batch.append((r["usn"], r["ts"], r["rec"], r["seq"], r["prec"], name, ext, parent + "\\" + name,
                          r["reason"], ntfs.usn_reason_text(r["reason"]), r["attrs"]))
            if len(batch) >= 20000:
                con.executemany(ins, batch)
                batch = []
                self._set(done=n)
                if self.cancel:
                    return
        if batch:
            con.executemany(ins, batch)
        self._set(done=n)
        r = con.execute("SELECT MIN(ts), MAX(ts), COUNT(*) FROM usn").fetchone()
        set_meta(con, "usn_range", {"first": r[0], "last": r[1], "count": r[2]})

    # ------------------------------------------------------------ registry ---
    def _load_hive(self, con, src, label, path):
        data = src.read(path)
        if not data or data[:4] != b"regf":
            return None
        logs = [src.read(path + ext) for ext in (".LOG1", ".LOG2", ".LOG")]
        logs = [lg for lg in logs if lg]
        info = {"label": label, "path": path, "size": len(data), "logs": len(logs)}
        try:
            primary = regf.Hive(data, label)
            info["dirty"] = primary.dirty
            info["written"] = primary.written
        except ValueError:
            return None
        new_bytes, applied, note = regf.replay(data, logs)
        info["replayed_entries"] = applied
        info["note"] = note
        hive = regf.Hive(new_bytes, label)
        hive.replayed = applied
        # save the replayed hive next to the database for browsing
        outdir = os.path.splitext(self.dbpath)[0] + "_hives"
        os.makedirs(outdir, exist_ok=True)
        fn = re.sub(r"[^\w.-]", "_", label) + ".hive"
        with open(os.path.join(outdir, fn), "wb") as f:
            f.write(new_bytes)
        info["file"] = fn
        if applied:
            try:
                changes = regf.diff(primary, hive)
                con.executemany("INSERT INTO regchanges(hive,kind,path,value,old,new,ts,source) VALUES(?,?,?,?,?,?,?,?)",
                                [(label, c["kind"], c["path"], c["value"], c["old"], c["new"], c["lastwrite"], "transaction log")
                                 for c in changes])
                info["log_changes"] = len(changes)
            except Exception as e:
                self._err("diff " + label, e)
        try:
            dk = hive.deleted_keys()
            rows = []
            for k in dk:
                rows.append((label, "deleted key", k["path"], "", "", "; ".join("%s=%s" % (a, c) for a, _b, c in k["values"])[:2000],
                             k["lastwrite"], "free space"))
            con.executemany("INSERT INTO regchanges(hive,kind,path,value,old,new,ts,source) VALUES(?,?,?,?,?,?,?,?)", rows)
            info["deleted_keys"] = len(rows)
        except Exception as e:
            self._err("deleted keys " + label, e)
        # key last-write times (recent ones only, the rest is noise)
        keys = [(p, k.lw, k.nval) for p, k in hive.walk()]
        if keys:
            newest = max(lw for _p, lw, _n in keys)
            cutoff = newest - self.opts.get("reg_days", 60) * 86400 * 10_000_000
            con.executemany("INSERT INTO regkeys(ts,hive,path,nvals) VALUES(?,?,?,?)",
                            [(ft(lw), label, p, nv) for p, lw, nv in keys if lw >= cutoff and ft(lw)])
            info["keys"] = len(keys)
        self.hive_info.append(info)
        return hive

    def stage_registry(self, con, src):
        self.hive_info = []
        cfg = "\\Windows\\System32\\config\\"
        plan = [(n, cfg + n) for n in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")]
        plan.append(("Amcache", "\\Windows\\AppCompat\\Programs\\Amcache.hve"))
        for p in src.glob("\\Users\\*\\NTUSER.DAT"):
            plan.append(("NTUSER " + p.split("\\")[2], p))
        for p in src.glob("\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"):
            plan.append(("UsrClass " + p.split("\\")[2], p))
        self._set(total=len(plan))
        for i, (label, path) in enumerate(plan):
            self._set(done=i, msg=label)
            try:
                h = self._load_hive(con, src, label, path)
                if h:
                    self.hives[label] = h
            except Exception as e:
                self._err("hive " + label, e)
            con.commit()
        set_meta(con, "hives", self.hive_info)
        H = self.hives
        system, software = H.get("SYSTEM"), H.get("SOFTWARE")
        info = winart.host_info(system, software)
        prof = winart.profiles(software)
        set_meta(con, "host", info)
        set_meta(con, "profiles", prof)
        set_meta(con, "accounts", winart.sam_accounts(H.get("SAM")))
        sid_user = {k: v["user"] for k, v in prof.items()}
        self.sid_user = sid_user
        # persistence
        prows = []

        def add_persist(ts, kind, location, name, value, extra_flags=()):
            flags = list(extra_flags)
            w = rules.odd_path(rules.image_path_of(value))
            if w:
                flags.append("in " + w)
            for rid, sev, cat, title, m in rules.scan_text(value):
                flags.append(title)
            t = rules.tool_hit(value)
            if t:
                flags.append("tool: " + t[0])
            sev = "high" if any(f.startswith("tool") or "Shadow" in f or "Defender" in f for f in flags) else ("medium" if flags else "info")
            prows.append((ts, kind, location, name, value, "; ".join(flags), sev))

        for r in winart.run_keys(software, "HKLM\\SOFTWARE"):
            add_persist(r["ts"], r["kind"], r["location"], r["name"], r["value"])
        for label, h in H.items():
            if label.startswith("NTUSER "):
                for r in winart.run_keys(h, "HKU\\" + label[7:], "Software\\"):
                    add_persist(r["ts"], r["kind"], r["location"], r["name"], r["value"])
        for svc in winart.services(system):
            fl = rules.service_flags(svc)
            sev = "high" if any("shell" in f or "tool" in f for f in fl) else ("medium" if fl else "info")
            prows.append((svc["ts"], "Service", "HKLM\\SYSTEM\\%s\\Services\\%s" % (system.control_set(), svc["name"]),
                          svc["name"], (svc["image"] + ("  [ServiceDll " + svc["dll"] + "]" if svc["dll"] else "") +
                                        "  start=%s account=%s" % (svc["start"], svc["account"])), "; ".join(fl), sev))
        for t in winart.task_cache(software):
            fl = ["hidden (no SD)"] if t["hidden"] else []
            fl += [x[3] for x in rules.scan_text(t["actions"])]
            prows.append((t["ts"], "Task (registry)", "TaskCache\\Tree" + t["path"], t["path"], t["actions"], "; ".join(fl),
                          "high" if t["hidden"] else ("medium" if fl else "info")))
        # IFEO / SilentProcessExit
        if software:
            base = "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
            for k in software.subkeys(software.get(base)):
                dbg = software.value(k, "Debugger")
                if dbg:
                    prows.append((k.lastwrite, "IFEO Debugger", "HKLM\\SOFTWARE\\" + base + "\\" + k.name, k.name, str(dbg),
                                  "debugger hijack", "high"))
            base = "Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
            for k in software.subkeys(software.get(base)):
                mp = software.value(k, "MonitorProcess")
                if mp:
                    prows.append((k.lastwrite, "SilentProcessExit", "HKLM\\SOFTWARE\\" + base + "\\" + k.name, k.name, str(mp),
                                  "monitor process on exit", "high"))
        # SafeBoot entries added later than the rest
        if system:
            for mode in ("Minimal", "Network"):
                kp = system.control_set() + "\\Control\\SafeBoot\\" + mode
                kids = system.subkeys(system.get(kp))
                if kids:
                    days = Counter((k.lw // (86400 * 10_000_000)) for k in kids)
                    common = days.most_common(1)[0][0]
                    for k in kids:
                        if abs(k.lw // (86400 * 10_000_000) - common) > 1:
                            prows.append((k.lastwrite, "SafeBoot entry", "HKLM\\SYSTEM\\" + kp + "\\" + k.name, k.name,
                                          str(system.value(k, "", "")), "added after the OS install: runs in Safe Mode", "high"))
        con.executemany("INSERT INTO persist(ts,kind,location,name,value,flags,sev) VALUES(?,?,?,?,?,?,?)", prows)
        # checks
        self._reg_checks(con)
        # execution evidence from the registry
        erows = []
        if system:
            cs = system.control_set()
            sc = system.value(cs + "\\Control\\Session Manager\\AppCompatCache", "AppCompatCache")
            if isinstance(sc, bytes):
                for e in winart.parse_shimcache(sc):
                    erows.append((None, "ShimCache", e["path"], _base(e["path"]), "position %d, file modified %s" % (e["pos"], e["modified"] or "?"),
                                  "", "", json.dumps({"modified": e["modified"], "pos": e["pos"]})))
        for b in winart.bam(system):
            erows.append((b["ts"], "BAM", b["path"], _base(b["path"]), "last run (background activity moderator)",
                          sid_user.get(b["sid"], b["sid"]), "", ""))
        for a in winart.amcache(H.get("Amcache")):
            if a["os"] == 1:
                continue
            erows.append((a["ts"], "Amcache", a["path"], _base(a["path"]),
                          "first seen; %s %s linked %s" % (a["publisher"], a["version"], a["linkdate"]), "", a["sha1"],
                          json.dumps({"size": a["size"]})))
        for label, h in H.items():
            if not label.startswith("NTUSER "):
                continue
            user = label[7:]
            for u in winart.userassist(h):
                erows.append((u["ts"], "UserAssist", u["path"], _base(u["path"]), "GUI launch, run count %s" % u["count"], user, "", ""))
            for r in winart.runmru(h):
                erows.append((r["ts"], "RunMRU", r["cmd"], _base(rules.image_path_of(r["cmd"])), "typed in Win+R (rank %d)" % r["rank"], user, "", ""))
            arows = [(r["ts"], "RDP client history", r["host"], "user hint " + r["user"], "", "") for r in winart.rdp_outbound(h)]
            arows += [(r["ts"], "Typed path", r["path"], "Explorer address bar", "", "") for r in winart.typed_paths(h)]
            wp = h.value("Control Panel\\Desktop", "Wallpaper")
            if wp:
                k = h.get("Control Panel\\Desktop")
                arows.append((k.lastwrite if k else None, "Wallpaper", str(wp), "user " + user, str(wp), ""))
            con.executemany("INSERT INTO artifacts(ts,kind,title,detail,path,extra) VALUES(?,?,?,?,?,?)", arows)
        ins_exec(con, erows)

    def _reg_checks(self, con):
        H = self.hives
        rows = []
        for hv, path, value, test, sev, title, why in rules.REG_CHECKS:
            h = H.get(hv)
            if not h:
                continue
            p = path.replace("CS\\", h.control_set() + "\\") if path.startswith("CS\\") else path
            k = h.get(p)
            if not k:
                continue
            for v in h.values(k):
                if v.name.lower() == value.lower():
                    try:
                        hit = test(v.data)
                    except Exception:
                        hit = False
                    if hit:
                        rows.append((HIVE_LABEL.get(hv, hv), p, v.name, v.text(600), sev, title, why, k.lastwrite))
        sw = H.get("SOFTWARE")
        if sw:
            for base in ("Microsoft\\Windows Defender\\Exclusions", "Policies\\Microsoft\\Windows Defender\\Exclusions"):
                for k in sw.subkeys(sw.get(base)):
                    for v in sw.values(k):
                        rows.append(("HKLM\\SOFTWARE", base + "\\" + k.name, v.name, v.text(200), "high",
                                     "Defender exclusion (%s)" % k.name, "excluded from scanning", k.lastwrite))
        con.executemany("INSERT INTO regchecks(hive,path,value,data,sev,title,why,ts) VALUES(?,?,?,?,?,?,?,?)", rows)

    # --------------------------------------------------------------- evtx ---
    CMD_FIELDS = ("CommandLine", "ScriptBlockText", "ImagePath", "ServiceFileName", "TaskContent", "ParentCommandLine",
                  "Payload", "HostApplication", "Details", "TargetObject", "Data1", "param1", "ContextInfo", "Value", "New Value")

    def stage_evtx(self, con, src):
        files = src.glob("\\Windows\\System32\\winevt\\Logs\\*.evtx")
        sizes = {}
        try:
            for r in con.execute("SELECT path, size FROM files WHERE path LIKE '\\Windows\\System32\\winevt\\Logs\\%' AND in_use=1"):
                sizes[r[0].lower()] = r[1] or 0
        except Exception:
            pass
        files.sort(key=lambda p: -sizes.get(p.lower(), 0))
        self._set(total=len(files))
        logs = []
        sid_user = getattr(self, "sid_user", {})
        for i, path in enumerate(files):
            if self.cancel:
                return
            self._set(done=i, msg=path.rsplit("\\", 1)[-1])
            try:
                data = src.read(path)
            except Exception as e:
                self._err("read " + path, e)
                continue
            if not data or data[:8] != b"ElfFile\0":
                continue
            info = evtx.file_info(data)
            evrows, frows, xrows, prows = [], [], [], []
            n, first, last, ids = 0, None, None, []
            fname = path.rsplit("\\", 1)[-1]
            for ev in evtx.iter_events(data):
                n += 1
                ts = ev["ts"]
                if ts:
                    first = ts if not first or ts < first else first
                    last = ts if not last or ts > last else last
                ids.append(ev["rec"])
                summ = rules.event_summary(ev)
                d = ev["data"]
                user = sid_user.get(ev["user"], ev["user"])
                evrows.append((ts, ev["channel"] or fname[:-5], ev["provider"], ev["eid"], ev["rec"], ev["computer"], user, summ,
                               json.dumps(d, ensure_ascii=False)[:20000], fname))
                ref = "ev:%s:%s" % (fname, ev["rec"])
                for sev, cat, title in rules.event_findings(ev, summ):
                    frows.append((ts, sev, cat, title, summ[:600], "event log", ref, "%s/%s" % (ev["channel"], ev["eid"])))
                text = " ".join(str(d.get(k, "")) for k in self.CMD_FIELDS if d.get(k))
                if text:
                    for rid, sev, cat, title, m in rules.scan_text(text):
                        frows.append((ts, sev, cat, title, ("%s %s: %s" % (ev["channel"], ev["eid"], text))[:600], "event log", ref, rid))
                ch, eid = (ev["channel"] or "").lower(), ev["eid"]
                if ch == "security" and eid == 4688:
                    img = d.get("NewProcessName", "")
                    xrows.append((ts, "Security 4688", img, _base(img), d.get("CommandLine", "") or "", d.get("SubjectUserName", ""), "",
                                  json.dumps({"parent": d.get("ParentProcessName", ""), "ref": ref})))
                elif "sysmon" in ch and eid == 1:
                    img = d.get("Image", "")
                    m = re.search(r"SHA1=([0-9A-Fa-f]{40})", d.get("Hashes", "") or "")
                    xrows.append((ts, "Sysmon 1", img, _base(img), d.get("CommandLine", "") or "", d.get("User", ""),
                                  m.group(1) if m else "", json.dumps({"parent": d.get("ParentImage", ""), "ref": ref})))
                elif ch == "system" and eid == 7045:
                    prows.append((ts, "Service (event 7045)", ref, d.get("ServiceName", ""), d.get("ImagePath", ""),
                                  "; ".join(rules.service_flags({"name": d.get("ServiceName", ""), "image": d.get("ImagePath", "")})), "medium"))
                elif ch == "security" and eid == 4698:
                    tc = d.get("TaskContent", "") or ""
                    cmd = " ".join(re.findall(r"<(?:Command|Arguments)>([^<]*)<", tc))
                    prows.append((ts, "Task (event 4698)", ref, d.get("TaskName", ""), cmd, "", "medium"))
                elif "wmi-activity" in ch and eid == 5861:
                    prows.append((ts, "WMI subscription", ref, "", summ, "", "high"))
                if len(evrows) >= 5000:
                    self._flush_ev(con, evrows, frows, xrows, prows)
                    evrows, frows, xrows, prows = [], [], [], []
            self._flush_ev(con, evrows, frows, xrows, prows)
            gaps = _id_gaps(ids)
            logs.append({"file": fname, "path": path, "records": n, "first": first, "last": last, "size": len(data),
                         "dirty": info.get("dirty"), "gaps": gaps[:20], "gap_total": sum(b - a - 1 for a, b in gaps)})
            if gaps:
                con.execute("INSERT INTO findings(ts,sev,cat,title,detail,source,ref,rule) VALUES(?,?,?,?,?,?,?,?)",
                            (None, "medium", "anti-forensics", "Missing event record IDs",
                             "%s: %d gap(s), %d records missing, e.g. after %s" % (fname, len(gaps), sum(b - a - 1 for a, b in gaps), gaps[0][0]),
                             "event log", "log:" + fname, "record-gap"))
            con.commit()
        set_meta(con, "evtx", logs)
        # brute force: many failed logons from one source
        for r in con.execute("""SELECT json_extract(data,'$.IpAddress') ip, COUNT(*) c, MIN(ts), MAX(ts),
                                COUNT(DISTINCT json_extract(data,'$.TargetUserName')) users
                                FROM events WHERE channel='Security' AND eid=4625 GROUP BY ip HAVING c>=20""").fetchall():
            pub = rules.is_public_ip(r[0] or "")
            con.execute("INSERT INTO findings(ts,sev,cat,title,detail,source,ref,rule) VALUES(?,?,?,?,?,?,?,?)",
                        (r[2], "high" if pub else "medium", "initial-access", "Password guessing" + (" from public IP" if pub else ""),
                         "%s failed logons from %s against %s account(s), %s → %s" % (r[1], r[0] or "?", r[4], r[2], r[3]),
                         "event log", "ip:%s" % r[0], "bruteforce"))

    def _flush_ev(self, con, evrows, frows, xrows, prows):
        con.executemany("INSERT INTO events(ts,channel,provider,eid,rec,computer,user,summary,data,file) VALUES(?,?,?,?,?,?,?,?,?,?)", evrows)
        con.executemany("INSERT INTO findings(ts,sev,cat,title,detail,source,ref,rule) VALUES(?,?,?,?,?,?,?,?)", frows)
        ins_exec(con, xrows)
        con.executemany("INSERT INTO persist(ts,kind,location,name,value,flags,sev) VALUES(?,?,?,?,?,?,?)", prows)

    # ----------------------------------------------------------- prefetch ---
    def stage_prefetch(self, con, src):
        files = src.glob("\\Windows\\Prefetch\\*.pf")
        self._set(total=len(files))
        rows = []
        for i, path in enumerate(files):
            self._set(done=i)
            try:
                raw = src.read(path)
                if not raw:
                    continue
                pf = winart.parse_prefetch(raw)
            except Exception as e:
                self._err("prefetch " + path.rsplit("\\", 1)[-1], e)
                continue
            exe_path = winart.device_to_path(pf["path"]) if pf["path"] else pf["exe"]
            created = None
            r = con.execute("SELECT si_c FROM files WHERE path=? COLLATE NOCASE", (path,)).fetchone()
            if r:
                created = r[0]
            extra = json.dumps({"pf": path.rsplit("\\", 1)[-1], "count": pf["count"], "runs": pf["runs"],
                                "files": [winart.device_to_path(f) for f in pf["files"][:400]], "volumes": pf["volumes"],
                                "pf_created": created})
            for j, t in enumerate(pf["runs"]):
                rows.append((t, "Prefetch", exe_path, pf["exe"], "run %d of last %d (total runs %s)" % (j + 1, len(pf["runs"]), pf["count"]),
                             "", "", extra if j == 0 else json.dumps({"pf": path.rsplit("\\", 1)[-1]})))
            if created:
                rows.append((created, "Prefetch (first run)", exe_path, pf["exe"], ".pf file created ≈ first run (+~10 s)", "", "",
                             json.dumps({"pf": path.rsplit("\\", 1)[-1]})))
        ins_exec(con, rows)

    # -------------------------------------------------------------- tasks ---
    def stage_tasks(self, con, src):
        files = src.under("\\Windows\\System32\\Tasks")
        self._set(total=len(files))
        rows = []
        for i, path in enumerate(files):
            try:
                raw = src.read(path, 1 << 20)
                if not raw:
                    continue
                t = winart.parse_task_xml(raw)
            except Exception:
                continue
            created = None
            r = con.execute("SELECT si_c FROM files WHERE path=? COLLATE NOCASE", (path,)).fetchone()
            if r:
                created = r[0]
            action = " | ".join(t["actions"])
            flags = []
            if t["hidden"]:
                flags.append("hidden")
            for rid, sev, cat, title, m in rules.scan_text(action):
                flags.append(title)
            for a in t["actions"]:
                w = rules.odd_path(rules.image_path_of(a))
                if w:
                    flags.append("in " + w)
                th = rules.tool_hit(a)
                if th:
                    flags.append("tool: " + th[0])
            if not t["author"] and not t["description"]:
                flags.append("no author/description")
            sev = "high" if any(x.startswith("tool") or "Shadow" in x for x in flags) else ("medium" if any(
                not x.startswith("no author") and x != "hidden" for x in flags) else ("low" if flags else "info"))
            rows.append((created, "Scheduled task", path, t["uri"] or path[len("\\Windows\\System32\\Tasks"):], action,
                         "; ".join(flags + (["registered %s by %s, runs as %s" % (t["date"], t["author"] or "?", t["user"] or "?")])), sev))
        con.executemany("INSERT INTO persist(ts,kind,location,name,value,flags,sev) VALUES(?,?,?,?,?,?,?)", rows)

    # ------------------------------------------------------- user artifacts ---
    def stage_user(self, con, src):
        arows, frows, prows = [], [], []

        def mtime(path, col="si_m"):
            r = con.execute("SELECT %s FROM files WHERE path=? COLLATE NOCASE" % col, (path,)).fetchone()
            return r[0] if r else None

        self._set(msg="recycle bin")
        for p in src.glob("\\$Recycle.Bin\\*\\$I*"):
            try:
                r = winart.parse_recycle_i(src.read(p, 8192) or b"")
                arows.append((r["deleted"], "Recycle Bin", r["path"], "deleted, %s bytes (SID folder %s)" % (r["size"], p.split("\\")[2]), p, ""))
            except Exception:
                pass
        self._set(msg="shortcuts")
        lnks = src.glob("\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk") + src.glob("\\Users\\*\\Desktop\\*.lnk")
        for p in lnks[:20000]:
            try:
                r = winart.parse_lnk(src.read(p, 1 << 20) or b"")
            except Exception:
                continue
            detail = "user %s; target times c=%s m=%s; %s" % (p.split("\\")[2], r["target_created"], r["target_modified"],
                                                              ("args: " + r["args"]) if r["args"] else "")
            arows.append((mtime(p), "Shortcut (LNK)", r["target"] or r["name"], detail, p, json.dumps(r)))
            for rid, sev, cat, title, m in rules.scan_text(r["args"]):
                frows.append((mtime(p), sev, cat, title, "LNK %s: %s %s" % (p, r["target"], r["args"]), "lnk", "path:" + p, rid))
        self._set(msg="startup folders")
        starts = src.glob("\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*") + \
            src.glob("\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
        for p in starts:
            if p.lower().endswith("desktop.ini"):
                continue
            val = p
            if p.lower().endswith(".lnk"):
                try:
                    r = winart.parse_lnk(src.read(p) or b"")
                    val = (r["target"] + " " + r["args"]).strip()
                except Exception:
                    pass
            flags = [x[3] for x in rules.scan_text(val)]
            w = rules.odd_path(val)
            if w:
                flags.append("in " + w)
            prows.append((mtime(p, "si_c"), "Startup folder", p, p.rsplit("\\", 1)[-1], val, "; ".join(flags), "medium" if flags else "low"))
        self._set(msg="PowerShell history")
        for p in src.glob("\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\*.txt"):
            data = src.read(p, 32 << 20) or b""
            lines = data.decode("utf-8", "replace").splitlines()
            last = mtime(p)
            user = p.split("\\")[2]
            for n, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                arows.append((last if n == len(lines) else None, "PowerShell history",
                              line[:1000], "user %s, line %d of %d (file last written %s)" % (user, n, len(lines), last), p, ""))
                for rid, sev, cat, title, m in rules.scan_text(line):
                    frows.append((None, sev, cat, title, "PSReadLine %s line %d: %s" % (user, n, line[:500]), "psreadline", "path:%s:%d" % (p, n), rid))
        self._set(msg="browser history")
        self._browsers(src, arows, frows)
        self._set(msg="remote access & Defender logs")
        self._text_logs(src, arows)
        con.executemany("INSERT INTO artifacts(ts,kind,title,detail,path,extra) VALUES(?,?,?,?,?,?)", arows)
        con.executemany("INSERT INTO findings(ts,sev,cat,title,detail,source,ref,rule) VALUES(?,?,?,?,?,?,?,?)", frows)
        con.executemany("INSERT INTO persist(ts,kind,location,name,value,flags,sev) VALUES(?,?,?,?,?,?,?)", prows)

    def _browsers(self, src, arows, frows):
        targets = []
        for p in src.glob("\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History"):
            targets.append(("Chrome", p))
        for p in src.glob("\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History"):
            targets.append(("Edge", p))
        for p in src.glob("\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite"):
            targets.append(("Firefox", p))
        from util import webkit, unix
        for browser, p in targets:
            data = src.read(p, 512 << 20)
            if not data:
                continue
            user = p.split("\\")[2]
            fd, tmp = tempfile.mkstemp(suffix=".sqlite")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                c = sqlite3.connect("file:%s?mode=ro&immutable=1" % tmp.replace("\\", "/"), uri=True)
                try:
                    if browser == "Firefox":
                        for url, title, vd in c.execute("SELECT p.url, p.title, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id ORDER BY v.visit_date DESC LIMIT 5000"):
                            arows.append((unix(vd, 1_000_000), "Browser visit", url, "%s %s: %s" % (browser, user, title or ""), p, ""))
                    else:
                        for url, title, vt in c.execute("SELECT u.url, u.title, v.visit_time FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time DESC LIMIT 5000"):
                            arows.append((webkit(vt), "Browser visit", url, "%s %s: %s" % (browser, user, title or ""), p, ""))
                        try:
                            q = "SELECT d.target_path, d.tab_url, d.start_time, d.total_bytes, (SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index DESC LIMIT 1) FROM downloads d"
                            for target, tab, st, size, url in c.execute(q):
                                arows.append((webkit(st), "Browser download", target, "%s %s: %s bytes from %s" % (browser, user, size, url or tab), p, ""))
                                ext = (target or "").rsplit(".", 1)[-1].lower()
                                if ext in rules.EXEC_EXT or ext in ("zip", "rar", "7z", "iso", "img", "vhd"):
                                    th = rules.tool_hit(target)
                                    frows.append((webkit(st), "high" if th else "low", th[1] if th else "initial-access",
                                                  "Tool downloaded: " + th[0] if th else "Executable / archive downloaded",
                                                  "%s %s: %s ← %s" % (browser, user, target, url or tab), "browser", "path:" + p, "download"))
                        except sqlite3.Error:
                            pass
                finally:
                    c.close()
            except Exception as e:
                self._err("browser " + p, e)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _text_logs(self, src, arows):
        pats = ["\\ProgramData\\AnyDesk\\connection_trace.txt", "\\ProgramData\\AnyDesk\\ad_svc.trace",
                "\\Users\\*\\AppData\\Roaming\\AnyDesk\\connection_trace.txt", "\\Users\\*\\AppData\\Roaming\\AnyDesk\\ad.trace",
                "\\Program Files\\TeamViewer\\Connections_incoming.txt", "\\Program Files (x86)\\TeamViewer\\Connections_incoming.txt",
                "\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-*.log"]
        keep = re.compile(r"incoming|logged in from|accept|connection from|remote|DETECTION|Threat|Exclusion|Tamper|disabled", re.I)
        tsrx = re.compile(r"(\d{4}-\d{2}-\d{2})[ T,]+(\d{2}:\d{2}(?::\d{2})?)|(\d{2})-(\d{2})-(\d{4}) (\d{2}:\d{2}:\d{2})")
        for pat in pats:
            for p in src.glob(pat) if "*" in pat else ([pat] if src.read(pat, 1) is not None else []):
                data = src.read(p, 64 << 20) or b""
                text = data.decode("utf-16") if data[:2] in (b"\xff\xfe",) else data.decode("utf-8", "replace")
                kind = "Defender MPLog" if "mplog" in p.lower() else "Remote access log"
                n = 0
                for line in text.splitlines():
                    if not keep.search(line) or n > 5000:
                        continue
                    m = tsrx.search(line)
                    ts = None
                    if m:
                        if m.group(1):
                            ts = m.group(1) + " " + (m.group(2) if len(m.group(2)) > 5 else m.group(2) + ":00") + ".000"
                        else:
                            ts = "%s-%s-%s %s.000" % (m.group(5), m.group(4), m.group(3), m.group(6))
                    arows.append((ts, kind, line.strip()[:800], "%s (times as written in the log, often local)" % p.rsplit("\\", 1)[-1], p, ""))
                    n += 1


def _base(p):
    return (p or "").replace("/", "\\").rsplit("\\", 1)[-1]


def ins_exec(con, rows):
    """Insert execution rows with paths normalised (drive letters, \\??\\, %SystemRoot%) so sources group together."""
    out = []
    for r in rows:
        r = list(r)
        if r[1] != "RunMRU":
            r[2] = rules.normalize_path(r[2])
        out.append(tuple(r))
    con.executemany("INSERT INTO exec(ts,source,path,name,detail,user,sha1,extra) VALUES(?,?,?,?,?,?,?,?)", out)


def _id_gaps(ids):
    s = sorted(set(i for i in ids if i))
    out = []
    for a, b in zip(s, s[1:]):
        if b - a > 1:
            out.append((a, b))
    return out


# ================================================================= analysis ===
def analyze(con, src, ix=None, overrides=None):
    """Ransomware impact analysis: extension, encrypted files, notes, window, payload, key events."""
    overrides = overrides or {}
    con.execute("UPDATE files SET enc=0, note=0, orig=NULL WHERE enc=1 OR note=1")
    have_mft = con.execute("SELECT COUNT(*) FROM files").fetchone()[0] > 0
    result = {"extensions": [], "chosen": [], "window": None, "notes": [], "payload": [], "encrypted": 0, "dirs": 0}

    # 1. extension candidates
    cands = []
    if have_mft:
        rows = con.execute("""SELECT ext, COUNT(*) n, COUNT(DISTINCT parent) d FROM files
                              WHERE in_use=1 AND is_dir=0 AND ext<>'' GROUP BY ext HAVING n>=10 ORDER BY n DESC LIMIT 4000""").fetchall()
        for ext, n, d in rows:
            known = ext in rules.KNOWN_RANSOM_EXTS
            if ext in rules.COMMON_EXTS and not known:
                continue
            names = [r[0] for r in con.execute("SELECT name FROM files WHERE in_use=1 AND is_dir=0 AND ext=? LIMIT 3000", (ext,))]
            prev = Counter()
            for nm in names:
                parts = nm.lower().split(".")
                if len(parts) >= 3:
                    prev[parts[-2]] += 1
            doc = sum(c for e, c in prev.items() if e in rules.DOC_EXTS)
            # appended-id styles (Phobos/Dharma: name.ext.id[XXXX].[mail].ext)
            idstyle = sum(1 for nm in names if re.search(r"\.id[\[\-][0-9a-f]{6,}", nm, re.I) or "@" in nm)
            ratio = (doc + idstyle) / max(1, len(names))
            ts = [r[0] for r in con.execute("SELECT si_e FROM files WHERE in_use=1 AND is_dir=0 AND ext=? AND si_e IS NOT NULL ORDER BY si_e", (ext,))]
            spread = None
            if len(ts) >= 5:
                a, b = parse_ts(ts[int(len(ts) * 0.05)]), parse_ts(ts[int(len(ts) * 0.95) - 1])
                spread = (b - a).total_seconds() / 3600 if a and b else None
            score = d * ratio * (2 if known else 1) * (2 if spread is not None and spread < 48 else 1)
            strong = (ratio >= 0.5 and n >= 20 and d >= 3) or (known and n >= 5)
            cands.append({"ext": ext, "files": n, "dirs": d, "doc_ratio": round(ratio, 2), "known": known,
                          "spread_hours": round(spread, 1) if spread is not None else None, "score": round(score, 1), "strong": strong,
                          "samples": names[:6], "prev_types": prev.most_common(8)})
        cands.sort(key=lambda c: -c["score"])
    result["extensions"] = cands[:15]
    chosen = overrides.get("extensions")
    if chosen is None:
        chosen = [c["ext"] for c in cands if c["strong"]][:3]
        if len(chosen) > 1:
            top = cands[0]["score"] if cands else 0
            chosen = [e for e in chosen if next(c["score"] for c in cands if c["ext"] == e) >= top * 0.2]
    result["chosen"] = chosen

    # 2. mark encrypted files, map original names from USN renames
    if chosen and have_mft:
        q = ",".join("?" * len(chosen))
        con.execute("UPDATE files SET enc=1 WHERE in_use=1 AND is_dir=0 AND ext IN (%s)" % q, chosen)
        orig = {}
        for rec, old, new_ts in con.execute(
                """SELECT n.rec, o.name, n.ts FROM usn n JOIN usn o ON o.rec=n.rec AND o.usn<n.usn AND o.usn>n.usn-100000
                   AND (o.reason & 4096)<>0 WHERE (n.reason & 8192)<>0 AND n.ext IN (%s)""" % q, chosen):
            orig[rec] = old
        if orig:
            con.executemany("UPDATE files SET orig=? WHERE rec=? AND enc=1", [(v, k) for k, v in orig.items()])

        def strip_ext(name):
            n = name
            for e in chosen:
                if n.lower().endswith("." + e):
                    n = n[:-len(e) - 1]
            n = re.sub(r"\.id[\[\-][^.]*(\.\[[^\]]*\])?$", "", n, flags=re.I)
            n = re.sub(r"\.\[[^\]]*@[^\]]*\]$", "", n)
            return n
        con.create_function("strip_ext", 1, strip_ext)
        con.execute("UPDATE files SET orig=strip_ext(name) WHERE enc=1 AND orig IS NULL")
        r = con.execute("SELECT COUNT(*), COUNT(DISTINCT parent) FROM files WHERE enc=1").fetchone()
        result["encrypted"], result["dirs"] = r[0], r[1]

    # 3. window
    window = overrides.get("window")
    if not window and result["encrypted"]:
        ts = [r[0] for r in con.execute("SELECT si_e FROM files WHERE enc=1 AND si_e IS NOT NULL ORDER BY si_e")]
        lo, hi = ts[int(len(ts) * 0.005)], ts[min(len(ts) - 1, int(len(ts) * 0.995))]
        q = ",".join("?" * len(chosen))
        u = con.execute("SELECT MIN(ts), MAX(ts), COUNT(*) FROM usn WHERE (reason & 8192)<>0 AND ext IN (%s)" % q, chosen).fetchone()
        src_note = "MFT entry-modified times of encrypted files (0.5–99.5 percentile)"
        if u and u[0] and u[2] >= 5:
            lo = min(lo, u[0])
            hi = max(hi, u[1])
            src_note += " and USN rename records"
        window = {"start": lo, "end": hi, "basis": src_note}
    if not window:
        # no encryption by extension: fall back to the busiest burst of document modifications
        burst = _burst(con)
        if burst:
            window = {"start": burst[0], "end": burst[1], "basis": "burst of document modifications (no ransom extension found)"}
    result["window"] = window

    # 4. ransom notes
    notes = []
    if have_mft:
        if window:
            a, b = shift(window["start"], hours=-3), shift(window["end"], hours=3)
        else:
            mx = con.execute("SELECT MAX(si_c) FROM files WHERE si_c < '2100'").fetchone()[0]
            a, b = shift(mx, days=-30), mx
        min_dirs = 4 if not result["dirs"] else max(4, min(50, int(result["dirs"] * 0.02)))
        for name, c, d, t0, t1, smin, smax in con.execute(
                """SELECT lower(name), COUNT(*), COUNT(DISTINCT parent), MIN(si_c), MAX(si_c), MIN(size), MAX(size) FROM files
                   WHERE in_use=1 AND is_dir=0 AND enc=0 AND si_c BETWEEN ? AND ? GROUP BY lower(name)
                   HAVING COUNT(DISTINCT parent) >= ? ORDER BY 3 DESC LIMIT 200""", (a, b, min_dirs)):
            ext = name.rsplit(".", 1)[-1] if "." in name else ""
            if name in rules.BENIGN_REPEATED or name.startswith("~$") or (ext not in rules.NOTE_EXTS):
                continue
            if (smax or 0) > 2_000_000:
                continue
            named = bool(rules.NOTE_NAME_RX.search(name))
            if not named and d < max(10, min_dirs * 2):
                continue
            notes.append({"name": name, "copies": c, "dirs": d, "first": t0, "last": t1, "size": [smin, smax], "named": named})
        notes.sort(key=lambda n: (-int(n["named"]), -n["dirs"]))
        notes = notes[:6]
        for n in notes:
            con.execute("UPDATE files SET note=1 WHERE lower(name)=? AND in_use=1 AND si_c BETWEEN ? AND ?", (n["name"], a, b))
            sample = con.execute("SELECT path FROM files WHERE note=1 AND lower(name)=? ORDER BY si_c LIMIT 1", (n["name"],)).fetchone()
            n["sample"] = sample[0] if sample else ""
            n["text"] = ""
            if src and sample:
                try:
                    raw = src.read(sample[0], 64 << 10) or b""
                    n["text"] = _note_text(raw)
                except Exception:
                    pass
            n["iocs"] = _iocs(n["text"])
    result["notes"] = notes

    # 5. payload candidates
    result["payload"] = _payload(con, window, chosen, notes) if window else []

    # 6. ransomware extension registered in the registry?
    if ix is not None and getattr(ix, "hives", None):
        for label in ["SOFTWARE"] + [k for k in ix.hives if k.startswith("UsrClass ")]:
            h = ix.hives.get(label)
            if not h:
                continue
            for e in chosen:
                k = h.get(("Classes\\." if label == "SOFTWARE" else ".") + e)
                if k:
                    icon = h.get(("Classes\\" if label == "SOFTWARE" else "") + (str(h.value(k, "", "")) or "") + "\\DefaultIcon")
                    con.execute("INSERT INTO regchecks(hive,path,value,data,sev,title,why,ts) VALUES(?,?,?,?,?,?,?,?)",
                                (HIVE_LABEL.get(label, label), ("Classes\\." if label == "SOFTWARE" else ".") + e, "(default)",
                                 str(h.value(k, "", "")) + (("  icon=" + str(h.value(icon, "", ""))) if icon else ""), "high",
                                 "Ransomware extension registered (.%s)" % e, "file type and icon set by the ransomware", k.lastwrite))

    # 7. analysis findings
    frows = []
    if window:
        frows.append((window["start"], "high", "impact", "Encryption starts",
                      "first file renamed/encrypted (%s); extensions: %s" % (window["basis"], ", ".join("." + e for e in chosen) or "none"), "analysis", "window", "enc-start"))
        frows.append((window["end"], "high", "impact", "Encryption ends", "%s files in %s folders" % (result["encrypted"], result["dirs"]), "analysis", "window", "enc-end"))
    for n in notes:
        frows.append((n["first"], "high", "impact", "Ransom note dropped: " + n["name"], "%d copies in %d folders" % (n["copies"], n["dirs"]), "analysis", "note:" + n["name"], "note"))
    for p in result["payload"][:5]:
        if p["score"] >= 3:
            frows.append((p["ts"], "high" if p["score"] >= 5 else "medium", "execution", "Possible ransomware payload",
                          "%s (%s)" % (p["path"], "; ".join(p["why"])), "analysis", "exec:" + p["path"], "payload"))
    if have_mft and window:
        a, b = shift(window["start"], days=-7), window["end"]
        for path, sic, fnc in con.execute("""SELECT path, si_c, fn_c FROM files WHERE in_use=1 AND flags LIKE '%SI<FN%'
                                             AND ext IN ('exe','dll','ps1','bat','sys','scr') AND fn_c BETWEEN ? AND ? LIMIT 200""", (a, b)):
            frows.append((fnc, "medium", "anti-forensics", "Timestomped executable", "%s: $SI created %s but $FN created %s" % (path, sic, fnc), "analysis", "path:" + path, "timestomp"))
    for ts, path in con.execute("""SELECT ts, path FROM usn WHERE (reason & 512)<>0 AND name LIKE '%{3808876b-c176-4e48-b7ae-04046e6cc752}%'
                                   GROUP BY name ORDER BY ts LIMIT 50"""):
        frows.append((ts, "high", "anti-recovery", "Shadow copy storage file deleted", path, "analysis", "usn:" + path, "vss-file"))
    for ts, path in con.execute("""SELECT ts, path FROM usn WHERE (reason & 512)<>0 AND (ext IN ('exe','dll','ps1','bat','cmd','scr','vbs','js','hta')) 
                                   AND ts BETWEEN ? AND ? GROUP BY path ORDER BY ts LIMIT 200""",
                                (shift(window["start"], hours=-6) if window else "9999", shift(window["end"], hours=6) if window else "9999")):
        frows.append((ts, "medium", "anti-forensics", "Executable/script deleted around encryption", path, "analysis", "usn:" + path, "exe-deleted"))
    con.executemany("INSERT INTO findings(ts,sev,cat,title,detail,source,ref,rule) VALUES(?,?,?,?,?,?,?,?)", frows)

    # 8. span for the timeline
    if window:
        span = {"from": shift(window["start"], days=-(get_meta(con, "options", {}) or {}).get("span_days", 14)),
                "to": shift(window["end"], days=2)}
    else:
        mx = con.execute("SELECT MAX(ts) FROM events WHERE ts < '2100'").fetchone()[0] or \
            con.execute("SELECT MAX(si_m) FROM files WHERE si_m < '2100'").fetchone()[0]
        span = {"from": shift(mx, days=-14), "to": shift(mx, days=1)} if mx else None
    if overrides.get("span"):
        span = overrides["span"]
    result["span"] = span
    set_meta(con, "impact", result)
    _story(con, result)


def _burst(con):
    rows = con.execute("""SELECT substr(si_m,1,16) m, COUNT(*) c FROM files WHERE in_use=1 AND is_dir=0 AND ext IN
                          ('doc','docx','xls','xlsx','pdf','jpg','png','txt','pptx','zip') GROUP BY m ORDER BY c DESC LIMIT 1""").fetchone()
    if not rows or rows[1] < 200:
        return None
    return rows[0] + ":00.000", rows[0] + ":59.999"


def _note_text(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        t = raw.decode("utf-16", "replace")
    elif raw[:3] == b"\xef\xbb\xbf":
        t = raw[3:].decode("utf-8", "replace")
    elif raw[1:2] == b"\0" and raw[3:4] == b"\0":
        t = raw.decode("utf-16-le", "replace")
    else:
        t = raw.decode("utf-8", "replace")
    if "<html" in t.lower() or "<body" in t.lower() or "<div" in t.lower():
        t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", t)
        t = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</h\d>", "\n", t)
        t = re.sub(r"<[^>]+>", " ", t)
        import html
        t = html.unescape(t)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n\s*\n+", "\n\n", t)
    return t.strip()[:12000]


def _iocs(text):
    if not text:
        return {}
    out = {
        "emails": sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)))[:20],
        "onion": sorted(set(re.findall(r"\b[a-z2-7]{16,56}\.onion\b[^\s\"'<>]*", text, re.I)))[:20],
        "urls": sorted(set(u for u in re.findall(r"https?://[^\s\"'<>]+", text) if ".onion" not in u))[:20],
        "btc": sorted(set(re.findall(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)))[:10],
        "tox": sorted(set(re.findall(r"\b[0-9A-F]{76}\b", text)))[:5],
        "ids": sorted(set(re.findall(r"(?i)(?:personal|your|decryption|client|victim)[ _-]?(?:id|key)\s*[:=]?\s*([A-Za-z0-9+/=_-]{8,})", text)))[:5],
    }
    return {k: v for k, v in out.items() if v}


def _payload(con, window, exts, notes):
    a6, a48, end = shift(window["start"], hours=-6), shift(window["start"], hours=-48), shift(window["end"], hours=1)
    note_names = [n["name"] for n in notes]
    cand = {}

    def add(path, ts, why, pts, src):
        if not path:
            return
        key = rules.normalize_path(path).lower()
        if key.startswith(("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\program files\\windows defender")):
            return
        if not key or key.endswith(("\\svchost.exe", "\\conhost.exe", "\\backgroundtaskhost.exe", "\\runtimebroker.exe",
                                    "\\searchprotocolhost.exe", "\\searchfilterhost.exe", "\\dllhost.exe", "\\wmiprvse.exe",
                                    "\\taskhostw.exe", "\\msmpeng.exe", "\\mpcmdrun.exe", "\\smartscreen.exe", "\\sppsvc.exe",
                                    "\\compattelrunner.exe", "\\microsoftedgeupdate.exe", "\\trustedinstaller.exe", "\\tiworker.exe")):
            return
        c = cand.setdefault(key, {"path": rules.normalize_path(path), "ts": ts, "why": [], "score": 0, "sources": set()})
        if ts and (not c["ts"] or ts < c["ts"]):
            c["ts"] = ts
        if why not in c["why"]:
            c["why"].append(why)
            c["score"] += pts
        c["sources"].add(src)

    for ts, source, path, extra in con.execute(
            "SELECT ts, source, path, extra FROM exec WHERE ts BETWEEN ? AND ? AND source NOT IN ('ShimCache')", (a6, end)):
        add(path, ts, "executed shortly before/during encryption", 2, source)
        w = rules.odd_path(path)
        if w:
            add(path, ts, "runs from " + w, 2, source)
        nm = _base(path)
        if looks_random(nm):
            add(path, ts, "random-looking name", 1, source)
        t = rules.tool_hit(path)
        if t:
            add(path, ts, "known tool " + t[0], 1, source)
        if extra and source == "Prefetch":
            try:
                fl = " ".join(json.loads(extra).get("files", [])).lower()
                if any(("." + e).lower() in fl for e in exts) or any(nn in fl for nn in note_names):
                    add(path, ts, "its prefetch references encrypted files / ransom notes", 5, source)
            except ValueError:
                pass
    for path, sic in con.execute("""SELECT path, si_c FROM files WHERE in_use=1 AND is_dir=0 AND ext IN ('exe','dll','ps1','bat','cmd','scr','msi','vbs','js','hta')
                                    AND si_c BETWEEN ? AND ? AND path NOT LIKE '\\Windows\\WinSxS\\%' AND path NOT LIKE '\\Windows\\SoftwareDistribution\\%'
                                    AND path NOT LIKE '\\Windows\\servicing\\%' AND path NOT LIKE '\\ProgramData\\Microsoft\\Windows Defender\\%'
                                    AND path NOT LIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\%' AND path NOT LIKE '\\Windows\\assembly\\%'""", (a48, end)):
        add(path, sic, "created in the 48 h before encryption", 1, "MFT")
        w = rules.odd_path(path)
        if w:
            add(path, sic, "runs from " + w, 2, "MFT")
        if looks_random(_base(path)):
            add(path, sic, "random-looking name", 1, "MFT")
    for path, ts in con.execute("""SELECT path, MIN(ts) FROM usn WHERE (reason & 512)<>0 AND ext IN ('exe','dll','ps1','bat','cmd','scr')
                                   AND ts BETWEEN ? AND ? GROUP BY path""", (a6, shift(window["end"], hours=6))):
        add(path, ts, "deleted right after use (USN)", 2, "USN")
    out = sorted(cand.values(), key=lambda c: (-c["score"], c["ts"] or ""))[:25]
    for c in out:
        c["sources"] = sorted(c["sources"])
    return out


def _story(con, impact):
    span = impact.get("span") or {}
    a, b = span.get("from") or "0000", span.get("to") or "9999"
    rows = con.execute("""SELECT ts, sev, cat, title, detail, source, ref FROM findings WHERE ts BETWEEN ? AND ? AND sev IN ('high','medium')
                          ORDER BY ts""", (a, b)).fetchall()
    out, seen = [], Counter()
    for r in rows:
        key = (r[3], r[4][:60])
        seen[r[3]] += 1
        if seen[r[3]] > 12 and r[1] != "high":
            continue
        if seen[r[3]] > 40:
            continue
        out.append({"ts": r[0], "sev": r[1], "cat": r[2], "title": r[3], "detail": r[4], "source": r[5], "ref": r[6]})
    set_meta(con, "story", out[:400])


# ================================================================= timeline ===
def build_timeline(con):
    con.execute("DELETE FROM timeline")
    impact = get_meta(con, "impact", {}) or {}
    span = impact.get("span") or {}
    a, b = span.get("from") or "0000", span.get("to") or "9999"
    p = (a, b)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'event',channel||' '||eid,summary,'ev:'||id,NULL FROM events WHERE ts BETWEEN ? AND ?", p)
    con.execute("""INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'usn',reasons,path,'usn:'||id,NULL FROM usn
                   WHERE ts BETWEEN ? AND ? AND (reason & 2147483648)<>0""", p)
    con.execute("""INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT si_c,'mft',CASE WHEN note=1 THEN 'note created' WHEN is_dir=1 THEN 'folder created' ELSE 'created' END,
                   path,'f:'||rec,CASE WHEN note=1 THEN 'high' END FROM files WHERE si_c BETWEEN ? AND ? AND enc=0""", p)
    con.execute("""INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT si_m,'mft','modified',path,'f:'||rec,NULL FROM files
                   WHERE si_m BETWEEN ? AND ? AND si_m<>si_c AND enc=0 AND is_dir=0""", p)
    con.execute("""INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT si_e,'mft','encrypted',path||'  ← '||coalesce(orig,''),'f:'||rec,NULL FROM files
                   WHERE enc=1 AND si_e BETWEEN ? AND ?""", p)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'execution',source,path||'  '||coalesce(detail,''),'ex:'||id,NULL FROM exec WHERE ts BETWEEN ? AND ?", p)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'persistence',kind,name||': '||coalesce(value,''),'pe:'||id,sev FROM persist WHERE ts BETWEEN ? AND ?", p)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'registry','key written',hive||'\\'||path,'rk:'||id,NULL FROM regkeys WHERE ts BETWEEN ? AND ?", p)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'registry',kind,hive||'\\'||path||' '||coalesce(value,''),'rc:'||id,'medium' FROM regchanges WHERE ts BETWEEN ? AND ?", p)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'artifact',kind,title||'  '||coalesce(detail,''),'ar:'||id,NULL FROM artifacts WHERE ts BETWEEN ? AND ?", p)
    con.execute("INSERT INTO timeline(ts,src,kind,text,ref,sev) SELECT ts,'finding',cat,title||': '||coalesce(detail,''),'fd:'||id,sev FROM findings WHERE ts BETWEEN ? AND ?", p)
