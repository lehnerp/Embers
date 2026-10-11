'use strict';

/* ------------------------------------------------------------ utilities --- */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = n => (n == null ? '–' : Number(n).toLocaleString());
const fmtB = b => {
  if (b == null) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(1) : b) + ' ' + u[i];
};
const qs = o => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== '' && v != null && v !== false)).toString();
const sevTag = s => s && s !== 'info' ? `<span class="sev ${esc(s)}">${esc(s)}</span>` : `<span class="sev info">${esc(s || 'info')}</span>`;

async function api(url, opts) {
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch (e) { /* not json */ }
  if (!r.ok) throw new Error((data && data.error) || `${r.status} ${r.statusText}`);
  return data;
}
const post = (url, body, method = 'POST') => api(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

let toastTimer;
function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'toast' + (err ? ' err' : ''); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), err ? 6000 : 2600);
}

/* ------------------------------------------------------------------ time --- */
const TZ = { mode: localStorage.getItem('embers-tz') || 'utc', offset: 0 };
const parseUTC = ts => ts ? new Date(ts.replace(' ', 'T').replace(/Z?$/, 'Z')) : null;
const iso = d => d.toISOString().replace('T', ' ').replace('Z', '');
function fmtT(ts, short = false) {
  if (!ts) return '–';
  let out = ts;
  if (TZ.mode === 'host' && TZ.offset) {
    const d = parseUTC(ts);
    if (!isNaN(d)) out = iso(new Date(d.getTime() + TZ.offset * 60000));
  }
  return short ? out.slice(0, 19) : out;
}
const tzLabel = () => TZ.mode === 'host' ? `host time (UTC${TZ.offset >= 0 ? '+' : ''}${TZ.offset / 60})` : 'UTC';
function toInput(ts) {
  if (!ts) return '';
  return fmtT(ts).slice(0, 19).replace(' ', 'T');
}
function fromInput(v) {
  if (!v) return '';
  let s = v.replace('T', ' ');
  if (s.length === 16) s += ':00';
  if (TZ.mode === 'host' && TZ.offset) {
    const d = parseUTC(s);
    s = iso(new Date(d.getTime() - TZ.offset * 60000)).slice(0, 19);
  }
  return s;
}
function dur(a, b) {
  const s = (parseUTC(b) - parseUTC(a)) / 1000;
  if (isNaN(s)) return '';
  if (s < 90) return Math.round(s) + ' s';
  if (s < 5400) return Math.round(s / 60) + ' min';
  if (s < 172800) return (s / 3600).toFixed(1) + ' h';
  return (s / 86400).toFixed(1) + ' days';
}

/* --------------------------------------------------------------- tables --- */
/** cols: [{h, k, f(row), cls}] ; opts.ref(row) -> ref string ; opts.pin(row) -> pin payload ; opts.rowCls(row) */
function table(cols, rows, opts = {}) {
  if (!rows.length) return `<div class="empty">${esc(opts.empty || 'Nothing here.')}</div>`;
  PINQ.length = 0;
  const head = cols.map(c => `<th>${esc(c.h)}</th>`).join('') + (opts.pin ? '<th></th>' : '');
  const body = rows.map(r => {
    const ref = opts.ref ? opts.ref(r) : null;
    const cls = [ref ? 'click' : '', opts.rowCls ? opts.rowCls(r) : ''].join(' ');
    let pin = '';
    if (opts.pin) { PINQ.push(opts.pin(r)); pin = `<td><button class="pinbtn" data-pin="${PINQ.length - 1}" title="Pin">📌</button></td>`; }
    return `<tr class="${cls}" ${ref ? `data-ref="${esc(ref)}"` : ''}>` + cols.map(c => {
      const v = c.f ? c.f(r) : esc(r[c.k]);
      return `<td class="${c.cls || ''}">${v ?? ''}</td>`;
    }).join('') + pin + '</tr>';
  }).join('');
  return `<div class="tblwrap"><table class="tbl"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}
const PINQ = [];
function bindTable(el, onRef) {
  el.addEventListener('click', e => {
    const pb = e.target.closest('[data-pin]');
    if (pb) { e.stopPropagation(); addPin(PINQ[+pb.dataset.pin]); return; }
    const tr = e.target.closest('[data-ref]');
    if (tr) (onRef || openRef)(tr.dataset.ref, tr);
  });
}
const T = ts => `${esc(fmtT(ts))}`;
const flags = s => (s || '').split(';').map(x => x.trim()).filter(Boolean)
  .map(x => `<span class="flag ${/tool|Shadow|Defender|hidden|shell/i.test(x) ? 'hi' : ''}">${esc(x)}</span>`).join('');
const pager = (total, offset, shown, id) => total > offset + shown
  ? `<div class="more"><button class="btn small" id="${id}">Load more (${fmtN(total - offset - shown)} left)</button></div>` : '';

/* ------------------------------------------------------------ histogram --- */
const SRC_COLORS = { event: '#56ccf2', usn: '#9b8afb', mft: '#6fcf97', execution: '#f2994a', persistence: '#eb5757',
  registry: '#bb6bd9', artifact: '#c8d46b', finding: '#f2c94c', enc: '#eb5757', ren: '#9b8afb', notes: '#f2c94c' };
/** Insert empty buckets so gaps in activity stay visible. keys look like 'YYYY-MM-DD', 'YYYY-MM-DD HH' or 'YYYY-MM-DD HH:MM'. */
function fillBuckets(buckets, unit) {
  if (buckets.length < 2) return buckets;
  const len = { day: 10, hour: 13, minute: 16 }[unit] || 13;
  const step = { day: 86400e3, hour: 3600e3, minute: 60e3 }[unit] || 3600e3;
  const toD = t => parseUTC(t.length === 10 ? t + ' 00:00:00' : t.length === 13 ? t + ':00:00' : t + ':00');
  const map = new Map(buckets.map(b => [b.t, b]));
  const a = toD(buckets[0].t), z = toD(buckets[buckets.length - 1].t);
  if ((z - a) / step > 3000) return buckets;
  const out = [];
  for (let t = a.getTime(); t <= z.getTime(); t += step) {
    const k = iso(new Date(t)).slice(0, len);
    out.push(map.get(k) || { t: k, v: {} });
  }
  return out;
}
const LEGEND = { enc: 'files encrypted', notes: 'ransom notes created' };
/** buckets: [{t, v:{key:n}}] */
function histSVG(buckets, keys, onClick) {
  if (!buckets.length) return '<div class="empty">No data in range.</div>';
  const W = 1000, H = 130, pad = 24;
  const max = Math.max(1, ...buckets.map(b => keys.reduce((s, k) => s + (b.v[k] || 0), 0)));
  const bw = (W - 10) / buckets.length;
  let bars = '';
  buckets.forEach((b, i) => {
    let y = H - pad;
    keys.forEach(k => {
      const n = b.v[k] || 0;
      if (!n) return;
      const h = Math.max(1, (n / max) * (H - pad - 8));
      y -= h;
      bars += `<rect class="b" data-i="${i}" x="${5 + i * bw}" y="${y}" width="${Math.max(1, bw - 1)}" height="${h}" fill="${SRC_COLORS[k] || '#8c9aae'}"><title>${esc(fmtT(b.t))} ${esc(LEGEND[k] || k)}: ${n}</title></rect>`;
    });
  });
  const step = Math.max(1, Math.ceil(buckets.length / 8));
  let ax = '';
  for (let i = 0; i < buckets.length; i += step) ax += `<text class="axis" x="${5 + i * bw}" y="${H - 6}">${esc(fmtT(buckets[i].t).slice(0, 16))}</text>`;
  ax += `<text class="axis" x="${W - 4}" y="12" text-anchor="end">max ${fmtN(max)}</text>`;
  const id = 'h' + Math.random().toString(36).slice(2);
  setTimeout(() => { const el = document.getElementById(id); if (el && onClick) el.addEventListener('click', e => { const r = e.target.closest('rect.b'); if (r) onClick(buckets[+r.dataset.i]); }); });
  return `<div class="hist"><svg id="${id}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="height:${H}px">${bars}${ax}</svg>
    <div class="legend">${keys.map(k => `<span><i style="background:${SRC_COLORS[k] || '#8c9aae'}"></i>${esc(LEGEND[k] || k)}</span>`).join('')}</div></div>`;
}
const unitEnd = (t, unit) => {
  const d = parseUTC(t.length === 10 ? t + ' 00:00:00' : t.length === 13 ? t + ':00:00' : t + ':00');
  const add = { minute: 60e3, hour: 3600e3, day: 86400e3 }[unit] || 3600e3;
  return [iso(d).slice(0, 19), iso(new Date(d.getTime() + add - 1)).slice(0, 19)];
};

/* ------------------------------------------------------------- routing --- */
const VIEWS = {};
let current = null;
function show(view) {
  if (!VIEWS[view]) view = 'overview';
  current = view;
  $$('.rail button[data-view]').forEach(b => b.toggleAttribute('aria-current', b.dataset.view === view) || b.setAttribute('aria-current', b.dataset.view === view ? 'page' : ''));
  $$('.rail button[data-view]').forEach(b => { if (b.dataset.view !== view) b.removeAttribute('aria-current'); else b.setAttribute('aria-current', 'page'); });
  $$('.view').forEach(v => (v.hidden = v.id !== 'v-' + view));
  if (location.hash.slice(1) !== view) history.replaceState(null, '', '#' + view);
  VIEWS[view]($('#v-' + view)).catch(e => { $('#v-' + view).innerHTML = `<div class="empty"><h2>Could not load</h2>${esc(e.message)}</div>`; });
}
$$('.rail button[data-view]').forEach(b => b.addEventListener('click', () => show(b.dataset.view)));
window.addEventListener('hashchange', () => show(location.hash.slice(1)));

/* ------------------------------------------------------------- drawer ---- */
let DPIN = null;
function openDrawer(title, meta, html, pin) {
  $('#dTitle').textContent = title;
  $('#dMeta').innerHTML = meta || '';
  $('#dBody').innerHTML = html;
  $('#drawer').hidden = false; $('#scrim').hidden = false;
  DPIN = pin || null;
  $('#dPin').hidden = !pin;
}
function closeDrawer() { $('#drawer').hidden = true; $('#scrim').hidden = true; }
$('#dClose').addEventListener('click', closeDrawer);
$('#scrim').addEventListener('click', closeDrawer);
$('#dPin').addEventListener('click', () => DPIN && addPin(DPIN));
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeDrawer();
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') { e.preventDefault(); $('#q').focus(); }
});
const kv = obj => `<table class="kvt">${Object.entries(obj).filter(([, v]) => v !== null && v !== '' && v !== undefined)
  .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(typeof v === 'object' ? JSON.stringify(v, null, 1) : (/^(ts|si_|fn_|first|last|lastwrite|created)/.test(k) && typeof v === 'string' && /^\d{4}-/.test(v) ? fmtT(v) : v))}</td></tr>`).join('')}</table>`;

const REF_SRC = { ev: 'event', usn: 'usn', f: 'mft', ex: 'execution', pe: 'persistence', rk: 'registry', rc: 'registry', ar: 'artifact', fd: 'finding' };
async function openRef(ref) {
  if (ref.startsWith('f:')) return openFile(+ref.slice(2));
  if (ref.startsWith('note:')) { show('impact'); return; }
  if (ref.startsWith('window')) { show('impact'); return; }
  if (ref.startsWith('ip:')) { show('logons'); return; }
  if (ref.startsWith('log:')) { show('events'); return; }
  const d = await api('/api/ref?' + qs({ ref }));
  if (d.missing) {
    if (ref.startsWith('path:') || ref.startsWith('usn:') || ref.startsWith('exec:')) {
      const p = ref.replace(/^(path|usn|exec):/, '');
      FS.q = p.split('\\').pop(); FS.filter = ''; FS.from = FS.to = ''; show('fs'); return;
    }
    return toast('No details for ' + ref, true);
  }
  if (d.kind === 'f') return openFile(d.row.rec);
  const r = d.row;
  let title = r.summary || r.title || r.path || r.name || ref;
  let html = '';
  if (d.kind === 'ev') {
    title = `${r.channel} ${r.eid}`;
    html += `<p class="m" style="font-family:var(--mono);font-size:13px">${esc(r.summary)}</p><h3>Event data</h3>${kv(r.data || {})}<h3>Record</h3>${kv({ time: fmtT(r.ts), channel: r.channel, provider: r.provider, event_id: r.eid, record_id: r.rec, computer: r.computer, user: r.user, file: r.file })}`;
  } else if (d.kind === 'ex' && r.extra && r.extra.files) {
    const ex = r.extra;
    html += kv({ time: fmtT(r.ts), source: r.source, path: r.path, detail: r.detail, run_count: ex.count, pf_created: fmtT(ex.pf_created) });
    html += `<h3>Last run times</h3><div class="pre">${(ex.runs || []).map(fmtT).join('\n')}</div>`;
    html += `<h3>Files touched in its first seconds (${ex.files.length})</h3><div class="pre">${esc(ex.files.join('\n'))}</div>`;
  } else {
    html += kv(r);
  }
  const src = REF_SRC[d.kind] || d.kind;
  openDrawer(title.slice(0, 200), `<span class="src ${src}">${esc(src)}</span> ${esc(fmtT(r.ts))}`, html,
    { ref, ts: r.ts, src, title: title.slice(0, 300), detail: r.summary || r.detail || r.value || r.path || '' });
}

async function openFile(rec) {
  const d = await api('/api/file?' + qs({ rec }));
  const r = d.row;
  const flagsTxt = [r.enc ? 'encrypted' : '', r.note ? 'ransom note' : '', r.in_use ? '' : 'deleted record', r.flags].filter(Boolean).join('; ');
  let html = `<table class="tbl" style="margin-bottom:12px"><thead><tr><th></th><th>Created</th><th>Modified</th><th>MFT entry modified</th><th>Accessed</th></tr></thead><tbody>
    <tr><td>$STANDARD_INFORMATION</td><td class="t">${T(r.si_c)}</td><td class="t">${T(r.si_m)}</td><td class="t">${T(r.si_e)}</td><td class="t">${T(r.si_a)}</td></tr>
    <tr><td>$FILE_NAME</td><td class="t">${T(r.fn_c)}</td><td class="t">${T(r.fn_m)}</td><td class="t">${T(r.fn_e)}</td><td class="t">${T(r.fn_a)}</td></tr></tbody></table>`;
  html += kv({ path: r.path, original_name: r.orig, size: r.size != null ? `${fmtN(r.size)} bytes` : '', mft_record: `${r.rec} (seq ${r.seq})`, flags: flagsTxt, attributes: '0x' + (r.attrs || 0).toString(16), alternate_streams: r.ads, downloaded_from: r.zone });
  html += `<p class="note">$SI times can be changed by any program (timestomping); $FN times are only set by the kernel. A $SI created time earlier than $FN created is a classic sign of backdating.</p>`;
  if (r.in_use && !r.is_dir) html += `<button class="btn small" id="readContent">Read content (first 64 KB)</button><div id="content"></div>`;
  html += `<h3>USN journal for this record (${d.usn.length})</h3>` + table([{ h: 'Time', f: x => T(x.ts), cls: 't' }, { h: 'Reasons', k: 'reasons' }, { h: 'Name', k: 'path', cls: 'm' }], d.usn, { empty: 'No USN records for this MFT record (journal may have rolled over).' });
  openDrawer(r.path, `<span class="src mft">MFT</span> record ${r.rec}`, html, { ref: 'f:' + r.rec, ts: r.si_e, src: 'mft', title: r.path, detail: flagsTxt });
  const b = $('#readContent');
  if (b) b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const c = await api('/api/file?' + qs({ rec, content: 1 }));
      if (c.content_error) throw new Error(c.content_error);
      if (c.hex == null) throw new Error('Evidence source is not reachable right now.');
      const hx = c.hex.match(/.{1,32}/g) || [];
      const lines = hx.map((h, i) => (i * 16).toString(16).padStart(6, '0') + '  ' + h.match(/../g).join(' ').padEnd(48) + '  ' +
        h.match(/../g).map(x => { const n = parseInt(x, 16); return n >= 32 && n < 127 ? String.fromCharCode(n) : '.'; }).join(''));
      $('#content').innerHTML = `<p>Entropy of the first 64 KB: <b>${c.entropy}</b> bits/byte ${c.entropy > 7.5 ? '<span class="flag hi">looks encrypted / compressed</span>' : ''}</p>
        <div class="pre hex">${esc(lines.join('\n'))}</div>${c.text && c.entropy < 6 ? `<h3>As text</h3><div class="pre">${esc(c.text)}</div>` : ''}`;
    } catch (e) { $('#content').innerHTML = `<p class="faint">${esc(e.message)}</p>`; }
  });
}

/* ------------------------------------------------------------------ pins --- */
async function addPin(p) {
  if (!p) return;
  await post('/api/pins', p);
  toast('Pinned to the evidence board');
  refreshCounts();
}

/* --------------------------------------------------------------- cache ---- */
let OV = null;
async function overview(force = false) {
  if (!OV || force) {
    OV = await api('/api/overview');
    TZ.offset = (OV.host && OV.host.utc_offset_min) || 0;
  }
  return OV;
}
function refreshCounts() {
  overview(true).then(o => {
    $('#cImpact').textContent = o.figures.encrypted ? fmtN(o.figures.encrypted) : '';
    $('#cFind').textContent = o.figures.high ? fmtN(o.figures.high) : '';
    $('#cPersist').textContent = o.figures.persist_flagged || '';
    $('#cReg').textContent = (o.figures.regchecks + o.figures.regchanges) || '';
  }).catch(() => {});
  api('/api/pins').then(p => ($('#cPins').textContent = p.length || '')).catch(() => {});
}

/* ============================================================ OVERVIEW === */
VIEWS.overview = async el => {
  const o = await overview(true);
  const h = o.host || {}, im = o.impact || {}, f = o.figures;
  if (!f.files && !f.events && !o.hives.length) {
    el.innerHTML = `<div class="empty"><h2>No evidence indexed yet</h2><p>Open <a href="#case">Case &amp; source</a> and point Embers at the mounted Macrium image (for example <code>\\\\.\\F:</code>).</p></div>`;
    return;
  }
  const w = im.window;
  const banner = (im.chosen && im.chosen.length) || w
    ? `<div class="banner"><div><div class="big">${fmtN(im.encrypted)} files encrypted in ${fmtN(im.dirs)} folders${im.chosen && im.chosen.length ? ` · extension ${im.chosen.map(e => `<span class="ext">.${esc(e)}</span>`).join(' ')}` : ''}</div>
       <div class="muted">${w ? `from <b>${esc(fmtT(w.start, true))}</b> to <b>${esc(fmtT(w.end, true))}</b> ${tzLabel()} (${dur(w.start, w.end)}), based on ${esc(w.basis)}` : ''}</div></div>
       <span class="grow"></span><button class="btn" onclick="show('impact')">Impact details</button><button class="btn primary" onclick="tlWindow()">Timeline around it</button></div>`
    : `<div class="banner none"><div><div class="big">No ransomware extension identified</div><div class="muted">Check <a href="#impact">Impact</a> for candidate extensions, or set the encryption window manually.</div></div></div>`;
  const fig = (n, l, cls = '') => `<div class="figure ${cls}"><b>${fmtN(n)}</b><span>${l}</span></div>`;
  const story = o.story.length ? o.story.map(s => `<div class="sitem2 ${s.source === 'analysis' ? 'milestone' : ''}" data-ref="${esc(s.ref || '')}">
      <span class="t">${esc(fmtT(s.ts, true))}</span><span class="s">${sevTag(s.sev)}</span>
      <span><b>${esc(s.title)}</b><div class="d" title="${esc(s.detail)}">${esc(s.detail)}</div></span></div>`).join('')
    : '<div class="empty">No high or medium findings in the analysis span.</div>';
  const payload = o.payload.length ? o.payload.map(p => `<div class="sitem2" data-ref="exec:${esc(p.path)}" style="grid-template-columns:1fr 60px">
      <span><b class="mono" style="font-size:13px">${esc(p.path)}</b><div class="mini">first seen ${esc(fmtT(p.ts, true))} · ${esc(p.sources.join(', '))}</div>
      <div class="why">${p.why.map(x => `<span>${esc(x)}</span>`).join('')}</div></span><span class="num"><b>${p.score}</b></span></div>`).join('')
    : '<div class="empty">No candidates (needs an encryption window).</div>';
  const notes = o.notes.length ? o.notes.map(n => `<div style="margin-bottom:10px"><b class="mono">${esc(n.name)}</b> <span class="muted">${n.copies} copies in ${n.dirs} folders, first ${esc(fmtT(n.first, true))}</span>
      <div>${Object.entries(n.iocs || {}).map(([k, v]) => v.map(x => `<span class="ioc" title="${esc(k)}">${esc(x)}</span>`).join('')).join('')}</div></div>`).join('')
    : '<div class="muted">No ransom note pattern found.</div>';
  const catBars = (() => {
    const by = {};
    o.cats.forEach(c => { by[c.cat] = by[c.cat] || { n: 0, high: 0 }; by[c.cat].n += c.n; if (c.sev === 'high') by[c.cat].high += c.n; });
    const arr = Object.entries(by).sort((a, b) => b[1].high - a[1].high || b[1].n - a[1].n);
    const max = Math.max(1, ...arr.map(a => a[1].n));
    return arr.map(([cat, v]) => `<div class="barrow" data-cat="${esc(cat)}"><span class="label">${esc(cat)} ${v.high ? `<span class="sev high">${v.high}</span>` : ''}</span>
      <div class="track"><div class="fill ${v.high ? 'high' : 'medium'}" style="width:${(100 * v.n / max).toFixed(1)}%"></div></div><span class="num">${fmtN(v.n)}</span></div>`).join('');
  })();
  const profiles = Object.values(o.profiles || {}).filter(p => /^S-1-5-21-/.test(p.sid));
  const accts = (o.accounts || []).map(a => `<tr><td>${esc(a.name)}</td><td class="t">${T(a.created)}</td><td class="t">${T(a.last_logon)}</td><td class="t">${T(a.pwd_set)}</td><td>${a.logons ?? ''}</td><td>${a.disabled ? 'disabled' : ''}</td></tr>`).join('');
  const hives = o.hives.map(x => `<tr><td>${esc(x.label)}</td><td>${x.dirty ? '<span class="flag">dirty</span>' : ''}</td><td>${x.replayed_entries || 0}${x.note ? ' <span class="faint">' + esc(x.note) + '</span>' : ''}</td><td>${fmtN(x.log_changes || 0)}</td><td>${fmtN(x.deleted_keys || 0)}</td><td class="t">${T(x.written)}</td></tr>`).join('');
  const logs = (o.evtx || []).filter(l => l.records).sort((a, b) => b.records - a.records).slice(0, 40).map(l => `<tr><td>${esc(l.file)}</td><td>${fmtN(l.records)}</td><td class="t">${T(l.first)}</td><td class="t">${T(l.last)}</td><td>${l.gap_total ? `<span class="flag hi">${fmtN(l.gap_total)} missing</span>` : ''}</td></tr>`).join('');
  el.innerHTML = `
    <div class="ov-head"><div><h1>${esc(h.computer_name || 'Unknown host')}</h1>
      <p class="sub">${esc([h.product, h.display_version, h.build && 'build ' + h.build, h.domain && 'domain ' + h.domain].filter(Boolean).join(' · '))}<br>
      ${esc([h.timezone && 'time zone ' + h.timezone + (h.utc_offset_min != null ? ` (UTC${h.utc_offset_min >= 0 ? '+' : ''}${h.utc_offset_min / 60})` : ''), (h.ips || []).length && 'IP ' + h.ips.join(', '), h.last_shutdown && 'last clean shutdown ' + fmtT(h.last_shutdown, true)].filter(Boolean).join(' · '))}</p></div>
      <div class="mini" style="text-align:right">Source: <span class="mono">${esc(o.source.source || '')}</span><br>Indexed ${esc(o.indexed_at || '–')}${o.errors.length ? ` · <a href="#case">${o.errors.length} parser warnings</a>` : ''}</div></div>
    ${banner}
    <div class="figures">${fig(f.encrypted, 'encrypted files', f.encrypted ? 'sev-high' : '')}${fig(f.notes, 'ransom note copies')}${fig(f.high, 'high findings', 'sev-high')}${fig(f.medium, 'medium findings', 'sev-medium')}
      ${fig(f.persist_flagged, 'flagged persistence')}${fig(f.regchecks, 'risky registry settings')}${fig(f.regchanges, 'unflushed registry changes')}${fig(f.events, 'event records')}${fig(f.usn, 'USN records')}${fig(f.files, 'MFT entries')}</div>
    <div class="grid2">
      <div class="panel"><h2>Key events <span class="faint">high &amp; medium findings in the analysis span, ${tzLabel()}</span></h2><div class="story" id="story" style="max-height:620px;overflow:auto">${story}</div></div>
      <div class="stack">
        <div class="panel"><h2>Payload candidates</h2><div class="story" id="payload">${payload}</div></div>
        <div class="panel"><h2>Ransom note</h2>${notes}</div>
        <div class="panel"><h2>Findings by category</h2><div class="bars" id="cats">${catBars || '<div class="muted">None</div>'}</div></div>
      </div>
    </div>
    <div class="grid2" style="margin-top:16px">
      <div class="panel"><h2>Users</h2>
        ${profiles.length ? `<p class="mini">Profiles: ${profiles.map(p => `<span class="ioc" title="${esc(p.sid)}">${esc(p.user)}</span>`).join('')}</p>` : ''}
        ${accts ? `<div class="tblwrap"><table class="tbl"><thead><tr><th>Local account</th><th>Created</th><th>Last logon</th><th>Password set</th><th>Logons</th><th></th></tr></thead><tbody>${accts}</tbody></table></div>` : '<p class="muted">No SAM hive.</p>'}</div>
      <div class="panel"><h2>Collection</h2>
        ${hives ? `<div class="tblwrap"><table class="tbl"><thead><tr><th>Hive</th><th></th><th>Log entries replayed</th><th>Unflushed changes</th><th>Deleted keys</th><th>Last written</th></tr></thead><tbody>${hives}</tbody></table></div>` : ''}
        ${logs ? `<h2 style="margin-top:14px">Event logs</h2><div class="tblwrap" style="max-height:300px;overflow:auto"><table class="tbl"><thead><tr><th>Log</th><th>Records</th><th>Oldest</th><th>Newest</th><th></th></tr></thead><tbody>${logs}</tbody></table></div>` : ''}
        ${o.usn_range ? `<p class="mini">USN journal covers ${esc(fmtT(o.usn_range.first, true))} → ${esc(fmtT(o.usn_range.last, true))} (${fmtN(o.usn_range.count)} records). Older file activity has rolled out of the journal.</p>` : ''}
      </div>
    </div>`;
  $('#story').addEventListener('click', e => { const r = e.target.closest('[data-ref]'); if (r && r.dataset.ref) openRef(r.dataset.ref); });
  $('#payload').addEventListener('click', e => { const r = e.target.closest('[data-ref]'); if (r) { EX.q = r.dataset.ref.slice(5).split('\\').pop(); show('execution'); } });
  $('#cats').addEventListener('click', e => { const r = e.target.closest('[data-cat]'); if (r) { FD.cat = r.dataset.cat; FD.sev = ''; show('findings'); } });
};
function tlWindow() {
  const w = OV && OV.impact && OV.impact.window;
  if (w) { TL.from = w.start.slice(0, 19); TL.to = w.end.slice(0, 19); const d = parseUTC(TL.from); TL.from = iso(new Date(d - 6 * 3600e3)).slice(0, 19); }
  show('timeline');
}

/* ============================================================== IMPACT === */
const IMP = { q: '', parent: '', type: '', offset: 0 };
VIEWS.impact = async el => {
  const [d, notes] = await Promise.all([api('/api/impact'), api('/api/notes')]);
  const im = d.impact || {};
  const w = im.window;
  const cands = (im.extensions || []).map(c => `<tr><td><input type="checkbox" class="extcb" value="${esc(c.ext)}" ${(im.chosen || []).includes(c.ext) ? 'checked' : ''}></td>
    <td class="m">.${esc(c.ext)} ${c.known ? '<span class="flag hi">known ransomware</span>' : ''}</td><td>${fmtN(c.files)}</td><td>${fmtN(c.dirs)}</td>
    <td>${Math.round(c.doc_ratio * 100)}%</td><td>${c.spread_hours == null ? '–' : c.spread_hours + ' h'}</td><td>${c.score}</td>
    <td class="m mini" style="min-width:200px">${esc((c.samples || [])[0] || '')}</td></tr>`).join('');
  const hist = d.hist.length ? histSVG(fillBuckets(d.hist.map(b => ({ t: b.t, v: { enc: b.enc, notes: b.notes } })), d.unit), ['enc', 'notes'], b => { const [a, z] = unitEnd(b.t, d.unit); TL.from = a; TL.to = z; show('timeline'); }) : '';
  const bars = (arr, lab, num, click) => { const max = Math.max(1, ...arr.map(num)); return arr.map((x, i) => `<div class="barrow" data-i="${i}" ${click ? '' : 'style="cursor:default"'}><span class="label mono" title="${esc(lab(x))}">${esc(lab(x))}</span><div class="track"><div class="fill high" style="width:${(100 * num(x) / max).toFixed(1)}%"></div></div><span class="num">${fmtN(num(x))}</span></div>`).join(''); };
  const noteHtml = notes.map(n => `<div class="panel" style="margin-bottom:12px"><h2 class="mono">${esc(n.name)} <span class="faint">${n.copies} copies · ${n.dirs} folders · first ${esc(fmtT(n.first, true))}</span></h2>
     ${Object.entries(n.iocs || {}).map(([k, v]) => `<div class="mini">${esc(k)}: ${v.map(x => `<span class="ioc">${esc(x)}</span>`).join('')}</div>`).join('')}
     ${n.text ? `<div class="pre" style="margin-top:8px">${esc(n.text)}</div>` : '<p class="faint">Content not read (source not reachable during analysis).</p>'}
     <details style="margin-top:8px"><summary class="mini">All locations</summary><div class="pre">${esc(n.locations.join('\n'))}</div></details></div>`).join('');
  const pay = (im.payload || []).map(p => ({ ...p, whyS: p.why.join('; ') }));
  el.innerHTML = `<h1>Impact</h1><p class="sub">What the ransomware touched. Encryption time is the MFT entry-modified time of each renamed file (the rename updates it) and USN rename records; original names come from USN rename pairs where the journal still holds them.</p>
    <div class="figures"><div class="figure sev-high"><b>${fmtN(im.encrypted)}</b><span>encrypted files</span></div><div class="figure"><b>${fmtN(im.dirs)}</b><span>folders</span></div>
      <div class="figure"><b>${fmtB(d.bytes)}</b><span>encrypted data</span></div><div class="figure"><b>${w ? dur(w.start, w.end) : '–'}</b><span>duration</span></div>
      <div class="figure"><b style="font-size:15px">${w ? esc(fmtT(w.start, true)) : '–'}</b><span>start (${tzLabel()})</span></div><div class="figure"><b style="font-size:15px">${w ? esc(fmtT(w.end, true)) : '–'}</b><span>end</span></div></div>
    ${hist ? `<h2>Encryption over time</h2>${hist}` : ''}
    <div class="grid2">
      <div class="panel"><h2>Ransomware extension</h2><p class="note">Extensions ranked by how often they sit on top of a document extension (<span class="mono">.docx.X</span>), how many folders they appear in and how tightly their timestamps cluster. Tick the right one(s) and re-analyse if the guess is wrong.</p>
        ${cands ? `<div class="tblwrap"><table class="tbl"><thead><tr><th></th><th>Extension</th><th>Files</th><th>Folders</th><th>On a doc ext</th><th>Spread</th><th>Score</th><th>Samples</th></tr></thead><tbody>${cands}</tbody></table></div>` : '<p class="muted">No unusual extensions.</p>'}
        <div class="toolbar" style="margin-top:10px"><label class="field">Other extension(s)<input class="input" id="extOther" placeholder=".abc, .xyz"></label>
          <label class="field">Window start (${tzLabel()})<input class="input" id="wStart" type="datetime-local" step="1" value="${w ? toInput(w.start) : ''}"></label>
          <label class="field">Window end<input class="input" id="wEnd" type="datetime-local" step="1" value="${w ? toInput(w.end) : ''}"></label>
          <button class="btn primary" id="reanalyse">Re-analyse</button></div></div>
      <div class="panel"><h2>Payload candidates</h2>${table([{ h: 'First seen', f: p => T(p.ts), cls: 't' }, { h: 'Path', f: p => `<span class="m" style="display:inline-block;min-width:200px">${esc(p.path)}</span>` }, { h: 'Why', f: p => `<div class="why">${p.why.map(x => `<span>${esc(x)}</span>`).join('')}</div>` }, { h: 'Score', k: 'score' }], pay, { empty: 'No candidates.', ref: p => 'exec:' + p.path })}</div>
    </div>
    <div class="grid2" style="margin-top:16px">
      <div class="panel"><h2>Where <span class="faint">top folders, click to list files</span></h2><div class="bars" id="dirBars">${bars(d.dirs, x => x.path || '?', x => x.n, true)}</div></div>
      <div class="panel"><h2>What <span class="faint">original file types</span></h2><div class="bars" id="typeBars">${bars(d.types, x => x.t ? '.' + x.t : '(none)', x => x.n, true)}</div>
        ${d.untouched.length ? `<p class="note" style="margin-top:12px">Not encrypted in the same folders: ${d.untouched.map(u => `<span class="ioc">.${esc(u.ext)} ${fmtN(u.n)}</span>`).join('')} (partial encryption, a crash, or file types it skips).</p>` : ''}</div>
    </div>
    <h2 style="margin-top:20px">Ransom notes</h2>${noteHtml || '<p class="muted">None found.</p>'}
    <h2 style="margin-top:20px">Encrypted files</h2>
    <div class="toolbar"><input class="input wide" id="impQ" placeholder="Filter by path or original name" value="${esc(IMP.q)}">
      <span class="mini" id="impFilt">${IMP.parent ? 'folder filter on · ' : ''}${IMP.type ? 'type .' + esc(IMP.type) + ' · ' : ''}</span>
      ${IMP.parent || IMP.type ? '<button class="btn small ghost" id="impClear">Clear filters</button>' : ''}
      <span class="grow"></span><a class="btn small" href="/api/impact/files.csv">Export CSV (all)</a></div>
    <div id="impFiles"></div>`;
  $$('#dirBars .barrow').forEach(b => b.addEventListener('click', () => { IMP.parent = d.dirs[+b.dataset.i].parent; IMP.offset = 0; loadImpFiles(); }));
  $$('#typeBars .barrow').forEach(b => b.addEventListener('click', () => { IMP.type = d.types[+b.dataset.i].t; IMP.offset = 0; loadImpFiles(); }));
  $('#impQ').addEventListener('input', debounce(() => { IMP.q = $('#impQ').value; IMP.offset = 0; loadImpFiles(); }, 300));
  if ($('#impClear')) $('#impClear').addEventListener('click', () => { IMP.parent = IMP.type = ''; VIEWS.impact(el); });
  bindTable(el.querySelector('.grid2 .panel:nth-child(2)'));
  $('#reanalyse').addEventListener('click', async () => {
    const exts = $$('.extcb').filter(c => c.checked).map(c => c.value).concat($('#extOther').value.split(/[,\s]+/).map(s => s.replace(/^\./, '')).filter(Boolean));
    const body = { extensions: exts };
    if ($('#wStart').value && $('#wEnd').value) body.window = { start: fromInput($('#wStart').value), end: fromInput($('#wEnd').value) };
    try { await post('/api/reanalyze', body); toast('Re-analysing…'); pollStatus(true, () => show('impact')); } catch (e) { toast(e.message, true); }
  });
  loadImpFiles();
};
async function loadImpFiles(append = false) {
  const box = $('#impFiles');
  if (!box) return;
  const d = await api('/api/impact/files?' + qs({ q: IMP.q, parent: IMP.parent, type: IMP.type, offset: IMP.offset }));
  IMP.rows = append ? IMP.rows.concat(d.rows) : d.rows;
  box.innerHTML = `<p class="mini">${fmtN(d.total)} files</p>` + table([
    { h: 'Encrypted (entry modified)', f: r => T(r.si_e), cls: 't' }, { h: 'Path', k: 'path', cls: 'm' }, { h: 'Original name', k: 'orig', cls: 'm' },
    { h: 'Size', f: r => fmtB(r.size) }, { h: '$SI created', f: r => T(r.si_c), cls: 't' }], IMP.rows,
    { ref: r => 'f:' + r.rec, pin: r => ({ ref: 'f:' + r.rec, ts: r.si_e, src: 'mft', title: 'Encrypted: ' + r.path, detail: 'original ' + (r.orig || '?') }) }) + pager(d.total, IMP.offset, d.rows.length, 'impMore');
  bindTable(box);
  const m = $('#impMore');
  if (m) m.addEventListener('click', () => { IMP.offset += d.rows.length; loadImpFiles(true); });
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

/* ============================================================ TIMELINE === */
const TL = { from: '', to: '', src: new Set(), q: '', sev: false, order: 'asc', offset: 0, rows: [] };
const TL_SRC = ['event', 'usn', 'mft', 'execution', 'persistence', 'registry', 'artifact', 'finding'];
VIEWS.timeline = async el => {
  const o = await overview();
  const span = (o.impact && o.impact.span) || {};
  if (!TL.from && span.from) TL.from = span.from.slice(0, 19);
  if (!TL.to && span.to) TL.to = span.to.slice(0, 19);
  el.innerHTML = `<h1>Super-timeline</h1><p class="sub">Event logs, USN journal, MFT, execution evidence, persistence, registry key writes, user artifacts and findings in one list. Built for the analysis span (${esc(fmtT(span.from, true))} → ${esc(fmtT(span.to, true))}); change it in Impact → Re-analyse.</p>
    <div class="toolbar">
      <label class="field">From (${tzLabel()})<input class="input" type="datetime-local" step="1" id="tlFrom" value="${toInput(TL.from)}"></label>
      <label class="field">To<input class="input" type="datetime-local" step="1" id="tlTo" value="${toInput(TL.to)}"></label>
      <label class="field">Text<input class="input wide" id="tlQ" value="${esc(TL.q)}" placeholder="words must all match, -word excludes"></label>
      <label class="field">Order<select class="input" id="tlOrder"><option value="asc">oldest first</option><option value="desc" ${TL.order === 'desc' ? 'selected' : ''}>newest first</option></select></label>
      <button class="btn small" id="tlSev" aria-pressed="${TL.sev}">Only flagged</button>
      <button class="btn primary" id="tlGo">Apply</button><button class="btn small ghost" id="tlReset">Reset</button></div>
    <div class="chips" id="tlSrc" style="margin-bottom:10px">${TL_SRC.map(s => `<button class="chip" data-s="${s}" aria-pressed="${TL.src.has(s)}"><span class="src ${s}" style="min-width:0">${s}</span> <span class="n faint"></span></button>`).join('')}</div>
    <div id="tlHist"></div><div id="tlRows"><div class="empty">Loading…</div></div>`;
  $('#tlSrc').addEventListener('click', e => { const b = e.target.closest('[data-s]'); if (!b) return; const s = b.dataset.s; TL.src.has(s) ? TL.src.delete(s) : TL.src.add(s); b.setAttribute('aria-pressed', TL.src.has(s)); loadTL(); });
  const apply = () => { TL.from = fromInput($('#tlFrom').value); TL.to = fromInput($('#tlTo').value); TL.q = $('#tlQ').value.trim(); TL.order = $('#tlOrder').value; loadTL(); };
  $('#tlGo').addEventListener('click', apply);
  $('#tlQ').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
  $('#tlSev').addEventListener('click', () => { TL.sev = !TL.sev; $('#tlSev').setAttribute('aria-pressed', TL.sev); loadTL(); });
  $('#tlReset').addEventListener('click', () => { TL.from = TL.to = TL.q = ''; TL.src.clear(); TL.sev = false; VIEWS.timeline(el); });
  loadTL();
};
async function loadTL(append = false) {
  if (!append) TL.offset = 0;
  const p = { from: TL.from, to: TL.to, q: TL.q, src: [...TL.src].join(','), sev: TL.sev ? 1 : '', order: TL.order, offset: TL.offset };
  const d = await api('/api/timeline?' + qs(p));
  TL.rows = append ? TL.rows.concat(d.rows) : d.rows;
  if (!append) {
    TL.total = d.total;
    const by = {}; d.hist.forEach(h => { (by[h.t] = by[h.t] || { t: h.t, v: {} }).v[h.src] = h.n; });
    const keys = TL_SRC.filter(s => d.hist.some(h => h.src === s));
    $('#tlHist').innerHTML = histSVG(fillBuckets(Object.values(by).sort((a, b) => a.t < b.t ? -1 : 1), d.unit), keys, b => { const [a, z] = unitEnd(b.t, d.unit); TL.from = a; TL.to = z; VIEWS.timeline($('#v-timeline')); });
    const counts = Object.fromEntries(d.by_src.map(x => [x.src, x.n]));
    $$('#tlSrc .chip').forEach(c => ($('.n', c).textContent = fmtN(counts[c.dataset.s] || 0)));
  }
  const box = $('#tlRows');
  box.innerHTML = `<p class="mini">${fmtN(TL.total)} entries · ${tzLabel()}</p>` + table([
    { h: 'Time', f: r => T(r.ts), cls: 't' }, { h: 'Source', f: r => `<span class="src ${r.src}">${esc(r.src)}</span>` },
    { h: 'What', f: r => `${r.sev && r.sev !== 'info' ? sevTag(r.sev) + ' ' : ''}<span class="muted">${esc(r.kind)}</span>` },
    { h: 'Detail', k: 'text', cls: 'm' }], TL.rows,
    { ref: r => r.ref, pin: r => ({ ref: r.ref, ts: r.ts, src: r.src, title: `${r.kind}: ${r.text}`.slice(0, 300), detail: r.text }),
      rowCls: r => r.kind === 'encrypted' ? 'enc' : '' }) + pager(TL.total, TL.offset, TL.rows.length - TL.offset, 'tlMore');
  bindTable(box);
  const m = $('#tlMore');
  if (m) m.addEventListener('click', () => { TL.offset = TL.rows.length; loadTL(true); });
}
$('#searchForm').addEventListener('submit', e => { e.preventDefault(); TL.q = $('#q').value.trim(); TL.offset = 0; show('timeline'); });

/* =========================================================== EXECUTION === */
const EX = { q: '', flagged: false };
VIEWS.execution = async el => {
  el.innerHTML = `<h1>Execution</h1><p class="sub">Everything that shows a program ran: Prefetch (last 8 runs + first run), Amcache (first seen, SHA-1), BAM, UserAssist, ShimCache (presence only, its time is the file's modified time), RunMRU, Security 4688 and Sysmon 1. Grouped by program.</p>
    <div class="toolbar"><input class="input wide" id="exQ" placeholder="Filter: name, path, command line, SHA-1" value="${esc(EX.q)}">
      <button class="btn small" id="exFlag" aria-pressed="${EX.flagged}">Only flagged</button></div><div id="exRows"><div class="empty">Loading…</div></div>`;
  $('#exQ').addEventListener('input', debounce(() => { EX.q = $('#exQ').value; loadEx(); }, 300));
  $('#exFlag').addEventListener('click', () => { EX.flagged = !EX.flagged; $('#exFlag').setAttribute('aria-pressed', EX.flagged); loadEx(); });
  loadEx();
};
async function loadEx() {
  let d = await api('/api/execution?' + qs({ q: EX.q }));
  if (EX.flagged) d = d.filter(r => r.flags.length);
  const box = $('#exRows');
  box.innerHTML = `<p class="mini">${fmtN(d.length)} programs</p>` + table([
    { h: 'Last', f: r => T(r.last), cls: 't' }, { h: 'First', f: r => T(r.first), cls: 't' },
    { h: 'Program', f: r => `<b>${esc(r.name)}</b><div class="mini m">${esc(r.path)}</div>${r.cmds ? `<div class="mini m" style="color:var(--text)">${esc(r.cmds.slice(0, 300))}</div>` : ''}` },
    { h: 'Evidence', f: r => esc((r.sources || '').replace(/,/g, ', ')) + ` <span class="faint">(${r.n})</span>` },
    { h: 'Flags', f: r => r.flags.map(x => `<span class="flag ${/tool|Shadow|Defender/.test(x) ? 'hi' : ''}">${esc(x)}</span>`).join('') },
    { h: 'SHA-1', f: r => r.sha1 ? `<a class="mono mini" href="https://www.virustotal.com/gui/search/${esc(r.sha1)}" target="_blank" rel="noopener">${esc(r.sha1.slice(0, 12))}…</a>` : '' }], d,
    { ref: r => 'name:' + r.name, rowCls: r => r.flags.length ? 'bad' : '', pin: r => ({ ref: 'exec:' + r.path, ts: r.first, src: 'execution', title: 'Executed: ' + r.path, detail: `${r.sources}; first ${r.first} last ${r.last}; ${r.flags.join(', ')}` }) });
  bindTable(box, async ref => {
    const name = ref.slice(5);
    const rows = await api('/api/execution/item?' + qs({ name }));
    const pf = rows.find(r => r.source === 'Prefetch' && r.extra && r.extra.includes('"files"'));
    let html = table([{ h: 'Time', f: r => T(r.ts), cls: 't' }, { h: 'Source', k: 'source' }, { h: 'Path', k: 'path', cls: 'm' }, { h: 'Detail', k: 'detail', cls: 'm' }, { h: 'User', k: 'user' }], rows, { ref: r => 'ex:' + r.id });
    if (pf) {
      const ex = JSON.parse(pf.extra);
      html += `<h3>Prefetch ${esc(ex.pf)}: files touched in the first seconds (${ex.files.length})</h3><div class="pre">${esc(ex.files.join('\n'))}</div>`;
    }
    openDrawer(name, `<span class="src execution">execution</span> ${rows.length} records`, html, { ref: 'exec:' + name, ts: rows[0] && rows[0].ts, src: 'execution', title: 'Executed: ' + name, detail: rows.map(r => r.source + ' ' + (r.ts || '')).join('; ') });
    bindTable($('#dBody'));
  });
}

/* ========================================================= PERSISTENCE === */
const PE = { kind: '', flagged: true, q: '' };
VIEWS.persistence = async el => {
  const d = await api('/api/persistence?' + qs({ kind: PE.kind, flagged: PE.flagged ? 1 : '', q: PE.q }));
  el.innerHTML = `<h1>Persistence</h1><p class="sub">Services, scheduled tasks (XML and TaskCache, incl. hidden ones), Run keys, startup folders, IFEO debuggers, SafeBoot entries, WMI subscriptions and services/tasks from event logs. "Flagged or recent" hides untouched defaults.</p>
    <div class="toolbar"><div class="chips" id="peKinds"><button class="chip" data-k="" aria-pressed="${!PE.kind}">all</button>${d.kinds.map(k => `<button class="chip" data-k="${esc(k.kind)}" aria-pressed="${PE.kind === k.kind}">${esc(k.kind)} <span class="faint">${k.n}${k.flagged ? ' · ' + k.flagged + ' flagged' : ''}</span></button>`).join('')}</div></div>
    <div class="toolbar"><input class="input wide" id="peQ" placeholder="Filter name, command, location" value="${esc(PE.q)}"><button class="btn small" id="peFlag" aria-pressed="${PE.flagged}">Flagged or recent only</button></div>
    <div id="peRows">${table([{ h: '', f: r => sevTag(r.sev) }, { h: 'Written / created', f: r => T(r.ts), cls: 't' }, { h: 'Kind', k: 'kind' },
      { h: 'Name', k: 'name', cls: 'm' }, { h: 'Command / value', k: 'value', cls: 'm' }, { h: 'Flags', f: r => flags(r.flags) }], d.rows,
      { ref: r => 'pe:' + r.id, rowCls: r => r.sev === 'high' ? 'bad' : '', pin: r => ({ ref: 'pe:' + r.id, ts: r.ts, src: 'persistence', title: `${r.kind}: ${r.name}`, detail: r.value + ' ' + (r.flags || '') }) })}</div>`;
  $('#peKinds').addEventListener('click', e => { const b = e.target.closest('[data-k]'); if (b) { PE.kind = b.dataset.k; VIEWS.persistence(el); } });
  $('#peFlag').addEventListener('click', () => { PE.flagged = !PE.flagged; VIEWS.persistence(el); });
  $('#peQ').addEventListener('change', () => { PE.q = $('#peQ').value; VIEWS.persistence(el); });
  bindTable($('#peRows'));
};

/* ============================================================ REGISTRY === */
const RG = { tab: 'checks', q: '', hive: '', from: '', to: '', noise: false, offset: 0, bhive: 'SOFTWARE', bpath: '' };
VIEWS.registry = async el => {
  const o = await overview();
  const tabs = [['checks', 'Risky settings', o.figures.regchecks], ['log', 'Unflushed changes (transaction logs)', o.figures.regchanges],
    ['deleted', 'Deleted keys', ''], ['recent', 'Recently written keys', ''], ['browse', 'Browse hives', '']];
  el.innerHTML = `<h1>Registry</h1><p class="sub">Hives are read straight from the image and their transaction logs (.LOG1/.LOG2) are replayed first. Changes that were still only in the logs are the most recent writes before the image was taken. The registry keeps no history of values: for older changes you only get each key's last-write time, plus keys recovered from free space.</p>
    <div class="subtabs" id="rgTabs">${tabs.map(([k, l, n]) => `<button data-t="${k}" aria-selected="${RG.tab === k}">${l}${n ? `<span class="count">${n}</span>` : ''}</button>`).join('')}</div><div id="rgBody"></div>`;
  $('#rgTabs').addEventListener('click', e => { const b = e.target.closest('[data-t]'); if (b) { RG.tab = b.dataset.t; RG.offset = 0; VIEWS.registry(el); } });
  const body = $('#rgBody');
  if (RG.tab === 'checks') {
    const d = await api('/api/registry/checks');
    body.innerHTML = table([{ h: '', f: r => sevTag(r.sev) }, { h: 'Setting', f: r => `<b>${esc(r.title)}</b><div class="mini">${esc(r.why)}</div>` },
      { h: 'Key', f: r => `<span class="m mini">${esc(r.hive)}\\${esc(r.path)}</span>` }, { h: 'Value', f: r => `<span class="m">${esc(r.value)} = ${esc(r.data)}</span>` },
      { h: 'Key written', f: r => T(r.ts), cls: 't' }], d,
      { empty: 'No risky settings found.', ref: r => 'browse:' + r.hive + '|' + r.path, pin: r => ({ ref: 'reg:' + r.hive + '\\' + r.path, ts: r.ts, src: 'registry', title: r.title, detail: `${r.hive}\\${r.path} ${r.value} = ${r.data}` }) });
    bindTable(body, ref => browseTo(ref.slice(7)));
  } else if (RG.tab === 'log' || RG.tab === 'deleted') {
    body.innerHTML = `<div class="toolbar"><input class="input wide" id="rgQ" placeholder="Filter key, value, data" value="${esc(RG.q)}"></div><div id="rgRows"></div>`;
    const load = async () => {
      const d = await api('/api/registry/changes?' + qs({ source: RG.tab === 'log' ? 'transaction log' : 'free space', q: RG.q }));
      $('#rgRows').innerHTML = `<p class="mini">${fmtN(d.total)} ${RG.tab === 'log' ? 'changes' : 'deleted keys (with whatever values could be recovered)'}</p>` + table([
        { h: 'Key written', f: r => T(r.ts), cls: 't' }, { h: 'Hive', k: 'hive' }, { h: 'Change', k: 'kind' }, { h: 'Key', k: 'path', cls: 'm' },
        { h: 'Value', k: 'value', cls: 'm' }, { h: 'Old', k: 'old', cls: 'm' }, { h: 'New', k: 'new', cls: 'm' }], d.rows,
        { empty: RG.tab === 'log' ? 'No unflushed changes: the hives were clean (fully written) when the image was taken.' : 'No deleted keys recovered.', ref: r => 'rc:' + r.id,
          pin: r => ({ ref: 'rc:' + r.id, ts: r.ts, src: 'registry', title: `${r.kind}: ${r.hive}\\${r.path} ${r.value || ''}`, detail: `old: ${r.old || ''} new: ${r.new || ''}` }) });
      bindTable($('#rgRows'));
    };
    $('#rgQ').addEventListener('change', () => { RG.q = $('#rgQ').value; load(); });
    load();
  } else if (RG.tab === 'recent') {
    if (!RG.from && o.impact && o.impact.window) { const d0 = parseUTC(o.impact.window.start); RG.from = iso(new Date(d0 - 24 * 3600e3)).slice(0, 19); RG.to = iso(new Date(parseUTC(o.impact.window.end).getTime() + 3600e3)).slice(0, 19); }
    body.innerHTML = `<div class="toolbar"><label class="field">From (${tzLabel()})<input class="input" type="datetime-local" step="1" id="rgFrom" value="${toInput(RG.from)}"></label>
      <label class="field">To<input class="input" type="datetime-local" step="1" id="rgTo" value="${toInput(RG.to)}"></label>
      <label class="field">Key contains<input class="input wide" id="rgQ" value="${esc(RG.q)}"></label><label class="field">Hive<select class="input" id="rgHive"><option value="">all</option></select></label>
      <button class="btn small" id="rgNoise" aria-pressed="${RG.noise}">Include noisy keys</button><button class="btn primary" id="rgGo">Apply</button></div><div id="rgRows"></div>`;
    const load = async (append) => {
      const d = await api('/api/registry/recent?' + qs({ from: RG.from, to: RG.to, q: RG.q, hive: RG.hive, noise: RG.noise ? 1 : '', offset: RG.offset }));
      if (!append) $('#rgHive').innerHTML = '<option value="">all</option>' + d.hives.map(h => `<option ${h === RG.hive ? 'selected' : ''}>${esc(h)}</option>`).join('');
      RG.rows = append ? RG.rows.concat(d.rows) : d.rows;
      $('#rgRows').innerHTML = `<p class="mini">${fmtN(d.total)} keys written in range. Click a key to browse it.</p>` + table([
        { h: 'Last write', f: r => T(r.ts), cls: 't' }, { h: 'Hive', k: 'hive' }, { h: 'Key', k: 'path', cls: 'm' }, { h: 'Values', k: 'nvals' }], RG.rows,
        { ref: r => 'browse:' + r.hive + '|' + r.path, pin: r => ({ ref: 'rk:' + r.id, ts: r.ts, src: 'registry', title: `Key written: ${r.hive}\\${r.path}`, detail: '' }) })
        + pager(d.total, RG.offset, d.rows.length, 'rgMore');
      bindTable($('#rgRows'), ref => browseTo(ref.slice(7)));
      const m = $('#rgMore');
      if (m) m.addEventListener('click', () => { RG.offset += d.rows.length; load(true); });
    };
    $('#rgGo').addEventListener('click', () => { RG.from = fromInput($('#rgFrom').value); RG.to = fromInput($('#rgTo').value); RG.q = $('#rgQ').value; RG.hive = $('#rgHive').value; RG.offset = 0; load(); });
    $('#rgNoise').addEventListener('click', () => { RG.noise = !RG.noise; $('#rgNoise').setAttribute('aria-pressed', RG.noise); RG.offset = 0; load(); });
    load();
  } else {
    const hives = await api('/api/registry/hives');
    body.innerHTML = `<div class="toolbar"><label class="field">Hive<select class="input" id="bHive">${hives.map(h => `<option ${h.label === RG.bhive ? 'selected' : ''}>${esc(h.label)}</option>`).join('')}</select></label>
      <label class="field">Path<input class="input" style="width:520px" id="bPath" value="${esc(RG.bpath)}" placeholder="Microsoft\\Windows\\CurrentVersion\\Run"></label><button class="btn primary" id="bGo">Open</button></div>
      <div id="bBody"></div>`;
    const go = () => { RG.bhive = $('#bHive').value; RG.bpath = $('#bPath').value.trim(); loadKey(); };
    $('#bGo').addEventListener('click', go);
    $('#bPath').addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    $('#bHive').addEventListener('change', () => { RG.bpath = ''; $('#bPath').value = ''; go(); });
    loadKey();
  }
};
const HIVE_ALIAS = { 'HKLM\\SOFTWARE': 'SOFTWARE', 'HKLM\\SYSTEM': 'SYSTEM', 'HKLM\\SAM': 'SAM', 'HKLM\\SECURITY': 'SECURITY', 'Amcache.hve': 'Amcache' };
function browseTo(s) {
  const [hive, path] = s.split('|');
  RG.tab = 'browse'; RG.bhive = HIVE_ALIAS[hive] || hive; RG.bpath = path || '';
  if (current === 'registry') VIEWS.registry($('#v-registry')); else show('registry');
}
async function loadKey() {
  const box = $('#bBody');
  if (!box) return;
  try {
    const d = await api('/api/registry/key?' + qs({ hive: RG.bhive, path: RG.bpath }));
    const parts = d.path ? d.path.split('\\') : [];
    const crumb = `<div class="crumb"><a data-p="">${esc(RG.bhive)}</a>${parts.map((p, i) => `<span>\\</span><a data-p="${esc(parts.slice(0, i + 1).join('\\'))}">${esc(p)}</a>`).join('')}</div>`;
    box.innerHTML = crumb + `<p class="mini">Key last written ${esc(fmtT(d.lastwrite))} ${tzLabel()}</p><div class="regsplit">
      <div class="list keylist">${d.subkeys.map(s => `<div class="item" data-p="${esc((d.path ? d.path + '\\' : '') + s.name)}"><span class="v">${esc(s.name)}</span><span class="t mini">${esc(fmtT(s.lastwrite, true))}</span></div>`).join('') || '<div class="empty">No subkeys</div>'}</div>
      <div>${table([{ h: 'Name', k: 'name', cls: 'm' }, { h: 'Type', k: 'type' }, { h: 'Data', k: 'data', cls: 'm' }], d.values, { empty: 'No values.', pin: v => ({ ref: `reg:${RG.bhive}\\${d.path}`, ts: d.lastwrite, src: 'registry', title: `${RG.bhive}\\${d.path} ${v.name}`, detail: v.data }) })}</div></div>`;
    box.addEventListener('click', e => { const a = e.target.closest('[data-p]'); if (a) { RG.bpath = a.dataset.p; $('#bPath').value = RG.bpath; loadKey(); } }, { once: true });
    bindTable(box);
  } catch (e) { box.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

/* ============================================================== EVENTS === */
const EV = { channel: '', eid: '', q: '', from: '', to: '', offset: 0, order: 'asc' };
const EV_PRESETS = [['Logons', 'Security', '4624,4625,4648,4672'], ['Process creation', 'Security', '4688'], ['Services', '', '7045,4697,7036,7040'],
  ['Log cleared', '', '1102,104'], ['Accounts & groups', 'Security', '4720,4722,4724,4728,4732,4756'], ['Tasks', '', '4698,4702,106,140,141,200'],
  ['PowerShell', 'Microsoft-Windows-PowerShell/Operational', '4103,4104'], ['Defender', 'Microsoft-Windows-Windows Defender/Operational', '1116,1117,5001,5007,5013'],
  ['RDP', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', '21,22,24,25'], ['Boot / shutdown', 'System', '6005,6006,6008,1074,12,13']];
VIEWS.events = async el => {
  const s = await api('/api/events/stats');
  el.innerHTML = `<h1>Event logs</h1><p class="sub">All .evtx records with BinXML decoded. Event IDs, fields and a one-line summary for common ransomware-relevant events.</p>
    <div class="chips" id="evPre" style="margin-bottom:10px">${EV_PRESETS.map((p, i) => `<button class="chip" data-i="${i}">${esc(p[0])}</button>`).join('')}</div>
    <div class="evsplit"><div class="list chlist" id="evCh"><div class="item ${!EV.channel ? 'active' : ''}" data-c=""><span class="v">all channels</span><span class="faint">${fmtN(s.channels.reduce((a, c) => a + c.n, 0))}</span></div>
      ${s.channels.map(c => `<div class="item ${EV.channel === c.channel ? 'active' : ''}" data-c="${esc(c.channel)}" title="${esc(fmtT(c.first, true))} → ${esc(fmtT(c.last, true))}"><span class="v">${esc(c.channel.replace('Microsoft-Windows-', ''))}</span><span class="faint">${fmtN(c.n)}</span></div>`).join('')}</div>
      <div><div class="toolbar"><label class="field">Event IDs<input class="input" id="evId" value="${esc(EV.eid)}" placeholder="4624, 4688" size="14"></label>
        <label class="field">Text<input class="input wide" id="evQ" value="${esc(EV.q)}"></label>
        <label class="field">From (${tzLabel()})<input class="input" type="datetime-local" step="1" id="evFrom" value="${toInput(EV.from)}"></label>
        <label class="field">To<input class="input" type="datetime-local" step="1" id="evTo" value="${toInput(EV.to)}"></label>
        <label class="field">Order<select class="input" id="evOrd"><option value="asc">oldest first</option><option value="desc" ${EV.order === 'desc' ? 'selected' : ''}>newest first</option></select></label>
        <button class="btn primary" id="evGo">Apply</button></div><div id="evRows"></div></div></div>`;
  $('#evCh').addEventListener('click', e => { const i = e.target.closest('[data-c]'); if (i) { EV.channel = i.dataset.c; EV.offset = 0; VIEWS.events(el); } });
  $('#evPre').addEventListener('click', e => { const b = e.target.closest('[data-i]'); if (b) { const p = EV_PRESETS[+b.dataset.i]; EV.channel = p[1]; EV.eid = p[2]; EV.offset = 0; VIEWS.events(el); } });
  const apply = () => { EV.eid = $('#evId').value; EV.q = $('#evQ').value; EV.from = fromInput($('#evFrom').value); EV.to = fromInput($('#evTo').value); EV.order = $('#evOrd').value; EV.offset = 0; loadEv(); };
  $('#evGo').addEventListener('click', apply);
  ['#evId', '#evQ'].forEach(s => $(s).addEventListener('keydown', e => { if (e.key === 'Enter') apply(); }));
  loadEv();
};
async function loadEv(append = false) {
  const d = await api('/api/events?' + qs({ channel: EV.channel, eid: EV.eid, q: EV.q, from: EV.from, to: EV.to, offset: EV.offset, order: EV.order }));
  EV.rows = append ? EV.rows.concat(d.rows) : d.rows;
  $('#evRows').innerHTML = `<p class="mini">${fmtN(d.total)} events</p>` + table([{ h: 'Time', f: r => T(r.ts), cls: 't' },
    { h: 'Channel', f: r => esc(r.channel.replace('Microsoft-Windows-', '')) }, { h: 'ID', k: 'eid' }, { h: 'Summary', k: 'summary', cls: 'm' }], EV.rows,
    { ref: r => 'ev:' + r.id, pin: r => ({ ref: 'ev:' + r.id, ts: r.ts, src: 'event', title: `${r.channel} ${r.eid}`, detail: r.summary }) }) + pager(d.total, EV.offset, d.rows.length, 'evMore');
  bindTable($('#evRows'));
  const m = $('#evMore');
  if (m) m.addEventListener('click', () => { EV.offset += d.rows.length; loadEv(true); });
}

/* ============================================================== LOGONS === */
VIEWS.logons = async el => {
  const d = await api('/api/logons');
  el.innerHTML = `<h1>Logons &amp; RDP</h1><p class="sub">Security 4624 (success), 4625 (failure) and 4648 (explicit credentials), grouped by account, logon type and source. Service and machine-account logons are hidden. Public source addresses are highlighted.</p>
    ${table([{ h: 'Event', f: r => r.eid === 4625 ? '<span class="sev high">failed</span>' : r.eid === 4648 ? 'explicit creds' : 'success' },
      { h: 'Account', k: 'user', cls: 'm' }, { h: 'Type', f: r => `${esc(r.type)} <span class="faint">${esc(r.type_name)}</span>` },
      { h: 'Source IP', f: r => r.ip && r.ip !== '-' ? `<span class="${r.public ? 'flag hi' : 'm'}">${esc(r.ip)}</span>` : '' }, { h: 'Workstation', k: 'ws' },
      { h: 'Auth', k: 'auth' }, { h: 'Count', k: 'n' }, { h: 'First', f: r => T(r.first), cls: 't' }, { h: 'Last', f: r => T(r.last), cls: 't' }], d.logons,
      { empty: 'No logon events (Security log missing, cleared or rolled over).', rowCls: r => r.public || (r.eid === 4625 && r.n > 20) ? 'bad' : '',
        pin: r => ({ ref: 'logon:' + r.user + '@' + r.ip, ts: r.first, src: 'event', title: `${r.eid === 4625 ? 'Failed logons' : 'Logons'} ${r.user} type ${r.type} from ${r.ip || r.ws}`, detail: `${r.n}× ${r.first} → ${r.last}` }) })}
    <h2 style="margin-top:20px">RDP sessions</h2>
    <div id="rdp">${table([{ h: 'Time', f: r => T(r.ts), cls: 't' }, { h: 'Channel', f: r => esc(r.channel.replace('Microsoft-Windows-', '')) }, { h: 'ID', k: 'eid' }, { h: 'Summary', k: 'summary', cls: 'm' }], d.rdp,
      { empty: 'No RDP session events.' })}</div>`;
  bindTable(el);
};

/* ========================================================== FILESYSTEM === */
const FS = { q: '', ext: '', field: 'si_c', from: '', to: '', filter: '', sort: 'time', offset: 0 };
VIEWS.fs = async el => {
  el.innerHTML = `<h1>Filesystem (MFT)</h1><p class="sub">Every $MFT entry, including deleted records still in the table. Search by path, filter by time on any $SI/$FN timestamp, and jump to executables, timestomped files, downloads (Zone.Identifier) and alternate data streams.</p>
    <div class="toolbar"><label class="field">Path contains<input class="input wide" id="fsQ" value="${esc(FS.q)}"></label>
      <label class="field">Extensions<input class="input" id="fsExt" value="${esc(FS.ext)}" placeholder="exe, ps1" size="12"></label>
      <label class="field">Show<select class="input" id="fsFilter">${[['', 'all files'], ['exec', 'executables & scripts'], ['deleted', 'deleted records'], ['timestomp', 'timestomped ($SI < $FN)'], ['zone', 'downloaded (Zone.Identifier)'], ['ads', 'other alternate streams'], ['encrypted', 'encrypted'], ['notes', 'ransom notes']].map(([v, l]) => `<option value="${v}" ${FS.filter === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <label class="field">Time field<select class="input" id="fsField">${[['si_c', '$SI created'], ['si_m', '$SI modified'], ['si_e', '$SI entry modified'], ['si_a', '$SI accessed'], ['fn_c', '$FN created'], ['fn_m', '$FN modified']].map(([v, l]) => `<option value="${v}" ${FS.field === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <label class="field">From (${tzLabel()})<input class="input" type="datetime-local" step="1" id="fsFrom" value="${toInput(FS.from)}"></label>
      <label class="field">To<input class="input" type="datetime-local" step="1" id="fsTo" value="${toInput(FS.to)}"></label>
      <label class="field">Sort<select class="input" id="fsSort"><option value="time">time, newest</option><option value="path" ${FS.sort === 'path' ? 'selected' : ''}>path</option><option value="size" ${FS.sort === 'size' ? 'selected' : ''}>size</option></select></label>
      <button class="btn primary" id="fsGo">Apply</button></div><div id="fsRows"></div>`;
  const apply = () => { FS.q = $('#fsQ').value; FS.ext = $('#fsExt').value; FS.filter = $('#fsFilter').value; FS.field = $('#fsField').value; FS.from = fromInput($('#fsFrom').value); FS.to = fromInput($('#fsTo').value); FS.sort = $('#fsSort').value; FS.offset = 0; loadFs(); };
  $('#fsGo').addEventListener('click', apply);
  ['#fsQ', '#fsExt'].forEach(s => $(s).addEventListener('keydown', e => { if (e.key === 'Enter') apply(); }));
  ['#fsFilter', '#fsField', '#fsSort'].forEach(s => $(s).addEventListener('change', apply));
  loadFs();
};
async function loadFs(append = false) {
  const d = await api('/api/files?' + qs({ q: FS.q, ext: FS.ext, filter: FS.filter, field: FS.field, from: FS.from, to: FS.to, sort: FS.sort, offset: FS.offset }));
  FS.rows = append ? FS.rows.concat(d.rows) : d.rows;
  $('#fsRows').innerHTML = `<p class="mini">${fmtN(d.total)} entries</p>` + table([
    { h: '$SI created', f: r => T(r.si_c), cls: 't' }, { h: '$SI modified', f: r => T(r.si_m), cls: 't' }, { h: 'Entry modified', f: r => T(r.si_e), cls: 't' },
    { h: 'Path', f: r => `<span class="m">${esc(r.path)}</span>${r.zone ? `<div class="mini">${esc(r.zone)}</div>` : ''}` }, { h: 'Size', f: r => fmtB(r.size) },
    { h: 'Flags', f: r => [r.in_use ? '' : '<span class="flag">deleted</span>', r.enc ? '<span class="flag hi">encrypted</span>' : '', r.note ? '<span class="flag hi">note</span>' : '', flags((r.flags || '').replace(/,/g, ';'))].join('') }], FS.rows,
    { ref: r => 'f:' + r.rec, rowCls: r => r.in_use ? '' : 'dim', pin: r => ({ ref: 'f:' + r.rec, ts: r.si_c, src: 'mft', title: r.path, detail: `created ${r.si_c}, modified ${r.si_m} ${r.flags || ''}` }) })
    + pager(d.total, FS.offset, d.rows.length, 'fsMore');
  bindTable($('#fsRows'));
  const m = $('#fsMore');
  if (m) m.addEventListener('click', () => { FS.offset += d.rows.length; loadFs(true); });
}

/* ================================================================= USN === */
const US = { q: '', reason: '', close: true, from: '', to: '', offset: 0, order: 'asc' };
VIEWS.usn = async el => {
  el.innerHTML = `<h1>USN journal</h1><p class="sub">$Extend\\$UsnJrnl:$J: every create, rename, overwrite and delete the filesystem recorded, with the file name at that moment. Deleted payloads and the original names of encrypted files show up here. "Final records only" keeps the Close record of each operation (it carries all reasons combined).</p>
    <div class="toolbar"><label class="field">Path contains<input class="input wide" id="usQ" value="${esc(US.q)}"></label>
      <label class="field">Reason<select class="input" id="usR">${['', 'create', 'delete', 'rename', 'overwrite', 'extend', 'truncate', 'security', 'basic', 'stream'].map(r => `<option ${US.reason === r ? 'selected' : ''} value="${r}">${r || 'any'}</option>`).join('')}</select></label>
      <label class="field">From (${tzLabel()})<input class="input" type="datetime-local" step="1" id="usFrom" value="${toInput(US.from)}"></label>
      <label class="field">To<input class="input" type="datetime-local" step="1" id="usTo" value="${toInput(US.to)}"></label>
      <button class="btn small" id="usClose" aria-pressed="${US.close}">Final records only</button>
      <label class="field">Order<select class="input" id="usOrd"><option value="asc">oldest first</option><option value="desc" ${US.order === 'desc' ? 'selected' : ''}>newest first</option></select></label>
      <button class="btn primary" id="usGo">Apply</button></div><div id="usRows"></div>`;
  const apply = () => { US.q = $('#usQ').value; US.reason = $('#usR').value; US.from = fromInput($('#usFrom').value); US.to = fromInput($('#usTo').value); US.order = $('#usOrd').value; US.offset = 0; loadUs(); };
  $('#usGo').addEventListener('click', apply);
  $('#usQ').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
  $('#usClose').addEventListener('click', () => { US.close = !US.close; $('#usClose').setAttribute('aria-pressed', US.close); US.offset = 0; loadUs(); });
  loadUs();
};
async function loadUs(append = false) {
  const d = await api('/api/usn?' + qs({ q: US.q, reason: US.reason, close: US.close ? 1 : '', from: US.from, to: US.to, offset: US.offset, order: US.order }));
  US.rows = append ? US.rows.concat(d.rows) : d.rows;
  $('#usRows').innerHTML = `<p class="mini">${fmtN(d.total)} records${d.range ? ` · journal covers ${esc(fmtT(d.range.first, true))} → ${esc(fmtT(d.range.last, true))}` : ''}</p>` + table([
    { h: 'Time', f: r => T(r.ts), cls: 't' }, { h: 'Reasons', f: r => esc(r.reasons.replace(/\|/g, ' ')) }, { h: 'Path (at that time)', k: 'path', cls: 'm' }, { h: 'MFT rec', k: 'rec' }], US.rows,
    { ref: r => 'f:' + r.rec, empty: 'No USN records (journal not found, or disabled).', pin: r => ({ ref: 'usn:' + r.id, ts: r.ts, src: 'usn', title: `${r.reasons}: ${r.path}`, detail: `MFT record ${r.rec}` }) })
    + pager(d.total, US.offset, d.rows.length, 'usMore');
  bindTable($('#usRows'));
  const m = $('#usMore');
  if (m) m.addEventListener('click', () => { US.offset += d.rows.length; loadUs(true); });
}

/* ============================================================ FINDINGS === */
const FD = { sev: '', cat: '', q: '', title: '' };
VIEWS.findings = async el => {
  const d = await api('/api/findings?' + qs({ sev: FD.sev, cat: FD.cat, q: FD.q }));
  const cats = [...new Set(d.groups.map(g => g.cat))].sort();
  const rows = FD.title ? d.rows.filter(r => r.title === FD.title) : d.rows;
  el.innerHTML = `<h1>Findings</h1><p class="sub">Rule hits from event logs, command lines (4688, Sysmon, PowerShell, tasks, services, Run keys, LNK arguments, PSReadLine history), browser downloads, and the ransomware analysis.</p>
    <div class="toolbar"><div class="seg" id="fdSev">${['', 'high', 'medium', 'low'].map(s => `<button type="button" data-s="${s}" aria-pressed="${FD.sev === s}">${s || 'all'}</button>`).join('')}</div>
      <label class="field">Category<select class="input" id="fdCat"><option value="">all</option>${cats.map(c => `<option ${FD.cat === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select></label>
      <input class="input wide" id="fdQ" placeholder="Filter" value="${esc(FD.q)}"></div>
    <div class="grid2"><div class="panel" style="padding:8px 10px"><div class="list" id="fdGroups" style="border:0">${d.groups.map(g => `<div class="item ${FD.title === g.title ? 'active' : ''}" data-t="${esc(g.title)}" style="grid-template-columns:70px 1fr 50px"><span>${sevTag(g.sev)}</span><span>${esc(g.title)}<div class="mini">${esc(g.cat)} · ${esc(fmtT(g.first, true))}</div></span><span class="num">${fmtN(g.n)}</span></div>`).join('') || '<div class="empty">No findings.</div>'}</div></div>
      <div id="fdRows">${table([{ h: 'Time', f: r => T(r.ts), cls: 't' }, { h: '', f: r => sevTag(r.sev) }, { h: 'Finding', f: r => `<b>${esc(r.title)}</b><div class="mini m">${esc(r.detail)}</div>` }], rows.slice(0, 1500),
        { ref: r => r.ref || 'fd:' + r.id, pin: r => ({ ref: r.ref || 'fd:' + r.id, ts: r.ts, src: 'finding', title: r.title, detail: r.detail }) })}</div></div>`;
  $('#fdSev').addEventListener('click', e => { const b = e.target.closest('[data-s]'); if (b) { FD.sev = b.dataset.s; FD.title = ''; VIEWS.findings(el); } });
  $('#fdCat').addEventListener('change', () => { FD.cat = $('#fdCat').value; FD.title = ''; VIEWS.findings(el); });
  $('#fdQ').addEventListener('change', () => { FD.q = $('#fdQ').value; VIEWS.findings(el); });
  $('#fdGroups').addEventListener('click', e => { const i = e.target.closest('[data-t]'); if (i) { FD.title = FD.title === i.dataset.t ? '' : i.dataset.t; VIEWS.findings(el); } });
  bindTable($('#fdRows'));
};

/* =========================================================== ARTIFACTS === */
const AR = { kind: '', q: '', offset: 0 };
VIEWS.artifacts = async el => {
  const d = await api('/api/artifacts?' + qs({ kind: AR.kind, q: AR.q }));
  el.innerHTML = `<h1>User artifacts</h1><p class="sub">Shortcuts (Recent, Desktop), Recycle Bin, PowerShell console history, browser history and downloads, RDP client history, typed paths, wallpaper, AnyDesk/TeamViewer connection logs and Defender MPLog lines. Times from text logs are as written (often local time).</p>
    <div class="toolbar"><div class="chips" id="arK"><button class="chip" data-k="" aria-pressed="${!AR.kind}">all</button>${d.kinds.map(k => `<button class="chip" data-k="${esc(k.kind)}" aria-pressed="${AR.kind === k.kind}">${esc(k.kind)} <span class="faint">${fmtN(k.n)}</span></button>`).join('')}</div></div>
    <div class="toolbar"><input class="input wide" id="arQ" placeholder="Filter" value="${esc(AR.q)}"></div>
    <div id="arRows">${table([{ h: 'Time', f: r => T(r.ts), cls: 't' }, { h: 'Kind', k: 'kind' }, { h: 'What', k: 'title', cls: 'm' }, { h: 'Detail', k: 'detail', cls: 'mini' }], d.rows,
      { ref: r => 'ar:' + r.id, empty: 'No user artifacts found.', pin: r => ({ ref: 'ar:' + r.id, ts: r.ts, src: 'artifact', title: `${r.kind}: ${r.title}`, detail: r.detail }) })}</div>`;
  $('#arK').addEventListener('click', e => { const b = e.target.closest('[data-k]'); if (b) { AR.kind = b.dataset.k; VIEWS.artifacts(el); } });
  $('#arQ').addEventListener('change', () => { AR.q = $('#arQ').value; VIEWS.artifacts(el); });
  bindTable($('#arRows'));
};

/* =============================================================== BOARD === */
VIEWS.board = async el => {
  const pins = await api('/api/pins');
  el.innerHTML = `<div class="row"><h1 class="grow">Evidence board</h1><a class="btn" href="/api/report.md">Download case report (Markdown)</a></div>
    <p class="sub">Pinned items in time order with your notes. The report adds host facts, impact, payload candidates, key events and risky registry settings.</p>
    ${pins.length ? pins.map(p => `<div class="panel" style="margin-bottom:10px"><div class="row"><span class="t mono mini">${esc(fmtT(p.ts))}</span><span class="src ${esc(p.src)}">${esc(p.src)}</span>
      <b class="grow">${esc(p.title)}</b><button class="btn small ghost" data-open="${esc(p.ref)}">Open</button><button class="btn small ghost danger" data-del="${p.id}">Remove</button></div>
      ${p.detail ? `<div class="mini m" style="margin:6px 0">${esc(p.detail)}</div>` : ''}
      <textarea class="input" data-note="${p.id}" style="width:100%;min-height:40px;padding:6px 8px" placeholder="Your note">${esc(p.note || '')}</textarea></div>`).join('')
      : '<div class="empty"><h2>Nothing pinned yet</h2>Use 📌 on any row or the Pin button in a detail drawer.</div>'}`;
  el.onclick = async e => {
    const d = e.target.closest('[data-del]'), o = e.target.closest('[data-open]');
    if (d) { await post('/api/pins/' + d.dataset.del, {}, 'DELETE'); refreshCounts(); VIEWS.board(el); }
    if (o) openRef(o.dataset.open).catch(err => toast(err.message, true));
  };
  $$('[data-note]', el).forEach(t => t.addEventListener('change', () => post('/api/pins/' + t.dataset.note, { note: t.value }, 'PATCH').then(() => toast('Note saved'))));
};

/* ================================================================ CASE === */
VIEWS.case = async el => {
  const st = await api('/api/status');
  const o = st.options || {};
  const src = st.source || {};
  el.innerHTML = `<h1>Case &amp; source</h1>
    <div class="grid2"><div class="panel"><h2>Evidence</h2>
      <p class="note">Mount the Macrium image read-only (Reflect → Restore → <b>Browse for an image</b> → <b>Explore image</b>, untick "Enable write access"), note the drive letter, and run Embers <b>as Administrator</b> with the raw volume path, e.g. <span class="mono">\\\\.\\F:</span>. Reading the raw volume gets $MFT, the USN journal, locked hives and files your account may not be allowed to open. Alternatively convert the image to VHD/VHDX (Other tasks → Convert image), attach it read-only and use <span class="mono">\\\\.\\PhysicalDriveN</span>, or give a raw/dd image file.</p>
      <div class="toolbar"><label class="field">Source<input class="input" style="width:340px" id="cSrc" value="${esc(o.spec || '')}" placeholder="\\\\.\\F:   or   D:\\cases\\disk.raw   or   F:\\"></label>
        <button class="btn" id="cParts">Detect partitions</button></div>
      <div id="cPartList"></div>
      <div class="toolbar"><label class="field">Partition<input class="input" id="cPart" size="6" value="${o.partition ?? ''}" placeholder="auto"></label>
        <label class="field">Folder mode: exported $MFT<input class="input" id="cMft" value="${esc(o.mft || '')}" size="24"></label>
        <label class="field">exported $J<input class="input" id="cUsn" value="${esc(o.usn || '')}" size="24"></label></div>
      <div class="toolbar"><label class="field">Registry key history (days)<input class="input" id="cReg" type="number" value="${o.reg_days || 60}" style="width:90px"></label>
        <label class="field">Timeline starts N days before encryption<input class="input" id="cSpan" type="number" value="${o.span_days || 14}" style="width:90px"></label>
        <button class="btn primary" id="cStart">${st.indexed_at ? 'Re-index' : 'Index'}</button>${st.running ? '<button class="btn danger" id="cCancel">Cancel</button>' : ''}</div></div>
    <div class="panel"><h2>Status</h2><div id="cStatus"></div>
      ${src.kind ? `<h2 style="margin-top:14px">Source</h2>${kv({ kind: src.kind, source: src.source, partition: src.partition, volume_size: src.volume_size && fmtB(src.volume_size), cluster: src.cluster, volume_serial: src.serial, mft_records: src.mft_records && fmtN(src.mft_records) })}` : ''}
      ${(st.errors_saved || []).length ? `<h2 style="margin-top:14px">Parser warnings</h2><div class="pre">${esc(st.errors_saved.join('\n'))}</div>` : ''}</div></div>`;
  $('#cParts').addEventListener('click', async () => {
    try {
      const d = await api('/api/partitions?' + qs({ source: $('#cSrc').value.trim() }));
      $('#cPartList').innerHTML = d.partitions.length ? table([{ h: '#', k: 'index' }, { h: 'Offset', f: p => fmtN(p.offset) }, { h: 'Size', f: p => fmtB(p.size) }, { h: 'NTFS', f: p => p.ntfs ? 'yes' : '' }, { h: 'Name', k: 'name' }], d.partitions, { ref: p => 'part:' + p.index })
        : '<p class="mini">A folder: files are read through the filesystem.</p>';
      bindTable($('#cPartList'), ref => ($('#cPart').value = ref.slice(5)));
    } catch (e) { toast(e.message, true); }
  });
  $('#cStart').addEventListener('click', async () => {
    try {
      await post('/api/index', { source: $('#cSrc').value.trim(), partition: $('#cPart').value.trim(), mft: $('#cMft').value.trim(), usn: $('#cUsn').value.trim(), reg_days: $('#cReg').value, span_days: $('#cSpan').value });
      toast('Indexing started'); pollStatus(true);
    } catch (e) { toast(e.message, true); }
  });
  if ($('#cCancel')) $('#cCancel').addEventListener('click', () => post('/api/cancel').then(() => toast('Cancelling…')));
  drawStatus(st);
};
function drawStatus(st) {
  const box = $('#cStatus');
  if (!box) return;
  const names = st.stages_all || [];
  const seen = (st.stages || []).map(s => s.name);
  box.innerHTML = `<div class="stages">${names.map(n => `<span class="${st.running && st.stage === n ? 'now' : seen.includes(n) ? 'done' : ''}">${esc(n)}</span>`).join('')}</div>
    ${st.running ? `<p>${esc(st.stage)} ${st.total ? `${fmtN(st.done)} / ${fmtN(st.total)}` : ''} <span class="faint">${esc(st.msg || '')}</span></p>
      <div class="progress"><div style="width:${st.total ? (100 * st.done / st.total).toFixed(1) : 5}%"></div></div>` : `<p class="muted">${st.indexed_at ? 'Indexed ' + esc(st.indexed_at) : 'Not indexed yet.'}</p>`}
    ${(st.errors || []).length && st.running ? `<div class="pre">${esc(st.errors.join('\n'))}</div>` : ''}`;
}

/* ------------------------------------------------------------- status ---- */
let pollTimer = null, wasRunning = false;
async function pollStatus(soon = false, after) {
  clearTimeout(pollTimer);
  try {
    const st = await api('/api/status');
    const dot = $('#indexChip .dot');
    dot.className = 'dot ' + (st.running ? 'run' : st.indexed_at ? 'ok' : '');
    $('#indexText').textContent = st.running ? `${st.stage}${st.total ? ` ${Math.round(100 * st.done / Math.max(1, st.total))}%` : ''}` : (st.indexed_at ? `${(st.source && st.source.source) || 'case'} · indexed ${st.indexed_at}` : 'No evidence yet');
    if (current === 'case') drawStatus(st);
    if (st.running) { wasRunning = true; pollTimer = setTimeout(() => pollStatus(false, after), 1200); }
    else if (wasRunning || soon) {
      wasRunning = false; OV = null; refreshCounts();
      if (after) after(); else if (current && current !== 'case') show(current);
    }
  } catch (e) { pollTimer = setTimeout(pollStatus, 4000); }
}
$('#indexChip').addEventListener('click', () => show('case'));

/* ---------------------------------------------------------- theme & tz ---- */
function setTheme(light) {
  document.documentElement.dataset.theme = light ? 'light' : '';
  try { localStorage.setItem('embers-theme', light ? 'light' : 'dark'); } catch (e) {}
  $('#themeBtn').textContent = light ? 'Dark theme' : 'Light theme';
}
$('#themeBtn').addEventListener('click', () => setTheme(document.documentElement.dataset.theme !== 'light'));
setTheme(document.documentElement.dataset.theme === 'light');
function setTZ(mode) {
  TZ.mode = mode;
  try { localStorage.setItem('embers-tz', mode); } catch (e) {}
  $$('[data-tz]').forEach(b => b.setAttribute('aria-pressed', b.dataset.tz === mode));
}
$$('[data-tz]').forEach(b => b.addEventListener('click', () => { setTZ(b.dataset.tz); if (current) show(current); }));
setTZ(TZ.mode);

/* ---------------------------------------------------------------- boot ---- */
(async () => {
  try { await overview(); } catch (e) { /* empty db */ }
  refreshCounts();
  show(location.hash.slice(1) || 'overview');
  pollStatus();
})();
