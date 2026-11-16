/* The Kingphisher-Man UI. SECURITY NOTE: all dynamic data is rendered with textContent / createElement only
   (never innerHTML) because e-mail contents are attacker-controlled. */
(() => {
'use strict';
const CSRF = document.querySelector('meta[name="csrf"]').content;
const $ = (s, r = document) => r.querySelector(s);
const qp = new URLSearchParams(location.search);

function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return e;
}
async function api(path, opts = {}) {
  const o = { method: opts.method || 'GET', headers: { ...(opts.headers || {}) } };
  if (o.method === 'POST') o.headers['X-CSRF-Token'] = CSRF;
  if (opts.json) { o.body = JSON.stringify(opts.json); o.headers['Content-Type'] = 'application/json'; }
  if (opts.body) o.body = opts.body;
  const r = await fetch(path, o);
  let data = null; try { data = await r.json(); } catch (_) { /* not json */ }
  if (!r.ok) { const e = new Error((data && data.error) || ('HTTP ' + r.status)); e.data = data; throw e; }
  return data;
}

/* ================= views ================= */
const VIEWS = ['intro', 'menu', 'demo', 'upload', 'pro', 'run', 'results'];
let current = 'intro';
function show(name) {
  current = name;
  VIEWS.forEach((v) => $('#view-' + v).classList.toggle('active', v === name));
  window.scrollTo(0, 0);
  if (name === 'menu') refreshStatus();
}
document.querySelectorAll('[data-goto]').forEach((b) => b.addEventListener('click', () => show(b.dataset.goto)));

/* ================= status / quota ================= */
let STATUS = null;
async function refreshStatus() {
  try {
    STATUS = await api('/api/status');
  } catch (_) {
    return;
  }

  // All three modes have unlimited runs
  document.querySelectorAll('.cq').forEach((c) => {
    c.textContent = 'UNLIMITED RUNS';
  });

  $('#uploadQuota').textContent = 'UNLIMITED RUNS';
  $('#proQuota').textContent = 'UNLIMITED RUNS';

  const warn = [];

  if (!STATUS.tool_ok) {
    warn.push('⚠ Analysis tool not found - check TOOL_SCRIPT');
  }

  if (!STATUS.domain_tool_ok) {
    warn.push('ℹ Domain analyzer unavailable');
  }

  $('#menuWarn').textContent = warn.join('   ');

  // Rookie can always run again
  $('#btnDemoStart').disabled = false;

  // Previous demo result remains accessible
  $('#btnDemoLast').classList.toggle(
    'hidden',
    !STATUS.last_demo
  );
}


/* ================= menu ================= */
const CARDS = [
  { key: 'a', cls: 'card-a', icon: 'fish', title: 'ROOKIE', sub: 'THE SHALLOWS', view: 'demo', q: 'demo',
    desc: 'Watch the Kingphisher-Man hook real phishing samples from the phishing_pot pond. Analyse as many as you like.' },
  { key: 'b', cls: 'card-b', icon: 'upload', title: 'AMATEUR', sub: 'OPEN WATER', view: 'upload', q: 'upload',
    desc: 'Upload your own .eml file and get the full Header · Domain · IP · File analysis.' },
  { key: 'c', cls: 'card-c', icon: 'shield', title: 'PRO', sub: 'THE DEEP SEA', view: 'pro', q: 'pro',
    desc: 'Connect a Gmail inbox. Mail from your test sender is held, analysed, then released.' },
];
let sel = 0, lastWheel = 0;
const cardEls = [];
function buildCards() {
  const box = $('#cards');
  CARDS.forEach((c, i) => {
    const cv = h('canvas', { width: 24, height: 24 });
    const el = h('div', { class: 'card ' + c.cls, role: 'option', tabindex: '0', 'aria-label': `${c.key.toUpperCase()}: ${c.title}` },
      h('div', { class: 'badge', text: c.key.toUpperCase() }), cv,
      h('div', { class: 'ct', text: c.title }), h('div', { class: 'cs', text: c.sub }),
      h('div', { class: 'cd', text: c.desc }), h('div', { class: 'cq', 'data-q': c.q, text: '...' }));
    el.addEventListener('mouseenter', () => select(i));
    el.addEventListener('focus', () => select(i));
    el.addEventListener('click', () => open(i));
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(i); } });
    box.append(el); cardEls.push(el);
    if (window.KP) KP.icon(cv, c.icon);
  });
  select(0);
}
function select(i) { sel = (i + CARDS.length) % CARDS.length; cardEls.forEach((el, k) => el.classList.toggle('sel', k === sel)); }
function open(i) { select(i); show(CARDS[sel].view); refreshStatus(); }
document.addEventListener('keydown', (e) => {
  if (current !== 'menu' || e.ctrlKey || e.metaKey || e.altKey) return;
  const k = e.key.toLowerCase();
  const idx = ['a', 'b', 'c'].indexOf(k) >= 0 ? ['a', 'b', 'c'].indexOf(k) : ['1', '2', '3'].indexOf(k);
  if (idx >= 0) { e.preventDefault(); open(idx); }
  else if (k === 'arrowright') { e.preventDefault(); select(sel + 1); }
  else if (k === 'arrowleft') { e.preventDefault(); select(sel - 1); }
  else if (k === 'enter' && document.activeElement && !document.activeElement.classList.contains('card')) { open(sel); }
});
$('#view-menu').addEventListener('wheel', (e) => {
  const now = Date.now(); if (now - lastWheel < 260) return; lastWheel = now;
  select(sel + (e.deltaY > 0 || e.deltaX > 0 ? 1 : -1));
}, { passive: true });

/* ================= shared run view ================= */
const STAGES = {
  demo: [['CAST THE LINE', 'Ask GitHub for the list of samples in the phishing_pot pond'], ['HOOK A SAMPLE', 'Download one random sample that was never caught before'],
         ['LOG THE CATCH', 'Record it so it can never be fetched again'], ['INSPECT', 'The analysis tool checks headers, domains, IPs and files'],
         ['VERDICT', 'The four layers are combined into one score']],
  upload: [['RECEIVE', 'Your file arrives at the local server'], ['VALIDATE', 'Checked: real .eml, size, readable headers'],
           ['INSPECT', 'The analysis tool runs on your file'], ['VERDICT', 'H·D·I·F layers + final score']],
  pro: [['LISTEN', 'Watching the inbox for the allowed sender'], ['HOLD', 'The mail is hidden (archived) the moment it lands'],
        ['DOWNLOAD', 'The raw .eml is saved locally'], ['INSPECT', 'The analysis tool runs on the held mail'],
        ['RELEASE', 'Banner added, delivered to Inbox or Spam']],
};
const RUN = { job: null, kind: null, since: 0, timer: null, stage: 0, alive: false };
function startRun(kind, job) {
  Object.assign(RUN, { job, kind, since: 0, stage: 0, alive: true });
  $('#runTitle').textContent = { demo: 'A · CASTING THE LINE', upload: 'B · ANALYSING YOUR FILE', pro: 'C · GUARDING THE INBOX' }[kind];
  const st = $('#stepper'); st.replaceChildren();
  STAGES[kind].forEach(([t, d], i) => st.append(h('li', {}, h('div', { class: 'n', text: String(i + 1) }), h('div', {}, h('div', { class: 't', text: t }), h('div', { class: 'd', text: d })))));
  $('#runLog').replaceChildren(); $('#runResult').className = 'run-result hidden'; $('#runResult').replaceChildren();
  $('#countdown').classList.toggle('hidden', kind !== 'pro');
  $('#btnStop').classList.toggle('hidden', kind !== 'pro');
  $('#btnClosePreview').classList.toggle('hidden', kind !== 'demo');
  $('#runBody').classList.remove('preview-closed');
  show('run');
  poll();
}
$('#btnClosePreview').addEventListener('click', () => $('#runBody').classList.toggle('preview-closed'));
$('#btnRunMenu').addEventListener('click', () => { RUN.alive = false; clearTimeout(RUN.timer); show('menu'); });
$('#btnStop').addEventListener('click', async () => { try { await api(`/api/job/${RUN.job}/stop`, { method: 'POST' }); } catch (_) { /* ignore */ } });
function setStage(n) {
  RUN.stage = Math.max(RUN.stage, n);
  [...$('#stepper').children].forEach((li, i) => { li.classList.toggle('done', i + 1 < RUN.stage); li.classList.toggle('active', i + 1 === RUN.stage); });
}
function addEvent(ev) {
  if (ev.stage) setStage(ev.stage);
  if (ev.tag === 'stage') return;
  const log = $('#runLog');
  log.append(h('div', { class: 'ln ' + ev.tag }, h('span', { class: 'tm', text: ev.t }), ev.msg));
  log.scrollTop = log.scrollHeight;
}
function fmt(sec) { return String(Math.floor(sec / 60)).padStart(2, '0') + ':' + String(sec % 60).padStart(2, '0'); }
async function poll() {
  if (!RUN.alive) return;
  let d;
  try { d = await api(`/api/job/${RUN.job}?since=${RUN.since}`); }
  catch (e) { return endRun('err', 'Lost contact with the server: ' + e.message); }
  d.events.forEach(addEvent); RUN.since += d.events.length;
  const cd = $('#countdown');
  if (d.countdown !== null && d.countdown !== undefined) cd.textContent = 'WAITING FOR MAIL ...  ' + fmt(d.countdown) + ' LEFT';
  if (d.status === 'running') { RUN.timer = setTimeout(poll, 700); return; }
  RUN.alive = false;
  if (d.status === 'done' && d.report) {
    setStage(99);
    try { const rep = await api('/api/report/' + d.report); setTimeout(() => showResults(rep), 900); }
    catch (e) { endRun('err', e.message); }
  } else if (d.status === 'timeout') endRun('warnc', 'NO NEW MAIL FOUND - nothing arrived from the allowed sender in time. Send your test mail and start the guard again.');
  else if (d.status === 'stopped') endRun('warnc', 'Guard stopped.');
  else endRun('err', d.error || 'Something went wrong.');
}
function endRun(cls, text) {
  const r = $('#runResult'); r.className = 'run-result ' + cls; r.replaceChildren(text);
  refreshStatus();
}

/* ================= A: demo ================= */
$('#btnDemoStart').addEventListener('click', async () => {
  $('#demoMsg').textContent = '';
  try { const d = await api('/api/demo/start', { method: 'POST' }); startRun('demo', d.job); }
  catch (e) { $('#demoMsg').textContent = e.message; refreshStatus(); }
});
$('#btnDemoLast').addEventListener('click', async () => {
  const id = STATUS && STATUS.last_demo; if (!id) return;
  try { showResults(await api('/api/report/' + id)); } catch (e) { $('#demoMsg').textContent = e.message; }
});

/* ================= B: upload ================= */
let chosen = null;
const dz = $('#dropzone'), fi = $('#fileInput');
function pick(f) {
  chosen = null; $('#uploadMsg').textContent = '';
  if (!f) return;
  if (!f.name.toLowerCase().endsWith('.eml')) { $('#uploadMsg').textContent = 'Only .eml files are accepted'; $('#dzFile').textContent = ''; $('#btnUpload').disabled = true; return; }
  if (f.size > 10 * 1024 * 1024) { $('#uploadMsg').textContent = 'File is larger than 10 MB'; $('#btnUpload').disabled = true; return; }
  chosen = f; $('#dzFile').textContent = `${f.name}  (${f.size.toLocaleString()} bytes)`; $('#btnUpload').disabled = false;
}
dz.addEventListener('click', () => fi.click());
dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fi.click(); } });
fi.addEventListener('change', () => pick(fi.files[0]));
['dragenter', 'dragover'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
dz.addEventListener('drop', (e) => pick(e.dataTransfer.files[0]));
$('#btnUpload').addEventListener('click', async () => {
  if (!chosen) return;
  $('#uploadMsg').textContent = '';
  try {
    const d = await api('/api/upload/start', { method: 'POST', body: chosen, headers: { 'X-Filename': encodeURIComponent(chosen.name), 'Content-Type': 'application/octet-stream' } });
    startRun('upload', d.job);
  } catch (e) { $('#uploadMsg').textContent = e.message; refreshStatus(); }
});

/* ================= C: pro ================= */
$('#btnProStart').addEventListener('click', async () => {
  $('#proMsg').textContent = '';
  const body = { target: $('#proTarget').value.trim(), password: $('#proPass').value, sender: $('#proSender').value.trim() };
  try {
    const d = await api('/api/pro/start', { method: 'POST', json: body });
    $('#proPass').value = '';                       // never keep the password in the page
    startRun('pro', d.job);
  } catch (e) { $('#proMsg').textContent = e.message; refreshStatus(); }
});

/* ================= results ================= */
const PILLARS = [['header', '1', 'HEADER ANALYSIS'], ['domain', '2', 'DOMAIN ANALYSIS'], ['ip', '3', 'IP LOOKUP'], ['file', '4', 'FILE ANALYSIS'], ['final', '★', 'FINAL VERDICT']];
let REP = null, TAB = 'header';
const ZCOL = { green: '#1ee37a', yellow: '#ffcc00', red: '#b3202f', na: '#6b7280' };

function ring(score, zone, size = 110) {
  const NS = 'http://www.w3.org/2000/svg', r = 44, c = 2 * Math.PI * r;
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 110 110'); svg.setAttribute('width', size); svg.setAttribute('height', size); svg.setAttribute('class', 'ring');
  const mk = (tag, attrs) => { const e = document.createElementNS(NS, tag); Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v)); return e; };
  svg.append(mk('circle', { cx: 55, cy: 55, r, fill: 'none', stroke: '#16222c', 'stroke-width': 12 }));
  if (score !== null) svg.append(mk('circle', { cx: 55, cy: 55, r, fill: 'none', stroke: ZCOL[zone], 'stroke-width': 12, 'stroke-linecap': 'butt',
    'stroke-dasharray': `${(c * score) / 100} ${c}`, transform: 'rotate(-90 55 55)' }));
  const t = mk('text', { x: 55, y: 62, 'text-anchor': 'middle', 'font-size': score === null ? 14 : 22, fill: '#fff' });
  t.textContent = score === null ? 'N/A' : String(score); svg.append(t);
  return svg;
}
function zoneChip(score, zone) { return h('span', { class: 's z-' + zone, text: score === null ? 'N/A' : String(score) }); }

function showResults(rep) {
  REP = rep; show('results');
  $('#resFile').textContent = (rep.file.name || 'email') + (rep.mode ? '  ·  ' + rep.mode.toUpperCase() : '');
  $('#btnDlHtml').href = `/api/report/${rep.id}.html`; $('#btnDlJson').href = `/api/report/${rep.id}.json`;
  const rr = $('#btnRerun'); rr.classList.toggle('hidden', rep.mode === 'demo'); rr.disabled = false;
  refreshStatus().then(() => {
    rr.textContent = '↻ RE-RUN';
    rr.disabled = false;
  });
  const nav = $('#sidebar'); nav.replaceChildren();
  PILLARS.forEach(([key, n, label]) => {
    const data = key === 'final' ? rep.final : rep.pillars[key];
    nav.append(h('button', { class: 'nav', 'data-k': key, onclick: () => selectTab(key) },
      h('span', { class: 'n', text: n }), h('span', { class: 'l', text: label }), zoneChip(data.score, data.zone)));
  });
  selectTab('header');
}
function selectTab(key) {
  TAB = key;
  document.querySelectorAll('.nav').forEach((b) => b.classList.toggle('sel', b.dataset.k === key));
  const main = $('#resMain'); main.replaceChildren(key === 'final' ? renderFinal(REP) : renderPillar(REP.pillars[key]));
  main.scrollTop = 0;
}
function renderPillar(p) {
  const root = h('div');
  root.append(h('div', { class: 'ph' }, ring(p.score, p.zone),
    h('div', {}, h('h2', { text: p.title }), h('div', { class: 'hl', text: p.headline }), h('span', { class: 'pill z-' + p.zone, text: p.verdict + (p.score !== null ? '  ·  ' + p.score + '/100' : '') }))));
  root.append(h('div', { class: 'cap', text: 'TOP SIGNALS' }));
  const grid = h('div', { class: 'grid' });
  p.top.forEach((c) => grid.append(h('div', { class: 'pcard l-' + c.level }, h('h3', { text: c.title }), c.lines.map((l) => h('div', { text: l })))));
  root.append(grid);
  if (p.details && p.details.length) {
    const det = h('div', { class: 'details hidden' });
    p.details.forEach((s) => {
      det.append(h('h4', { text: s.title }));
      const t = h('table', { class: 'dt' });
      s.rows.forEach((r) => t.append(h('tr', { class: 'r-' + (r.level || 'none') }, h('td', { text: r.k }), h('td', { text: r.v }))));
      det.append(t);
    });
    const btn = h('button', { class: 'btn more px', text: 'VIEW MORE ▾' });
    btn.addEventListener('click', () => { const hid = det.classList.toggle('hidden'); btn.textContent = hid ? 'VIEW MORE ▾' : 'VIEW LESS ▴'; });
    root.append(btn, det);
  }
  root.append(h('div', { class: 'foot', text: 'For the full per-indicator breakdown of every score, download the report (⭳ REPORT, top right).' }));
  return root;
}
function renderFinal(rep) {
  const f = rep.final, root = h('div');
  const cv = h('canvas', { width: 48, height: 27 });
  if (window.KP) KP.verdictFish(cv, f.zone);
  root.append(h('div', { class: 'final-top' }, ring(f.score, f.zone, 150), cv,
    h('div', {}, h('h2', { class: 'px', text: 'FINAL VERDICT' }), h('div', { class: 'hl', text: f.headline }),
      h('span', { class: 'pill z-' + f.zone, text: f.verdict + '  ·  ' + f.score + '/100' }),
      h('div', { class: 'hl', text: 'Analysis-tool correlated severity: ' + f.tool_severity }))));
  root.append(h('div', { class: 'cap', text: 'HOW THE FOUR LAYERS CONTRIBUTE' }));
  const bars = h('div', { class: 'bars' });
  f.breakdown.forEach((b) => bars.append(h('div', { class: 'b' }, h('div', { class: 'lab', text: b.title.toUpperCase() }),
    h('div', { class: 'track' }, (() => { const d = h('div', { class: 'fill' }); d.style.width = (b.score || 0) + '%'; d.style.background = ZCOL[b.zone]; return d; })()),
    h('div', { text: b.score === null ? 'N/A' : b.score + '/100' }))));
  root.append(bars);
  root.append(h('div', { class: 'cap', text: 'WHY - TOP REASONS' }));
  root.append(h('ul', { class: 'reasons' }, f.reasons.length ? f.reasons.map((r) => h('li', { text: `${r.label}  (+${r.points})` })) : [h('li', { text: 'No risk indicators were triggered.' })]));
  root.append(h('div', { class: 'foot' }, rep.notes.map((n) => h('div', { text: '• ' + n }))));
  return root;
}
$('#btnRerun').addEventListener('click', async () => {
  if (!REP) return;
  try { const d = await api('/api/rerun/' + REP.id, { method: 'POST' }); startRun('upload', d.job); }
  catch (e) { alert(e.message); refreshStatus(); }
});
document.addEventListener('keydown', (e) => {
  if (current !== 'results' || e.ctrlKey || e.metaKey) return;
  const keys = PILLARS.map((p) => p[0]); let i = keys.indexOf(TAB);
  if (e.key === 'ArrowDown') i = Math.min(keys.length - 1, i + 1);
  else if (e.key === 'ArrowUp') i = Math.max(0, i - 1);
  else if (['1', '2', '3', '4', '5'].includes(e.key)) i = Number(e.key) - 1;
  else if (e.key === 'Escape') return show('menu');
  else return;
  e.preventDefault(); selectTab(keys[i]);
});

/* ================= boot ================= */
buildCards();
refreshStatus();
let introDone = false;
function leaveIntro() { if (introDone) return; introDone = true; show('menu'); }
if (qp.get('intro') === 'skip') leaveIntro();
else if (window.KP) KP.startIntro(leaveIntro, Number(qp.get('introt') || 0));
else leaveIntro();
$('#skipIntro').addEventListener('click', () => { if (window.KP) KP.skipIntro(); leaveIntro(); });
document.addEventListener('keydown', (e) => { if (current === 'intro' && !introDone) { if (window.KP) KP.skipIntro(); leaveIntro(); } });
$('#view-intro').addEventListener('click', () => { if (window.KP) KP.skipIntro(); leaveIntro(); });
})();
