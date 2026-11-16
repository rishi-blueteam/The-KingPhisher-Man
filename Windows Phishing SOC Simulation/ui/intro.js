/* The Kingphisher-Man - pixel intro + sprite helpers.  Everything is drawn with fillRect on a 320x180 canvas,
   then CSS scales it up with image-rendering:pixelated. */
(() => {
'use strict';
const W = 320, H = 180, WATER = 112;
const COL = { green: '#1ee37a', dgreen: '#0b8f4a', lgreen: '#9bffc4', red: '#ff2a2a', dred: '#9c0f12', white: '#f4f4f4',
              gold: '#ffb81c', gold2: '#ffe27a', orange: '#ff7a1a', deep: '#06121a', yellow: '#ffcc00', dyellow: '#a37f00' };
let ctx = null;

/* ---------- primitives ---------- */
const px = (x, y, c) => { ctx.fillStyle = c; ctx.fillRect(Math.round(x), Math.round(y), 1, 1); };
const rect = (x, y, w, h, c) => { ctx.fillStyle = c; ctx.fillRect(Math.round(x), Math.round(y), Math.round(w), Math.round(h)); };
function line(x0, y0, x1, y1, c) {
  x0 = Math.round(x0); y0 = Math.round(y0); x1 = Math.round(x1); y1 = Math.round(y1);
  const dx = Math.abs(x1 - x0), dy = -Math.abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
  let err = dx + dy;
  for (let n = 0; n < 2000; n++) {
    px(x0, y0, c);
    if (x0 === x1 && y0 === y1) break;
    const e2 = 2 * err;
    if (e2 >= dy) { err += dy; x0 += sx; }
    if (e2 <= dx) { err += dx; y0 += sy; }
  }
}
function disc(cx, cy, r, c) {
  for (let y = -r; y <= r; y++) for (let x = -r; x <= r; x++) if (x * x + y * y <= r * r + r * 0.5) px(cx + x, cy + y, c);
}
const ease = (x) => (x <= 0 ? 0 : x >= 1 ? 1 : 1 - Math.pow(1 - x, 3));
const seg = (t, a, b) => Math.min(1, Math.max(0, (t - a) / (b - a)));
function sparkle(x, y, t, c = COL.gold2, size = 2) {
  const s = Math.round(size * (0.5 + 0.5 * Math.sin(t * 9 + x)));
  px(x, y, c);
  for (let i = 1; i <= s; i++) { px(x + i, y, c); px(x - i, y, c); px(x, y + i, c); px(x, y - i, c); }
}

/* ---------- sprites ---------- */
/* envelope-fish: a green e-mail with a tail. dir = 1 faces right, -1 faces left */
function mailFish(x, y, dir, t, pal = {}) {
  const body = pal.body || COL.green, edge = pal.edge || COL.dgreen, flap = pal.flap || COL.dgreen;
  const P = (lx, ly, c) => px(x + (dir > 0 ? lx : -lx), y + ly, c);
  const wag = Math.round(Math.sin(t * 8 + x * 0.1));
  for (let ly = 0; ly < 8; ly++) for (let lx = 5; lx < 17; lx++) P(lx, ly, body);
  for (let lx = 5; lx < 17; lx++) { P(lx, 0, edge); P(lx, 7, edge); }
  for (let ly = 0; ly < 8; ly++) { P(5, ly, edge); P(16, ly, edge); }
  for (let i = 0; i < 5; i++) { P(6 + i, 1 + i, flap); P(15 - i, 1 + i, flap); }
  for (let lx = 0; lx < 5; lx++) {
    const half = 4 - lx, top = Math.max(0, Math.round(3.5 - half) + wag), bot = Math.min(7, Math.round(3.5 + half) + wag);
    for (let ly = top; ly <= bot; ly++) P(lx, ly, body);
  }
  P(14, 2, COL.white); P(14, 3, '#000');
  if (pal.check) { P(9, 5, COL.white); P(10, 6, COL.white); P(11, 5, COL.white); P(12, 4, COL.white); P(13, 3, COL.white); }
}
/* the red phish: angry, toothy */
function redPhish(x, y, dir, t, pal = {}) {
  const body = pal.body || COL.red, edge = pal.edge || COL.dred;
  const P = (lx, ly, c) => px(x + (dir > 0 ? lx : -lx), y + ly, c);
  const wag = Math.round(Math.sin(t * 10) * 1.5);
  const inside = (lx, ly) => { const a = (lx - 9) / 9.5, b = (ly - 5) / 5.5; return a * a + b * b <= 1; };
  for (let ly = -1; ly < 12; ly++) for (let lx = -1; lx < 20; lx++) {
    if (inside(lx, ly)) P(lx, ly, (!inside(lx - 1, ly) || !inside(lx + 1, ly) || !inside(lx, ly - 1) || !inside(lx, ly + 1)) ? edge : body);
  }
  for (let lx = 0; lx < 6; lx++) {                       // tail
    const half = 5 - lx * 0.7;
    for (let ly = Math.round(5 - half) + wag; ly <= Math.round(5 + half) + wag; ly++) P(-lx + 1, ly, body);
  }
  for (let lx = 6; lx < 12; lx++) P(lx, -2 + Math.abs(lx - 9) / 2, edge);   // dorsal fin
  P(14, 3, COL.white); P(15, 3, COL.white); P(15, 4, '#000');               // eye
  line(dir > 0 ? x + 12 : x - 12, y + 1, dir > 0 ? x + 17 : x - 17, y + 3, '#000'); // angry brow
  for (let i = 0; i < 4; i++) { P(15 + (i % 2), 6 + i, COL.white); }       // teeth
  P(14, 7, '#000'); P(15, 8, '#000');
  if (pal.check) { P(7, 6, COL.white); P(8, 7, COL.white); P(9, 6, COL.white); P(10, 5, COL.white); }
}
function envelope(x, y, c) {
  for (let i = 0; i < 7; i++) { px(x + i, y, c); px(x + i, y + 4, c); }
  for (let j = 0; j < 5; j++) { px(x, y + j, c); px(x + 6, y + j, c); }
  px(x + 1, y + 1, c); px(x + 2, y + 2, c); px(x + 3, y + 2, c); px(x + 4, y + 2, c); px(x + 5, y + 1, c);
}
const CROWN = ['y...y...y', 'yy.yyy.yy', 'yyyyyyyyy', 'yyoyyyoyy', 'yyyyyyyyy'];
function crown(x, y, t) {
  CROWN.forEach((row, ry) => [...row].forEach((ch, rx) => { if (ch !== '.') px(x + rx, y + ry, ch === 'o' ? COL.orange : (ry < 2 ? COL.gold2 : COL.gold)); }));
  sparkle(x - 3, y - 2, t, COL.gold2, 2); sparkle(x + 11, y - 3, t + 1, COL.gold2, 1); sparkle(x + 4, y - 6, t + 2, COL.gold2, 2);
}
function boat(bx, by, t) {
  const W1 = COL.white;
  for (let r = 0; r < 9; r++) { rect(bx + Math.round(r * 1.3), by + r, 62 - Math.round(r * 2.4), 1, '#000'); }
  line(bx, by, bx + 62, by, W1);                                   // deck
  line(bx, by, bx + 12, by + 9, W1); line(bx + 62, by, bx + 51, by + 9, W1); line(bx + 12, by + 9, bx + 51, by + 9, W1);
  line(bx + 6, by + 4, bx + 55, by + 4, '#3a3a3a');                // plank
  rect(bx + 4, by - 11, 15, 11, '#000');                           // briefcase with a shield
  for (let i = 0; i < 15; i++) { px(bx + 4 + i, by - 11, W1); px(bx + 4 + i, by - 1, W1); }
  for (let j = 0; j < 11; j++) { px(bx + 4, by - 11 + j, W1); px(bx + 18, by - 11 + j, W1); }
  rect(bx + 9, by - 14, 5, 3, W1); rect(bx + 10, by - 13, 3, 1, '#000');
  rect(bx + 8, by - 9, 7, 6, COL.green); px(bx + 9, by - 6, COL.white); px(bx + 10, by - 5, COL.white); px(bx + 12, by - 7, COL.white); px(bx + 13, by - 8, COL.white);
}
function king(bx, by, t) {
  const hx = bx + 32, hy = by - 22;
  disc(hx, hy, 4, COL.white);                                       // head
  px(hx + 2, hy - 1, '#000');
  line(hx - 1, hy + 5, hx - 3, by - 3, COL.white); line(hx, hy + 5, hx - 2, by - 3, COL.white);   // torso
  line(hx - 3, by - 3, hx + 6, by - 2, COL.white);                  // thigh
  line(hx + 6, by - 2, hx + 9, by + 5, COL.white);                  // shin
  line(hx, hy + 8, hx + 10, hy + 11, COL.white);                    // arm to the rod
  crown(hx - 4, hy - 11, t);
  const tip = { x: bx + 90, y: WATER - 52 };
  line(hx + 9, hy + 12, tip.x, tip.y, COL.white);                   // rod
  px(hx + 9, hy + 11, COL.white);
  return tip;
}
/* sprites on small canvases (menu icons / final verdict) */
function withCtx(canvas, fn) {
  const prev = ctx; ctx = canvas.getContext('2d'); ctx.clearRect(0, 0, canvas.width, canvas.height); fn(); ctx = prev;
}
function icon(canvas, kind) {
  withCtx(canvas, () => {
    if (kind === 'fish') { mailFish(3, 7, 1, 0.3, { check: true }); sparkle(21, 3, 0.4, COL.lgreen, 1); }
    else if (kind === 'upload') {
      envelope(7, 11, COL.white);
      for (let i = 0; i < 7; i++) px(10, 3 + i, COL.gold2);
      line(10, 2, 7, 5, COL.gold2); line(10, 2, 13, 5, COL.gold2);
      for (let i = 0; i < 15; i++) px(5 + i, 19, COL.white);
    } else if (kind === 'shield') {
      for (let r = 0; r < 14; r++) { const half = r < 9 ? 7 : 7 - (r - 9) * 1.5; rect(12 - Math.round(half), 6 + r, Math.round(half * 2), 1, '#0d3a8a'); }
      crown(7, 1, 0.5);
      for (let r = 8; r < 14; r++) { px(12, 6 + r - 1, COL.white); }
      px(10, 14, COL.white); px(11, 15, COL.white); px(13, 14, COL.white); px(14, 13, COL.white); px(15, 12, COL.white);
    }
  });
}
function verdictFish(canvas, zone, t = 0.3) {
  withCtx(canvas, () => {
    if (zone === 'red') { redPhish(24, 9, -1, t); line(2, 2, 22, 14, COL.white); px(22, 15, COL.white); }
    else if (zone === 'yellow') { mailFish(18, 11, -1, t, { body: COL.yellow, edge: COL.dyellow, flap: COL.dyellow }); sparkle(8, 6, t, COL.yellow, 2); }
    else { mailFish(18, 11, -1, t, { check: true }); crown(14, 1, t); }
  });
}

/* ---------- the intro scene ---------- */
let cv, running = false, raf = 0, t0 = 0, onDone = null, startOffset = 0;
const greens = Array.from({ length: 8 }, (_, i) => ({ x: (i * 53) % 330, y: WATER + 12 + ((i * 17) % 44), dir: i % 3 === 0 ? -1 : 1, v: 12 + (i * 7) % 14, ph: i }));
const bubbles = Array.from({ length: 12 }, (_, i) => ({ x: (i * 41) % 320, y: WATER + 10 + (i * 23) % 60, v: 6 + (i % 5) * 2 }));
const stars = Array.from({ length: 26 }, (_, i) => ({ x: (i * 97) % 320, y: (i * 53) % (WATER - 6), s: i % 3 }));
const CAPTIONS = [[0, 'The inbox pond is calm ...'], [3700, '... until something PHISHY swims in.'], [5600, '!! DANGER !! A RED PHISH !!'],
                  [7600, 'Enter ... the KING.'], [9400, 'Hooked!'], [10900, 'CAUGHT!']];

function frame(now) {
  if (!running) return;
  const t = now - t0 + startOffset, s = t / 1000;
  ctx.fillStyle = '#05070a'; ctx.fillRect(0, 0, W, H);
  stars.forEach((st) => { if (Math.sin(s * 3 + st.x) > -0.3) px(st.x, st.y, st.s === 0 ? COL.green : '#1a3b2a'); });
  rect(0, WATER + 2, W, H - WATER, COL.deep);
  for (let i = 0; i < 14; i++) { const lx = ((i * 71 + s * 8 * (i % 2 ? 1 : -1)) % 330 + 330) % 330 - 5; rect(lx, WATER + 8 + (i * 13) % 58, 10 + (i % 3) * 6, 1, '#0f4d33'); }

  const red = { x: 345 - 137 * seg(t, 3800, 7200), y: WATER + 15 + Math.sin(s * 4) * 2, vis: t > 3800 && t < 10900 };
  const bx = -75 + 185 * ease(seg(t, 6000, 8000)), by = WATER - 8 + Math.sin(s * 2.2) * 1.5;
  const tipX = bx + 90, tipY = WATER - 52;
  const reel = ease(seg(t, 9300, 10900)), descend = ease(seg(t, 8200, 8900));

  // green mail-fish (flee from the red one)
  greens.forEach((g) => {
    let dir = g.dir, v = g.v;
    if (red.vis && Math.abs(g.x - red.x) < 90) { dir = g.x < red.x ? -1 : 1; v *= 2; }
    g.x += dir * v * 0.016; g.dir = dir;
    if (g.x > 345) g.x = -25; if (g.x < -25) g.x = 345;
    mailFish(g.x, g.y + Math.sin(s * 2 + g.ph) * 2, dir, s + g.ph, { check: t > 10900 });
  });

  // boat + king
  if (t > 5900) { boat(bx, by, s); king(bx, by, s); }

  // red phish + fishing line
  let fishX = red.x, fishY = red.y;
  if (t >= 8200) {
    const hookX = tipX - 2;
    let hookY = tipY + (WATER + 17 - tipY) * descend;
    if (t >= 9300) hookY = (WATER + 17) + ((WATER - 36) - (WATER + 17)) * reel;
    line(tipX, tipY, hookX, hookY, COL.white); px(hookX, hookY + 1, COL.white); px(hookX - 1, hookY + 2, COL.white);
    if (t >= 8900) { fishX = hookX + 10; fishY = hookY + 2 + (t < 9300 ? Math.sin(s * 40) * 1.5 : 0); }
  }
  if (red.vis) {
    redPhish(fishX, fishY, -1, s);
    if (t < 8900 && Math.sin(s * 14) > 0) { for (let i = 0; i < 3; i++) line(red.x + 4 + i * 5, fishY - 12 - (i % 2) * 2, red.x + 4 + i * 5, fishY - 7, COL.red); }
  }
  if (t > 10900 && t < 12400) { for (let i = 0; i < 9; i++) sparkle(fishX + Math.cos(i * 0.7 + s * 3) * 26, fishY + Math.sin(i * 0.9 + s * 3) * 16, s + i, i % 2 ? COL.gold2 : COL.lgreen, 2); }

  // waves
  for (let x = 0; x < W; x++) { const y = WATER + Math.round(Math.sin(x * 0.16 + s * 3) * 1.3); px(x, y, COL.white); if ((x + Math.round(s * 20)) % 9 < 3) px(x, y + 1, '#5b8a77'); }
  // bubbles (tiny envelopes)
  bubbles.forEach((b) => { b.y -= b.v * 0.016; b.x += Math.sin(s + b.v) * 0.1; if (b.y < WATER + 4) { b.y = H - 4; } if (b.v > 10) envelope(b.x, b.y, '#2f6b52'); else px(b.x, b.y, '#3a8f6b'); });

  // red alarm tint
  if (t > 5000 && t < 8600) { ctx.fillStyle = `rgba(255,30,30,${0.10 + 0.10 * Math.sin(s * 10)})`; ctx.fillRect(0, 0, W, H); }
  // caption + final logo reveal
  const cap = [...CAPTIONS].reverse().find((c) => t >= c[0]);
  const capEl = document.getElementById('introCaption');
  if (cap && capEl.dataset.k !== String(cap[0])) { capEl.dataset.k = String(cap[0]); capEl.textContent = cap[1]; capEl.className = 'px ' + (cap[0] === 5600 ? 'alarm' : cap[0] >= 9400 ? 'win' : ''); }
  if (t > 11300) { document.getElementById('introLogo').classList.add('show'); cv.classList.add('fade'); capEl.classList.add('gone'); }
  if (t > 15200) return finish();
  raf = requestAnimationFrame(frame);
}
function finish() {
  if (!running) return;
  running = false; cancelAnimationFrame(raf);
  const cb = onDone; onDone = null; if (cb) cb();
}
function startIntro(cb, offset = 0) {
  cv = document.getElementById('introCanvas'); ctx = cv.getContext('2d'); ctx.imageSmoothingEnabled = false;
  onDone = cb; startOffset = offset; t0 = performance.now(); running = true; raf = requestAnimationFrame(frame);
}
window.KP = { startIntro, skipIntro: finish, icon, verdictFish };
})();
