(function () {
  'use strict';
  const M = window.GAME_MANIFEST;
  const $ = s => document.querySelector(s);
  const nojs = $('#nojs');
  if (nojs) nojs.parentNode.removeChild(nojs);
  if (typeof BigInt === 'undefined' || typeof TextEncoder === 'undefined' || !window.JSON) {
    document.body.innerHTML = '<div class="fatal"><h2>打不开</h2><p>当前浏览器版本过旧。请换用手机自带浏览器、Chrome 或 Safari 打开本文件。</p></div>';
    return;
  }

  const te = new TextEncoder(), td = new TextDecoder();
  const utf8 = s => te.encode(s);
  function b64dec(s) {
    const bin = atob(s), a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }
  function hex(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }
  function unhex(h) {
    if (h.length % 2) h = '0' + h;
    const a = new Uint8Array(h.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  }
  function concat() {
    let n = 0;
    for (const a of arguments) n += a.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arguments) { out.set(a, o); o += a.length; }
    return out;
  }
  function eq(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }
  function xor(a, b) {
    const o = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i];
    return o;
  }
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const now = () => Math.floor(Date.now() / 1000);

  let NORM_RE;
  try { NORM_RE = new RegExp('[\\s\\p{P}\\p{S}\\p{Z}]', 'gu'); }
  catch (e) { NORM_RE = /[\s!-\/:-@\[-`{-~\u00a0-\u00bf\u00d7\u00f7\u2000-\u206f\u2190-\u2bff\u3000-\u303f\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40\uff5b-\uff65]/g; }
  const norm = s => String(s).normalize('NFKC').toLowerCase().replace(NORM_RE, '');

  const SHA_K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const SHA_IV = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const SW = new Int32Array(64);
  function compress(H, X, o) {
    const w = SW;
    for (let i = 0; i < 16; i++) w[i] = X[o + i];
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2];
      w[i] = (((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ (a >>> 3)) + w[i - 7] +
              ((b >>> 17 | b << 15) ^ (b >>> 19 | b << 13) ^ (b >>> 10)) + w[i - 16]) | 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const t1 = (h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
      const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  function be32(b) {
    const w = new Int32Array(b.length >> 2);
    for (let i = 0; i < w.length; i++) w[i] = b[4 * i] << 24 | b[4 * i + 1] << 16 | b[4 * i + 2] << 8 | b[4 * i + 3];
    return w;
  }
  function unbe32(w) {
    const b = new Uint8Array(w.length * 4);
    for (let i = 0; i < w.length; i++) { b[4 * i] = w[i] >>> 24; b[4 * i + 1] = w[i] >>> 16; b[4 * i + 2] = w[i] >>> 8; b[4 * i + 3] = w[i]; }
    return b;
  }
  function sha256(m) {
    const n = m.length, nw = (((n + 8) >> 6) + 1) << 4;
    const w = new Int32Array(nw);
    for (let i = 0; i < n; i++) w[i >> 2] |= m[i] << (24 - ((i & 3) << 3));
    w[n >> 2] |= 0x80 << (24 - ((n & 3) << 3));
    w[nw - 1] = n * 8;
    w[nw - 2] = Math.floor(n / 0x20000000);
    const H = SHA_IV.slice();
    for (let o = 0; o < nw; o += 16) compress(H, w, o);
    return unbe32(H);
  }
  function hmac(key, msg) {
    if (key.length > 64) key = sha256(key);
    const ip = new Uint8Array(64 + msg.length), op = new Uint8Array(96);
    for (let i = 0; i < 64; i++) { const k = i < key.length ? key[i] : 0; ip[i] = k ^ 0x36; op[i] = k ^ 0x5c; }
    ip.set(msg, 64);
    op.set(sha256(ip), 64);
    return sha256(op);
  }
  function pbkdf2JS(pw, salt, iter) {
    if (pw.length > 64) pw = sha256(pw);
    const ip = new Uint8Array(64), op = new Uint8Array(64);
    for (let i = 0; i < 64; i++) { const k = i < pw.length ? pw[i] : 0; ip[i] = k ^ 0x36; op[i] = k ^ 0x5c; }
    const Hi = SHA_IV.slice(), Ho = SHA_IV.slice();
    compress(Hi, be32(ip), 0);
    compress(Ho, be32(op), 0);
    const T = be32(hmac(pw, concat(salt, new Uint8Array([0, 0, 0, 1]))));
    const blk = new Int32Array(16), H = new Int32Array(8);
    blk.set(T, 0); blk[8] = 0x80000000 | 0; blk[15] = 96 * 8;
    for (let it = 1; it < iter; it++) {
      H.set(Hi); compress(H, blk, 0); blk.set(H, 0);
      H.set(Ho); compress(H, blk, 0); blk.set(H, 0);
      for (let i = 0; i < 8; i++) T[i] ^= H[i];
    }
    return unbe32(T);
  }
  const subtle = (window.isSecureContext !== false && window.crypto && window.crypto.subtle) || null;
  let subtleOK = !!subtle;
  async function pbkdf2(pw, salt) {
    if (subtleOK) {
      try {
        const k = await subtle.importKey('raw', pw, { name: 'PBKDF2' }, false, ['deriveBits']);
        return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', salt, iterations: M.iter, hash: 'SHA-256' }, k, 256));
      } catch (e) { subtleOK = false; }
    }
    await sleep(40);
    return pbkdf2JS(pw, salt, M.iter);
  }
  function decryptBlob(key, blob) {
    const body = blob.subarray(0, blob.length - 16), tag = blob.subarray(blob.length - 16);
    if (!eq(hmac(key, body).subarray(0, 16), tag)) throw new Error('mac');
    const ct = body.subarray(12), out = new Uint8Array(ct.length);
    const blk = new Int32Array(16), H = new Int32Array(8);
    blk.set(be32(key), 0); blk.set(be32(body.subarray(0, 12)), 8);
    blk[12] = 0x80000000 | 0; blk[15] = 48 * 8;
    for (let ctr = 0, off = 0; off < ct.length; ctr++, off += 32) {
      blk[11] = ctr; H.set(SHA_IV); compress(H, blk, 0);
      const lim = Math.min(32, ct.length - off);
      for (let i = 0; i < lim; i++) out[off + i] = ct[off + i] ^ (H[i >> 2] >>> (24 - ((i & 3) << 3)));
    }
    return out;
  }
  const tag = (prefix, ...parts) => sha256(concat(utf8(prefix), ...parts));

  const P = BigInt('0x' + M.P_hex), ZERO = BigInt(0), ONE = BigInt(1);
  const mod = a => ((a % P) + P) % P;
  const big = b => BigInt('0x' + (hex(b) || '0'));
  const big32 = x => unhex(x.toString(16).padStart(64, '0'));
  function inv(a) {
    let r0 = mod(a), r1 = P, s0 = ONE, s1 = ZERO;
    while (r1 !== ZERO) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [s0, s1] = [s1, s0 - q * s1];
    }
    return mod(s0);
  }
  function lagrange0(pts) {
    let s = ZERO;
    for (let i = 0; i < pts.length; i++) {
      let num = ONE, den = ONE;
      for (let j = 0; j < pts.length; j++) {
        if (i === j) continue;
        num = num * mod(-pts[j][0]) % P;
        den = den * mod(pts[i][0] - pts[j][0]) % P;
      }
      s = (s + pts[i][1] * num % P * inv(den)) % P;
    }
    return s;
  }

  const NS = 'autumn-orient-' + M.gameId;
  let wiped = false;
  const store = {
    get(k, d) { try { const v = localStorage.getItem(NS + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { if (wiped) return; try { localStorage.setItem(NS + k, JSON.stringify(v)); } catch (e) {} },
    del(k) { try { localStorage.removeItem(NS + k); } catch (e) {} },
    wipe() {
      wiped = true;
      try {
        const ks = [];
        for (let i = 0; i < localStorage.length; i++) ks.push(localStorage.key(i));
        for (const k of ks) if (k && k.startsWith(NS + '-')) localStorage.removeItem(k);
      } catch (e) {}
    },
  };
  const canSave = (() => {
    try { localStorage.setItem(NS + '-probe', '1'); const ok = localStorage.getItem(NS + '-probe') === '1'; localStorage.removeItem(NS + '-probe'); return ok; }
    catch (e) { return false; }
  })();
  if (!canSave) {
    const bar = document.createElement('div');
    bar.id = 'nosave'; bar.className = 'nosave';
    bar.innerHTML = '这个浏览器<strong>存不了进度</strong>，页面一关就要重新答。请换一个浏览器打开本文件（别用无痕模式）。';
    document.body.appendChild(bar);
    document.body.classList.add('no-save');
  }
  function freshState(s) {
    s = s || {};
    s.user = s.user || null;
    s.solved = s.solved || {};
    s.acked = s.acked || {};
    s.bad = s.bad || {};
    return s;
  }
  let state = freshState(store.get('-state', null));
  const save = () => store.set('-state', state);
  const keepKey = c => '-keep-' + c;

  const SALT = b64dec(M.globalSalt);
  const metaById = {};
  for (const p of M.panels) metaById[p.id] = p;
  let unlocked = {}, keys = {}, secrets = {};

  function findQ(qid) {
    for (const p of M.panels) {
      const panel = unlocked[p.id];
      if (!panel) continue;
      for (const q of panel.questions) if (q.id === qid) return { panel, q };
    }
    return null;
  }

  function reconstruct(panel) {
    const T = panel.threshold;
    if (!T) return null;
    const got = panel.questions.filter(q => state.solved[q.id]);
    if (got.length < T) return null;
    const pts = got.slice(0, T).map(q =>
      [BigInt(q.x), mod(BigInt('0x' + q.y) - big(unhex(state.solved[q.id].m)) % P)]);
    return big32(lagrange0(pts));
  }
  function rebuild() {
    const before = unlocked;
    unlocked = {}; keys = {}; secrets = {};
    if (!state.user) return [];
    secrets.LOGIN = unhex(state.user.k);
    let changed = true;
    while (changed) {
      changed = false;
      for (const p of M.panels) {
        if (unlocked[p.id] || !p.requires.every(r => secrets[r])) continue;
        const key = tag('unlock|', ...p.requires.map(r => secrets[r]));
        try {
          unlocked[p.id] = JSON.parse(td.decode(decryptBlob(key, b64dec(p.enc))));
          keys[p.id] = key;
          changed = true;
        } catch (e) { console.warn('decrypt failed', p.id, e); }
      }
      for (const id of Object.keys(unlocked)) {
        if (secrets[id]) continue;
        const s = reconstruct(unlocked[id]);
        if (s) { secrets[id] = s; changed = true; }
      }
    }
    save();
    return M.panels.filter(p => unlocked[p.id] && !before[p.id]).map(p => unlocked[p.id]);
  }
  const panelDone = id => !!secrets[id] || (unlocked[id] && !unlocked[id].questions.length);

  function verifyCode() {
    const fin = M.panels.find(p => p.finale);
    if (!fin || !keys[fin.id]) return null;
    const h = hmac(tag('verify|', keys[fin.id]), utf8(state.user.c));
    return String((h[0] * 16777216 + (h[1] << 16) + (h[2] << 8) + h[3]) % 1000000).padStart(6, '0');
  }

  const imgCache = {};
  function imgUrl(panelId, qid) {
    if (imgCache[qid]) return imgCache[qid];
    const blob = M.imgs[qid];
    if (!blob || !keys[panelId]) return '';
    try {
      const bytes = decryptBlob(tag('img|', keys[panelId], utf8(qid)), b64dec(blob));
      imgCache[qid] = URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' }));
    } catch (e) { console.warn('img', qid, e); return ''; }
    return imgCache[qid];
  }

  const main = $('#main'), drawer = $('#drawer'), drawerMask = $('#drawer-mask'), drawerList = $('#drawer-list');
  const titleEl = $('#app-title'), input = $('#global-input'), submitBtn = $('#global-submit');
  const toastEl = $('#toast'), netBtn = $('#net-btn'), sheet = $('#sheet'), sheetMask = $('#sheet-mask'), sheetBody = $('#sheet-body');
  const STATS_VIEW = '__stats';

  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const inlineMd = s => esc(s).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  function md(src) {
    const lines = String(src || '').split('\n'), out = [];
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      if (!line.trim()) { i++; continue; }
      if (line.startsWith('- ')) {
        const items = [];
        while (i < lines.length && lines[i].startsWith('- ')) items.push('<li>' + inlineMd(lines[i++].slice(2)) + '</li>');
        out.push('<ul>' + items.join('') + '</ul>'); continue;
      }
      if (line.startsWith('> ')) {
        const buf = [];
        while (i < lines.length && lines[i].startsWith('> ')) buf.push(inlineMd(lines[i++].slice(2)));
        out.push('<blockquote>' + buf.join('<br>') + '</blockquote>'); continue;
      }
      const buf = [];
      while (i < lines.length && lines[i].trim() && !lines[i].startsWith('- ') && !lines[i].startsWith('> ')) buf.push(inlineMd(lines[i++]));
      out.push('<p>' + buf.join('<br>') + '</p>');
    }
    return out.join('');
  }
  function toast(msg, type, ms) {
    toastEl.textContent = msg;
    toastEl.className = 'toast show' + (type ? ' ' + type : '');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { toastEl.className = 'toast'; }, ms || 2200);
  }
  function fmtTime(t) {
    if (!t) return '';
    const d = new Date(t * 1000);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }

  let view = store.get('-view', M.panels[0].id);
  const scrollMem = store.get('-scroll', {});
  function rememberScroll() { scrollMem[view] = window.scrollY || 0; store.set('-scroll', scrollMem); }
  function restoreScroll() { const y = Number(scrollMem[view]) || 0; requestAnimationFrame(() => window.scrollTo(0, y)); }
  function go(id) {
    if (id === view) { render(); return; }
    rememberScroll();
    view = id;
    store.set('-view', view);
    render();
    restoreScroll();
  }

  function showUnlockBanner(from, newly) {
    const overlay = document.createElement('div');
    overlay.className = 'unlock-overlay';
    const target = newly[0];
    overlay.innerHTML = `
      <div class="unlock-card">
        <div class="unlock-badge">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M7 11V7a5 5 0 0 1 9.9-1"/><rect x="4" y="11" width="16" height="10" rx="2"/>
          </svg>
        </div>
        <p class="unlock-eyebrow">${esc(from.label)} 已完成</p>
        <h2 class="unlock-title">已解锁「${esc(target.label)}」</h2>
        <div class="unlock-actions">
          <button class="btn-ghost" data-act="stay">留在这里</button>
          <button class="btn-primary" data-act="go">前往</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('show'));
    overlay.addEventListener('click', e => {
      const act = e.target === overlay ? 'stay' : e.target.getAttribute && e.target.getAttribute('data-act');
      if (!act) return;
      overlay.classList.remove('show');
      setTimeout(() => overlay.remove(), 300);
      if (act === 'go') go(target.id);
    });
  }

  const wrongLog = {};
  function coolingDown(k) {
    const t = Date.now(), log = (wrongLog[k] || []).filter(x => t - x < 60000);
    wrongLog[k] = log;
    return log.length >= 5 ? Math.ceil((log[log.length - 5] + 60000 - t) / 1000) : 0;
  }
  const allQids = [];
  for (const p of M.panels) for (const qid of p.qids) allQids.push(qid);
  allQids.sort((a, b) => b.length - a.length);

  function record(panel, q, s) {
    state.solved[q.id] = s;
    const newly = rebuild();
    if (newly.length) showUnlockBanner(panel, newly);
    else toast(q.id + ' ✓ 答对了', 'ok');
    const y = window.scrollY;
    if (view !== panel.id) go(panel.id);
    else { render(); requestAnimationFrame(() => window.scrollTo(0, y)); }
    Sync.soon();
  }

  async function submit(qid, ans) {
    const f = findQ(qid);
    if (!f) {
      const owner = M.panels.find(p => p.qids.indexOf(qid) >= 0);
      toast(owner ? `${qid} 所在的「${owner.label}」还没解锁` : `没有题号「${qid}」`, 'warn');
      return;
    }
    const { panel, q } = f;
    if (state.solved[q.id]) { toast(q.id + ' 已经完成啦', 'ok'); return; }
    if (!norm(ans)) { toast('在题号后面空一格，再写答案', 'warn'); return; }
    const wait = coolingDown(q.id);
    if (wait) { toast(`${q.id} 错太多次了，${wait} 秒后再试`, 'warn'); return; }

    const prf = await pbkdf2(utf8(norm(ans)), concat(SALT, utf8(panel.id + '|' + q.id)));
    const chk = tag('', prf, utf8('check')).subarray(0, 16), qchk = b64dec(q.check);
    let key = eq(chk, qchk) ? prf : null;
    if (!key) {
      for (const a of q.alts || []) {
        if (!eq(chk, b64dec(a.c))) continue;
        const cand = xor(b64dec(a.w), hmac(prf, utf8('alt|' + q.id)));
        if (eq(tag('', cand, utf8('check')).subarray(0, 16), qchk)) key = cand;
        break;
      }
    }
    if (!key) {
      wrongLog[q.id].push(Date.now());
      toast(q.id + ' 答案不对，再想想', 'warn');
      return;
    }
    record(panel, q, {
      m: hex(hmac(key, utf8('mask'))), at: now(), ans,
      p: hex(hmac(key, utf8('proof|' + state.user.c)).subarray(0, 16)),
    });
  }

  let busy = false;
  async function handleSubmit() {
    if (busy || !state.user) return;
    const raw = input.value.replace(/　/g, ' ').trim();
    if (!raw) return;
    const s = raw.normalize('NFKC'), up = s.toUpperCase();
    const qid = allQids.find(id => up.startsWith(id)) || up.split(/\s+/)[0];
    const ans = s.slice(qid.length).trim();
    input.value = ''; input.blur();
    busy = true; submitBtn.disabled = true;
    const old = submitBtn.textContent;
    submitBtn.textContent = '校验…';
    try { await submit(qid, ans); }
    catch (e) { console.error(e); toast('出错了：' + e.message, 'warn'); }
    finally { busy = false; submitBtn.disabled = false; submitBtn.textContent = old; }
  }

  const Net = (() => {
    const list = [];
    if (/^https?:$/.test(location.protocol)) list.push(location.origin);
    for (const a of apiList()) if (list.indexOf(a) < 0) list.push(a);
    const eps = location.protocol === 'https:' ? list.filter(a => a.startsWith('https:')) : list;
    let good = store.get('-api', null);
    async function post(path, body) {
      const order = eps.slice();
      const gi = order.indexOf(good);
      if (gi > 0) { order.splice(gi, 1); order.unshift(good); }
      let err = new Error('no endpoint');
      for (const base of order) {
        const ctl = typeof AbortController === 'function' ? new AbortController() : null;
        const to = setTimeout(() => { if (ctl) ctl.abort(); }, 4000);
        try {
          const res = await fetch(base + path, {
            method: 'POST', body, cache: 'no-store', signal: ctl ? ctl.signal : undefined,
            headers: { 'Content-Type': 'text/plain' },
          });
          const data = await res.json();
          if (typeof data.ok !== 'boolean') throw new Error('not our server');
          if (good !== base) { good = base; store.set('-api', base); }
          return { res, data };
        } catch (e) { err = e; }
        finally { clearTimeout(to); }
      }
      throw err;
    }
    function apiList() {
      try {
        const s = atob(M.ep || ''), k = M.gameId;
        let o = '';
        for (let i = 0; i < s.length; i++) o += String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length));
        return o ? JSON.parse(o) : [];
      } catch (e) { return []; }
    }
    return { post, get has() { return eps.length > 0; } };
  })();

  const Sync = (() => {
    const BACKOFF = [15, 30, 60, 120, 300];
    let timer = null, inflight = false, fails = 0, lastAt = 0;
    let status = Net.has ? 'idle' : 'off';
    let stats = store.get('-stats', null);
    let lastOkAt = stats ? stats._at || 0 : 0;

    function schedule(sec) { clearTimeout(timer); timer = setTimeout(run, Math.max(1, sec) * 1000); }
    function soon() {
      if (!Net.has || !state.user) return;
      schedule(Math.max(2, 10 - (Date.now() - lastAt) / 1000));
    }
    function pending() {
      const out = [];
      for (const qid of Object.keys(state.solved)) {
        const s = state.solved[qid];
        if (!s.p || state.bad[qid]) continue;
        out.push({ qid, proof: s.p, at: s.at });
        if (out.length >= 40) break;
      }
      return out;
    }
    function apply(data) {
      fails = 0; status = 'ok'; lastOkAt = Date.now();
      if (data.stats) { stats = data.stats; stats._at = lastOkAt; store.set('-stats', stats); }
      const id = x => (x && typeof x === 'object' ? x.qid : x);
      for (const x of data.acked || []) if (state.solved[id(x)]) state.acked[id(x)] = 1;
      for (const x of data.rejected || []) if (state.solved[id(x)]) state.bad[id(x)] = 1;
      save();
      render();
    }
    async function run(manual) {
      clearTimeout(timer);
      if (!Net.has || !state.user || inflight) return;
      if (!manual && document.visibilityState === 'hidden') return;
      inflight = true; lastAt = Date.now();
      if (status !== 'ok') { status = 'idle'; renderNet(); }
      let next = 45;
      try {
        const { res, data } = await Net.post('/api/sync', JSON.stringify({ code: state.user.c, solves: pending() }));
        if (res.status === 403 && data.err === 'unknown_code') {
          status = 'bad'; next = 300;
          toast('服务器上找不到你的队伍，答题不受影响；请联系工作人员', 'warn', 4000);
          return;
        }
        if (res.status === 429) { next = Number(data.retry) || 30; status = 'ok'; return; }
        if (!res.ok || !data.ok) throw new Error('http ' + res.status);
        next = data.next || 45;
        apply(data);
      } catch (e) {
        status = 'err';
        next = BACKOFF[Math.min(fails, BACKOFF.length - 1)];
        fails++;
      } finally {
        inflight = false;
        renderNet();
        if (view === STATS_VIEW) renderMain();
        if (state.user) schedule(next + Math.random() * 15);
      }
    }
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && Date.now() - lastAt > 20000) soon();
    });
    window.addEventListener('online', soon);
    return {
      soon, run,
      get status() { return status; }, get stats() { return stats; },
      get lastOkAt() { return lastOkAt; }, get busy() { return inflight; },
    };
  })();

  const solvedIn = panel => panel.questions.reduce((n, q) => n + (state.solved[q.id] ? 1 : 0), 0);
  const crowd = qid => {
    const S = Sync.stats, v = S && S.questions && S.questions[qid];
    return typeof v === 'number' ? v : null;
  };

  function renderDrawer() {
    const items = [];
    for (const p of M.panels) {
      const panel = unlocked[p.id];
      if (!panel) {
        items.push(`<div class="drawer-item locked" data-locked="${esc(p.id)}"><span class="di-name">${esc(p.label)}</span><span class="di-meta">🔒</span></div>`);
        continue;
      }
      const n = panel.questions.length, k = solvedIn(panel);
      const meta = n ? `<span class="di-meta${panelDone(p.id) ? ' full' : ''}"><span class="dot"></span>${k} / ${n}</span>`
                     : `<span class="di-meta full"><span class="dot"></span>✓</span>`;
      items.push(`<div class="drawer-item${p.id === view ? ' active' : ''}" data-go="${esc(p.id)}"><span class="di-name">${esc(p.label)}</span>${meta}</div>`);
    }
    items.push('<div class="drawer-sep"></div>');
    items.push(`<div class="drawer-item${view === STATS_VIEW ? ' active' : ''}" data-go="${STATS_VIEW}"><span class="di-name">全场进度</span><span class="di-meta">${Sync.stats ? Sync.stats.active + ' 队' : ''}</span></div>`);
    drawerList.innerHTML = items.join('');
  }

  function cardHtml(panel, q) {
    const s = state.solved[q.id], n = crowd(q.id);
    const status = s ? '已完成' : '';
    const shown = s ? `<div class="q-answer-shown">✓ ${esc(s.ans || '')}</div>` : '';
    const url = q.img ? imgUrl(panel.id, q.id) : '';
    return `<div class="q-card${s ? ' solved' : ''}">
      <div class="q-head">
        <span class="q-id">${esc(q.id)}</span><span class="q-tag">${esc(q.kind)}</span>
        ${n !== null ? `<span class="q-crowd">${n} 队已找到</span>` : ''}
        <span class="q-status">${status}</span>
      </div>
      <p class="q-prompt">${esc(q.prompt)}</p>
      ${q.img ? `<div class="q-image">${url ? `<img src="${url}" alt="${esc(q.id)}">` : '<span>图片解密失败</span>'}</div>` : ''}
      ${q.format ? `<p class="q-format">格式：${esc(q.format)}</p>` : ''}
      ${shown}
    </div>`;
  }

  function renderMain() {
    if (view === STATS_VIEW) return renderStats();
    if (!unlocked[view]) view = M.panels[0].id;
    const panel = unlocked[view];
    if (!panel) { main.innerHTML = ''; return; }
    titleEl.textContent = panel.label;
    document.body.classList.toggle('is-finale', !!panel.finale);
    main.classList.toggle('is-finale', !!panel.finale);
    if (panel.finale) return renderFinale(panel);
    const n = panel.questions.length, k = solvedIn(panel), T = panel.threshold || n;
    const parts = [`<div class="panel-head"><h1>${esc(panel.title || panel.label)}</h1>
      ${n ? `<div class="panel-progress"><span>${k} / ${n}</span>
        <div class="progress-track"><div class="progress-fill" style="width:${Math.min(100, Math.round(k / T * 100))}%"></div></div></div>` : ''}
      </div>`];
    if (panel.intro) parts.push(`<div class="panel-intro">${md(panel.intro)}</div>`);
    if (panel.info) parts.push(`<div class="info-card">${md(panel.info)}</div>`);
    for (const q of panel.questions) parts.push(cardHtml(panel, q));
    main.innerHTML = parts.join('');
  }

  function renderFinale(panel) {
    const zones = M.panels.filter(p => p.qids.length);
    let last = 0;
    const unsynced = Object.keys(state.solved).filter(q => state.solved[q].p && !state.acked[q] && !state.bad[q]).length;
    for (const qid of Object.keys(state.solved)) last = Math.max(last, state.solved[qid].at || 0);
    const rows = zones.map(p => `<div class="fin-zone"><span class="fz-name">${esc(p.label.replace(/^.*·\s*/, ''))}</span>${p.qids.map(qid =>
      `<span class="fz-q ${state.solved[qid] ? 'ok' : 'miss'}">${esc(qid)}</span>`).join('')}</div>`).join('');
    const card = `<div class="fin-team">${esc(state.user.t)}<span>${esc(state.user.n)}</span></div>
          <div class="fin-code"><span>核验码</span><b>${verifyCode() || '——'}</b></div>
          <div class="fin-meta">完成于 ${fmtTime(last)}</div>
          <div class="fin-sync ${unsynced ? 'warn' : 'ok'}">${!Net.has ? '' : unsynced ? `还有 ${unsynced} 题未上报到服务器（不影响核对），联网后会自动补报` : '进度已全部上报 ✓'}</div>
          ${rows}`;
    const old = main.querySelector('.finale .fin-card');
    if (old) { old.innerHTML = card; return; }
    main.innerHTML = `<section class="finale">
      <div class="finale-bg"></div>
      <div class="finale-inner">
        <p class="finale-eyebrow">AUTUMN · TSINGHUA</p>
        <h2 class="finale-title">${esc(panel.title || '终章')}</h2>
        ${panel.info ? `<div class="finale-info">${md(panel.info)}</div>` : ''}
        <div class="fin-card">${card}</div>
      </div>
    </section>`;
  }

  function renderStats() {
    titleEl.textContent = '全场进度';
    document.body.classList.remove('is-finale');
    main.classList.remove('is-finale');
    const S = Sync.stats, st = Sync.status;
    const ago = Sync.lastOkAt ? Math.max(0, Math.round((Date.now() - Sync.lastOkAt) / 1000)) : null;
    const line = !Net.has ? '本版本不联网'
      : st === 'ok' ? `已连接 · ${ago < 60 ? ago + ' 秒' : Math.round(ago / 60) + ' 分钟'}前更新`
      : st === 'idle' ? '连接中…'
      : st === 'bad' ? '服务器上找不到本队，请联系工作人员'
      : '暂时连不上服务器' + (ago !== null ? `（下面是 ${fmtTime(Sync.lastOkAt / 1000)} 的数据）` : '');
    const parts = [`<div class="st-bar-top"><span class="st-dot st-${st}"></span><span>${esc(line)}</span>
      <button data-act="refresh"${Sync.busy ? ' disabled' : ''}>${Sync.busy ? '刷新中' : '刷新'}</button></div>`];
    if (!S) {
      parts.push('<div class="st-empty">还没拿到全场数据。<br>连不上服务器时答题完全不受影响，进度会在恢复联网后自动上报。</div>');
    } else {
      const den = Math.max(1, S.active || 0);
      parts.push(`<div class="sh-grid">
        <div><b>${S.active || 0}</b><span>队已出发</span></div>
        <div><b>${S.solvedTotal || 0}</b><span>个点已找到</span></div>
        <div><b>${S.finishedCount || 0}</b><span>队已通关</span></div></div>`);
      for (const p of M.panels.filter(x => x.stat)) {
        const rows = p.qids.map(qid => {
          const v = +(S.questions && S.questions[qid]) || 0, me = state.solved[qid];
          return `<div class="st-row"><span class="st-q${me ? ' me' : ''}">${esc(qid)}</span>
            <span class="st-track"><i style="width:${Math.min(100, v / den * 100)}%"></i></span>
            <span class="st-n">${v}/${S.active || 0}</span></div>`;
        }).join('');
        parts.push(`<div class="st-zone"><div class="st-zh"><span>${esc(p.label)}</span><span>${(S.panels && S.panels[p.id]) || 0} 队完成</span></div>${rows}</div>`);
      }
      parts.push('<p class="st-legend">分母为已出发队数 · 题号加粗为本机已完成</p>');
      if (S.finished && S.finished.length) {
        parts.push(`<h3 class="st-h">通关</h3><ol class="sh-rank">${S.finished.map(f =>
          `<li><span>${esc(f.name)}</span><span>${fmtTime(f.at)}</span></li>`).join('')}</ol>`);
      }
    }
    main.innerHTML = parts.join('');
  }

  function renderLogin() {
    titleEl.textContent = M.title;
    document.body.classList.remove('is-finale');
    main.classList.remove('is-finale');
    main.innerHTML = `<section class="login">
      <div class="login-leaf" aria-hidden="true"></div>
      <h1>${esc(M.title)}</h1>
      <p class="login-sub">清华园 · 2026 秋</p>
      <label><span>姓名</span><input id="lg-name" type="text" autocomplete="off" spellcheck="false" placeholder="报名时填写的姓名"></label>
      <label><span>口令</span><input id="lg-pw" type="text" inputmode="numeric" autocomplete="off" placeholder="全队学号后四位之和"></label>
      <button id="lg-go">进入</button>
      <p class="login-note">口令：把全队每位队员学号的<strong>后四位</strong>加起来。例如两人学号尾号是 1234 和 0567，口令就是 1801。<br>每位队员用自己的姓名登录，登录一次后自动记住。</p>
    </section>`;
    const name = $('#lg-name'), pw = $('#lg-pw'), btn = $('#lg-go');
    const goLogin = async () => {
      if (btn.disabled) return;
      const wait = coolingDown('login');
      if (wait) { toast(`试太多次了，${wait} 秒后再试`, 'warn'); return; }
      const pwd = pw.value.normalize('NFKC').replace(/\D/g, '');
      if (!norm(name.value) || !pwd) { toast('请填写姓名和口令', 'warn'); return; }
      btn.disabled = true; btn.textContent = '核对中…';
      try {
        const kdf = await pbkdf2(utf8(norm(name.value) + '|' + String(parseInt(pwd, 10))), concat(SALT, utf8('login')));
        const blob = M.logins[hex(tag('', kdf, utf8('id')).subarray(0, 8))];
        let user = null;
        if (blob) { try { user = JSON.parse(td.decode(decryptBlob(tag('', kdf, utf8('key')), b64dec(blob)))); } catch (e) {} }
        if (!user) {
          wrongLog.login.push(Date.now());
          toast('姓名或口令不对。请核对，或找工作人员', 'warn', 3500);
          return;
        }
        state = freshState(Object.assign(store.get(keepKey(user.c), {}), { user }));
        rebuild();
        store.del(keepKey(user.c));
        view = M.panels[0].id;
        store.set('-view', view);
        render();
        toast(`欢迎，${user.n}（${user.t}）`, 'ok');
        Sync.run(true);
      } finally { btn.disabled = false; btn.textContent = '进入'; }
    };
    btn.addEventListener('click', goLogin);
    pw.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); goLogin(); } });
    name.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); pw.focus(); } });
  }

  function renderNet() {
    const s = !state.user ? 'off' : !Net.has ? 'off' : Sync.status;
    netBtn.className = 'net-btn net-' + s;
    if (sheet.classList.contains('show')) renderSheet();
  }

  function renderSheet() {
    const u = state.user;
    if (!u) { sheetBody.innerHTML = ''; return; }
    const st = { ok: '已连接', idle: '连接中…', err: '暂时连不上服务器，答题不受影响，会自动重试', bad: '服务器上找不到本队，请联系工作人员', off: '不联网' }[Net.has ? Sync.status : 'off'];
    const ago = Sync.lastOkAt ? Math.round((Date.now() - Sync.lastOkAt) / 1000) : null;
    sheetBody.innerHTML = `<h3>${esc(u.n)}</h3>
      <p class="sh-note">${esc(u.t)} · 本机 ${Object.keys(state.solved).length} 题已完成</p>
      <h3>网络</h3>
      <p class="sh-note">${st}${ago !== null && Sync.status === 'ok' ? ` · ${ago} 秒前` : ''}</p>
      <p class="sh-note">联网只用来上报本机进度、查看全场进度；不联网也能完整答题、解锁和核对。</p>
      <div class="sh-actions"><button data-act="sync">刷新全场进度</button></div>
      <h3>账号</h3>
      <p class="sh-note">进度只保存在这台手机上（同队手机之间不同步）。退出登录后，在本机再用本队账号登录，进度会自动恢复。</p>
      <p class="sh-note">「清除」会删掉本机的全部进度和登录信息，无法恢复（比如手机要借给别人用）。</p>
      <div class="sh-actions"><button data-act="logout">退出登录</button><button data-act="wipe" class="danger">清除进度和账号</button></div>`;
  }

  function render() {
    document.body.classList.toggle('need-login', !state.user);
    if (!state.user) { renderLogin(); renderNet(); return; }
    renderDrawer();
    renderMain();
    renderNet();
  }

  function openViewer(src) {
    const v = document.createElement('div');
    v.className = 'viewer';
    v.innerHTML = `<div class="viewer-scroll"><img src="${src}" alt=""></div><button class="viewer-x" aria-label="关闭">×</button><p class="viewer-tip">点图片放大 / 缩小</p>`;
    document.body.appendChild(v);
    const img = v.querySelector('img');
    img.addEventListener('click', e => {
      e.stopPropagation();
      const sc = v.querySelector('.viewer-scroll');
      const fx = e.offsetX / img.clientWidth, fy = e.offsetY / img.clientHeight;
      v.classList.toggle('zoom');
      if (v.classList.contains('zoom')) {
        sc.scrollLeft = fx * img.clientWidth - sc.clientWidth / 2;
        sc.scrollTop = fy * img.clientHeight - sc.clientHeight / 2;
      }
    });
    v.addEventListener('click', e => { if (e.target === v || e.target.classList.contains('viewer-x') || e.target.classList.contains('viewer-scroll')) v.remove(); });
  }

  const openDrawer = () => { drawer.classList.add('show'); drawerMask.classList.add('show'); drawer.setAttribute('aria-hidden', 'false'); };
  const closeDrawer = () => { drawer.classList.remove('show'); drawerMask.classList.remove('show'); drawer.setAttribute('aria-hidden', 'true'); };
  const openSheet = () => { renderSheet(); sheet.classList.add('show'); sheetMask.classList.add('show'); };
  const closeSheet = () => { sheet.classList.remove('show'); sheetMask.classList.remove('show'); };
  $('#menu-btn').addEventListener('click', openDrawer);
  drawerMask.addEventListener('click', closeDrawer);
  netBtn.addEventListener('click', () => { if (state.user) openSheet(); });
  sheetMask.addEventListener('click', closeSheet);
  submitBtn.addEventListener('click', handleSubmit);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); handleSubmit(); } });

  drawerList.addEventListener('click', e => {
    const it = e.target.closest('.drawer-item');
    if (!it) return;
    if (it.dataset.locked) {
      const p = metaById[it.dataset.locked], prev = p.requires.filter(r => r !== 'LOGIN').map(r => metaById[r].label);
      toast(prev.length ? `完成「${prev.join('、')}」后解锁` : '尚未解锁', 'warn');
      return;
    }
    closeDrawer();
    go(it.dataset.go);
  });

  main.addEventListener('click', e => {
    const t = e.target;
    const img = t.closest('.q-image img');
    if (img) { openViewer(img.src); return; }
    if (t.closest('[data-act="refresh"]')) { Sync.run(true); renderMain(); return; }
  });

  sheetBody.addEventListener('click', e => {
    const act = e.target.getAttribute && e.target.getAttribute('data-act');
    if (act === 'sync') { Sync.run(true); toast('刷新中…'); }
    if (act === 'logout') {
      if (!confirm('确定退出登录？本机进度会保留，在这台手机上再用本队账号登录即可恢复。')) return;
      store.set(keepKey(state.user.c), { solved: state.solved, acked: state.acked, bad: state.bad });
      state = freshState({});
      save();
      rebuild();
      closeSheet();
      render();
    }
    if (act === 'wipe') {
      if (!confirm('确定清除？这台手机上的答题进度和登录信息会全部删除，之后要重新登录、从 A 区重新答。')) return;
      if (!confirm('再确认一次：清除后无法恢复。')) return;
      store.wipe();
      location.reload();
    }
  });

  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
  let scrollTimer = null;
  window.addEventListener('scroll', () => {
    scrollMem[view] = window.scrollY || 0;
    if (scrollTimer) return;
    scrollTimer = setTimeout(() => { scrollTimer = null; store.set('-scroll', scrollMem); }, 300);
  }, { passive: true });
  window.addEventListener('pagehide', rememberScroll);

  rebuild();
  render();
  restoreScroll();
  if (state.user) Sync.run(true);
})();
