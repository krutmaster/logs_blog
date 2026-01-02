/**
 * LOG VIEWER MVP
 * URL: /t/#<ID>&k=<TOKEN>
 * Stores tokens per ID in localStorage.
 * JSON: /logs/<ID>.json
 * Each fragment includes need_hash (sha256(salt || token)) and is encrypted with key=sha256(token) using AES-GCM.
 */

const els = {
  subtitle: document.getElementById('subtitle'),
  logId: document.getElementById('logId'),
  progress: document.getElementById('progress'),
  tokenCount: document.getElementById('tokenCount'),
  out: document.getElementById('out'),
  btnClear: document.getElementById('btnClear'),
  btnScan: document.getElementById('btnScan'),

  scanModal: document.getElementById('scanModal'),
  scanVideo: document.getElementById('scanVideo'),
  scanHint: document.getElementById('scanHint'),
  btnScanClose: document.getElementById('btnScanClose'),
};

const LS_KEY = 'log_tokens_v1';

function loadStore() {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || '{}'); } catch { return {}; }
}
function saveStore(obj) {
  localStorage.setItem(LS_KEY, JSON.stringify(obj));
}
function addTokenToStore(id, token) {
  if (!id || !token) return;
  const store = loadStore();
  store[id] = store[id] || [];
  if (!store[id].includes(token)) store[id].push(token);
  saveStore(store);
}
function getTokens(id) {
  const store = loadStore();
  return store[id] || [];
}

function parseHash() {
  const raw = location.hash.replace(/^#/, '').trim();
  if (!raw) return { id: null, token: null };
  const parts = raw.split('&');
  const id = parts[0] || null;
  const kPart = parts.find(p => p.startsWith('k='));
  const token = kPart ? decodeURIComponent(kPart.slice(2)) : null;
  return { id, token };
}

function b64ToU8(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
function u8ToHex(u8) {
  return [...u8].map(b => b.toString(16).padStart(2,'0')).join('');
}
async function sha256U8(u8) {
  const buf = await crypto.subtle.digest('SHA-256', u8);
  return new Uint8Array(buf);
}
async function tokenHashHex(saltU8, tokenStr) {
  const enc = new TextEncoder();
  const tokU8 = enc.encode(tokenStr);
  const merged = new Uint8Array(saltU8.length + tokU8.length);
  merged.set(saltU8, 0);
  merged.set(tokU8, saltU8.length);
  const h = await sha256U8(merged);
  return u8ToHex(h);
}
async function tokenKeyU8(tokenStr) {
  const enc = new TextEncoder();
  return sha256U8(enc.encode(tokenStr));
}

async function decryptTextFragment(tokenStr, frag) {
  const keyU8 = await tokenKeyU8(tokenStr);
  const key = await crypto.subtle.importKey('raw', keyU8, { name: 'AES-GCM' }, false, ['decrypt']);
  const iv = b64ToU8(frag.nonce_b64);
  const ct = b64ToU8(frag.ct_b64);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

function renderHeader(id, tokens, recovered, total) {
  els.logId.textContent = id || '—';
  els.tokenCount.textContent = String(tokens.length);
  els.progress.textContent = `${recovered}/${total}`;
}

function setStatus(s) { els.subtitle.textContent = s; }

function extractTokenFromAny(s) {
  const str = (s || '').trim();
  if (!str) return null;
  const kMatch = str.match(/(?:\bk=)([^&#\s]+)/);
  if (kMatch) return decodeURIComponent(kMatch[1]);

  if (str.startsWith('http')) {
    try {
      const u = new URL(str);
      const m = (u.hash || '').match(/(?:\bk=)([^&]+)/);
      return m ? decodeURIComponent(m[1]) : null;
    } catch {}
  }
  // token itself
  return str;
}

function extractIdFromAny(s) {
  const str = (s || '').trim();
  if (!str) return null;

  // full url
  if (str.startsWith('http')) {
    try {
      const u = new URL(str);
      const raw = (u.hash || '').replace(/^#/, '');
      const id = raw.split('&')[0];
      return id || null;
    } catch {}
  }

  // hash-like
  if (str.startsWith('#')) {
    const raw = str.replace(/^#/, '');
    const id = raw.split('&')[0];
    return id || null;
  }

  // allow scanning just "A7F3&k=..."
  if (str.includes('&') && !str.includes(' ')) {
    const id = str.split('&')[0];
    return id || null;
  }

  return null;
}

async function loadLogJson(id) {
  const res = await fetch(`/logs/${encodeURIComponent(id)}.json`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function showLog(id) {
  if (!id) {
    setStatus('no log id');
    els.out.textContent = 'Открой /t/#A7F3&k=TOKEN или /t/#A7F3';
    return;
  }

  setStatus('fetching log...');
  const log = await loadLogJson(id);

  const saltU8 = b64ToU8(log.salt_b64);
  const tokens = getTokens(id);

  const tokenHashToToken = new Map();
  for (const t of tokens) {
    const h = await tokenHashHex(saltU8, t);
    tokenHashToToken.set(h, t);
  }

  const outLines = [];
  let recovered = 0;
  const total = log.fragments.length;

  setStatus('decrypting fragments...');

  for (const frag of log.fragments) {
    const needHex = frag.need_hash_hex;
    const token = tokenHashToToken.get(needHex);

    if (!token) {
      outLines.push(`▒▒▒ [CORRUPTED:${frag.i}]  CRC_FAIL  need=${needHex.slice(0,10)}…`);
      continue;
    }

    try {
      const txt = await decryptTextFragment(token, frag);
      recovered++;
      outLines.push(txt);
    } catch {
      outLines.push(`███ [DECRYPT_FAIL:${frag.i}]  KEY_MISMATCH`);
    }
  }

  renderHeader(id, tokens, recovered, total);
  setStatus(`ready // recovered ${recovered}/${total}`);
  els.out.textContent = outLines.join('\n');
}

function registerSW() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

function clearCache() {
  localStorage.removeItem(LS_KEY);
  els.out.textContent = 'CACHE CLEARED.';
  setStatus('cleared');
}

let qrScanner = null;

function openScanModal() {
  els.scanModal.classList.remove('hidden');
  els.scanModal.setAttribute('aria-hidden', 'false');
}

function closeScanModal() {
  els.scanModal.classList.add('hidden');
  els.scanModal.setAttribute('aria-hidden', 'true');
}

async function startQrScan() {
  if (typeof QrScanner === 'undefined') {
    setStatus('qr lib missing');
    return;
  }

  // worker path нужен, иначе часто не найдёт worker при UMD-использовании :contentReference[oaicite:2]{index=2}
  QrScanner.WORKER_PATH = '/t/vendor/qr-scanner-worker.min.js';

  openScanModal();
  els.scanHint.textContent = 'Разреши камеру. Наводи на QR.';

  if (!qrScanner) {
    qrScanner = new QrScanner(
      els.scanVideo,
      (result) => onQrResult(result),
      {
        preferredCamera: 'environment',
        returnDetailedScanResult: true,
        highlightScanRegion: true,
      }
    );
  }

  try {
    await qrScanner.start();
    setStatus('scanning...');
  } catch (e) {
    setStatus('camera blocked');
    els.scanHint.textContent = 'Камера недоступна: разрешения/HTTPS/браузер.';
  }
}

async function stopQrScan() {
  if (!qrScanner) return;
  try { qrScanner.stop(); } catch {}
  setStatus('ready');
}

async function onQrResult(res) {
  const data = (res && res.data) ? res.data : String(res || '');
  if (!data) return;

  // 1) если QR содержит ссылку/хэш с id — переключаемся на этот лог
  const scannedId = extractIdFromAny(data);
  const scannedToken = extractTokenFromAny(data);

  const cur = parseHash();
  const targetId = scannedId || cur.id;

  if (targetId && scannedToken) addTokenToStore(targetId, scannedToken);

  // переключение лога делаем через hash, чтобы вся логика осталась одна
  if (scannedId && scannedId !== cur.id) {
    location.hash = scannedToken ? `#${scannedId}&k=${encodeURIComponent(scannedToken)}` : `#${scannedId}`;
  } else {
    await showLog(cur.id);
  }

  await stopQrScan();
  closeScanModal();
}

function wireUI() {
  els.btnClear.addEventListener('click', () => clearCache());

  els.btnScan.addEventListener('click', async () => {
    await startQrScan(); // важно: по клику пользователя (для мобилок)
  });

  els.btnScanClose.addEventListener('click', async () => {
    await stopQrScan();
    closeScanModal();
  });

  // тап по фону закрывает
  els.scanModal.addEventListener('click', async (e) => {
    if (e.target === els.scanModal) {
      await stopQrScan();
      closeScanModal();
    }
  });

  window.addEventListener('hashchange', async () => boot());
}

async function boot() {
  const { id, token } = parseHash();
  if (id && token) addTokenToStore(id, token);
  await showLog(id);
}

registerSW();
wireUI();
boot();