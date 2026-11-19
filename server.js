// Code-based file sharing server. No dependencies, just Node 16+.
// Run: node server.js   then open http://localhost:3000
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const MAX_MB = Number(process.env.MAX_MB || 1024);      // max file size (1 GB)
const TTL_MIN = Number(process.env.TTL_MIN || 1440);    // minutes until a file expires (24 hours)
const TRUST_PROXY = process.env.TRUST_PROXY === '1';    // set if behind nginx/Cloudflare etc.
const MAX_BYTES = MAX_MB * 1024 * 1024;
const TTL_MS = TTL_MIN * 60 * 1000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// code -> { name, size, expires }
const files = new Map();
const reserved = new Set(); // codes claimed by in-progress uploads

const metaPath = (c) => path.join(UPLOAD_DIR, c + '.json');
const dataPath = (c) => path.join(UPLOAD_DIR, c + '.bin');

function removeCode(code) {
  files.delete(code);
  reserved.delete(code);
  fs.unlink(metaPath(code), () => {});
  fs.unlink(dataPath(code), () => {});
}

// Reload anything still valid from disk, clean up the rest
for (const f of fs.readdirSync(UPLOAD_DIR)) {
  const m = f.match(/^(\d{4})\.json$/);
  if (!m) { if (!f.endsWith('.json') && !f.endsWith('.bin')) continue; }
  if (m) {
    try {
      const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR, f), 'utf8'));
      if (meta.expires > Date.now() && fs.existsSync(dataPath(m[1]))) files.set(m[1], meta);
      else removeCode(m[1]);
    } catch { removeCode(m[1]); }
  }
}
// orphaned .bin files with no metadata
for (const f of fs.readdirSync(UPLOAD_DIR)) {
  const m = f.match(/^(\d{4})\.bin$/);
  if (m && !files.has(m[1])) fs.unlink(path.join(UPLOAD_DIR, f), () => {});
}

setInterval(() => {
  const now = Date.now();
  for (const [code, meta] of files) if (meta.expires <= now) removeCode(code);
}, 30 * 1000).unref();

function newCode() {
  if (files.size + reserved.size >= 10000) return null;
  for (let i = 0; i < 200; i++) {
    const c = String(Math.floor(Math.random() * 10000)).padStart(4, '0');
    if (!files.has(c) && !reserved.has(c)) return c;
  }
  for (let n = 0; n < 10000; n++) {
    const c = String(n).padStart(4, '0');
    if (!files.has(c) && !reserved.has(c)) return c;
  }
  return null;
}

// Only 10,000 possible codes, so throttle guessing per IP.
const fails = new Map(); // ip -> { count, resetAt }
const MAX_FAILS = 8, FAIL_WINDOW = 60 * 1000;
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return req.headers['x-forwarded-for'].split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}
function blocked(ip) {
  const f = fails.get(ip);
  if (!f) return 0;
  if (f.resetAt <= Date.now()) { fails.delete(ip); return 0; }
  return f.count >= MAX_FAILS ? Math.ceil((f.resetAt - Date.now()) / 1000) : 0;
}
function recordFail(ip) {
  const f = fails.get(ip);
  if (!f || f.resetAt <= Date.now()) fails.set(ip, { count: 1, resetAt: Date.now() + FAIL_WINDOW });
  else f.count++;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of fails) if (v.resetAt <= n) fails.delete(k); }, 60 * 1000).unref();

function json(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', ...extra });
  res.end(body);
}

function cleanName(raw) {
  let n = '';
  try { n = decodeURIComponent(raw || ''); } catch { n = String(raw || ''); }
  n = path.basename(n.replace(/\\/g, '/')).replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (n.length > 200) n = n.slice(0, 200);
  return n || 'file';
}

function handleUpload(req, res) {
  const declared = Number(req.headers['content-length']);
  if (!declared) return json(res, 411, { error: 'Empty or unknown file size.' });
  if (declared > MAX_BYTES) { res.setHeader('Connection', 'close'); return json(res, 413, { error: `File too large (max ${MAX_MB} MB).` }); }
  const code = newCode();
  if (!code) return json(res, 503, { error: 'Server is full, try again in a few minutes.' });
  reserved.add(code);

  const name = cleanName(req.headers['x-filename']);
  const out = fs.createWriteStream(dataPath(code));
  let size = 0, aborted = false;

  const fail = (status, msg) => {
    if (aborted) return;
    aborted = true;
    out.destroy();
    removeCode(code);
    if (!res.headersSent) json(res, status, { error: msg });
  };

  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_BYTES) { req.unpipe(out); fail(413, `File too large (max ${MAX_MB} MB).`); req.destroy(); }
  });
  req.on('aborted', () => fail(400, 'Upload cancelled.'));
  req.on('error', () => fail(400, 'Upload failed.'));
  out.on('error', () => fail(500, 'Could not save file.'));
  out.on('finish', () => {
    if (aborted) return;
    const meta = { name, size, expires: Date.now() + TTL_MS };
    fs.writeFile(metaPath(code), JSON.stringify(meta), (err) => {
      if (err) return fail(500, 'Could not save file.');
      reserved.delete(code);
      files.set(code, meta);
      json(res, 200, { code, name, size, expiresInMinutes: TTL_MIN });
    });
  });
  req.pipe(out);
}

function lookup(req, res, code) {
  const ip = clientIp(req);
  const wait = blocked(ip);
  if (wait) return json(res, 429, { error: `Too many wrong codes. Try again in ${wait}s.` }, { 'Retry-After': String(wait) }), null;
  const meta = files.get(code);
  if (!meta || meta.expires <= Date.now()) {
    if (meta) removeCode(code);
    recordFail(ip);
    return json(res, 404, { error: 'No file found for that code. It may have expired.' }), null;
  }
  return meta;
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'POST' && p === '/api/upload') return handleUpload(req, res);

  let m;
  if (req.method === 'GET' && (m = p.match(/^\/api\/info\/(\d{4})$/))) {
    const meta = lookup(req, res, m[1]);
    if (meta) json(res, 200, { name: meta.name, size: meta.size, expiresInSeconds: Math.round((meta.expires - Date.now()) / 1000) });
    return;
  }

  if (req.method === 'GET' && (m = p.match(/^\/api\/download\/(\d{4})$/))) {
    const meta = lookup(req, res, m[1]);
    if (!meta) return;
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': meta.size,
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(meta.name).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    fs.createReadStream(dataPath(m[1])).on('error', () => res.destroy()).pipe(res);
    return;
  }

  if (req.method === 'GET') {
    const file = p === '/' ? 'index.html' : p.slice(1);
    const full = path.join(PUBLIC_DIR, file);
    if (!full.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
    fs.readFile(full, (err, data) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
      res.end(data);
    });
    return;
  }

  res.writeHead(405); res.end();
});

server.listen(PORT, () => console.log(`File share running on http://localhost:${PORT}  (max ${MAX_MB} MB, expires after ${TTL_MIN} min)`));
