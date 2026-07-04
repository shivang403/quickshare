const express = require('express');
const multer = require('multer');
const qrcode = require('qrcode');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;

const ROOMS_DIR = path.join(os.tmpdir(), 'quickshare-rooms');
const ROOM_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
const IMAGE_EXTS = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp']);
const ICONS = {
  '.pdf': '📄', '.doc': '📝', '.docx': '📝', '.txt': '📄',
  '.zip': '🗜️', '.rar': '🗜️', '.7z': '🗜️',
  '.xls': '📊', '.xlsx': '📊', '.csv': '📊',
  '.ppt': '📽️', '.pptx': '📽️',
  '.mp3': '🎵', '.wav': '🎵', '.m4a': '🎵',
  '.mp4': '🎬', '.mov': '🎬', '.avi': '🎬', '.mkv': '🎬',
  '.apk': '📱', '.exe': '⚙️'
};

if (!fs.existsSync(ROOMS_DIR)) fs.mkdirSync(ROOMS_DIR, { recursive: true });

// Cleanup expired rooms every 10 min based on their fixed creation time
setInterval(() => {
  for (const room of fs.readdirSync(ROOMS_DIR)) {
    const meta = readMeta(room);
    if (Date.now() - meta.created > ROOM_TTL_MS) {
      fs.rmSync(path.join(ROOMS_DIR, room), { recursive: true, force: true });
    }
  }
}, 10 * 60 * 1000);

function newRoomId() {
  return crypto.randomBytes(4).toString('hex');
}
function roomDir(id) {
  return path.join(ROOMS_DIR, id);
}
function metaPath(id) {
  return path.join(roomDir(id), 'meta.json');
}
function clipboardPath(id) {
  return path.join(roomDir(id), '.clipboard.txt');
}
function readMeta(id) {
  try {
    return JSON.parse(fs.readFileSync(metaPath(id), 'utf8'));
  } catch {
    return { created: Date.now() };
  }
}
function ensureRoom(id) {
  const dir = roomDir(id);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(metaPath(id))) {
    fs.writeFileSync(metaPath(id), JSON.stringify({ created: Date.now() }));
  }
}
function getBaseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}
function isValidRoom(id) {
  return /^[a-f0-9]{8}$/.test(id);
}

app.get('/', (req, res) => {
  const id = newRoomId();
  ensureRoom(id);
  res.redirect(`/r/${id}`);
});

app.get('/r/:id', async (req, res) => {
  const { id } = req.params;
  if (!isValidRoom(id)) return res.status(404).send('Room not found');
  ensureRoom(id);
  const meta = readMeta(id);
  const expiresAt = meta.created + ROOM_TTL_MS;
  const url = `${getBaseUrl(req)}/r/${id}`;
  const qrDataUrl = await qrcode.toDataURL(url, { width: 260, margin: 1 });

  res.send(renderPage({ id, url, qrDataUrl, expiresAt }));
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    ensureRoom(req.params.id);
    cb(null, roomDir(req.params.id));
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

app.post('/r/:id/upload', upload.array('files', 10), (req, res) => {
  res.redirect(`/r/${req.params.id}`);
});

app.get('/r/:id/files', (req, res) => {
  const dir = roomDir(req.params.id);
  if (!fs.existsSync(dir)) return res.json([]);
  const files = fs.readdirSync(dir)
    .filter(f => f !== 'meta.json' && f !== '.clipboard.txt')
    .sort().reverse()
    .map(f => {
      const ext = path.extname(f).toLowerCase();
      const name = f.replace(/^\d+-/, '');
      return {
        stored: f,
        name,
        isImage: IMAGE_EXTS.has(ext),
        icon: ICONS[ext] || '📁'
      };
    });
  res.json(files);
});

app.get('/r/:id/download/:filename', (req, res) => {
  const filePath = path.join(roomDir(req.params.id), req.params.filename);
  const originalName = req.params.filename.replace(/^\d+-/, '');
  res.download(filePath, originalName);
});

app.get('/r/:id/thumb/:filename', (req, res) => {
  const ext = path.extname(req.params.filename).toLowerCase();
  if (!IMAGE_EXTS.has(ext)) return res.status(404).end();
  const filePath = path.join(roomDir(req.params.id), req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.get('/r/:id/clipboard', (req, res) => {
  try {
    res.json({ text: fs.readFileSync(clipboardPath(req.params.id), 'utf8') });
  } catch {
    res.json({ text: '' });
  }
});

app.post('/r/:id/clipboard', (req, res) => {
  ensureRoom(req.params.id);
  const text = (req.body && req.body.text) || '';
  fs.writeFileSync(clipboardPath(req.params.id), text, 'utf8');
  res.json({ ok: true });
});

function renderPage({ id, url, qrDataUrl, expiresAt }) {
  return `<!DOCTYPE html>
<html>
<head>
<title>QuickShare</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg1: #012a4a; --bg2: #01497c; --bg3: #013a63;
    --card-bg: rgba(255,255,255,0.10); --card-border: rgba(255,255,255,0.25);
    --text: #eaf4ff; --text-dim: #a9c6de; --accent: #48cae4; --accent2: #90e0ef;
  }
  body.light {
    --bg1: #b8e2f2; --bg2: #d6f0fb; --bg3: #eaf7fd;
    --card-bg: rgba(255,255,255,0.65); --card-border: rgba(1,73,124,0.15);
    --text: #013a63; --text-dim: #4c7690; --accent: #0077b6; --accent2: #0096c7;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, 'Segoe UI', Arial, sans-serif;
    background: linear-gradient(180deg, var(--bg1), var(--bg2) 50%, var(--bg3));
    color: var(--text); min-height: 100vh; overflow-x: hidden; transition: background 0.4s;
  }
  #ocean { position: fixed; inset: 0; overflow: hidden; z-index: 0; pointer-events: none; }
  .bubble {
    position: absolute; bottom: -40px; border-radius: 50%;
    background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.9), rgba(255,255,255,0.1));
    animation: rise linear infinite;
  }
  @keyframes rise {
    0% { transform: translateY(0) translateX(0); opacity: 0.8; }
    100% { transform: translateY(-110vh) translateX(20px); opacity: 0; }
  }
  .fish { position: absolute; font-size: 28px; animation: swim linear infinite; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2)); }
  .fish.rev { transform: scaleX(-1); }
  @keyframes swim {
    0% { transform: translateX(-10vw); }
    100% { transform: translateX(110vw); }
  }
  .fish.rev { animation-name: swimrev; }
  @keyframes swimrev {
    0% { transform: translateX(110vw) scaleX(-1); }
    100% { transform: translateX(-10vw) scaleX(-1); }
  }
  .seaweed { position: absolute; bottom: 0; font-size: 40px; transform-origin: bottom center; animation: sway 4s ease-in-out infinite; opacity: 0.6; }
  @keyframes sway { 0%,100% { transform: rotate(-6deg); } 50% { transform: rotate(6deg); } }

  .wrap { position: relative; z-index: 1; padding: 16px; max-width: 460px; margin: 0 auto; }
  .topbar { display:flex; justify-content:flex-end; padding: 6px 0; }
  .toggle-btn {
    background: var(--card-bg); border: 1px solid var(--card-border); color: var(--text);
    border-radius: 999px; padding: 8px 14px; cursor: pointer; font-size: 14px; backdrop-filter: blur(6px);
  }
  .box {
    background: var(--card-bg); border: 1px solid var(--card-border); backdrop-filter: blur(10px);
    border-radius: 18px; padding: 22px; margin: 14px 0; box-shadow: 0 8px 24px rgba(0,0,0,0.15);
  }
  h1 { font-size: 18px; margin: 0 0 14px; display:flex; align-items:center; gap:8px; }
  .badge { display:inline-block; background: rgba(72,202,228,0.2); color: var(--accent2); padding:4px 12px; border-radius:999px; font-size:12px; margin-bottom:10px; }
  img.qr { border-radius: 10px; display:block; margin: 0 auto; background:#fff; padding:8px; }
  .url { font-size: 13px; color: var(--text-dim); word-break: break-all; text-align:center; margin-top:10px;}
  .timer { text-align:center; font-size: 13px; color: var(--text-dim); margin-top: 6px; }
  .dropzone {
    border: 2px dashed var(--card-border); border-radius: 14px; padding: 28px 16px; text-align:center;
    color: var(--text-dim); cursor: pointer; transition: 0.2s; font-size: 14px;
  }
  .dropzone.drag { border-color: var(--accent); background: rgba(72,202,228,0.08); }
  .btn {
    background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #012a4a; border:none;
    padding: 12px 20px; border-radius: 12px; cursor: pointer; font-size: 15px; font-weight:600; width:100%; margin-top:10px;
  }
  .btn.secondary { background: var(--card-bg); color: var(--text); border:1px solid var(--card-border); }
  ul { list-style:none; padding:0; margin:0; }
  li { display:flex; align-items:center; gap:10px; padding:10px 4px; border-bottom:1px solid var(--card-border); }
  li:last-child { border-bottom:none; }
  .thumb { width:38px; height:38px; border-radius:8px; object-fit:cover; flex-shrink:0; }
  .icon { font-size:24px; width:38px; text-align:center; flex-shrink:0; }
  .fname { flex:1; word-break:break-all; font-size:14px; }
  a.dl { color: var(--accent2); font-weight:600; text-decoration:none; font-size:14px; white-space:nowrap; }
  textarea {
    width:100%; min-height:100px; border-radius:12px; border:1px solid var(--card-border);
    background: rgba(255,255,255,0.08); color: var(--text); padding:12px; font-size:14px; resize:vertical;
  }
  .row { display:flex; gap:10px; }
  .row .btn { margin-top:0; }
  .empty { color: var(--text-dim); font-size:14px; text-align:center; padding: 6px 0; }
</style>
</head>
<body>
<div id="ocean"></div>
<div class="wrap">
  <div class="topbar"><button class="toggle-btn" id="themeToggle">🌙 Dark</button></div>

  <div class="box">
    <div class="badge">Room ${id}</div>
    <h1>📱 Scan to join this room</h1>
    <img class="qr" src="${qrDataUrl}" width="220" height="220" />
    <p class="url">or open: <b>${url}</b></p>
    <div class="timer" id="timer">Expires in --:--:--</div>
  </div>

  <div class="box">
    <h1>📋 Shared clipboard</h1>
    <textarea id="clip" placeholder="Type or paste text here, then Save. The other device can Copy it."></textarea>
    <div class="row">
      <button class="btn" id="saveClip">💾 Save</button>
      <button class="btn secondary" id="copyClip">📄 Copy</button>
    </div>
  </div>

  <div class="box">
    <h1>⬆️ Send files</h1>
    <form id="uploadForm" action="/r/${id}/upload" method="post" enctype="multipart/form-data">
      <div class="dropzone" id="dropzone">
        📥 Drag & drop files here, or click to browse
        <input type="file" name="files" id="fileInput" multiple hidden />
      </div>
    </form>
  </div>

  <div class="box">
    <h1>⬇️ Files in this room</h1>
    <ul id="filelist"><li class="empty">Loading...</li></ul>
  </div>
</div>

<script>
  // ---- Underwater background ----
  const ocean = document.getElementById('ocean');
  const fishEmojis = ['🐠','🐟','🐡','🦈','🐬'];
  for (let i = 0; i < 6; i++) {
    const f = document.createElement('div');
    f.className = 'fish' + (Math.random() > 0.5 ? ' rev' : '');
    f.textContent = fishEmojis[i % fishEmojis.length];
    f.style.top = (10 + Math.random() * 70) + 'vh';
    f.style.animationDuration = (14 + Math.random() * 12) + 's';
    f.style.animationDelay = (-Math.random() * 20) + 's';
    ocean.appendChild(f);
  }
  for (let i = 0; i < 18; i++) {
    const b = document.createElement('div');
    b.className = 'bubble';
    const size = 4 + Math.random() * 12;
    b.style.width = size + 'px'; b.style.height = size + 'px';
    b.style.left = Math.random() * 100 + 'vw';
    b.style.animationDuration = (6 + Math.random() * 8) + 's';
    b.style.animationDelay = (-Math.random() * 10) + 's';
    ocean.appendChild(b);
  }
  ['🌿','🌱','🪸'].forEach((s, i) => {
    const w = document.createElement('div');
    w.className = 'seaweed';
    w.textContent = s;
    w.style.left = (10 + i * 35) + 'vw';
    w.style.animationDelay = (i * 0.7) + 's';
    ocean.appendChild(w);
  });

  // ---- Theme toggle ----
  const themeBtn = document.getElementById('themeToggle');
  function applyTheme(light) {
    document.body.classList.toggle('light', light);
    themeBtn.textContent = light ? '☀️ Light' : '🌙 Dark';
  }
  const savedTheme = localStorage.getItem('quickshare-theme');
  applyTheme(savedTheme === 'light');
  themeBtn.onclick = () => {
    const light = !document.body.classList.contains('light');
    applyTheme(light);
    localStorage.setItem('quickshare-theme', light ? 'light' : 'dark');
  };

  // ---- Expiry countdown ----
  const expiresAt = ${expiresAt};
  function tick() {
    const remaining = expiresAt - Date.now();
    const el = document.getElementById('timer');
    if (remaining <= 0) { el.textContent = 'Room expired — refreshing...'; setTimeout(() => location.href = '/', 1200); return; }
    const h = Math.floor(remaining / 3600000);
    const m = Math.floor((remaining % 3600000) / 60000);
    const s = Math.floor((remaining % 60000) / 1000);
    el.textContent = 'Expires in ' + String(h).padStart(2,'0') + ':' + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
  }
  tick(); setInterval(tick, 1000);

  // ---- File list ----
  const roomId = '${id}';
  async function refreshFiles() {
    const res = await fetch('/r/' + roomId + '/files');
    const files = await res.json();
    const list = document.getElementById('filelist');
    if (!files.length) { list.innerHTML = '<li class="empty">No files yet</li>'; return; }
    list.innerHTML = files.map(f => {
      const thumb = f.isImage
        ? '<img class="thumb" src="/r/' + roomId + '/thumb/' + encodeURIComponent(f.stored) + '" />'
        : '<div class="icon">' + f.icon + '</div>';
      return '<li>' + thumb + '<span class="fname">' + f.name + '</span><a class="dl" href="/r/' + roomId + '/download/' + encodeURIComponent(f.stored) + '">Download</a></li>';
    }).join('');
  }
  refreshFiles(); setInterval(refreshFiles, 3000);

  // ---- Drag & drop upload ----
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const uploadForm = document.getElementById('uploadForm');
  dropzone.onclick = () => fileInput.click();
  fileInput.onchange = () => { if (fileInput.files.length) uploadForm.submit(); };
  ['dragenter','dragover'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave','drop'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.remove('drag'); }));
  dropzone.addEventListener('drop', e => {
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      uploadForm.submit();
    }
  });

  // ---- Clipboard sync ----
  const clip = document.getElementById('clip');
  let clipFocused = false;
  clip.addEventListener('focus', () => clipFocused = true);
  clip.addEventListener('blur', () => clipFocused = false);
  async function refreshClipboard() {
    if (clipFocused) return;
    const res = await fetch('/r/' + roomId + '/clipboard');
    const data = await res.json();
    if (document.activeElement !== clip) clip.value = data.text;
  }
  refreshClipboard(); setInterval(refreshClipboard, 3000);
  document.getElementById('saveClip').onclick = async () => {
    await fetch('/r/' + roomId + '/clipboard', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: clip.value })
    });
    const btn = document.getElementById('saveClip');
    const old = btn.textContent; btn.textContent = '✅ Saved'; setTimeout(() => btn.textContent = old, 1200);
  };
  document.getElementById('copyClip').onclick = async () => {
    try {
      await navigator.clipboard.writeText(clip.value);
      const btn = document.getElementById('copyClip');
      const old = btn.textContent; btn.textContent = '✅ Copied'; setTimeout(() => btn.textContent = old, 1200);
    } catch { alert('Could not copy — select the text manually.'); }
  };
</script>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`QuickShare running on port ${PORT}`);
});
