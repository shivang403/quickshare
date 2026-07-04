const express = require('express');
const multer = require('multer');
const qrcode = require('qrcode');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const ROOMS_DIR = path.join(os.tmpdir(), 'quickshare-rooms');
if (!fs.existsSync(ROOMS_DIR)) fs.mkdirSync(ROOMS_DIR, { recursive: true });

// Delete rooms older than 2 hours, every 30 min, so the free server doesn't fill up
setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 60 * 1000;
  for (const room of fs.readdirSync(ROOMS_DIR)) {
    const dir = path.join(ROOMS_DIR, room);
    const stat = fs.statSync(dir);
    if (stat.mtimeMs < cutoff) fs.rmSync(dir, { recursive: true, force: true });
  }
}, 30 * 60 * 1000);

function newRoomId() {
  return crypto.randomBytes(4).toString('hex'); // short, hard-to-guess-enough id
}

function roomDir(id) {
  return path.join(ROOMS_DIR, id);
}

function getBaseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}

// Landing page -> create a fresh room and redirect
app.get('/', (req, res) => {
  const id = newRoomId();
  fs.mkdirSync(roomDir(id), { recursive: true });
  res.redirect(`/r/${id}`);
});

app.get('/r/:id', async (req, res) => {
  const { id } = req.params;
  if (!/^[a-f0-9]{8}$/.test(id)) return res.status(404).send('Room not found');
  fs.mkdirSync(roomDir(id), { recursive: true }); // recreate if it expired
  const url = `${getBaseUrl(req)}/r/${id}`;
  const qrDataUrl = await qrcode.toDataURL(url, { width: 260 });

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>QuickShare</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: -apple-system, Arial, sans-serif; text-align: center; padding: 16px; background:#f2f2f7; margin:0; }
        .box { background:white; border-radius:16px; padding:24px; max-width:420px; margin:16px auto; box-shadow:0 2px 12px rgba(0,0,0,0.08);}
        h1 { font-size: 19px; margin-top:0; }
        img { border-radius:8px; }
        ul { list-style:none; padding:0; text-align:left; }
        li { padding:10px 4px; border-bottom:1px solid #eee; display:flex; justify-content:space-between; align-items:center; }
        a.file { color:#111; text-decoration:none; word-break:break-all; }
        a.dl { color:#2563eb; font-weight:600; text-decoration:none; margin-left:8px; }
        input[type=file] { width:100%; margin-bottom:12px; }
        input[type=submit] { background:#2563eb; color:white; border:none; padding:12px 24px; border-radius:10px; cursor:pointer; font-size:15px; width:100%; }
        .url { font-size:14px; color:#555; word-break:break-all; }
        .badge { display:inline-block; background:#eef2ff; color:#3730a3; padding:4px 10px; border-radius:999px; font-size:12px; margin-bottom:8px;}
      </style>
    </head>
    <body>
      <div class="box">
        <div class="badge">Room ${id}</div>
        <h1>📱 Scan to join this room</h1>
        <img src="${qrDataUrl}" width="220" height="220" />
        <p class="url">or open: <b>${url}</b></p>
        <p style="font-size:13px;color:#888;">Works on any network — WiFi or mobile data. Room auto-expires in 2 hours.</p>
      </div>

      <div class="box">
        <h1>⬆️ Send a file</h1>
        <form action="/r/${id}/upload" method="post" enctype="multipart/form-data">
          <input type="file" name="file" required />
          <input type="submit" value="Upload" />
        </form>
      </div>

      <div class="box">
        <h1>⬇️ Files in this room</h1>
        <ul id="filelist">Loading...</ul>
      </div>

      <script>
        async function refresh() {
          const res = await fetch('/r/${id}/files');
          const files = await res.json();
          const list = document.getElementById('filelist');
          list.innerHTML = files.length
            ? files.map(f => \`<li><span class="file">\${f.name}</span><a class="dl" href="/r/${id}/download/\${encodeURIComponent(f.stored)}">Download</a></li>\`).join('')
            : '<li style="color:#999;">No files yet</li>';
        }
        refresh();
        setInterval(refresh, 3000);
      </script>
    </body>
    </html>
  `);
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, roomDir(req.params.id)),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB cap

app.post('/r/:id/upload', upload.single('file'), (req, res) => {
  res.redirect(`/r/${req.params.id}`);
});

app.get('/r/:id/files', (req, res) => {
  const dir = roomDir(req.params.id);
  if (!fs.existsSync(dir)) return res.json([]);
  const files = fs.readdirSync(dir)
    .sort().reverse()
    .map(f => ({ stored: f, name: f.replace(/^\d+-/, '') }));
  res.json(files);
});

app.get('/r/:id/download/:filename', (req, res) => {
  const filePath = path.join(roomDir(req.params.id), req.params.filename);
  const originalName = req.params.filename.replace(/^\d+-/, '');
  res.download(filePath, originalName);
});

app.listen(PORT, () => {
  console.log(`QuickShare running on port ${PORT}`);
});
