const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const app = express();
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 3000;
const ROOMS_DIR = path.join(os.tmpdir(), 'quickshare-rooms');
const GLOBAL_DIR = path.join(os.tmpdir(), 'quickshare-global');
const ROOM_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
const STALE_DEVICE_MS = 20 * 1000;

if (!fs.existsSync(ROOMS_DIR)) fs.mkdirSync(ROOMS_DIR, { recursive: true });
if (!fs.existsSync(GLOBAL_DIR)) fs.mkdirSync(GLOBAL_DIR, { recursive: true });

setInterval(() => {
  for (const room of fs.readdirSync(ROOMS_DIR)) {
    const meta = readJson(metaPath(room), { created: Date.now() });
    if (Date.now() - meta.created > ROOM_TTL_MS) {
      fs.rmSync(path.join(ROOMS_DIR, room), { recursive: true, force: true });
    }
  }
}, 10 * 60 * 1000);

// ---------- helpers ----------
function newRoomId() { return crypto.randomBytes(4).toString('hex'); }
function isValidRoom(id) { return /^[a-f0-9]{8}$/.test(id); }
function roomDir(id) { return path.join(ROOMS_DIR, id); }
function metaPath(id) { return path.join(roomDir(id), 'meta.json'); }
function devicesPath(id) { return path.join(roomDir(id), 'devices.json'); }
function manifestPath(id) { return path.join(roomDir(id), 'manifest.json'); }
function clipboardPath(id) { return path.join(roomDir(id), 'clipboard.json'); }

function readJson(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; }
}
function writeJson(p, data) { fs.writeFileSync(p, JSON.stringify(data)); }

function ensureRoom(id) {
  const dir = roomDir(id);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(metaPath(id))) writeJson(metaPath(id), { created: Date.now() });
}
function getMeta(id) { return readJson(metaPath(id), { created: Date.now() }); }
function getDevices(id) { return readJson(devicesPath(id), {}); }
function getManifest(id) { return readJson(manifestPath(id), []); }

function isOwnerReq(req, id) {
  const meta = getMeta(id);
  return !!meta.ownerToken && req.cookies['qs_owner_' + id] === meta.ownerToken;
}
function pinOk(req, id) {
  const meta = getMeta(id);
  if (!meta.pinHash) return true;
  if (isOwnerReq(req, id)) return true;
  return req.cookies['qs_pin_' + id] === meta.pinAccessToken;
}
function isKicked(id, deviceId) {
  const devices = getDevices(id);
  return !!(devices[deviceId] && devices[deviceId].kicked);
}
function labelFromUA(ua) {
  ua = ua || '';
  let osName = 'Unknown device';
  if (/windows/i.test(ua)) osName = 'Windows';
  else if (/android/i.test(ua)) osName = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) osName = 'iOS';
  else if (/mac os x/i.test(ua)) osName = 'Mac';
  else if (/linux/i.test(ua)) osName = 'Linux';
  let browser = 'Browser';
  if (/edg\//i.test(ua)) browser = 'Edge';
  else if (/chrome\//i.test(ua)) browser = 'Chrome';
  else if (/firefox\//i.test(ua)) browser = 'Firefox';
  else if (/safari\//i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';
  return `${browser} on ${osName}`;
}

// ================= SITE-WIDE ADMIN + APPROVAL GATE =================
const ADMIN_FILE = path.join(GLOBAL_DIR, 'admin.json');
const GLOBAL_DEVICES_FILE = path.join(GLOBAL_DIR, 'devices.json');

function initAdmin() {
  if (fs.existsSync(ADMIN_FILE)) return readJson(ADMIN_FILE, {});
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(4).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  const admin = { salt, hash, adminToken: crypto.randomBytes(16).toString('hex') };
  writeJson(ADMIN_FILE, admin);
  if (!process.env.ADMIN_PASSWORD) {
    console.log('\n================================================');
    console.log(' No ADMIN_PASSWORD set. Generated one for you:');
    console.log(' Admin password: ' + password);
    console.log(' Log in at /admin — change it there once logged in.');
    console.log('================================================\n');
  }
  return admin;
}
const adminState = initAdmin();
function getAdmin() { return readJson(ADMIN_FILE, adminState); }
function isAdminReq(req) {
  const admin = getAdmin();
  return req.cookies['qs_admin'] === admin.adminToken;
}
function getGlobalDevices() { return readJson(GLOBAL_DEVICES_FILE, {}); }
function saveGlobalDevices(d) { writeJson(GLOBAL_DEVICES_FILE, d); }

function siteGate(req, res, next) {
  if (isAdminReq(req)) return next(); // owner always allowed
  let deviceId = req.cookies['qs_site_device'];
  if (!deviceId) {
    deviceId = crypto.randomUUID();
    res.cookie('qs_site_device', deviceId, { httpOnly: true, sameSite: 'lax', maxAge: 365 * 24 * 60 * 60 * 1000 });
  }
  const devices = getGlobalDevices();
  let entry = devices[deviceId];
  if (!entry) {
    entry = { status: 'pending', label: labelFromUA(req.headers['user-agent']), ip: req.ip, firstSeen: Date.now() };
  }
  entry.lastSeen = Date.now();
  devices[deviceId] = entry;
  saveGlobalDevices(devices);

  if (entry.status === 'blocked') return res.send(renderBlockedPage());
  if (entry.status === 'approved') return next();
  res.cookie('qs_pending_dest', req.originalUrl, { httpOnly: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 });
  return res.send(renderPendingPage());
}

app.get('/site-status', (req, res) => {
  const deviceId = req.cookies['qs_site_device'];
  const devices = getGlobalDevices();
  const entry = devices[deviceId];
  res.json({ status: entry ? entry.status : 'pending' });
});

app.get('/admin', (req, res) => {
  if (!isAdminReq(req)) return res.send(renderAdminLogin());
  res.send(renderAdminDashboard());
});

app.post('/admin/login', (req, res) => {
  const admin = getAdmin();
  const password = req.body.password || '';
  const hash = crypto.scryptSync(password, admin.salt, 64).toString('hex');
  if (hash === admin.hash) {
    res.cookie('qs_admin', admin.adminToken, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000 });
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false });
});

app.post('/admin/change-password', (req, res) => {
  if (!isAdminReq(req)) return res.status(403).json({ ok: false });
  const admin = getAdmin();
  const oldHash = crypto.scryptSync(req.body.oldPassword || '', admin.salt, 64).toString('hex');
  if (oldHash !== admin.hash) return res.status(401).json({ ok: false, error: 'Wrong current password' });
  const newPassword = (req.body.newPassword || '').trim();
  if (!newPassword) return res.status(400).json({ ok: false, error: 'New password required' });
  admin.salt = crypto.randomBytes(16).toString('hex');
  admin.hash = crypto.scryptSync(newPassword, admin.salt, 64).toString('hex');
  admin.adminToken = crypto.randomBytes(16).toString('hex');
  writeJson(ADMIN_FILE, admin);
  res.cookie('qs_admin', admin.adminToken, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ ok: true });
});

app.get('/admin/devices', (req, res) => {
  if (!isAdminReq(req)) return res.status(403).json([]);
  const devices = getGlobalDevices();
  res.json(Object.entries(devices).map(([deviceId, d]) => ({ deviceId, ...d })));
});

app.post('/admin/approve', (req, res) => {
  if (!isAdminReq(req)) return res.status(403).json({ ok: false });
  const devices = getGlobalDevices();
  if (devices[req.body.deviceId]) { devices[req.body.deviceId].status = 'approved'; saveGlobalDevices(devices); }
  res.json({ ok: true });
});
app.post('/admin/block', (req, res) => {
  if (!isAdminReq(req)) return res.status(403).json({ ok: false });
  const devices = getGlobalDevices();
  if (devices[req.body.deviceId]) { devices[req.body.deviceId].status = 'blocked'; saveGlobalDevices(devices); }
  res.json({ ok: true });
});
app.post('/admin/unblock', (req, res) => {
  if (!isAdminReq(req)) return res.status(403).json({ ok: false });
  const devices = getGlobalDevices();
  if (devices[req.body.deviceId]) { devices[req.body.deviceId].status = 'approved'; saveGlobalDevices(devices); }
  res.json({ ok: true });
});

// ---------- room creation ----------
app.get('/', siteGate, (req, res) => {
  const id = newRoomId();
  ensureRoom(id);
  const meta = getMeta(id);
  meta.ownerToken = crypto.randomBytes(16).toString('hex');
  writeJson(metaPath(id), meta);
  res.cookie('qs_owner_' + id, meta.ownerToken, { httpOnly: true, sameSite: 'lax', maxAge: ROOM_TTL_MS });
  res.redirect(`/r/${id}`);
});

app.get('/r/:id', siteGate, (req, res) => {
  const { id } = req.params;
  if (!isValidRoom(id)) return res.status(404).send('Room not found');
  ensureRoom(id);
  const meta = getMeta(id);
  const isOwner = isOwnerReq(req, id);
  if (!pinOk(req, id)) return res.send(renderPinGate(id));
  res.send(renderPage({ id, expiresAt: meta.created + ROOM_TTL_MS, isOwner, hasPin: !!meta.pinHash }));
});

// ---------- PIN ----------
app.post('/r/:id/verify-pin', (req, res) => {
  const { id } = req.params;
  const meta = getMeta(id);
  if (!meta.pinHash) return res.json({ ok: true });
  const pin = req.body.pin || '';
  const hash = crypto.scryptSync(pin, meta.pinSalt, 64).toString('hex');
  if (hash === meta.pinHash) {
    res.cookie('qs_pin_' + id, meta.pinAccessToken, { httpOnly: true, sameSite: 'lax', maxAge: ROOM_TTL_MS });
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false });
});

app.post('/r/:id/owner/set-pin', (req, res) => {
  const { id } = req.params;
  if (!isOwnerReq(req, id)) return res.status(403).json({ ok: false });
  const meta = getMeta(id);
  const pin = (req.body.pin || '').trim();
  if (!pin) {
    delete meta.pinHash; delete meta.pinSalt; delete meta.pinAccessToken;
  } else {
    meta.pinSalt = crypto.randomBytes(16).toString('hex');
    meta.pinHash = crypto.scryptSync(pin, meta.pinSalt, 64).toString('hex');
    meta.pinAccessToken = crypto.randomBytes(16).toString('hex');
  }
  writeJson(metaPath(id), meta);
  res.json({ ok: true });
});

// ---------- device presence (per room) ----------
app.post('/r/:id/presence', (req, res) => {
  const { id } = req.params;
  ensureRoom(id);
  const deviceId = req.headers['x-device-id'] || 'unknown';
  const devices = getDevices(id);
  if (!devices[deviceId]) devices[deviceId] = { label: labelFromUA(req.headers['user-agent']), kicked: false };
  devices[deviceId].lastSeen = Date.now();
  writeJson(devicesPath(id), devices);
  res.json({ kicked: !!devices[deviceId].kicked });
});

app.get('/r/:id/devices', (req, res) => {
  const { id } = req.params;
  if (!isOwnerReq(req, id)) return res.status(403).json([]);
  const devices = getDevices(id);
  const now = Date.now();
  const list = Object.entries(devices)
    .filter(([, d]) => now - d.lastSeen < STALE_DEVICE_MS)
    .map(([deviceId, d]) => ({ deviceId, label: d.label, kicked: !!d.kicked }));
  res.json(list);
});

app.post('/r/:id/kick', (req, res) => {
  const { id } = req.params;
  if (!isOwnerReq(req, id)) return res.status(403).json({ ok: false });
  const devices = getDevices(id);
  const target = req.body.deviceId;
  if (devices[target]) devices[target].kicked = true;
  writeJson(devicesPath(id), devices);
  res.json({ ok: true });
});

// ---------- encrypted file storage (server never sees plaintext) ----------
app.post('/r/:id/upload/:stored', express.raw({ type: '*/*', limit: '55mb' }), (req, res) => {
  const { id, stored } = req.params;
  const deviceId = req.headers['x-device-id'] || 'unknown';
  if (isKicked(id, deviceId)) return res.status(403).end();
  if (!/^[a-f0-9-]{8,40}$/.test(stored)) return res.status(400).end();
  ensureRoom(id);
  fs.writeFileSync(path.join(roomDir(id), stored + '.bin'), req.body);
  res.json({ ok: true });
});

app.post('/r/:id/manifest', (req, res) => {
  const { id } = req.params;
  const deviceId = req.headers['x-device-id'] || 'unknown';
  if (isKicked(id, deviceId)) return res.status(403).json({ ok: false });
  ensureRoom(id);
  const list = getManifest(id);
  list.push({ stored: req.body.stored, cipher: req.body.cipher, uploadedAt: Date.now() });
  writeJson(manifestPath(id), list);
  res.json({ ok: true });
});

app.get('/r/:id/manifest', (req, res) => {
  res.json(getManifest(req.params.id));
});

app.get('/r/:id/download/:stored', (req, res) => {
  const { id, stored } = req.params;
  const deviceId = req.headers['x-device-id'] || 'unknown';
  if (isKicked(id, deviceId)) return res.status(403).end();
  const filePath = path.join(roomDir(id), stored + '.bin');
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath, (err) => {
    if (!err) {
      fs.unlink(filePath, () => {});
      const list = getManifest(id).filter(e => e.stored !== stored);
      writeJson(manifestPath(id), list);
    }
  });
});

// ---------- encrypted clipboard ----------
app.get('/r/:id/clipboard', (req, res) => {
  res.json(readJson(clipboardPath(req.params.id), { cipher: '' }));
});
app.post('/r/:id/clipboard', (req, res) => {
  const { id } = req.params;
  const deviceId = req.headers['x-device-id'] || 'unknown';
  if (isKicked(id, deviceId)) return res.status(403).json({ ok: false });
  ensureRoom(id);
  writeJson(clipboardPath(id), { cipher: req.body.cipher || '' });
  res.json({ ok: true });
});

// ================= PAGES =================
function pageShell(title, bodyHtml) {
  return `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title>
  <style>
    body{font-family:-apple-system,Arial,sans-serif;background:#012a4a;color:#eaf4ff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;}
    .box{background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.25);border-radius:18px;padding:28px;max-width:360px;width:100%;text-align:center;}
    input{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,0.3);background:rgba(255,255,255,0.08);color:#fff;font-size:15px;margin:10px 0;box-sizing:border-box;}
    button{width:100%;padding:12px;border:none;border-radius:10px;background:linear-gradient(135deg,#48cae4,#90e0ef);color:#012a4a;font-weight:700;font-size:15px;cursor:pointer;margin-top:6px;}
    .err{color:#ff8fa3;font-size:13px;min-height:16px;}
  </style></head><body>${bodyHtml}</body></html>`;
}

function renderPendingPage() {
  return pageShell('Waiting for approval', `
  <div class="box">
    <h2>⏳ Waiting for approval</h2>
    <p style="color:#a9c6de;font-size:14px;">The site owner needs to approve your device before you can use QuickShare. This page will continue automatically once approved.</p>
  </div>
  <script>
    async function poll(){
      const res = await fetch('/site-status');
      const data = await res.json();
      if (data.status === 'approved') location.reload();
      else if (data.status === 'blocked') location.reload();
      else setTimeout(poll, 3000);
    }
    poll();
  </script>`);
}

function renderBlockedPage() {
  return pageShell('Blocked', `<div class="box"><h2>🚫 Access blocked</h2><p style="color:#a9c6de;font-size:14px;">The site owner has blocked this device from using QuickShare.</p></div>`);
}

function renderAdminLogin() {
  return pageShell('Admin login', `
  <div class="box">
    <h2>🔑 Admin login</h2>
    <input id="password" type="password" placeholder="Admin password" autofocus />
    <div class="err" id="err"></div>
    <button id="go">Log in</button>
  </div>
  <script>
    async function submit(){
      const password = document.getElementById('password').value;
      const res = await fetch('/admin/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
      if (res.ok) location.reload(); else document.getElementById('err').textContent = 'Wrong password';
    }
    document.getElementById('go').onclick = submit;
    document.getElementById('password').addEventListener('keydown', e => { if (e.key==='Enter') submit(); });
  </script>`);
}

function renderAdminDashboard() {
  return `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Admin - QuickShare</title>
  <style>
    body{font-family:-apple-system,Arial,sans-serif;background:#012a4a;color:#eaf4ff;margin:0;padding:20px;}
    .wrap{max-width:640px;margin:0 auto;}
    .box{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.2);border-radius:16px;padding:18px;margin:14px 0;}
    h1{font-size:18px;} h2{font-size:15px;color:#90e0ef;margin-bottom:10px;}
    .row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.1);font-size:14px;gap:10px;}
    .row:last-child{border-bottom:none;}
    .meta{color:#a9c6de;font-size:12px;}
    button{border:none;border-radius:8px;padding:6px 12px;cursor:pointer;font-size:13px;font-weight:600;}
    .approve{background:#48cae4;color:#012a4a;} .block{background:#ef476f;color:#fff;} .unblock{background:#ffd166;color:#333;}
    input{padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.3);background:rgba(255,255,255,0.08);color:#fff;margin-right:6px;}
    .empty{color:#a9c6de;font-size:13px;}
  </style></head><body><div class="wrap">
  <h1>🛠️ QuickShare Admin</h1>

  <div class="box">
    <h2>⏳ Pending approval</h2>
    <div id="pending"><p class="empty">Loading...</p></div>
  </div>
  <div class="box">
    <h2>✅ Approved devices</h2>
    <div id="approved"><p class="empty">Loading...</p></div>
  </div>
  <div class="box">
    <h2>🚫 Blocked devices</h2>
    <div id="blocked"><p class="empty">Loading...</p></div>
  </div>
  <div class="box">
    <h2>Change admin password</h2>
    <input id="oldPw" type="password" placeholder="Current password" />
    <input id="newPw" type="password" placeholder="New password" />
    <button class="approve" id="changePw">Update</button>
    <div id="pwMsg" style="font-size:13px;margin-top:8px;"></div>
  </div>
  </div>
  <script>
    function fmt(t){ return t ? new Date(t).toLocaleTimeString() : '-'; }
    async function load(){
      const res = await fetch('/admin/devices');
      const devices = await res.json();
      const pending = devices.filter(d=>d.status==='pending');
      const approved = devices.filter(d=>d.status==='approved');
      const blocked = devices.filter(d=>d.status==='blocked');
      document.getElementById('pending').innerHTML = pending.length ? pending.map(d=>row(d,['approve','block'])).join('') : '<p class="empty">None</p>';
      document.getElementById('approved').innerHTML = approved.length ? approved.map(d=>row(d,['block'])).join('') : '<p class="empty">None</p>';
      document.getElementById('blocked').innerHTML = blocked.length ? blocked.map(d=>row(d,['unblock'])).join('') : '<p class="empty">None</p>';
    }
    function row(d, actions){
      const btns = actions.map(a => '<button class="'+a+'" onclick="act(\\''+a+'\\',\\''+d.deviceId+'\\')">'+a[0].toUpperCase()+a.slice(1)+'</button>').join(' ');
      return '<div class="row"><div>'+d.label+'<div class="meta">'+ (d.ip||'') +' · last seen '+fmt(d.lastSeen)+'</div></div><div>'+btns+'</div></div>';
    }
    window.act = async (action, deviceId) => {
      await fetch('/admin/'+action, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({deviceId})});
      load();
    };
    document.getElementById('changePw').onclick = async () => {
      const oldPassword = document.getElementById('oldPw').value, newPassword = document.getElementById('newPw').value;
      const res = await fetch('/admin/change-password', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldPassword,newPassword})});
      const data = await res.json();
      document.getElementById('pwMsg').textContent = data.ok ? '✅ Password updated' : ('❌ ' + (data.error||'Failed'));
    };
    load(); setInterval(load, 4000);
  </script></body></html>`;
}

function renderPinGate(id) {
  return pageShell('Enter PIN', `
  <div class="box">
    <h2>🔒 This room is locked</h2>
    <p style="color:#a9c6de;font-size:14px;">Enter the PIN to continue</p>
    <input id="pin" type="password" inputmode="numeric" maxlength="12" placeholder="••••" autofocus />
    <div class="err" id="err"></div>
    <button id="go">Enter</button>
  </div>
  <script>
    async function submit() {
      const pin = document.getElementById('pin').value;
      const res = await fetch(location.pathname + '/verify-pin', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});
      if (res.ok) { location.reload(); } else { document.getElementById('err').textContent = 'Wrong PIN, try again'; }
    }
    document.getElementById('go').onclick = submit;
    document.getElementById('pin').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  </script>`);
}

const OCEAN_SCRIPT = `
  // ===== Interactive coral reef background =====
  const oceanCanvas = document.getElementById('oceanCanvas');
  const octx = oceanCanvas.getContext('2d');
  let W = oceanCanvas.width = window.innerWidth;
  let H = oceanCanvas.height = window.innerHeight;
  let bgCanvas = document.createElement('canvas');
  let bgCtx = bgCanvas.getContext('2d');

  function drawBackground(){
    bgCanvas.width = W; bgCanvas.height = H;
    const grad = bgCtx.createLinearGradient(0,0,0,H);
    grad.addColorStop(0, '#0a6ea8');
    grad.addColorStop(0.55, '#0d5c96');
    grad.addColorStop(1, '#e8d9a8');
    bgCtx.fillStyle = grad; bgCtx.fillRect(0,0,W,H);

    bgCtx.save();
    bgCtx.globalAlpha = 0.10;
    for (let i=0;i<5;i++){
      const x = (i/5)*W + 40;
      bgCtx.beginPath();
      bgCtx.moveTo(x, 0); bgCtx.lineTo(x+120, 0);
      bgCtx.lineTo(x-60, H*0.7); bgCtx.lineTo(x-180, H*0.7);
      bgCtx.closePath(); bgCtx.fillStyle = '#ffffff'; bgCtx.fill();
    }
    bgCtx.restore();

    const sandTop = H*0.82;
    bgCtx.fillStyle = '#e8d9a8';
    bgCtx.beginPath(); bgCtx.moveTo(0, sandTop);
    for (let x=0;x<=W;x+=40) bgCtx.lineTo(x, sandTop + Math.sin(x*0.02)*8);
    bgCtx.lineTo(W,H); bgCtx.lineTo(0,H); bgCtx.closePath(); bgCtx.fill();

    function branchCoral(x,y,color,scale){
      bgCtx.strokeStyle = color; bgCtx.lineWidth = 4*scale; bgCtx.lineCap='round';
      function branch(x1,y1,angle,len,depth){
        if (depth<=0) return;
        const x2 = x1 + Math.cos(angle)*len, y2 = y1 + Math.sin(angle)*len;
        bgCtx.beginPath(); bgCtx.moveTo(x1,y1); bgCtx.lineTo(x2,y2); bgCtx.stroke();
        branch(x2,y2, angle - 0.4 - Math.random()*0.2, len*0.72, depth-1);
        branch(x2,y2, angle + 0.4 + Math.random()*0.2, len*0.72, depth-1);
      }
      branch(x,y,-Math.PI/2, 32*scale, 4);
    }
    function fanCoral(x,y,color,scale){
      bgCtx.fillStyle = color; bgCtx.globalAlpha = 0.85;
      bgCtx.beginPath();
      for (let a=-1.1;a<=1.1;a+=0.15){
        const r = 40*scale*(0.85+0.15*Math.sin(a*5));
        bgCtx.lineTo(x + Math.cos(a-Math.PI/2)*r, y + Math.sin(a-Math.PI/2)*r);
      }
      bgCtx.closePath(); bgCtx.fill(); bgCtx.globalAlpha = 1;
    }
    function brainCoral(x,y,color,scale){
      bgCtx.fillStyle = color;
      bgCtx.beginPath(); bgCtx.ellipse(x,y,30*scale,20*scale,0,0,Math.PI*2); bgCtx.fill();
    }
    function starfish(x,y,color,scale){
      bgCtx.fillStyle = color;
      bgCtx.beginPath();
      for (let i=0;i<10;i++){
        const ang = (Math.PI*2*i)/10 - Math.PI/2;
        const r = (i%2===0) ? 22*scale : 9*scale;
        const px = x + Math.cos(ang)*r, py = y + Math.sin(ang)*r*0.6;
        if (i===0) bgCtx.moveTo(px,py); else bgCtx.lineTo(px,py);
      }
      bgCtx.closePath(); bgCtx.fill();
    }

    const n = Math.max(3, Math.floor(W/260));
    for (let i=0;i<n;i++){
      const x = (i+0.5)/n * W + (Math.random()*60-30);
      const y = sandTop + 4;
      branchCoral(x-30, y, '#6a4c93', 0.9+Math.random()*0.4);
      fanCoral(x+40, y, i%2? '#e07a5f' : '#3a86ff', 0.8+Math.random()*0.4);
      brainCoral(x, y+2, '#52b788', 0.7+Math.random()*0.3);
      if (i%2===0) starfish(x-60, sandTop+18, '#ff7f50', 0.8);
      if (i%3===0) starfish(x+80, sandTop+22, '#ef476f', 0.7);
    }
  }
  drawBackground();
  window.addEventListener('resize', () => {
    W = oceanCanvas.width = window.innerWidth;
    H = oceanCanvas.height = window.innerHeight;
    drawBackground();
  });

  const oceanPalettes = [
    {body:'#ffd166', stripe:'#073b4c', fin:'#ef476f'},
    {body:'#4cc9f0', stripe:'#03045e', fin:'#ffd166'},
    {body:'#ff7f50', stripe:'#4a2c2a', fin:'#ffd166'},
    {body:'#90e0ef', stripe:'#0077b6', fin:'#f72585'},
    {body:'#b5e48c', stripe:'#1b4332', fin:'#ffb703'}
  ];
  const fishCount = Math.min(14, Math.max(8, Math.floor(W/110)));
  const fishes = [];
  for (let i=0;i<fishCount;i++){
    const depth = Math.random();
    fishes.push({
      x: Math.random()*W, y: H*0.15 + Math.random()*H*0.55,
      angle: Math.random()*Math.PI*2,
      speed: 0.4 + Math.random()*0.5 + depth*0.3,
      size: 14 + depth*16, depth,
      palette: oceanPalettes[i % oceanPalettes.length],
      wiggle: Math.random()*10, turnBias: (Math.random()-0.5)*0.02, startle: 0, fleeAngle: 0
    });
  }

  const oceanPointer = { x: -1000, y: -1000, active:false };
  oceanCanvas.addEventListener('mousemove', e => { oceanPointer.x=e.clientX; oceanPointer.y=e.clientY; oceanPointer.active=true; });
  oceanCanvas.addEventListener('mouseleave', () => oceanPointer.active=false);
  oceanCanvas.addEventListener('touchmove', e => { if (e.touches[0]) { oceanPointer.x=e.touches[0].clientX; oceanPointer.y=e.touches[0].clientY; oceanPointer.active=true; } }, {passive:true});

  const oceanParticles = [];
  function oceanTouch(x,y){
    oceanParticles.push({type:'ripple', x, y, r:4, alpha:0.6});
    for (let i=0;i<6;i++) oceanParticles.push({type:'bubble', x: x+(Math.random()*20-10), y, vy:-0.6-Math.random()*0.8, r:2+Math.random()*3, alpha:0.8});
    fishes.forEach(f => {
      const d = Math.hypot(f.x-x, f.y-y);
      if (d < 70) { f.startle = 60; f.fleeAngle = Math.atan2(f.y-y, f.x-x); }
    });
  }
  oceanCanvas.addEventListener('pointerdown', e => oceanTouch(e.clientX, e.clientY));

  function drawFish(f){
    octx.save();
    octx.translate(f.x, f.y);
    const facing = Math.cos(f.angle) < 0 ? -1 : 1;
    octx.scale(facing, 1);
    octx.globalAlpha = 0.55 + f.depth*0.45;
    const s = f.size;
    const wag = Math.sin(f.wiggle) * 0.5;
    octx.fillStyle = f.palette.fin;
    octx.beginPath();
    octx.moveTo(-s*0.9, 0);
    octx.lineTo(-s*1.5, -s*0.5 + wag*s*0.3);
    octx.lineTo(-s*1.5, s*0.5 + wag*s*0.3);
    octx.closePath(); octx.fill();
    octx.fillStyle = f.palette.body;
    octx.beginPath(); octx.ellipse(0,0, s, s*0.55, 0, 0, Math.PI*2); octx.fill();
    octx.strokeStyle = f.palette.stripe; octx.lineWidth = Math.max(1.5, s*0.12);
    octx.beginPath(); octx.moveTo(-s*0.1, -s*0.5); octx.lineTo(-s*0.1, s*0.5); octx.stroke();
    octx.fillStyle = f.palette.fin;
    octx.beginPath(); octx.moveTo(-s*0.1, -s*0.5); octx.lineTo(s*0.1, -s*0.95); octx.lineTo(s*0.35, -s*0.45); octx.closePath(); octx.fill();
    octx.fillStyle = '#fff'; octx.beginPath(); octx.arc(s*0.55, -s*0.08, s*0.14, 0, Math.PI*2); octx.fill();
    octx.fillStyle = '#111'; octx.beginPath(); octx.arc(s*0.58, -s*0.08, s*0.07, 0, Math.PI*2); octx.fill();
    octx.restore();
  }

  function oceanUpdate(){
    fishes.forEach(f => {
      f.wiggle += 0.25 + f.speed*0.1;
      let steer = f.turnBias, speedMul = 1;
      if (f.startle > 0) {
        f.startle--; f.angle = f.fleeAngle + (Math.random()-0.5)*0.3; speedMul = 2.4;
      } else if (oceanPointer.active) {
        const d = Math.hypot(f.x-oceanPointer.x, f.y-oceanPointer.y);
        if (d < 160 && d > 70) {
          const toP = Math.atan2(oceanPointer.y-f.y, oceanPointer.x-f.x);
          let diff = toP - f.angle; diff = Math.atan2(Math.sin(diff), Math.cos(diff));
          steer += diff * 0.02;
        } else if (d <= 70) {
          f.startle = 40; f.fleeAngle = Math.atan2(f.y-oceanPointer.y, f.x-oceanPointer.x);
        }
      }
      f.angle += steer + (Math.random()-0.5)*0.03;
      const spd = f.speed * speedMul;
      f.x += Math.cos(f.angle) * spd; f.y += Math.sin(f.angle) * spd;
      const margin = 40;
      if (f.x < margin) f.angle = 0;
      if (f.x > W-margin) f.angle = Math.PI;
      if (f.y < H*0.1) f.angle = Math.PI/2;
      if (f.y > H*0.78) f.angle = -Math.PI/2;
    });
    for (let i=oceanParticles.length-1;i>=0;i--){
      const p = oceanParticles[i];
      if (p.type==='ripple'){ p.r += 2.5; p.alpha -= 0.02; } else { p.y += p.vy; p.alpha -= 0.015; }
      if (p.alpha <= 0) oceanParticles.splice(i,1);
    }
  }
  function oceanRender(){
    octx.clearRect(0,0,W,H);
    octx.drawImage(bgCanvas, 0, 0);
    fishes.slice().sort((a,b)=>a.depth-b.depth).forEach(drawFish);
    oceanParticles.forEach(p => {
      octx.globalAlpha = Math.max(0,p.alpha);
      if (p.type==='ripple'){ octx.strokeStyle='#ffffff'; octx.lineWidth=2; octx.beginPath(); octx.arc(p.x,p.y,p.r,0,Math.PI*2); octx.stroke(); }
      else { octx.fillStyle='#ffffff'; octx.beginPath(); octx.arc(p.x,p.y,p.r,0,Math.PI*2); octx.fill(); }
      octx.globalAlpha = 1;
    });
  }
  function oceanLoop(){ oceanUpdate(); oceanRender(); requestAnimationFrame(oceanLoop); }
  oceanLoop();
`;

function renderPage({ id, expiresAt, isOwner, hasPin }) {
  return `<!DOCTYPE html>
<html>
<head>
<title>QuickShare</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
  :root {
    --bg1:#012a4a;--bg2:#01497c;--bg3:#013a63;--card-bg:rgba(255,255,255,0.10);--card-border:rgba(255,255,255,0.25);
    --text:#eaf4ff;--text-dim:#a9c6de;--accent:#48cae4;--accent2:#90e0ef;
  }
  body.light {
    --bg1:#b8e2f2;--bg2:#d6f0fb;--bg3:#eaf7fd;--card-bg:rgba(255,255,255,0.65);--card-border:rgba(1,73,124,0.15);
    --text:#013a63;--text-dim:#4c7690;--accent:#0077b6;--accent2:#0096c7;
  }
  * { box-sizing:border-box; }
  body { margin:0;font-family:-apple-system,'Segoe UI',Arial,sans-serif;color:var(--text);min-height:100vh;overflow-x:hidden;background:#013a63; }
  #ocean { position:fixed;inset:0;z-index:0; }
  #oceanCanvas { position:fixed;inset:0;width:100%;height:100%;z-index:0; }
  .wrap { position:relative;z-index:1;padding:16px;max-width:460px;margin:0 auto; }
  .topbar { display:flex;justify-content:space-between;align-items:center;padding:6px 0; }
  .toggle-btn,.link-btn { background:var(--card-bg);border:1px solid var(--card-border);color:var(--text);border-radius:999px;padding:8px 14px;cursor:pointer;font-size:13px;text-decoration:none; }
  .box { background:var(--card-bg);border:1px solid var(--card-border);backdrop-filter:blur(10px);border-radius:18px;padding:22px;margin:14px 0;box-shadow:0 8px 24px rgba(0,0,0,.15); }
  h1 { font-size:18px;margin:0 0 14px;display:flex;align-items:center;gap:8px; }
  .badge { display:inline-block;background:rgba(72,202,228,.2);color:var(--accent2);padding:4px 12px;border-radius:999px;font-size:12px;margin-bottom:10px; }
  #qrcode { display:flex;justify-content:center;margin:10px 0; }
  #qrcode img, #qrcode canvas { border-radius:10px;background:#fff;padding:8px; }
  .url { font-size:12px;color:var(--text-dim);word-break:break-all;text-align:center;margin-top:10px; }
  .timer { text-align:center;font-size:13px;color:var(--text-dim);margin-top:6px; }
  .warn { background:rgba(255,193,7,.15);border:1px solid rgba(255,193,7,.4);color:#ffd166;padding:10px;border-radius:10px;font-size:13px;margin-bottom:10px; }
  .dropzone { border:2px dashed var(--card-border);border-radius:14px;padding:28px 16px;text-align:center;color:var(--text-dim);cursor:pointer;font-size:14px; }
  .dropzone.drag { border-color:var(--accent);background:rgba(72,202,228,.08); }
  .btn { background:linear-gradient(135deg,var(--accent),var(--accent2));color:#012a4a;border:none;padding:12px 20px;border-radius:12px;cursor:pointer;font-size:15px;font-weight:600;width:100%;margin-top:10px; }
  .btn.secondary { background:var(--card-bg);color:var(--text);border:1px solid var(--card-border); }
  ul { list-style:none;padding:0;margin:0; }
  li { display:flex;align-items:center;gap:10px;padding:10px 4px;border-bottom:1px solid var(--card-border); }
  li:last-child { border-bottom:none; }
  .icon { font-size:24px;width:38px;text-align:center;flex-shrink:0; }
  .fname { flex:1;word-break:break-all;font-size:14px; }
  button.dl { color:var(--accent2);font-weight:600;text-decoration:none;font-size:14px;white-space:nowrap;background:none;border:none;cursor:pointer;font-family:inherit; }
  textarea { width:100%;min-height:100px;border-radius:12px;border:1px solid var(--card-border);background:rgba(255,255,255,.08);color:var(--text);padding:12px;font-size:14px;resize:vertical; }
  input[type=password] { width:100%;padding:10px;border-radius:10px;border:1px solid var(--card-border);background:rgba(255,255,255,.08);color:var(--text);font-size:14px; }
  .row { display:flex;gap:10px; }
  .row .btn { margin-top:0; }
  .empty { color:var(--text-dim);font-size:14px;text-align:center;padding:6px 0; }
  .devrow { display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--card-border);font-size:14px; }
  .devrow:last-child { border-bottom:none; }
</style>
</head>
<body>
<canvas id="oceanCanvas"></canvas>
<div class="wrap">
  <div class="topbar">
    <a class="link-btn" href="/">🔄 New room</a>
    <button class="toggle-btn" id="themeToggle">🌙 Dark</button>
  </div>

  <div class="box" id="keyWarningBox" style="display:none;">
    <div class="warn">⚠️ This link is missing its encryption key, so files here can't be decrypted on this device. Ask the room owner to re-share the QR code or full link.</div>
  </div>

  <div class="box">
    <div class="badge">Room ${id} ${hasPin ? '· 🔒 PIN protected' : ''}</div>
    <h1>📱 Scan to join this room</h1>
    <div id="qrcode"></div>
    <p class="url" id="shareUrl"></p>
    <div class="timer" id="timer">Expires in --:--:--</div>
    <p style="font-size:12px;color:var(--text-dim);text-align:center;">🔐 End-to-end encrypted — the server never sees your files' content or names.</p>
  </div>

  ${isOwner ? `
  <div class="box">
    <h1>🛠️ Room settings (owner)</h1>
    <p style="font-size:13px;color:var(--text-dim);margin-top:-8px;">Set a PIN so only people who know it can open this room, even with the link.</p>
    <input type="password" id="pinInput" placeholder="Set PIN (leave empty to remove)" maxlength="12" />
    <button class="btn" id="savePin">Save PIN</button>
    <h1 style="margin-top:20px;">👥 Connected devices</h1>
    <div id="deviceList"><p class="empty">No devices yet</p></div>
  </div>` : ''}

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
    <div class="dropzone" id="dropzone">
      📥 Drag & drop files here, or click to browse
      <input type="file" id="fileInput" multiple hidden />
    </div>
    <p id="uploadStatus" style="font-size:12px;color:var(--text-dim);text-align:center;margin-top:8px;"></p>
  </div>

  <div class="box">
    <h1>⬇️ Files in this room</h1>
    <ul id="filelist"><li class="empty">Loading...</li></ul>
  </div>
</div>

<script>
${OCEAN_SCRIPT}

  // ---- Theme ----
  const themeBtn = document.getElementById('themeToggle');
  function applyTheme(light){document.body.classList.toggle('light',light);themeBtn.textContent=light?'☀️ Light':'🌙 Dark';}
  applyTheme(localStorage.getItem('quickshare-theme')==='light');
  themeBtn.onclick=()=>{const l=!document.body.classList.contains('light');applyTheme(l);localStorage.setItem('quickshare-theme',l?'light':'dark');};

  // ---- Device ID ----
  let deviceId = sessionStorage.getItem('qs-device-id');
  if (!deviceId) { deviceId = crypto.randomUUID(); sessionStorage.setItem('qs-device-id', deviceId); }
  const roomId = '${id}';

  // ---- E2EE key: lives ONLY in the URL fragment, never sent to the server ----
  function b64urlFromBytes(bytes){return btoa(String.fromCharCode(...bytes)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
  function bytesFromB64url(str){str=str.replace(/-/g,'+').replace(/_/g,'/');while(str.length%4)str+='=';return Uint8Array.from(atob(str),c=>c.charCodeAt(0));}
  function toB64(bytes){return btoa(String.fromCharCode(...bytes));}
  function fromB64(str){return Uint8Array.from(atob(str),c=>c.charCodeAt(0));}

  let cryptoKey = null;
  async function initKey(){
    const params = new URLSearchParams(location.hash.slice(1));
    let k = params.get('k');
    if (!k) {
      const key = await crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
      k = b64urlFromBytes(raw);
      history.replaceState(null, '', location.pathname + '#k=' + k);
    }
    try {
      cryptoKey = await crypto.subtle.importKey('raw', bytesFromB64url(k), 'AES-GCM', false, ['encrypt','decrypt']);
    } catch(e) {
      document.getElementById('keyWarningBox').style.display = 'block';
    }
    renderQR();
  }
  function renderQR(){
    document.getElementById('shareUrl').textContent = location.href;
    new QRCode(document.getElementById('qrcode'), { text: location.href, width: 220, height: 220 });
  }
  async function encryptBytes(bytes){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, cryptoKey, bytes));
    const out = new Uint8Array(12 + ct.length); out.set(iv,0); out.set(ct,12); return out;
  }
  async function decryptBytes(combined){
    const iv = combined.slice(0,12), data = combined.slice(12);
    return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv}, cryptoKey, data));
  }

  // ---- Expiry countdown ----
  const expiresAt = ${expiresAt};
  function tick(){
    const remaining = expiresAt - Date.now();
    const el = document.getElementById('timer');
    if (remaining<=0){el.textContent='Room expired — refreshing...';setTimeout(()=>location.href='/',1200);return;}
    const h=Math.floor(remaining/3600000),m=Math.floor((remaining%3600000)/60000),s=Math.floor((remaining%60000)/1000);
    el.textContent='Expires in '+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
  }
  tick(); setInterval(tick,1000);

  // ---- Presence heartbeat ----
  async function heartbeat(){
    try {
      const res = await fetch('/r/'+roomId+'/presence', {method:'POST',headers:{'Content-Type':'application/json','X-Device-Id':deviceId},body:'{}'});
      const data = await res.json();
      if (data.kicked) {
        document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;color:#fff;background:#012a4a;font-family:sans-serif;text-align:center;padding:20px;"><div>🚫 You were removed from this room by the owner.</div></div>';
        clearInterval(hbInterval); clearInterval(fileInterval); clearInterval(clipInterval);
      }
    } catch(e){}
  }
  const hbInterval = setInterval(heartbeat, 5000); heartbeat();

  // ---- Owner panel ----
  ${isOwner ? `
  document.getElementById('savePin').onclick = async () => {
    const pin = document.getElementById('pinInput').value;
    await fetch('/r/'+roomId+'/owner/set-pin', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});
    const btn = document.getElementById('savePin'); const old = btn.textContent; btn.textContent='✅ Saved'; setTimeout(()=>btn.textContent=old,1200);
  };
  async function refreshDevices(){
    const res = await fetch('/r/'+roomId+'/devices');
    const devices = await res.json();
    const el = document.getElementById('deviceList');
    if (!devices.length){el.innerHTML='<p class="empty">No devices yet</p>';return;}
    el.innerHTML = devices.map(d=>'<div class="devrow"><span>'+d.label+'</span><button class="dl" onclick="kickDevice(\\''+d.deviceId+'\\')">Remove</button></div>').join('');
  }
  window.kickDevice = async (id) => { await fetch('/r/'+roomId+'/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({deviceId:id})}); refreshDevices(); };
  refreshDevices(); setInterval(refreshDevices, 4000);
  ` : ''}

  // ---- File list ----
  const manifestCache = {};
  const ICONS = {'.pdf':'📄','.doc':'📝','.docx':'📝','.txt':'📄','.zip':'🗜️','.rar':'🗜️','.xls':'📊','.xlsx':'📊','.csv':'📊','.ppt':'📽️','.pptx':'📽️','.mp3':'🎵','.wav':'🎵','.mp4':'🎬','.mov':'🎬','.apk':'📱'};
  function extOf(name){const i=name.lastIndexOf('.');return i>=0?name.slice(i).toLowerCase():'';}
  let fileInterval;
  async function refreshFiles(){
    if (!cryptoKey) return;
    const res = await fetch('/r/'+roomId+'/manifest');
    const entries = await res.json();
    const list = document.getElementById('filelist');
    if (!entries.length){list.innerHTML='<li class="empty">No files yet</li>';return;}
    const items = [];
    for (const e of entries) {
      let meta = manifestCache[e.stored];
      if (!meta) {
        try {
          const plain = await decryptBytes(fromB64(e.cipher));
          meta = JSON.parse(new TextDecoder().decode(plain));
          manifestCache[e.stored] = meta;
        } catch { continue; }
      }
      items.push({ stored: e.stored, ...meta });
    }
    list.innerHTML = items.map(f => {
      const icon = (f.type||'').startsWith('image/') ? '🖼️' : (ICONS[extOf(f.name)] || '📁');
      return '<li><div class="icon">'+icon+'</div><span class="fname">'+f.name+'</span><button class="dl" onclick="downloadFile(\\''+f.stored+'\\')">Download</button></li>';
    }).join('');
  }
  window.downloadFile = async (stored) => {
    const res = await fetch('/r/'+roomId+'/download/'+stored, {headers:{'X-Device-Id':deviceId}});
    if (!res.ok) { alert('File no longer available (already downloaded or expired).'); refreshFiles(); return; }
    const buf = new Uint8Array(await res.arrayBuffer());
    const plain = await decryptBytes(buf);
    const meta = manifestCache[stored] || {name:'file', type:'application/octet-stream'};
    const blob = new Blob([plain], {type: meta.type});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download=meta.name; document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    refreshFiles();
  };

  // ---- Upload ----
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const uploadStatus = document.getElementById('uploadStatus');
  dropzone.onclick = () => fileInput.click();
  fileInput.onchange = () => handleFiles(fileInput.files);
  ['dragenter','dragover'].forEach(ev=>dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.add('drag');}));
  ['dragleave','drop'].forEach(ev=>dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.remove('drag');}));
  dropzone.addEventListener('drop', e => { if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files); });
  async function handleFiles(files){
    if (!cryptoKey) { alert('Encryption key missing — cannot upload securely on this device.'); return; }
    for (const file of files) {
      uploadStatus.textContent = 'Encrypting & sending ' + file.name + '...';
      const buf = new Uint8Array(await file.arrayBuffer());
      const enc = await encryptBytes(buf);
      const stored = crypto.randomUUID();
      await fetch('/r/'+roomId+'/upload/'+stored, {method:'POST',headers:{'Content-Type':'application/octet-stream','X-Device-Id':deviceId},body:enc});
      const metaBytes = new TextEncoder().encode(JSON.stringify({name:file.name,type:file.type||'application/octet-stream',size:file.size}));
      const metaEnc = await encryptBytes(metaBytes);
      await fetch('/r/'+roomId+'/manifest', {method:'POST',headers:{'Content-Type':'application/json','X-Device-Id':deviceId},body:JSON.stringify({stored,cipher:toB64(metaEnc)})});
    }
    uploadStatus.textContent = 'Done ✅';
    setTimeout(()=>uploadStatus.textContent='',2000);
    refreshFiles();
  }

  // ---- Clipboard ----
  const clip = document.getElementById('clip');
  let clipFocused = false;
  clip.addEventListener('focus', ()=>clipFocused=true);
  clip.addEventListener('blur', ()=>clipFocused=false);
  let clipInterval;
  async function refreshClipboard(){
    if (clipFocused || !cryptoKey) return;
    const res = await fetch('/r/'+roomId+'/clipboard');
    const data = await res.json();
    if (!data.cipher) { return; }
    try { const plain = await decryptBytes(fromB64(data.cipher)); clip.value = new TextDecoder().decode(plain); } catch(e){}
  }
  document.getElementById('saveClip').onclick = async () => {
    if (!cryptoKey) { alert('Encryption key missing.'); return; }
    const enc = await encryptBytes(new TextEncoder().encode(clip.value));
    await fetch('/r/'+roomId+'/clipboard', {method:'POST',headers:{'Content-Type':'application/json','X-Device-Id':deviceId},body:JSON.stringify({cipher:toB64(enc)})});
    const btn=document.getElementById('saveClip'); const old=btn.textContent; btn.textContent='✅ Saved'; setTimeout(()=>btn.textContent=old,1200);
  };
  document.getElementById('copyClip').onclick = async () => {
    try { await navigator.clipboard.writeText(clip.value); const btn=document.getElementById('copyClip'); const old=btn.textContent; btn.textContent='✅ Copied'; setTimeout(()=>btn.textContent=old,1200); }
    catch { alert('Could not copy — select the text manually.'); }
  };

  // ---- Boot ----
  initKey().then(() => {
    refreshFiles(); fileInterval = setInterval(refreshFiles, 3000);
    refreshClipboard(); clipInterval = setInterval(refreshClipboard, 3000);
  });
</script>
</body>
</html>`;
}

app.listen(PORT, () => console.log(`QuickShare (secure) running on port ${PORT}`));
