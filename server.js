const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, 'data.json');

// The full list of permission keys the owner can grant to any account.
const PERMISSION_KEYS = [
  'positionsManage',   // create / edit / delete job positions
  'candidatesView',    // view & search the candidate bank
  'candidatesAdd',     // add new candidates
  'candidatesManage',  // edit / delete candidates
  'clientsView',       // view the client list (needed to pick a client in a placement)
  'clientsManage',     // create / edit / delete clients
  'placementsView',    // view placements
  'placementsAdd',     // register a new placement
  'placementsManage',  // edit / delete placements
  'usersManage'        // create / delete staff accounts and set their permissions
];

function emptyPermissions() {
  const p = {};
  PERMISSION_KEYS.forEach(k => { p[k] = false; });
  return p;
}
function defaultStaffPermissions() {
  // sensible default for a newly created account: can search/add candidates and register placements
  return Object.assign(emptyPermissions(), {
    candidatesView: true,
    candidatesAdd: true,
    placementsView: true,
    placementsAdd: true,
    clientsView: true
  });
}
function fullPermissions() {
  const p = {};
  PERMISSION_KEYS.forEach(k => { p[k] = true; });
  return p;
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    return { users: [], positions: [], candidates: [], clients: [], placements: [] };
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let data = loadData();

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

async function seedOwner() {
  if (data.users.length === 0) {
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
    const passwordHash = await bcrypt.hash(password, 10);
    data.users.push({
      id: uid(), username, passwordHash, name: 'المالك',
      isOwner: true, permissions: fullPermissions()
    });
    saveData();
    console.log('---------------------------------------------');
    console.log('تم إنشاء الحساب الرئيسي (المالك):');
    console.log('اسم المستخدم:', username);
    if (!process.env.ADMIN_PASSWORD) console.log('كلمة المرور:', password, '(غيّرها فورًا)');
    console.log('هذا الحساب هو الوحيد الذي يحدد صلاحيات باقي الحسابات.');
    console.log('---------------------------------------------');
  }
}
seedOwner();

const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'please-change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, 'public')));

function currentUser(req) {
  return data.users.find(u => u.id === req.session.userId);
}
function requireAuth(req, res, next) {
  if (!req.session.userId || !currentUser(req)) return res.status(401).json({ error: 'يجب تسجيل الدخول' });
  next();
}
// The owner account always has every permission, regardless of what is stored.
function hasPermission(user, key) {
  return !!user && (user.isOwner || (user.permissions && user.permissions[key]));
}
function requirePermission(key) {
  return function (req, res, next) {
    const u = currentUser(req);
    if (!hasPermission(u, key)) return res.status(403).json({ error: 'صلاحيات غير كافية' });
    next();
  };
}
function publicUser(u) {
  return { id: u.id, username: u.username, name: u.name, isOwner: !!u.isOwner, permissions: u.isOwner ? fullPermissions() : u.permissions };
}

// ---------- AUTH ----------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = data.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  req.session.userId = user.id;
  res.json(publicUser(user));
});
app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/me', requireAuth, (req, res) => res.json(publicUser(currentUser(req))));
app.get('/api/permission-keys', requireAuth, (req, res) => res.json(PERMISSION_KEYS));

// ---------- USERS (only the owner, or anyone explicitly granted usersManage) ----------
app.get('/api/users', requireAuth, requirePermission('usersManage'), (req, res) => {
  res.json(data.users.map(publicUser));
});
app.post('/api/users', requireAuth, requirePermission('usersManage'), async (req, res) => {
  const { username, password, name, permissions } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبين' });
  if (data.users.find(u => u.username === username)) return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
  const passwordHash = await bcrypt.hash(password, 10);
  const perms = Object.assign(defaultStaffPermissions(), permissions || {});
  // strip unknown keys and coerce to booleans
  const cleanPerms = emptyPermissions();
  PERMISSION_KEYS.forEach(k => { cleanPerms[k] = !!perms[k]; });
  const u = { id: uid(), username, passwordHash, name: name || username, isOwner: false, permissions: cleanPerms };
  data.users.push(u);
  saveData();
  res.json(publicUser(u));
});
app.put('/api/users/:id/permissions', requireAuth, requirePermission('usersManage'), (req, res) => {
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'غير موجود' });
  if (u.isOwner) return res.status(400).json({ error: 'لا يمكن تعديل صلاحيات الحساب الرئيسي' });
  const perms = req.body.permissions || {};
  PERMISSION_KEYS.forEach(k => { u.permissions[k] = !!perms[k]; });
  saveData();
  res.json(publicUser(u));
});
app.delete('/api/users/:id', requireAuth, requirePermission('usersManage'), (req, res) => {
  const target = data.users.find(u => u.id === req.params.id);
  if (target && target.isOwner) return res.status(400).json({ error: 'لا يمكن حذف الحساب الرئيسي' });
  if (req.params.id === currentUser(req).id) return res.status(400).json({ error: 'لا يمكنك حذف حسابك الحالي' });
  data.users = data.users.filter(u => u.id !== req.params.id);
  saveData();
  res.json({ ok: true });
});

// ---------- POSITIONS ----------
app.get('/api/positions', requireAuth, (req, res) => res.json(data.positions));
app.post('/api/positions', requireAuth, requirePermission('positionsManage'), (req, res) => {
  const p = { id: uid(), title: req.body.title || '', category: req.body.category || '', notes: req.body.notes || '' };
  data.positions.push(p); saveData(); res.json(p);
});
app.put('/api/positions/:id', requireAuth, requirePermission('positionsManage'), (req, res) => {
  const p = data.positions.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(p, req.body); saveData(); res.json(p);
});
app.delete('/api/positions/:id', requireAuth, requirePermission('positionsManage'), (req, res) => {
  data.positions = data.positions.filter(x => x.id !== req.params.id);
  data.candidates.forEach(c => { if (c.positionId === req.params.id) c.positionId = ''; });
  saveData(); res.json({ ok: true });
});

// ---------- CANDIDATES ----------
app.get('/api/candidates', requireAuth, requirePermission('candidatesView'), (req, res) => {
  let list = data.candidates;
  if (req.query.positionId) list = list.filter(c => c.positionId === req.query.positionId);
  res.json(list);
});
app.post('/api/candidates', requireAuth, requirePermission('candidatesAdd'), (req, res) => {
  const c = {
    id: uid(),
    name: req.body.name || '',
    phone: req.body.phone || '',
    positionId: req.body.positionId || '',
    skills: req.body.skills || '',
    status: req.body.status || 'new',
    notes: req.body.notes || '',
    addedBy: currentUser(req).username
  };
  data.candidates.push(c); saveData(); res.json(c);
});
app.put('/api/candidates/:id', requireAuth, requirePermission('candidatesManage'), (req, res) => {
  const c = data.candidates.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(c, req.body); saveData(); res.json(c);
});
app.delete('/api/candidates/:id', requireAuth, requirePermission('candidatesManage'), (req, res) => {
  data.candidates = data.candidates.filter(x => x.id !== req.params.id);
  saveData(); res.json({ ok: true });
});

// ---------- CLIENTS ----------
app.get('/api/clients', requireAuth, requirePermission('clientsView'), (req, res) => res.json(data.clients));
app.post('/api/clients', requireAuth, requirePermission('clientsManage'), (req, res) => {
  const c = { id: uid(), name: req.body.name || '', contact: req.body.contact || '', phone: req.body.phone || '', status: req.body.status || 'lead', notes: req.body.notes || '' };
  data.clients.push(c); saveData(); res.json(c);
});
app.put('/api/clients/:id', requireAuth, requirePermission('clientsManage'), (req, res) => {
  const c = data.clients.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(c, req.body); saveData(); res.json(c);
});
app.delete('/api/clients/:id', requireAuth, requirePermission('clientsManage'), (req, res) => {
  data.clients = data.clients.filter(x => x.id !== req.params.id);
  saveData(); res.json({ ok: true });
});

// ---------- PLACEMENTS ----------
app.get('/api/placements', requireAuth, requirePermission('placementsView'), (req, res) => res.json(data.placements));
app.post('/api/placements', requireAuth, requirePermission('placementsAdd'), (req, res) => {
  const p = {
    id: uid(),
    candidateId: req.body.candidateId,
    clientId: req.body.clientId,
    positionId: req.body.positionId || '',
    salary: Number(req.body.salary) || 0,
    commission: Number(req.body.commission) || 0,
    status: req.body.status || 'pending',
    addedBy: currentUser(req).username
  };
  data.placements.push(p); saveData(); res.json(p);
});
app.put('/api/placements/:id', requireAuth, requirePermission('placementsManage'), (req, res) => {
  const p = data.placements.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(p, req.body); saveData(); res.json(p);
});
app.delete('/api/placements/:id', requireAuth, requirePermission('placementsManage'), (req, res) => {
  data.placements = data.placements.filter(x => x.id !== req.params.id);
  saveData(); res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Prime Connect system running on port ' + PORT));
