const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

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
  'requestsView',      // view client hiring requests
  'requestsManage',    // create / edit / delete client hiring requests
  'submissionsView',   // view candidates submitted to client requests (interview / result / salary)
  'submissionsAdd',    // submit a candidate to a client request
  'submissionsManage', // edit / delete submissions (interview status, result, salary)
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
    clientsView: true,
    requestsView: true,
    submissionsView: true,
    submissionsAdd: true
  });
}
function fullPermissions() {
  const p = {};
  PERMISSION_KEYS.forEach(k => { p[k] = true; });
  return p;
}

// ---------- STORAGE ----------
// With DATABASE_URL set (Postgres, e.g. Neon or Render Postgres) all data lives in one JSONB row,
// so it survives restarts and redeploys. Without it, data goes to data.json (fine for local testing only:
// on Render the disk is wiped on every deploy/restart).
const COLLECTIONS = ['users', 'positions', 'candidates', 'clients', 'placements', 'requests', 'submissions'];
function normalize(d) {
  d = d && typeof d === 'object' ? d : {};
  COLLECTIONS.forEach(k => { if (!Array.isArray(d[k])) d[k] = []; });
  return d;
}
function loadFile() {
  if (!fs.existsSync(DATA_FILE)) return normalize({});
  return normalize(JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
}

let data = normalize({});
let pool = null;
let writing = Promise.resolve();
let dirty = false;

async function initStore() {
  if (!process.env.DATABASE_URL) {
    data = loadFile();
    console.log('Storage: data.json (set DATABASE_URL to use Postgres)');
    return;
  }
  pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  await pool.query('CREATE TABLE IF NOT EXISTS app_data (id INT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())');
  const r = await pool.query('SELECT data FROM app_data WHERE id = 1');
  if (r.rows[0]) {
    data = normalize(r.rows[0].data);
  } else {
    // first run on Postgres: carry over a local data.json if one exists
    data = loadFile();
    await pool.query('INSERT INTO app_data (id, data) VALUES (1, $1)', [JSON.stringify(data)]);
  }
  console.log('Storage: Postgres');
}

// Writes are queued so they never overlap; a burst of changes is written once.
function saveData() {
  if (!pool) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    return Promise.resolve();
  }
  dirty = true;
  writing = writing.then(async () => {
    if (!dirty) return;
    dirty = false;
    try {
      await pool.query('UPDATE app_data SET data = $1, updated_at = now() WHERE id = 1', [JSON.stringify(data)]);
    } catch (e) {
      dirty = true;
      console.error('Failed to save data:', e.message);
    }
  });
  return writing;
}

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
    await saveData();
    console.log('---------------------------------------------');
    console.log('تم إنشاء الحساب الرئيسي (المالك):');
    console.log('اسم المستخدم:', username);
    if (!process.env.ADMIN_PASSWORD) console.log('كلمة المرور:', password, '(غيّرها فورًا)');
    console.log('هذا الحساب هو الوحيد الذي يحدد صلاحيات باقي الحسابات.');
    console.log('---------------------------------------------');
  }
}

const IS_PROD = process.env.NODE_ENV === 'production';
if (IS_PROD && !process.env.SESSION_SECRET) console.warn('WARNING: SESSION_SECRET is not set — set it in Render environment variables.');

const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy; needed for secure cookies
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'please-change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, sameSite: 'lax', httpOnly: true, secure: IS_PROD }
}));
app.get('/healthz', (req, res) => res.json({ ok: true }));
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
  const perms = u.isOwner ? fullPermissions() : Object.assign(emptyPermissions(), u.permissions || {});
  return { id: u.id, username: u.username, name: u.name, isOwner: !!u.isOwner, permissions: perms };
}

// ---------- AUTH ----------
// basic brute-force protection: 10 failed attempts per IP+username lock it for 15 minutes
const failedLogins = new Map();
function loginKey(req, username) { return (req.ip || '') + '|' + String(username || '').toLowerCase(); }
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const key = loginKey(req, username);
  const f = failedLogins.get(key);
  if (f && f.count >= 10 && Date.now() - f.last < 15 * 60 * 1000) return res.status(429).json({ error: 'محاولات كتير غلط، جرّب بعد ربع ساعة' });
  const fail = () => { const x = failedLogins.get(key) || { count: 0, last: 0 }; x.count = (Date.now() - x.last > 15 * 60 * 1000) ? 1 : x.count + 1; x.last = Date.now(); failedLogins.set(key, x); };
  const user = data.users.find(u => u.username === username);
  if (!user) { fail(); return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' }); }
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  if (!ok) { fail(); return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' }); }
  failedLogins.delete(key);
  req.session.userId = user.id;
  res.json(publicUser(user));
});
app.post('/api/logout', async (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/me', requireAuth, (req, res) => res.json(publicUser(currentUser(req))));
// change your own password
app.put('/api/me/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const u = currentUser(req);
  if (!newPassword || String(newPassword).length < 6) return res.status(400).json({ error: 'كلمة المرور الجديدة لازم تكون 6 حروف على الأقل' });
  if (!(await bcrypt.compare(currentPassword || '', u.passwordHash))) return res.status(400).json({ error: 'كلمة المرور الحالية غلط' });
  u.passwordHash = await bcrypt.hash(String(newPassword), 10);
  await saveData();
  res.json({ ok: true });
});
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
  await saveData();
  res.json(publicUser(u));
});
app.put('/api/users/:id/permissions', requireAuth, requirePermission('usersManage'), async (req, res) => {
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'غير موجود' });
  if (u.isOwner) return res.status(400).json({ error: 'لا يمكن تعديل صلاحيات الحساب الرئيسي' });
  const perms = req.body.permissions || {};
  u.permissions = u.permissions || {};
  PERMISSION_KEYS.forEach(k => { u.permissions[k] = !!perms[k]; });
  await saveData();
  res.json(publicUser(u));
});
// set a new password for a staff account (the owner's password is changed only by the owner)
app.put('/api/users/:id/password', requireAuth, requirePermission('usersManage'), async (req, res) => {
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'غير موجود' });
  if (u.isOwner) return res.status(400).json({ error: 'كلمة مرور الحساب الرئيسي يغيّرها المالك بنفسه' });
  const pw = String((req.body || {}).password || '');
  if (pw.length < 6) return res.status(400).json({ error: 'كلمة المرور لازم تكون 6 حروف على الأقل' });
  u.passwordHash = await bcrypt.hash(pw, 10);
  await saveData();
  res.json({ ok: true });
});
app.delete('/api/users/:id', requireAuth, requirePermission('usersManage'), async (req, res) => {
  const target = data.users.find(u => u.id === req.params.id);
  if (target && target.isOwner) return res.status(400).json({ error: 'لا يمكن حذف الحساب الرئيسي' });
  if (req.params.id === currentUser(req).id) return res.status(400).json({ error: 'لا يمكنك حذف حسابك الحالي' });
  data.users = data.users.filter(u => u.id !== req.params.id);
  await saveData();
  res.json({ ok: true });
});

// ---------- POSITIONS ----------
app.get('/api/positions', requireAuth, (req, res) => res.json(data.positions));
app.post('/api/positions', requireAuth, requirePermission('positionsManage'), async (req, res) => {
  const p = { id: uid(), title: req.body.title || '', category: req.body.category || '', notes: req.body.notes || '' };
  data.positions.push(p); await saveData(); res.json(p);
});
app.put('/api/positions/:id', requireAuth, requirePermission('positionsManage'), async (req, res) => {
  const p = data.positions.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'غير موجود' });
  const { id: _i, addedBy: _a, ...b } = req.body || {}; Object.assign(p, b); await saveData(); res.json(p);
});
app.delete('/api/positions/:id', requireAuth, requirePermission('positionsManage'), async (req, res) => {
  data.positions = data.positions.filter(x => x.id !== req.params.id);
  data.candidates.forEach(c => { if (c.positionId === req.params.id) c.positionId = ''; });
  await saveData(); res.json({ ok: true });
});

// ---------- CANDIDATES ----------
app.get('/api/candidates', requireAuth, requirePermission('candidatesView'), (req, res) => {
  let list = data.candidates;
  if (req.query.positionId) list = list.filter(c => c.positionId === req.query.positionId);
  res.json(list);
});
app.post('/api/candidates', requireAuth, requirePermission('candidatesAdd'), async (req, res) => {
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
  data.candidates.push(c); await saveData(); res.json(c);
});
app.put('/api/candidates/:id', requireAuth, requirePermission('candidatesManage'), async (req, res) => {
  const c = data.candidates.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'غير موجود' });
  const { id: _i, addedBy: _a, ...b } = req.body || {}; Object.assign(c, b); await saveData(); res.json(c);
});
app.delete('/api/candidates/:id', requireAuth, requirePermission('candidatesManage'), async (req, res) => {
  data.candidates = data.candidates.filter(x => x.id !== req.params.id);
  data.submissions = data.submissions.filter(x => x.candidateId !== req.params.id);
  await saveData(); res.json({ ok: true });
});

// ---------- CLIENTS ----------
app.get('/api/clients', requireAuth, requirePermission('clientsView'), (req, res) => res.json(data.clients));
app.post('/api/clients', requireAuth, requirePermission('clientsManage'), async (req, res) => {
  const c = { id: uid(), name: req.body.name || '', contact: req.body.contact || '', phone: req.body.phone || '', status: req.body.status || 'lead', notes: req.body.notes || '' };
  data.clients.push(c); await saveData(); res.json(c);
});
app.put('/api/clients/:id', requireAuth, requirePermission('clientsManage'), async (req, res) => {
  const c = data.clients.find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'غير موجود' });
  const { id: _i, addedBy: _a, ...b } = req.body || {}; Object.assign(c, b); await saveData(); res.json(c);
});
app.delete('/api/clients/:id', requireAuth, requirePermission('clientsManage'), async (req, res) => {
  data.clients = data.clients.filter(x => x.id !== req.params.id);
  data.requests = data.requests.filter(x => x.clientId !== req.params.id);
  data.submissions = data.submissions.filter(x => x.clientId !== req.params.id);
  await saveData(); res.json({ ok: true });
});

// ---------- PLACEMENTS ----------
app.get('/api/placements', requireAuth, requirePermission('placementsView'), (req, res) => res.json(data.placements));
app.post('/api/placements', requireAuth, requirePermission('placementsAdd'), async (req, res) => {
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
  data.placements.push(p); await saveData(); res.json(p);
});
app.put('/api/placements/:id', requireAuth, requirePermission('placementsManage'), async (req, res) => {
  const p = data.placements.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'غير موجود' });
  const { id: _i, addedBy: _a, ...b } = req.body || {}; Object.assign(p, b); await saveData(); res.json(p);
});
app.delete('/api/placements/:id', requireAuth, requirePermission('placementsManage'), async (req, res) => {
  data.placements = data.placements.filter(x => x.id !== req.params.id);
  await saveData(); res.json({ ok: true });
});

// ---------- CLIENT HIRING REQUESTS (طلبات التوظيف) ----------
const REQUEST_STATUSES = ['open', 'filled', 'paused'];
const INTERVIEW_STATUSES = ['none', 'scheduled', 'done'];
const RESULT_STATUSES = ['pending', 'accepted', 'rejected', 'started'];
function pick(v, allowed, fallback) { return allowed.includes(v) ? v : fallback; }
function str(v) { return v == null ? '' : String(v).trim(); }
function num(v) { return v === '' || v == null || isNaN(Number(v)) ? '' : Number(v); }

function cleanRequest(body, existing) {
  const b = body || {}, e = existing || {};
  const has = k => Object.prototype.hasOwnProperty.call(b, k);
  return {
    clientId: has('clientId') ? str(b.clientId) : (e.clientId || ''),
    positionId: has('positionId') ? str(b.positionId) : (e.positionId || ''),
    title: has('title') ? str(b.title) : (e.title || ''),
    count: has('count') ? num(b.count) : (e.count ?? ''),
    salaryRange: has('salaryRange') ? str(b.salaryRange) : (e.salaryRange || ''),
    date: has('date') ? str(b.date) : (e.date || ''),
    status: has('status') ? pick(b.status, REQUEST_STATUSES, 'open') : (e.status || 'open'),
    notes: has('notes') ? str(b.notes) : (e.notes || '')
  };
}
app.get('/api/requests', requireAuth, requirePermission('requestsView'), (req, res) => res.json(data.requests));
app.post('/api/requests', requireAuth, requirePermission('requestsManage'), async (req, res) => {
  const r = Object.assign({ id: uid() }, cleanRequest(req.body), { createdAt: Date.now(), addedBy: currentUser(req).username });
  if (!r.clientId || !data.clients.find(c => c.id === r.clientId)) return res.status(400).json({ error: 'اختر الشركة' });
  if (!r.title) return res.status(400).json({ error: 'اكتب الوظيفة المطلوبة' });
  data.requests.push(r); await saveData(); res.json(r);
});
app.put('/api/requests/:id', requireAuth, requirePermission('requestsManage'), async (req, res) => {
  const r = data.requests.find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(r, cleanRequest(req.body, r), { updatedAt: Date.now() });
  // keep submissions pointing at the request's company
  data.submissions.forEach(s => { if (s.requestId === r.id) s.clientId = r.clientId; });
  await saveData(); res.json(r);
});
app.delete('/api/requests/:id', requireAuth, requirePermission('requestsManage'), async (req, res) => {
  data.requests = data.requests.filter(x => x.id !== req.params.id);
  data.submissions.forEach(s => { if (s.requestId === req.params.id) s.requestId = ''; });
  await saveData(); res.json({ ok: true });
});

// ---------- SUBMISSIONS (ترشيح مرشح لطلب شركة: انترفيو / نتيجة / مرتب) ----------
function cleanSubmission(body, existing) {
  const b = body || {}, e = existing || {};
  const has = k => Object.prototype.hasOwnProperty.call(b, k);
  const out = {
    candidateId: has('candidateId') ? str(b.candidateId) : (e.candidateId || ''),
    requestId: has('requestId') ? str(b.requestId) : (e.requestId || ''),
    clientId: has('clientId') ? str(b.clientId) : (e.clientId || ''),
    interview: has('interview') ? pick(b.interview, INTERVIEW_STATUSES, 'none') : (e.interview || 'none'),
    interviewDate: has('interviewDate') ? str(b.interviewDate) : (e.interviewDate || ''),
    result: has('result') ? pick(b.result, RESULT_STATUSES, 'pending') : (e.result || 'pending'),
    salary: has('salary') ? num(b.salary) : (e.salary ?? ''),
    notes: has('notes') ? str(b.notes) : (e.notes || '')
  };
  const r = out.requestId && data.requests.find(x => x.id === out.requestId);
  if (r) out.clientId = r.clientId;
  return out;
}
app.get('/api/submissions', requireAuth, requirePermission('submissionsView'), (req, res) => res.json(data.submissions));
app.post('/api/submissions', requireAuth, requirePermission('submissionsAdd'), async (req, res) => {
  const s = Object.assign({ id: uid() }, cleanSubmission(req.body), { createdAt: Date.now(), addedBy: currentUser(req).username });
  if (!s.candidateId || !data.candidates.find(c => c.id === s.candidateId)) return res.status(400).json({ error: 'اختر المرشح' });
  if (!s.clientId || !data.clients.find(c => c.id === s.clientId)) return res.status(400).json({ error: 'اختر الشركة' });
  if (s.requestId && data.submissions.find(x => x.requestId === s.requestId && x.candidateId === s.candidateId))
    return res.status(400).json({ error: 'المرشح ده مترشح للطلب ده بالفعل' });
  data.submissions.push(s); await saveData(); res.json(s);
});
app.put('/api/submissions/:id', requireAuth, requirePermission('submissionsManage'), async (req, res) => {
  const s = data.submissions.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'غير موجود' });
  Object.assign(s, cleanSubmission(req.body, s), { updatedAt: Date.now() });
  await saveData(); res.json(s);
});
app.delete('/api/submissions/:id', requireAuth, requirePermission('submissionsManage'), async (req, res) => {
  data.submissions = data.submissions.filter(x => x.id !== req.params.id);
  await saveData(); res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
process.on('SIGTERM', () => { writing.finally(() => process.exit(0)); });

initStore()
  .then(seedOwner)
  .then(() => app.listen(PORT, () => console.log('Prime Connect system running on port ' + PORT)))
  .catch(err => { console.error('Could not start:', err); process.exit(1); });
