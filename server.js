require('dotenv').config();
const express = require('express'), session = require('express-session'), bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const { TURNSTILE_SECRET_KEY: SECRET, TURNSTILE_SITE_KEY: SITE_KEY, SESSION_SECRET, NODE_ENV } = process.env;
if (!SECRET || !SITE_KEY || !SESSION_SECRET) { console.error('Set TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY and SESSION_SECRET in .env'); process.exit(1); }
const HOSTS = (process.env.TURNSTILE_HOSTNAMES || '').split(',').map(s => s.trim()).filter(Boolean);
const IS_TEST_KEY = /^[123]x0000/.test(SECRET);

/* ---------- Turnstile server-side verification (siteverify) ---------- */
async function verifyTurnstile(token, ip) {
  if (typeof token !== 'string' || !token || token.length > 2048) return false;   // missing/oversized token
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: SECRET, response: token, remoteip: ip }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return false;
    const d = await r.json();
    if (d.success !== true) return false;               // forged, expired (5 min) or already-used token
    if (!IS_TEST_KEY) {
      if (d.action !== 'signup') return false;          // token minted for a different widget/action
      if (HOSTS.length && !HOSTS.includes(d.hostname)) return false;  // token solved on another site
    }
    return true;
  } catch { return false; }                             // fail CLOSED on network errors
}

/* ---------- tiny JSON user store ---------- */
const DB = path.join(__dirname, 'data', 'users.json');
fs.mkdirSync(path.dirname(DB), { recursive: true });
let users = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, 'utf8')) : [];
const save = () => fs.writeFileSync(DB, JSON.stringify(users, null, 2));
const DUMMY_HASH = bcrypt.hashSync('timing-pad', 12);
const dn = u => u.fullName || u.name;
const pub = u => ({ id: u.id, role: u.role, name: dn(u), identifier: u.role === 'student' ? u.gmail : u.teacherId, createdAt: u.createdAt });

/* ---------- validation (mirrors the frontend; the server is the real gate) ---------- */
const RULES = { student: ['lrn', 'fullName', 'gmail'], teacher: ['teacherId', 'name'], librarian: ['teacherId', 'name'] };
const nameOk = v => v.length >= 2 && v.length <= 80;
const CHECK = {
  lrn: v => /^\d{12}$/.test(v), fullName: nameOk, name: nameOk,
  gmail: v => /^[^\s@]+@gmail\.com$/i.test(v), teacherId: v => /^[A-Za-z0-9-]{3,20}$/.test(v),
};
const idField = r => (r === 'student' ? 'gmail' : 'teacherId');

/* ---------- app ---------- */
const app = express();
if (NODE_ENV === 'production') app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(session({
  secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: NODE_ENV === 'production', maxAge: 864e5 },
}));
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const clientIp = req => req.get('CF-Connecting-IP') || req.ip;
const needAdmin = (req, res, next) => {
  const u = users.find(x => x.id === req.session.uid);
  return u && u.role === 'librarian' ? next() : res.status(403).json({ error: 'Librarian access only.' });
};

app.get('/api/config', (_req, res) => res.json({ siteKey: SITE_KEY }));   // site key is public

app.post('/api/signup', limiter, async (req, res) => {
  const b = req.body || {};
  // 1) Turnstile first: nothing else runs (or reveals anything) until the challenge is proven.
  if (!(await verifyTurnstile(b['cf-turnstile-response'], clientIp(req))))
    return res.status(403).json({ error: 'Human verification failed. Please try again.' });
  // 2) Re-validate everything server-side.
  const fields = RULES[b.role];
  if (!fields) return res.status(400).json({ error: 'Choose a valid user type.' });
  const rec = {};
  for (const f of fields) {
    const v = typeof b[f] === 'string' ? b[f].trim() : '';
    if (!CHECK[f](v)) return res.status(400).json({ error: `Invalid ${f}.` });
    rec[f] = v;
  }
  if (typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 72) return res.status(400).json({ error: 'Password must be 8 to 72 characters.' });
  if (b.password !== b.confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
  const key = rec[idField(b.role)].toLowerCase();
  if (users.some(u => u.role === b.role && u[idField(b.role)].toLowerCase() === key))
    return res.status(409).json({ error: 'An account with that ID already exists.' });
  users.push({ id: crypto.randomUUID(), role: b.role, ...rec, hash: await bcrypt.hash(b.password, 12), createdAt: new Date().toISOString() });
  save();
  res.status(201).json({ ok: true });
});

app.post('/api/login', limiter, async (req, res) => {
  const { role, identifier, password } = req.body || {};
  const id = String(identifier || '').trim().toLowerCase();
  const u = RULES[role] && users.find(x => x.role === role && x[idField(role)].toLowerCase() === id);
  const ok = await bcrypt.compare(String(password || ''), u ? u.hash : DUMMY_HASH);   // same cost either way
  if (!u || !ok) return res.status(401).json({ error: 'Invalid credentials.' });
  req.session.regenerate(() => { req.session.uid = u.id; res.json(pub(u)); });
});

app.get('/api/me', (req, res) => {
  const u = users.find(x => x.id === req.session.uid);
  u ? res.json(pub(u)) : res.status(401).json({ error: 'Not logged in.' });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/users', needAdmin, (_req, res) => res.json(users.map(pub)));
app.patch('/api/users/:id', needAdmin, (req, res) => {
  const u = users.find(x => x.id === req.params.id), name = String((req.body || {}).name || '').trim();
  if (!u || !nameOk(name)) return res.status(400).json({ error: 'Invalid user or name.' });
  u[u.role === 'student' ? 'fullName' : 'name'] = name; save(); res.json(pub(u));
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, () => console.log('E-Library running on http://localhost:' + (process.env.PORT || 3000)));
