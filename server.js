const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { promisify } = require('util');
const { neon } = require('@neondatabase/serverless');

const app = express();
const scrypt = promisify(crypto.scrypt);
const allowedOrigins = new Set([
  'https://microsatoshi.wapka.top',
  'https://microsatoshi-backend.vercel.app'
]);
const rateBuckets = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(cors({
  origin: (origin, callback) => callback(null, !origin || allowedOrigins.has(origin)),
  credentials: true
}));
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.json({ limit: '32kb' }));

function db() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL belum dikonfigurasi');
  return neon(process.env.DATABASE_URL);
}

function rateLimit(name, windowMs = 15 * 60 * 1000, max = 20) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${name}:${req.ip || 'unknown'}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + windowMs };
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    if (rateBuckets.size > 10000) {
      for (const [storedKey, storedBucket] of rateBuckets) {
        if (storedBucket.resetAt <= now) rateBuckets.delete(storedKey);
      }
    }
    if (bucket.count > max) {
      res.setHeader('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
    }
    next();
  };
}

let schemaPromise;
async function ensureSchema() {
  if (!schemaPromise) {
    const sql = db();
    schemaPromise = (async () => {
      await sql`CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
      await sql`CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
      await sql`CREATE TABLE IF NOT EXISTS profiles (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, display_name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
      await sql`CREATE TABLE IF NOT EXISTS balances (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, amount NUMERIC(20,8) NOT NULL DEFAULT 0 CHECK (amount >= 0), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
      await sql`CREATE TABLE IF NOT EXISTS miners (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, active BOOLEAN NOT NULL DEFAULT false, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
      await sql`CREATE TABLE IF NOT EXISTS audit_log (id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
    })().catch(error => { schemaPromise = null; throw error; });
  }
  return schemaPromise;
}

function validEmail(value) {
  if (typeof value !== 'string') return false;
  const parts = value.trim().split('@');
  return parts.length === 2 && parts[0].length > 0 && parts[1].includes('.') && !parts[1].startsWith('.') && !parts[1].endsWith('.');
}
function validUsername(value) { return typeof value === 'string' && /^[A-Za-z0-9_]{3,32}$/.test(value); }
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${derived.toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const derived = await scrypt(password, parts[1], 64);
  const expected = Buffer.from(parts[2], 'hex');
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}
function cookieValue(req, name) {
  try {
    const raw = req.headers.cookie || '';
    const item = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
    return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
  } catch (_) { return null; }
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `ms_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`);
}
async function currentUser(req) {
  await ensureSchema();
  const token = cookieValue(req, 'ms_session');
  if (!token) return null;
  const sql = db();
  const rows = await sql`SELECT u.id, u.username, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=${tokenHash(token)} AND s.expires_at > now()`;
  return rows[0] || null;
}

app.get('/', (req, res) => res.json({ ok: true, service: 'microsatoshi', mode: 'vercel-neon-staging' }));
app.get('/health', async (req, res) => {
  try { await ensureSchema(); await db()`SELECT 1`; res.json({ ok: true, service: 'microsatoshi', database: 'connected' }); }
  catch (error) { res.status(503).json({ ok: false, service: 'microsatoshi', database: 'unavailable' }); }
});

app.post('/register', rateLimit('register'), async (req, res) => {
  const rawUsername = req.body && req.body.username;
  const rawEmail = req.body && req.body.email;
  const password = req.body && req.body.password;
  const username = typeof rawUsername === 'string' ? rawUsername.trim() : rawUsername;
  const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : rawEmail;
  if (!validUsername(username) || !validEmail(email) || typeof password !== 'string' || password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Data pendaftaran tidak valid' });
  try {
    await ensureSchema();
    const sql = db();
    const passwordHash = await hashPassword(password);
    // Satu perintah SQL membuat user dan seluruh record awal secara atomik.
    const rows = await sql`WITH new_user AS (
      INSERT INTO users (username, email, password_hash)
      VALUES (${username}, ${email}, ${passwordHash})
      RETURNING id, username, email
    ), new_profile AS (
      INSERT INTO profiles (user_id, display_name)
      SELECT id, username FROM new_user RETURNING user_id
    ), new_balance AS (
      INSERT INTO balances (user_id)
      SELECT id FROM new_user RETURNING user_id
    ), new_miner AS (
      INSERT INTO miners (user_id)
      SELECT id FROM new_user RETURNING user_id
    ), new_audit AS (
      INSERT INTO audit_log (user_id, action)
      SELECT id, 'register' FROM new_user RETURNING id
    )
    SELECT id, username, email FROM new_user`;
    res.status(201).json({ ok: true, user: rows[0] });
  } catch (error) {
    if (error && error.code === '23505') return res.status(409).json({ error: 'Nama pengguna atau email sudah terdaftar' });
    res.status(500).json({ error: 'Pendaftaran gagal' });
  }
});

app.post('/login', rateLimit('login'), async (req, res) => {
  const rawLogin = req.body && req.body.login;
  const password = req.body && req.body.password;
  const login = typeof rawLogin === 'string' ? rawLogin.trim() : rawLogin;
  if (typeof login !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Login tidak valid' });
  try {
    await ensureSchema();
    const sql = db();
    const rows = await sql`SELECT id, username, email, password_hash FROM users WHERE username=${login} OR email=${login.toLowerCase()} LIMIT 1`;
    if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) return res.status(401).json({ error: 'Nama pengguna atau kata sandi salah' });
    const token = crypto.randomBytes(32).toString('hex');
    await sql`DELETE FROM sessions WHERE expires_at <= now()`;
    await sql`INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (${tokenHash(token)},${rows[0].id},now()+interval '7 days')`;
    setSessionCookie(res, token);
    res.json({ ok: true, user: { id: rows[0].id, username: rows[0].username, email: rows[0].email } });
  } catch (error) { res.status(500).json({ error: 'Login gagal' }); }
});
app.get('/me', async (req, res) => {
  try { const user = await currentUser(req); if (!user) return res.status(401).json({ error: 'Perlu masuk' }); res.json({ ok: true, user }); }
  catch (error) { res.status(500).json({ error: 'Tidak dapat membaca sesi' }); }
});
app.get('/balance', async (req, res) => {
  try { const user = await currentUser(req); if (!user) return res.status(401).json({ error: 'Perlu masuk' }); const rows = await db()`SELECT amount, updated_at FROM balances WHERE user_id=${user.id}`; res.json({ ok: true, balance: rows[0] || { amount: 0 } }); }
  catch (error) { res.status(500).json({ error: 'Saldo belum tersedia' }); }
});
app.post('/logout', async (req, res) => {
  try { const token = cookieValue(req, 'ms_session'); if (token) await db()`DELETE FROM sessions WHERE token_hash=${tokenHash(token)}`; res.setHeader('Set-Cookie', 'ms_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'); res.json({ ok: true }); }
  catch (error) { res.status(500).json({ error: 'Logout gagal' }); }
});
app.all('/payments', (req, res) => res.status(403).json({ error: 'Payment masih dinonaktifkan untuk staging' }));
app.all('/withdrawals', (req, res) => res.status(403).json({ error: 'Withdrawal masih dinonaktifkan untuk staging' }));

app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && error.status === 400 && error.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON tidak valid' });
  res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

module.exports = app;
