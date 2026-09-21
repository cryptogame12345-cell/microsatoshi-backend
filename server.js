const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { promisify } = require('util');
const { neon } = require('@neondatabase/serverless');

const app = express();
const scrypt = promisify(crypto.scrypt);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '32kb' }));

function db() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL belum dikonfigurasi');
  return neon(process.env.DATABASE_URL);
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

function validEmail(value) { return typeof value === 'string' && /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(value); }
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
  const raw = req.headers.cookie || '';
  const item = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
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
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!validUsername(username) || !validEmail(email) || typeof password !== 'string' || password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Data pendaftaran tidak valid' });
  try {
    await ensureSchema();
    const sql = db();
    const passwordHash = await hashPassword(password);
    const rows = await sql`INSERT INTO users (username,email,password_hash) VALUES (${username},${email.toLowerCase()},${passwordHash}) RETURNING id, username, email`;
    const user = rows[0];
    await sql`INSERT INTO profiles (user_id, display_name) VALUES (${user.id}, ${user.username})`;
    await sql`INSERT INTO balances (user_id) VALUES (${user.id})`;
    await sql`INSERT INTO miners (user_id) VALUES (${user.id})`;
    res.status(201).json({ ok: true, user });
  } catch (error) {
    if (error && error.code === '23505') return res.status(409).json({ error: 'Nama pengguna atau email sudah terdaftar' });
    res.status(500).json({ error: 'Pendaftaran gagal' });
  }
});
app.post('/login', async (req, res) => {
  const { login, password } = req.body || {};
  if (typeof login !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Login tidak valid' });
  try {
    await ensureSchema();
    const sql = db();
    const rows = await sql`SELECT id, username, email, password_hash FROM users WHERE username=${login} OR email=${login.toLowerCase()} LIMIT 1`;
    if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) return res.status(401).json({ error: 'Nama pengguna atau kata sandi salah' });
    const token = crypto.randomBytes(32).toString('hex');
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

module.exports = app;
