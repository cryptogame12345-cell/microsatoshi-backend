const crypto = require('crypto');
const { promisify } = require('util');
const { neon } = require('@neondatabase/serverless');

const scrypt = promisify(crypto.scrypt);
const sql = neon(process.env.DATABASE_URL);
const allowed = new Set(['https://microsatoshi.wapka.top', 'https://microsatoshi-backend.vercel.app']);

async function verify(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const derived = await scrypt(password, parts[1], 64);
  const expected = Buffer.from(parts[2], 'hex');
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  if (!origin || allowed.has(origin)) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method tidak diizinkan' });
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch (_) {
    return res.status(400).json({ error: 'JSON tidak valid' });
  }
  const login = typeof body.login === 'string' ? body.login.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!login || !password) return res.status(400).json({ error: 'Login tidak valid' });
  try {
    const rows = await sql`SELECT id,username,email,password_hash FROM users WHERE username=${login} OR email=${login.toLowerCase()} LIMIT 1`;
    if (!rows[0] || !(await verify(password, rows[0].password_hash))) return res.status(401).json({ error: 'Nama pengguna atau kata sandi salah' });
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await sql`DELETE FROM sessions WHERE expires_at <= now()`;
    await sql`INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(${tokenHash},${rows[0].id},now()+interval '7 days')`;
    res.setHeader('Set-Cookie', `ms_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=None; Partitioned; Path=/; Max-Age=604800`);
    return res.json({ ok: true, user: { id: rows[0].id, username: rows[0].username, email: rows[0].email } });
  } catch (_) {
    return res.status(500).json({ error: 'Login gagal' });
  }
};
