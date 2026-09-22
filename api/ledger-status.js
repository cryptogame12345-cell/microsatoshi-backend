const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

const sql = neon(process.env.DATABASE_URL);

module.exports = async (req, res) => {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method tidak diizinkan' });
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)ms_session=([^;]+)/);
  if (!match) return res.status(401).json({ error: 'Perlu masuk' });
  try {
    const tokenHash = crypto.createHash('sha256').update(decodeURIComponent(match[1])).digest('hex');
    const rows = await sql`SELECT 1 FROM sessions WHERE token_hash=${tokenHash} AND expires_at > now() LIMIT 1`;
    if (!rows[0]) return res.status(401).json({ error: 'Sesi tidak valid' });
    return res.json({ ok: true, enabled: false, writes: false });
  } catch (_) {
    return res.status(500).json({ error: 'Status ledger belum tersedia' });
  }
};
