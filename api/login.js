const app = require('../server');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method tidak diizinkan' });
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw || '{}');
  } catch (_) {
    return res.status(400).json({ error: 'JSON tidak valid' });
  }
  req.body = parsed;
  req.url = '/login';
  return app(req, res);
};
