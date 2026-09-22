module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method tidak diizinkan' });
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const upstream = await fetch('https://microsatoshi-backend.vercel.app/login', {
    method: 'POST',
    headers: {
      'Content-Type': req.headers['content-type'] || 'application/json',
      'Origin': req.headers.origin || 'https://microsatoshi.wapka.top'
    },
    body: Buffer.concat(chunks)
  });
  res.status(upstream.status);
  for (const key of ['content-type', 'set-cookie', 'access-control-allow-origin', 'access-control-allow-credentials', 'cache-control']) {
    const value = upstream.headers.get(key);
    if (value) res.setHeader(key, value);
  }
  res.send(await upstream.text());
};
