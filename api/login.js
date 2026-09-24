// Vercel maps /api/login to this function before the catch-all rewrite.
// Delegate to the hardened app so login uses the shared limiter and body limit.
const app = require('../server_hardened');

module.exports = (req, res) => {
  if (req.url && req.url.startsWith('/api')) {
    req.url = req.url.slice(4) || '/';
  }
  return app(req, res);
};
