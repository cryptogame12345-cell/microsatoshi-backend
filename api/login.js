const app = require('../server');

module.exports = (req, res) => {
  req.url = '/login';
  return app(req, res);
};
