const { setSecurityHeaders, handleCors, checkRateLimit, verifyJwt } = require('../helpers');

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (!handleCors(req, res)) return;
  if (!checkRateLimit(req, res)) return;
  const token = req.headers.cookie?.split(';').find((c) => c.trim().startsWith('token='))?.split('=')[1];
  const user = token ? verifyJwt(token) : null;
  if (!user) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }
  // Stub: If data were stored, it would be deleted here. This endpoint
  // acknowledges the request and returns success. Since nothing is stored,
  // there is nothing to delete.
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ message: 'All stored data deleted.' }));
};