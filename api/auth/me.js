const { setSecurityHeaders, handleCors, checkRateLimit, verifyJwt } = require('../helpers');

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (!handleCors(req, res)) return;
  if (!checkRateLimit(req, res)) return;
  const cookieHeader = req.headers.cookie || '';
  const token = cookieHeader
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith('token='))?.split('=')[1];
  const user = token ? verifyJwt(token) : null;
  if (!user) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ email: user.email, region: user.region }));
};