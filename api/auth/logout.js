const { setSecurityHeaders, handleCors, checkRateLimit } = require('../helpers');

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (!handleCors(req, res)) return;
  if (!checkRateLimit(req, res)) return;
  // Clear cookie by setting expiration in the past
  const expires = new Date(0).toUTCString();
  const cookie = `token=; Path=/; Expires=${expires}; HttpOnly; SameSite=Lax`;
  res.setHeader('Set-Cookie', cookie);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ message: 'Logged out' }));
};