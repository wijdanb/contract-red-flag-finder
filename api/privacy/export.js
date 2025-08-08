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
  // Stub: In a real implementation this would assemble and return all data
  // stored about the user, e.g. analysis history. Since the app does not
  // persist data, there is nothing to return.
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ message: 'No stored data for this user.' }));
};