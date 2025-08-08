const fs = require('fs');
const path = require('path');
const { setSecurityHeaders, handleCors, checkRateLimit } = require('./helpers');

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (!handleCors(req, res)) return;
  if (!checkRateLimit(req, res)) return;
  try {
    const jsonPath = path.join(process.cwd(), 'legal', 'subprocessors.json');
    const content = fs.readFileSync(jsonPath, 'utf8');
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 200;
    res.end(content);
  } catch (err) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: 'Failed to load subprocessors' }));
  }
};