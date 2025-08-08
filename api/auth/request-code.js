const { setSecurityHeaders, handleCors, checkRateLimit, generateMagicCode, sendMagicLink } = require('../helpers');
const config = require('../config');

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (!handleCors(req, res)) return;
  if (!checkRateLimit(req, res)) return;
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.end(JSON.stringify({ error: 'Method Not Allowed' }));
    return;
  }
  // Collect body
  let body = '';
  req.on('data', (chunk) => {
    body += chunk.toString();
  });
  req.on('end', async () => {
    let email;
    try {
      const parsed = JSON.parse(body);
      email = String(parsed.email || '').trim().toLowerCase();
    } catch (err) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }
    // Basic email validation
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!email || !emailRegex.test(email)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'A valid email is required' }));
      return;
    }
    const code = generateMagicCode(email);
    // Determine base URL for login link: prefer the request origin if allowed
    const origin = req.headers.origin && config.allowedOrigins.includes(req.headers.origin) ? req.headers.origin : config.allowedOrigins[0] || '';
    try {
      await sendMagicLink(email, code, origin);
    } catch (err) {
      // We don't expose internal errors to clients for security reasons
      console.error('Error sending magic link:', err.message);
    }
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    const result = { message: 'If that email exists, a login link has been sent.' };
    if (config.devAuthMode === 'code_in_response') {
      result.code = code;
    }
    res.end(JSON.stringify(result));
  });
};