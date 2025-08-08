const { setSecurityHeaders, handleCors, checkRateLimit, consumeMagicCode, signJwt } = require('../helpers');
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
  let body = '';
  req.on('data', (chunk) => {
    body += chunk.toString();
  });
  req.on('end', () => {
    let code, region;
    try {
      const parsed = JSON.parse(body);
      code = String(parsed.code || '').trim();
      region = String(parsed.region || config.defaultRegion).toLowerCase();
    } catch (err) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }
    if (!code) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Code is required' }));
      return;
    }
    const email = consumeMagicCode(code);
    if (!email) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid or expired code' }));
      return;
    }
    const token = signJwt({ email, region });
    // Set cookie; SameSite=Lax prevents CSRF; Secure ensures HTTPS; HttpOnly hides from JS
    const cookieParts = [
      `token=${token}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
    ];
    // Only set Secure flag when deployed over HTTPS. In local dev, origin may be http.
    const origin = req.headers.origin;
    if (origin && origin.startsWith('https')) {
      cookieParts.push('Secure');
    }
    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ email, region }));
  });
};