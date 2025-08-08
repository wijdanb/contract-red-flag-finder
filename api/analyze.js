const fs = require('fs');
const formidable = require('formidable');
const { setSecurityHeaders, handleCors, checkRateLimit, extractText, redactPII, callAI, verifyJwt } = require('./helpers');
const config = require('./config');

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (!handleCors(req, res)) return;
  if (!checkRateLimit(req, res)) return;
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.end(JSON.stringify({ error: 'Method Not Allowed' }));
    return;
  }
  // Require authentication via JWT cookie
  const token = req.headers.cookie?.split(';').find((c) => c.trim().startsWith('token='))?.split('=')[1];
  const user = token ? verifyJwt(token) : null;
  if (!user) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }
  const os = require('os');
  const form = new formidable.IncomingForm({
    maxFileSize: config.maxFileMB * 1024 * 1024,
    keepExtensions: true,
    multiples: false,
    uploadDir: os.tmpdir(),
  });
  form.parse(req, async (err, fields, files) => {
    if (err) {
      let status = 400;
      let message = 'Failed to parse form data';
      if (err.code === 'LIMIT_FILE_SIZE') {
        message = `File exceeds maximum size of ${config.maxFileMB}MB`;
      }
      res.statusCode = status;
      res.end(JSON.stringify({ error: message }));
      return;
    }
    const file = files.file || files.upload || Object.values(files)[0];
    if (!file) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'No file uploaded' }));
      return;
    }
    const filePath = file.filepath || file.path;
    try {
      let text = await extractText(filePath);
      if (config.piiRedaction) {
        text = redactPII(text);
      }
      const docType = fields.docType || 'freelance_contract';
      const region = fields.region || user.region || config.defaultRegion;
      const analysis = await callAI(text, docType, region);
      // Delete the uploaded file immediately
      try {
        fs.unlinkSync(filePath);
      } catch (e) {
        // ignore
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(analysis));
    } catch (e) {
      console.error('Analysis error:', e.message);
      try {
        fs.unlinkSync(filePath);
      } catch (err) {}
      res.statusCode = 500;
      res.end(JSON.stringify({ error: e.message }));
    }
  });
};