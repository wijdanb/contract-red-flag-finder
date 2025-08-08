const path = require('path');
const express = require('express');

// Require API handlers (Vercel-style) and mount them on Express
const analyze = require('./api/analyze');
const subprocessors = require('./api/subprocessors');
const authRequestCode = require('./api/auth/request-code');
const authVerifyCode = require('./api/auth/verify-code');
const authMe = require('./api/auth/me');
const authLogout = require('./api/auth/logout');
const privacyExport = require('./api/privacy/export');
const privacyDelete = require('./api/privacy/delete');

const app = express();

// Serve static assets
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/legal', express.static(path.join(__dirname, 'legal')));

// API routes (use app.all so OPTIONS pass through to handlers which set CORS)
app.all('/api/analyze', (req, res) => analyze(req, res));
app.all('/api/subprocessors', (req, res) => subprocessors(req, res));
app.all('/api/auth/request-code', (req, res) => authRequestCode(req, res));
app.all('/api/auth/verify-code', (req, res) => authVerifyCode(req, res));
app.all('/api/auth/me', (req, res) => authMe(req, res));
app.all('/api/auth/logout', (req, res) => authLogout(req, res));
app.all('/api/privacy/export', (req, res) => privacyExport(req, res));
app.all('/api/privacy/delete', (req, res) => privacyDelete(req, res));

// Root -> index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Local dev server running at http://localhost:${port}`);
});

