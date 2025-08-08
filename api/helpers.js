const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { nanoid } = require('nanoid');
const { fileTypeFromFile } = require('file-type');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
let OpenAIClient = require('openai');
OpenAIClient = OpenAIClient && OpenAIClient.default ? OpenAIClient.default : OpenAIClient;
const z = require('zod');
const config = require('./config');

// In-memory stores. Since Vercel functions are stateless between cold starts
// these stores are reset periodically. They are adequate for small scale use
// but a persistent store should be used for production at scale.
const rateLimitStore = {};
const authCodes = {};

/**
 * Apply a set of standard security headers on all responses. These mirror
 * Helmet's defaults but are implemented manually to avoid dependency on
 * Express within serverless functions.
 *
 * @param {object} res HTTP response object
 */
function setSecurityHeaders(res) {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'geolocation=()');
}

/**
 * Simple CORS implementation. If the request's Origin header matches one of
 * the configured allowed origins then the appropriate Access-Control headers
 * are set. Preflight (OPTIONS) requests are short-circuited.
 *
 * @param {object} req HTTP request object
 * @param {object} res HTTP response object
 * @returns {boolean} false if the request has been handled (e.g. OPTIONS)
 */
function handleCors(req, res) {
  const origin = req.headers.origin;
  if (origin && config.allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  // Always allow these methods and headers
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return false;
  }
  return true;
}

/**
 * Naive in-memory rate limiter. Tracks requests per IP on a sliding window
 * defined by windowMs and enforces a maximum number of requests. When the
 * limit is exceeded the request is rejected with status code 429.
 *
 * @param {object} req HTTP request object
 * @param {object} res HTTP response object
 * @param {number} [windowMs=60000] Duration of the rate limiting window in ms
 * @param {number} [max=20] Maximum number of requests allowed per window
 * @returns {boolean} true if the request may proceed, false otherwise
 */
function checkRateLimit(req, res, windowMs = 60000, max = 20) {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  if (!rateLimitStore[ip]) {
    rateLimitStore[ip] = { count: 0, start: now };
  }
  const entry = rateLimitStore[ip];
  if (now - entry.start > windowMs) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count++;
  if (entry.count > max) {
    res.statusCode = 429;
    res.setHeader('Retry-After', Math.ceil((windowMs - (now - entry.start)) / 1000));
    res.end(JSON.stringify({ error: 'Too many requests. Please try again later.' }));
    return false;
  }
  return true;
}

/**
 * Redact personally identifiable information from a string. This function
 * removes email addresses, phone numbers, Social Security numbers and long
 * sequences of digits that could represent account numbers. Redacted
 * substrings are replaced with the placeholder "[REDACTED]".
 *
 * @param {string} text Input text
 * @returns {string} Redacted text
 */
function redactPII(text) {
  if (!text) return text;
  // Email addresses
  const emailRegex = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  // Phone numbers (international, US, with spaces, dashes or parentheses)
  const phoneRegex = /\+?\d[\d\s().-]{7,}\d/g;
  // US SSNs
  const ssnRegex = /\b\d{3}-?\d{2}-?\d{4}\b/g;
  // Long digit sequences (9 or more digits)
  const longDigitsRegex = /\b\d{9,}\b/g;
  return text
    .replace(emailRegex, '[REDACTED]')
    .replace(phoneRegex, '[REDACTED]')
    .replace(ssnRegex, '[REDACTED]')
    .replace(longDigitsRegex, '[REDACTED]');
}

/**
 * Extract text from a supported file type (PDF or DOCX). Throws an
 * exception if the file is not a supported type. PDF extraction uses
 * pdf-parse and DOCX extraction uses mammoth. Both libraries read files
 * synchronously from disk.
 *
 * @param {string} filePath Absolute path to the uploaded file
 * @returns {Promise<string>} Extracted plain text
 */
async function extractText(filePath) {
  const fileType = await fileTypeFromFile(filePath);
  const ext = fileType ? fileType.ext : path.extname(filePath).slice(1).toLowerCase();
  // Allow simple .txt files during local dev to simplify testing
  if (ext === 'txt' && (config.devAuthMode === 'code_in_response')) {
    return fs.readFileSync(filePath, 'utf8');
  }
  if (ext === 'pdf') {
    const dataBuffer = fs.readFileSync(filePath);
    const data = await pdfParse(dataBuffer);
    return data.text;
  }
  if (ext === 'docx') {
    const result = await mammoth.extractRawText({ path: filePath });
    return result.value;
  }
  throw new Error('Unsupported file type');
}

/**
 * Zod schema describing the expected structure of the AI's JSON output. A
 * contract analysis must include a risk score between 0 and 1, a free-form
 * summary and a list of issues, each with the clause text, a description
 * of the issue, its severity (low|medium|high) and a suggested edit.
 */
const aiOutputSchema = z.object({
  riskScore: z.number().min(0).max(1),
  summary: z.string().min(1),
  issues: z.array(
    z.object({
      clauseText: z.string().min(1),
      issue: z.string().min(1),
      severity: z.enum(['low', 'medium', 'high']),
      suggestion: z.string().min(1),
    }),
  ),
});

/**
 * Validate the AI's JSON output against the expected schema. If the output
 * fails validation a human-readable error is thrown. This prevents
 * accidentally trusting malformed or malicious responses from the model.
 *
 * @param {any} data Parsed JSON from the AI response
 * @returns {object} Validated data matching the schema
 */
function validateAIOutput(data) {
  const parsed = aiOutputSchema.safeParse(data);
  if (!parsed.success) {
    throw new Error('Invalid AI output: ' + JSON.stringify(parsed.error.issues));
  }
  return parsed.data;
}

/**
 * Compose a prompt for the AI model based on the document type. At the
 * moment only a single document type (freelance contract) is supported but
 * this helper makes it easy to extend in future. The template instructs
 * the model to return a strict JSON object. The contract text is inserted
 * directly into the user message.
 *
 * @param {string} docText The extracted (and redacted) contract text
 * @param {string} docType Type of the document (e.g. freelance_contract)
 * @returns {Array<{role: string, content: string}>} Messages for Chat API
 */
function buildPrompt(docText, docType) {
  const system =
    'You are a legal risk assistant specialised in analysing contract clauses for freelancers. ' +
    'For the given contract text, return a JSON object with a floating point riskScore between 0 and 1 ' +
    '(where 1 is highest risk), a concise summary highlighting the overall risk picture, ' +
    'and an array of issues. Each issue should include the exact clauseText, a description of why it is risky, ' +
    'its severity (low, medium or high) and a suggested fix. Strictly output JSON and nothing else.';
  const user =
    `Document type: ${docType || 'freelance_contract'}\n` +
    `Contract text:\n${docText}\n` +
    'Respond only with JSON.';
  return [
    { role: 'system', content: system },
    { role: 'user', content: user },
  ];
}

/**
 * Invoke the configured AI provider (OpenAI or Azure OpenAI) to analyse a
 * contract. When region is explicitly "eu" the Azure provider is used,
 * otherwise the provider defined by MODEL_VENDOR is used. The function
 * composes a prompt using the supplied text and document type, sends it to
 * the chat API and returns the parsed JSON response. Network errors or
 * invalid responses will result in exceptions.
 *
 * @param {string} text Redacted contract text
 * @param {string} docType Document type
 * @param {string} region Region hint ('us' or 'eu')
 * @returns {Promise<object>} Validated AI output
 */
async function callAI(text, docType = 'freelance_contract', region = config.defaultRegion) {
  const vendor = region === 'eu' ? 'azure-openai' : config.modelVendor;
  const messages = buildPrompt(text, docType);
  let response;
  // Stub response in local dev when API keys are not configured
  const shouldStub = config.devAuthMode === 'code_in_response' && (
    (vendor === 'openai' && !config.openaiApiKey) ||
    (vendor === 'azure-openai' && (!config.azureEndpoint || !config.azureDeployment || !config.azureKey))
  );
  if (shouldStub) {
    const stub = {
      riskScore: 0.42,
      summary: 'This is a stubbed local-dev analysis summary. Replace with real provider by adding API keys.',
      issues: [
        {
          clauseText: 'Payment terms: Net 90',
          issue: 'Long payment terms increase cash flow risk for freelancers.',
          severity: 'medium',
          suggestion: 'Request Net 15 or Net 30 payment terms.',
        },
      ],
    };
    return validateAIOutput(stub);
  }
  if (vendor === 'openai') {
    const openai = new OpenAIClient({ apiKey: config.openaiApiKey });
    const completion = await openai.chat.completions.create({
      model: config.openaiModel,
      messages,
      temperature: 0.2,
    });
    response = completion.choices[0].message.content;
  } else if (vendor === 'azure-openai') {
    // Azure OpenAI uses a different API path; use fetch directly
    const endpoint = config.azureEndpoint;
    const deployment = config.azureDeployment;
    if (!endpoint || !deployment || !config.azureKey) {
      throw new Error('Azure OpenAI configuration is incomplete');
    }
    const url = `${endpoint.replace(/\/?$/, '/') }openai/deployments/${deployment}/chat/completions?api-version=2023-05-15`;
    const body = {
      messages,
      temperature: 0.2,
    };
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': config.azureKey,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Azure OpenAI error: ${res.status} ${errText}`);
    }
    const json = await res.json();
    response = json.choices[0].message.content;
  } else {
    throw new Error(`Unsupported AI vendor: ${vendor}`);
  }
  // Parse and validate the model's output
  let parsed;
  try {
    parsed = JSON.parse(response);
  } catch (err) {
    throw new Error('AI response is not valid JSON');
  }
  return validateAIOutput(parsed);
}

/**
 * Generate a short-lived magic code for email verification. The code is
 * mapped to the supplied email and stored in memory with a 10 minute
 * expiration time. Returns the generated code.
 *
 * @param {string} email
 * @returns {string}
 */
function generateMagicCode(email) {
  const code = nanoid(32);
  const expires = Date.now() + 10 * 60 * 1000; // 10 minutes
  authCodes[code] = { email, expires };
  return code;
}

/**
 * Consume a magic code, returning the associated email if the code is
 * present and valid. Once consumed the code is removed from the store.
 *
 * @param {string} code
 * @returns {string|null}
 */
function consumeMagicCode(code) {
  const entry = authCodes[code];
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    delete authCodes[code];
    return null;
  }
  delete authCodes[code];
  return entry.email;
}

/**
 * Send a magic login link to the provided email address. Uses nodemailer
 * with SMTP details from the configuration. If email sending fails the
 * promise rejects. When devAuthMode is set to "code_in_response" the
 * function resolves without sending.
 *
 * @param {string} email
 * @param {string} code
 * @param {string} baseUrl The base URL of the frontend to include in the link
 */
async function sendMagicLink(email, code, baseUrl) {
  // When in dev mode we skip sending emails
  if (config.devAuthMode === 'code_in_response') return;
  const transporter = nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpPort === 465,
    auth: {
      user: config.smtpUser,
      pass: config.smtpPass,
    },
  });
  const link = `${baseUrl}/?code=${encodeURIComponent(code)}`;
  const mailOptions = {
    from: config.emailFrom,
    to: email,
    subject: 'Your magic login link',
    text: `Click the link below to log in:\n\n${link}\n\nThis link will expire in 10 minutes.`,
  };
  await transporter.sendMail(mailOptions);
}

/**
 * Create a signed JWT for the authenticated user. The token contains the
 * email and region claims and expires in 7 days. The result is a string
 * suitable for setting as a cookie.
 *
 * @param {object} payload
 * @returns {string}
 */
function signJwt(payload) {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: '7d' });
}

/**
 * Verify an incoming JWT. Returns the decoded payload if valid or null if
 * verification fails.
 *
 * @param {string} token
 * @returns {object|null}
 */
function verifyJwt(token) {
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (err) {
    return null;
  }
}

module.exports = {
  setSecurityHeaders,
  handleCors,
  checkRateLimit,
  redactPII,
  extractText,
  validateAIOutput,
  callAI,
  generateMagicCode,
  consumeMagicCode,
  sendMagicLink,
  signJwt,
  verifyJwt,
};