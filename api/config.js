const dotenv = require('dotenv');

// Load environment variables. When running on Vercel the .env file is not read, but
// locally this will populate process.env. Values are injected via the Vercel UI.
dotenv.config();

/**
 * Centralised configuration object. All environment variables referenced by the
 * rest of the application are defined here. Where possible defaults are
 * provided to ensure reasonable behaviour if a variable is missing. Booleans
 * derived from string values default to sensible settings (e.g. PII redaction
 * is on by default).
 */
const config = {
  // AI provider configuration
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  openaiModel: process.env.OPENAI_MODEL || 'gpt-4o-mini',
  modelVendor: (process.env.MODEL_VENDOR || 'openai').toLowerCase(),
  azureEndpoint: process.env.AZURE_OPENAI_ENDPOINT || '',
  azureKey: process.env.AZURE_OPENAI_KEY || '',
  azureDeployment: process.env.AZURE_OPENAI_DEPLOYMENT || '',

  // Authentication & JWT
  jwtSecret: process.env.JWT_SECRET || '',

  // Email / magic link settings
  emailFrom: process.env.EMAIL_FROM || '',
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: Number(process.env.SMTP_PORT) || 587,
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',

  // Application settings
  maxFileMB: Number(process.env.MAX_FILE_MB) || 10,
  piiRedaction: (process.env.PII_REDACTION || 'on').toLowerCase() !== 'off',
  allowedOrigins: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
    : [],
  devAuthMode: process.env.DEV_AUTH_MODE || (process.env.NODE_ENV !== 'production' ? 'code_in_response' : ''),
  defaultRegion: (process.env.DEFAULT_REGION || 'us').toLowerCase(),
  dataRetentionMinutes: Number(process.env.DATA_RETENTION_MINUTES) || 0,

  // Logging
  logLevel: (process.env.LOG_LEVEL || 'info').toLowerCase(),
};

module.exports = config;