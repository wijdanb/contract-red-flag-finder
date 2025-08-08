# Contract / PDF Red Flag Finder

Upload a freelance contract in PDF or DOCX format and receive an AI‑generated risk assessment. The tool extracts text locally, optionally redacts personally identifiable information, and passes it to a language model for analysis. The resulting JSON includes an overall risk score, a summary of the major issues and suggested edits for each flagged clause.

> **Not legal advice**: The output provided by this service is for informational purposes only and does not constitute legal advice. Always consult a qualified lawyer before acting on contract recommendations.

## Features

- **Magic link authentication** – users log in via a one‑time code delivered to their email. Sessions are stored in a secure, httpOnly cookie.
- **Consent gate** – users must accept Terms of Service and Privacy Policy before analysing documents.
- **PII redaction** – emails, phone numbers, SSNs and long digit sequences are removed before sending text to the AI. Enabled by default.
- **Region‑aware AI** – automatically routes to OpenAI in the US or Azure OpenAI in the EU based on configuration or user preference.
- **No document retention** – uploaded files are processed from `/tmp` and deleted immediately after extraction. No contract text or secrets are logged or stored.
- **Privacy endpoints** – `/api/privacy/export` and `/api/privacy/delete` return user data or perform deletion (stubbed, since nothing is stored).
- **Subprocessors transparency** – `/api/subprocessors` returns a JSON listing of all vendors used.

## Getting started

### Installation

```bash
# Install dependencies
cd contract_red_flag_finder
npm install
```

### Environment variables

Copy `.env.example` to `.env` and fill in the required keys:

- `OPENAI_API_KEY` – your OpenAI API key (US region).
- `OPENAI_MODEL` – model name (default `gpt-4o-mini`).
- `MODEL_VENDOR` – `openai` or `azure-openai` (default `openai`).
- `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_KEY` / `AZURE_OPENAI_DEPLOYMENT` – required for Azure OpenAI.
- `JWT_SECRET` – strong random string for signing JWTs.
- `EMAIL_FROM` / SMTP credentials – for sending magic links via nodemailer.
- `MAX_FILE_MB` – maximum upload size in MB (default `10`).
- `PII_REDACTION` – `on` or `off` (default `on`).
- `ALLOWED_ORIGINS` – comma‑separated list of allowed front‑end origins.
- `DEV_AUTH_MODE` – set to `code_in_response` during local development to display the login code in the API response instead of sending email.
- `DEFAULT_REGION` – `us` or `eu`; determines which AI provider is used when the user does not specify.
- `DATA_RETENTION_MINUTES` – minutes to retain uploaded files (default `0`, meaning immediate deletion).

### Running locally

The project uses Vercel’s Node runtime. You can run it locally with the Vercel CLI:

```bash
# Install the Vercel CLI if you haven't already
npm i -g vercel

# Run the development server
vercel dev

# Visit http://localhost:3000 in your browser
```

When testing authentication locally, set `DEV_AUTH_MODE=code_in_response` and `ALLOWED_ORIGINS=http://localhost:3000`. The API will return the magic code directly so you can copy/paste it without sending email.

### Deployment

To deploy the project to Vercel:

1. Log in to Vercel (`vercel login`) and follow the prompts.
2. From the project root run `vercel --prod`. The CLI will detect the `vercel.json` configuration and deploy the API endpoints and static assets.
3. After deployment, set the environment variables in the Vercel dashboard using the keys from your `.env` file.

## API overview

| Endpoint | Method | Description |
|---------|--------|-------------|
| `/api/analyze` | `POST` | Authenticated. Accepts a file (PDF/DOCX) and optional `docType` & `region`. Returns AI analysis JSON. |
| `/api/auth/request-code` | `POST` | Public. Sends a magic login link to the specified email (or returns the code in dev mode). |
| `/api/auth/verify-code` | `POST` | Public. Exchanges a valid code for a session cookie. |
| `/api/auth/me` | `GET` | Authenticated. Returns the current user’s email and region. |
| `/api/auth/logout` | `GET` | Authenticated. Clears the session cookie. |
| `/api/subprocessors` | `GET` | Public. Returns a JSON array of third‑party services used by the app. |
| `/api/privacy/export` | `GET` | Authenticated. Stubbed; would return stored user data. |
| `/api/privacy/delete` | `POST` | Authenticated. Stubbed; would delete stored user data. |

## Security & compliance

This project was designed with privacy and security in mind:

- **Strict CORS** using the `ALLOWED_ORIGINS` environment variable.
- **Security headers** (HSTS, Referrer‑Policy, X‑Content‑Type‑Options, X‑Frame‑Options, Permissions‑Policy) applied on every response via `vercel.json` and runtime helpers.
- **Rate limiting** – naive in‑memory limiter restricts each IP to 20 requests per minute per function instance.
- **PII redaction** – on by default; detects emails, phone numbers, SSNs and long digit strings.
- **Immediate file deletion** – uploaded documents are deleted from `/tmp` as soon as they are processed.
- **JSON schema validation** – AI responses are validated with [Zod](https://zod.dev/) before being returned to clients.

## License

This project is provided without warranty of any kind. You are free to adapt and build upon it for your own use.