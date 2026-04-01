<div align="center">

# 🔐 SecureKey Scanner v2.0

**Detect exposed API credentials. Validate them live. Know your blast radius.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)](https://reactjs.org)
[![OWASP](https://img.shields.io/badge/OWASP-API_Top_10_2023-000000?style=flat)](https://owasp.org/API-Security)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

</div>

---

## What It Does

SecureKey Scanner scans source code, files, live websites, and GitHub repositories for hardcoded credentials using **104 regex patterns** across 10 categories. When a credential is found, it validates whether the key is still **active** by calling the real service — returning account identity, permission scopes, and a calculated blast radius.

Every finding maps to the **OWASP API Security Top 10 (2023)** with compliance tags for PCI-DSS, GDPR, HIPAA, SOC2, and ISO 27001.

---

## Live Validation — How It Works

Each supported credential type uses a different read-only API endpoint. No writes. No charges. No side effects.

| Service | Method | What We Get |
|---|---|---|
| **AWS** | AWS Signature V4 → STS GetCallerIdentity | Account ID, IAM ARN, username |
| **GitHub** | Bearer token → GET /user | X-OAuth-Scopes header — exact permissions |
| **GitLab** | PRIVATE-TOKEN → /user + /personal_access_tokens/self | Scopes, is_admin flag, project count |
| **Stripe** | Basic auth → GET /v1/balance | livemode (real money vs test), balance |
| **Slack** | Bearer → POST auth.test | Workspace name, token type, scopes |
| **SendGrid** | Bearer → GET /v3/scopes | Exact API permissions, subscriber count |
| **npm** | Bearer → GET /-/whoami | Username, owned packages, token type |
| **Discord** | Bot token → GET /users/@me | Bot name, accessible guild count |
| **Twilio** | Basic auth → GET /Accounts/{SID} | Account name, type, status |
| **Mailchimp** | Basic auth → GET /3.0/ | Account name, subscriber count |
| **Google API** | URL param → Maps + YouTube + Places | Which services are accessible |
| **JWT** | Local base64 decode — no API call | Algorithm, claims, attack vectors |

**HTTP status meanings (AWS example):**
- `200` → Key is **ACTIVE** — rotate immediately
- `403 InvalidClientTokenId` → Key does not exist or already deleted
- `403 SignatureDoesNotMatch` → Key ID valid but wrong secret

---

## Detection — 104 Patterns Across 10 Categories

| Category | Examples | Count |
|---|---|---|
| Cloud — AWS | Access Key ID, Secret Key | 4 |
| Version Control | GitHub (ghp/gho/ghu/ghs), GitLab (glpat) | 8 |
| Payment | Stripe live/test/restricted, Braintree | 6 |
| Communication | Slack (xoxb/xoxp), Discord, Twilio, Mailchimp | 8 |
| Email delivery | SendGrid, Mailgun, Postmark | 5 |
| Database | MongoDB URI, PostgreSQL, MySQL, Redis | 10 |
| Authentication | JWT tokens, session secrets | 6 |
| Cloud / Infra | GCP, Firebase, Azure, Kubernetes | 12 |
| Package managers | npm, PyPI, RubyGems | 5 |
| Cryptographic | RSA private key, EC key, PEM, PKCS8 | 8 |
| Generic / CI-CD | Generic secrets, Jenkins, Docker Hub, Heroku | 32 |

**Scanning modes:** Code/text input · File upload · Website crawl (JS bundles included) · GitHub repo clone

---

## OWASP API Security Top 10 — 2023 Mapping

| Category | What It Means | What We Detect |
|---|---|---|
| **API2** Broken Authentication | Credentials allow attackers to authenticate as victim | AWS keys, GitHub tokens, Stripe, JWT, Slack |
| **API3** Broken Object Property | APIs expose data that should be private | MongoDB URIs, PostgreSQL, MySQL, Redis |
| **API8** Security Misconfiguration | Secrets in wrong places — code, CI, config files | RSA keys, CI/CD tokens, Docker Hub, Heroku |
| **API10** Unsafe API Consumption | Third-party package credentials enable supply chain attacks | npm tokens, PyPI tokens, RubyGems |

**Compliance tags per finding:**

| Framework | Clause | Triggered By |
|---|---|---|
| PCI-DSS | 6.3, 3.4, 3.2.1 | Stripe key, any payment credential |
| GDPR | Article 32 | Database URI with personal data |
| HIPAA | §164.312 | Healthcare database credentials |
| SOC2 | CC6.1 | Any exposed credential |
| ISO 27001 | A.9.4, A.10.1 | Cryptographic keys, AWS credentials |

---

## Features

- **Risk score 0–100** — Critical×25 + High×10 + Medium×5 + Low×2, capped at 100
- **Blast radius** — calculated from real API scope responses, not guessed
- **AI fix suggestions** — powered by Groq (free). Only masked credential type is sent — real key value never leaves your machine
- **AI security chat** — ask questions about any finding
- **PDF + HTML + JSON export** — full audit-ready reports
- **Email delivery** — scan report with attachments sent to any address
- **Multi-user system** — JWT auth, PBKDF2-HMAC-SHA256 password hashing, brute force protection
- **HTTP header analyzer** — checks CSP, HSTS, CORS, X-Frame-Options
- **Exposed file checker** — tests for /.env, /.git/config, /docker-compose.yml

---

## Security of the Tool Itself

| Protection | What It Prevents |
|---|---|
| CSP with per-request nonces | XSS — no inline scripts without server nonce |
| SSRF + DNS resolution check | Internal network probing via URL scanner |
| 7-layer file upload validation | RCE via webshells, disguised executables |
| IDOR protection | Accessing other users' scan history |
| Brute force lockout (5 attempts / 15 min) | Password guessing |
| Parameterised SQL queries | SQL injection |
| PBKDF2-HMAC-SHA256 (260k iterations) | Password cracking |
| Duplicate parameter blocking | HTTP parameter pollution |
| Path traversal detection | Directory traversal |

---

## Tech Stack

```
Frontend    React 18 · CSS custom properties · Geist font
Backend     Python Flask · SQLite · flask-limiter
Auth        JWT (HS256) · PBKDF2-HMAC-SHA256
AI          Groq API — llama-3.3-70b-versatile (free tier)
Reports     ReportLab (PDF) · HTML templates
Scanning    Python re module — 104 compiled regex patterns
```

---

## Setup

**Requirements:** Python 3.10+, Node.js 18+

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/securekey-scanner.git
cd securekey-scanner

# 2. Configure environment
copy backend\.env.example backend\.env
# Open .env and add your keys (see below)

# 3. Backend
cd backend
pip install -r requirements.txt
python app.py          # runs on http://localhost:5000

# 4. Frontend
cd frontend\scanner-ui
npm install
npm start              # runs on http://localhost:3000
```

Open [http://localhost:3000](http://localhost:3000) → Register → Start scanning.

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in:

```env
# Required for AI features (free — no card needed)
# Get at: console.groq.com → Sign in → API Keys → Create
GROQ_API_KEY=gsk_your_key_here


# Optional — enables email report delivery
SMTP_SENDER_EMAIL=your_gmail@gmail.com
SMTP_SENDER_PASSWORD=your_app_password
```

---

## Project Structure

```
securekey-scanner/
├── backend/
│   ├── app.py              
│   ├── requirements.txt    
│   ├── .env.example        ← copy to .env and fill in your keys
│   └── patterns.json       ← optional pattern override
└── frontend/
    └── scanner-ui/
        └── src/
            ├── App.js      
            └── App.css     
```

---

## Why I Built This

API key leaks are the most common cause of cloud breaches.So this tool detect → validate → quantify impact → fix.

---

<div align="center">
Built by Kavipreethy &nbsp;·&nbsp; React + Flask + OWASP API Top 10
</div>