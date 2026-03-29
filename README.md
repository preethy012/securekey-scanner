# 🔐 SecureKey Scanner v2.0

> **AI-Powered API Credential Exposure Detection Platform**  
> Detects exposed secrets across source code, websites, folders, and GitHub repositories.  
> Maps findings to OWASP API Security Top 10 — 2023 with compliance frameworks.

[![Python](https://img.shields.io/badge/Python-3.9+-blue)](https://python.org)
[![React](https://img.shields.io/badge/React-18.0-61DAFB)](https://reactjs.org)
[![Flask](https://img.shields.io/badge/Flask-2.3-black)](https://flask.palletsprojects.com)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red)](https://owasp.org/API-Security)

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
5. [How to Run](#how-to-run)
6. [How to Test](#how-to-test)
7. [Architecture](#architecture)
8. [Technologies Used](#technologies-used)
9. [Key Functions & Methodology](#key-functions--methodology)
10. [OWASP Mapping](#owasp-mapping)
11. [API Endpoints](#api-endpoints)
12. [Deployment](#deployment)

---

## 🎯 Project Overview

SecureKey Scanner is a **full-stack cybersecurity tool** that detects hardcoded API keys, passwords, tokens, and credentials in source code. It uses **104 regex patterns** across 10 credential categories to find exposed secrets and automatically maps them to industry-standard **OWASP API Security Top 10 — 2023** categories with compliance frameworks (PCI-DSS, GDPR, HIPAA, ISO 27001, SOC2).

### The Problem It Solves

According to the **2023 Verizon Data Breach Report**, 83% of breaches involve credentials. Developers accidentally commit API keys, passwords, and tokens to source code — these can be exploited by attackers within **4 minutes** of exposure on public repositories.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📝 **Text/Code Scan** | Paste any code, config file, or text to detect secrets |
| 🌐 **Website Scan** | Crawl any URL, scan HTML + JavaScript bundles |
| 📁 **Folder Scan** | Upload entire project folder, scan all text files |
| 🐙 **GitHub Scan** | Clone and scan any public GitHub repository |
| 🏛️ **OWASP Mapping** | Auto-map findings to OWASP API Top 10 — 2023 |
| 📊 **Risk Scoring** | 0–100 weighted risk score per scan |
| 🔴 **Live Validation** | Test if found credentials are still active (AWS, GitHub, Stripe, Slack) |
| 🤖 **AI Fix** | Generate fix code + rotation steps per finding (Groq/free AI) |
| 💬 **AI Chat Bot** | Built-in security assistant — answers fix questions offline |
| 🛡️ **Header Analyzer** | OWASP security header checker |
| 📧 **Email Reports** | HTML email + JSON attachment after each scan |
| 📄 **HTML/JSON Export** | Download professional scan reports |
| 🎯 **Pattern Management** | View, filter, enable/disable all 104 detection patterns |
| 📜 **Scan History** | View, re-open, download past scans |
| 🔔 **Desktop Notifications** | Browser notifications on scan completion |

---

## 📁 Project Structure

```
API-KEY-SCANNER/
│
├── backend/                          ← Flask Python backend
│   ├── app.py                        ← Main backend (ALL logic here)
│   ├── .env                          ← Your API keys (never commit this)
│   ├── requirements.txt              ← Python dependencies
│   ├── patterns.json                 ← (optional) pattern export
│   ├── testmail.py                   ← Email testing utility
│   └── validator.py                  ← (optional) standalone validator
│
├── frontend/scanner-ui/              ← React frontend
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── App.js                    ← Main React app (ALL UI here)
│   │   ├── App.css                   ← All styling
│   │   ├── index.js                  ← React entry point
│   │   └── index.css                 ← Base styles
│   ├── package.json                  ← Node dependencies
│   └── README.md                     ← This file
│
├── .gitignore                        ← Git ignore rules
└── .venv/                            ← Python virtual environment
```

### Files to KEEP ✅
```
backend/app.py          ← Core — keep always
backend/.env            ← Your keys — keep, NEVER commit
backend/requirements.txt
frontend/src/App.js
frontend/src/App.css
frontend/src/index.js
frontend/src/index.css
frontend/public/index.html
frontend/package.json
.gitignore
README.md
```

### Files to DELETE ❌
```
backend/__pycache__/    ← Auto-generated, delete
backend/.venv/          ← Virtual env — don't commit
backend/testmail.py     ← Only for testing email, not needed
backend/validator.py    ← Standalone script, not needed
frontend/node_modules/  ← Auto-generated — delete before push
frontend/src/App.test.js
frontend/src/reportWebVitals.js
frontend/src/setupTests.js
frontend/src/logo.svg
.venv/                  ← Root venv — delete
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.9+
- Node.js 16+
- Git

### Backend Setup
```bash
cd backend
python -m venv .venv

# Windows:
.venv\Scripts\activate

# Mac/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### Frontend Setup
```bash
cd frontend/scanner-ui
npm install
```

### Environment Variables
Create `backend/.env`:
```env
# Required for AI Fix feature (free — get at console.groq.com)
GROQ_API_KEY=gsk_your_groq_key_here

# Required for Email Reports (Gmail App Password)
SMTP_SENDER_EMAIL=your@gmail.com
SMTP_SENDER_PASSWORD=your_16_char_app_password
```

---

## 🚀 How to Run

### Start Backend (Terminal 1)
```bash
cd backend
.venv\Scripts\activate    # Windows
python app.py
# Running on http://localhost:5000
```

### Start Frontend (Terminal 2)
```bash
cd frontend/scanner-ui
npm start
# Running on http://localhost:3000
```

Open browser: `http://localhost:3000`

---

## 🧪 How to Test

### Test 1 — Text/Code Scan
Go to **Dashboard → Code/Text** tab. Paste:
```python
AWS_ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID_HERE"
GITHUB_TOKEN = "GITHUB_TOKEN_HERE"
STRIPE_SECRET_KEY = "STRIPE_SECRET_KEY_HERE"
MONGODB_URI = "mongodb://<username>:<password>@<host>/<db>"
SLACK_TOKEN = "SLACK_TOKEN_HERE"
NPM_TOKEN = "NPM_TOKEN_HERE"
```
Expected: 6+ findings | Risk Score 100 | OWASP 3 violated

### Test 2 — Website Scan
Go to **Dashboard → Website** tab. Enter:
```
https://httpbin.org
```
Expected: Header security issues detected

### Test 3 — Folder Scan
Go to **Dashboard → Folder** tab. Select any project folder.
Expected: Scans all .py, .js, .env, .yaml files

### Test 4 — GitHub Scan
Go to **Dashboard → GitHub** tab. Enter:
```
https://github.com/OWASP/wrongsecrets
```
Expected: 400+ files, 800+ findings, Risk Score 100

### Test 5 — Header Analyzer
Go to **Headers** tab. Enter:
```
https://httpbin.org
```
Expected: Missing HSTS, CSP, X-Frame-Options

### Test 6 — OWASP Report
Run Text Scan first → Click **OWASP Top 10** tab
Expected: Violation cards with compliance tags

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         React Frontend (Port 3000)       │
│  Dashboard | OWASP | Headers | History  │
│  AI Chat Bot | AI Fix Modal             │
└──────────────┬──────────────────────────┘
               │ HTTP REST API (axios)
               ▼
┌─────────────────────────────────────────┐
│         Flask Backend (Port 5000)        │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │   Scanner   │  │   OWASP Engine   │  │
│  │  104 Regex  │  │  10 Categories   │  │
│  │  Patterns   │  │  + Compliance    │  │
│  └─────────────┘  └──────────────────┘  │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │  Web Crawler│  │  Live Validator  │  │
│  │  BFS + JS   │  │  AWS/GitHub/     │  │
│  │  Bundles    │  │  Stripe/Slack    │  │
│  └─────────────┘  └──────────────────┘  │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │  AI Fix     │  │  Risk Scorer     │  │
│  │  Groq API   │  │  0-100 weighted  │  │
│  │  (free)     │  │  scoring         │  │
│  └─────────────┘  └──────────────────┘  │
└─────────────────────────────────────────┘
               │
     ┌─────────┴──────────┐
     ▼                    ▼
┌─────────┐        ┌───────────┐
│ Groq AI │        │  GitHub   │
│  (free) │        │   Repos   │
└─────────┘        └───────────┘
```

---

## 🛠️ Technologies Used

### Backend
| Technology | Version | Purpose |
|---|---|---|
| Python | 3.9+ | Core language |
| Flask | 2.3+ | REST API server |
| Flask-CORS | 4.0+ | Cross-origin requests |
| Flask-Limiter | 3.5+ | Rate limiting |
| BeautifulSoup4 | 4.12+ | HTML parsing for URL scan |
| GitPython | 3.1+ | GitHub repo cloning |
| Requests | 2.31+ | HTTP calls (crawler + validators) |
| Werkzeug | 3.0+ | Secure file handling |

### Frontend
| Technology | Version | Purpose |
|---|---|---|
| React | 18.0+ | UI framework |
| Axios | 1.6+ | HTTP API calls |
| CSS3 | — | Custom dark theme |

### AI / External APIs
| Service | Cost | Purpose |
|---|---|---|
| Groq (Llama3) | **FREE** | AI Fix suggestions |
| Anthropic Claude | Paid | (optional) Better AI quality |

---

## 🔬 Key Functions & Methodology

### 1. `SecretDetector.scan_text()` — Core Detection Engine
**Method:** Regex pattern matching  
**How it works:**
- Runs all 104 compiled regex patterns against input text
- Calculates SHA-256 hash of each match to avoid duplicates
- Calls `is_false_positive()` to filter test/dummy values
- Returns structured findings with context, position, severity

```python
def scan_text(text, source='text_input'):
    for pname, pcfg in self.patterns.items():
        for match in re.compile(pcfg['pattern']).finditer(text):
            secret = match.group(0)
            hash   = sha256(secret)
            if hash in seen: continue
            if is_false_positive(secret, context): continue
            findings.append({...owasp_info, compliance, impact})
```

### 2. `is_false_positive()` — Noise Reduction
**Method:** Heuristic filtering  
**Checks:**
- Contains placeholder indicators: `your_`, `replace_`, `TODO`, `<your`
- Matches low-entropy patterns: `xxx+`, `000+`, `aaa+`
- Secret has fewer than 5 unique characters (not a real key)

### 3. `WebCrawler.crawl()` — URL Scanner
**Method:** BFS (Breadth-First Search) web crawling  
**How it works:**
- Starts at the given URL, fetches HTML
- Extracts all `<a href>` links on same domain
- Visits each link up to `max_depth=2` levels deep
- Also calls `scan_js_bundles()` to download all `<script src>` files
- Runs all 104 patterns against page text + raw HTML + JS bundles

### 4. `scan_github()` — GitHub Repository Scanner
**Method:** Git shallow clone + recursive file walk  
**How it works:**
- Uses `subprocess git clone --depth=1` (gets latest commit only, fast)
- Walks all files using `os.walk()`
- Skips `node_modules`, `.git`, `__pycache__`, binary files >2MB
- Scans every text file: `.py`, `.js`, `.env`, `.yaml`, `.key`, `.pem`, etc.

### 5. `calculate_risk_score()` — Risk Scoring
**Method:** Weighted severity scoring  
**Formula:**
```
score = min(
    (critical × 25) + (high × 10) + (medium × 5) + (low × 2),
    100
)
```
- Critical = 25 points (e.g., AWS key, private key)
- High = 10 points (e.g., GitHub token, Stripe key)
- Medium = 5 points (e.g., JWT, UUID)
- Low = 2 points (e.g., entropy strings)

### 6. `get_owasp_summary()` — OWASP Compliance Report
**Method:** Pattern-to-category mapping  
**How it works:**
- Each of the 104 patterns is pre-mapped to an OWASP category
- After a scan, findings are grouped by OWASP category
- Calculates: violated categories, passing categories, compliance %
- Maps to compliance frameworks: PCI-DSS, GDPR, HIPAA, ISO 27001, SOC2

### 7. Live Key Validators — Credential Verification
**Method:** Read-only API calls to real services  
**Services supported:**

| Service | API Called | What it checks |
|---|---|---|
| AWS | STS GetCallerIdentity | Account ID, IAM user, active? |
| GitHub | GET /user | Username, email, scopes, active? |
| Stripe | GET /v1/balance | Balance, live/test mode, active? |
| Slack | auth.test | Workspace name, user, active? |
| SendGrid | GET /v3/user/profile | Email, username, active? |
| GitLab | GET /api/v4/user | Username, admin status, active? |
| npm | GET /-/whoami | Username, active? |

All calls are **read-only** — no data is modified.

### 8. AI Fix Suggestion — `get_fix_suggestion()`
**Method:** LLM prompt engineering  
**How it works:**
1. Receives finding details (type, severity, context, OWASP category)
2. Looks up `FIX_GUIDES` dictionary for credential-specific rotation steps
3. Builds a detailed prompt with finding context
4. Calls **Groq API** (Llama3 model, free)
5. Returns JSON with: `fixed_code`, `rotation_steps`, `prevention_tips`, `risk_explanation`
6. Falls back to static template if AI unavailable

### 9. AI Chat Bot — `generateSecurityResponse()`
**Method:** Pattern-matched intent detection (runs 100% offline, no API needed)  
**How it works:**
- Analyzes user question for keywords
- Detects intent: rotate / git-history / python-fix / node-fix / risk / report
- Generates specific response based on **finding type** (AWS vs GitHub vs DB)
- No API key needed — runs entirely in browser JavaScript

### 10. HTTP Header Analyzer — `scan_headers()`
**Method:** HTTP response header inspection  
**Checks for:**
- Missing: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`
- Info leakage: `Server`, `X-Powered-By`, `X-Runtime`
- CORS misconfiguration: `Access-Control-Allow-Origin: *`

### 11. `group_duplicate_findings()` — Deduplication
**Method:** SHA-256 hash grouping  
**How it works:**
- Groups findings with identical secret hash
- Tracks all source files where the same secret appears
- Shows: "This AWS key appears in 4 files — rotate once to fix all"

---

## 🏛️ OWASP Mapping

| OWASP Category | Credentials Detected | % of Findings |
|---|---|---|
| API2 — Broken Authentication | AWS, GitHub, Stripe, JWT, Google, Azure | ~60% |
| API3 — Data Exposure | MongoDB, PostgreSQL, MySQL, Redis | ~20% |
| API8 — Misconfiguration | Slack, private keys, CI/CD tokens | ~15% |
| API10 — Unsafe APIs | npm, PyPI, RubyGems, NuGet | ~5% |
| API1,4,5,6,7,9 | Require runtime testing — not detectable statically | 0% |

**Why only 4 categories?**  
Static credential scanning can only detect hardcoded secrets. OWASP categories API1, API4, API5, API6, API7, and API9 require live runtime testing with actual API calls — this is outside the scope of static analysis. This is consistent with industry tools like GitGuardian and TruffleHog.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/scan/text` | Scan text input |
| POST | `/api/scan/url` | Scan website URL |
| POST | `/api/scan/file` | Scan single file |
| POST | `/api/scan/github` | Scan GitHub repo |
| POST | `/api/scan/headers` | HTTP header analysis |
| POST | `/api/fix-suggestion` | AI fix for finding |
| POST | `/api/validate-key` | Live credential test |
| GET | `/api/validate-key/supported` | Supported validators list |
| POST | `/api/owasp/summary` | OWASP compliance report |
| GET | `/api/owasp/top10` | OWASP reference data |
| POST | `/api/report/html` | Generate HTML report |
| POST | `/api/send-email` | Send scan email report |
| GET | `/api/patterns` | List all 104 patterns |

---

## 🚀 Deployment

### Deploy Backend (Render.com — Free)
```bash
# 1. Push backend/ to GitHub
# 2. Go to render.com → New Web Service
# 3. Connect GitHub repo → Select backend/ folder
# 4. Build command: pip install -r requirements.txt
# 5. Start command: python app.py
# 6. Add environment variables: GROQ_API_KEY, SMTP_SENDER_EMAIL etc.
```

### Deploy Frontend (Vercel — Free)
```bash
# 1. Push frontend/scanner-ui to GitHub
# 2. Go to vercel.com → New Project
# 3. Import GitHub repo
# 4. Framework: Create React App
# 5. Change API_URL in App.js to your Render backend URL
# 6. Deploy
```

### .gitignore (Important)
Make sure these are in your `.gitignore`:
```
backend/.env
backend/__pycache__/
backend/.venv/
frontend/node_modules/
*.pyc
.DS_Store
```

---

## 🔒 Security Features

- **Rate Limiting** — 100 req/hour per IP (Flask-Limiter)
- **SSRF Protection** — Blocks AWS metadata endpoint (169.254.169.254), private IPs
- **Input Sanitization** — Max 100,000 chars, null byte removal
- **CORS Restriction** — Only allows localhost:3000 and localhost:3001
- **File Size Limit** — Max 10MB per file upload
- **Secure Filename** — Werkzeug secure_filename() on uploads

---

## 📊 Detection Statistics

- **Total Patterns:** 104
- **Categories:** 10 (Cloud, Database, Payment, Communication, CI/CD, Cryptography, Auth, Social, Package Manager, Generic)
- **Cloud Providers:** AWS (7), GCP (4), Azure (6), Heroku, DigitalOcean, Cloudflare, Alibaba, Linode, Vultr
- **Databases:** MongoDB, PostgreSQL, MySQL, MSSQL, Redis, Elasticsearch, CouchDB, Neo4j, InfluxDB, Oracle, DynamoDB
- **Payment:** Stripe, PayPal, Square, Braintree, Shopify
- **Communication:** Slack, Discord, Twilio, SendGrid, MailChimp, Mailgun
- **Version Control:** GitHub (4 token types), GitLab (3), Bitbucket

---

## 👨‍💻 Built With

- **Frontend:** React.js 18, CSS3 (custom dark theme)
- **Backend:** Python 3.9, Flask 2.3
- **AI:** Groq (Llama3-8b, free tier)
- **Security Standard:** OWASP API Security Top 10 — 2023
- **Compliance:** PCI-DSS 3.2.1, GDPR Article 32, HIPAA §164.312, ISO 27001, SOC2, NIST CSF

---

## 📄 License

MIT License — Free to use for educational and commercial purposes.

---

*Built as a final year cybersecurity project demonstrating full-stack development, AI integration, and industry-standard security practices.*