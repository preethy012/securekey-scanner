import React, { useState, useEffect, useRef } from 'react';
import './App.css';
import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scanType, setScanType] = useState('text');
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [copyNotification, setCopyNotification] = useState(false);
  const [uploadedFolder, setUploadedFolder] = useState(null);
  const [folderFiles, setFolderFiles] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, totalScans: 0 });
  // ── AUTH STATE ──
  const [currentUser, setCurrentUser] = useState(null);
  const [authToken, setAuthToken]     = useState(() => localStorage.getItem('sk_token') || null);
  const [authView, setAuthView]       = useState('login'); // 'login' | 'register'
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError]     = useState('');
  const [authForm, setAuthForm]       = useState({ name:'', username:'', password:'' });
  const [showPassword, setShowPassword] = useState(false);

  // Load user from token on startup
  useEffect(() => {
    if (authToken) {
      axios.get(`${API_URL}/auth/me`, { headers: { Authorization: `Bearer ${authToken}` } })
        .then(r => setCurrentUser(r.data))
        .catch(() => { localStorage.removeItem('sk_token'); setAuthToken(null); });
    }
  }, [authToken]);

  const handleLogin = async (e) => {
    e && e.preventDefault();
    setAuthLoading(true); setAuthError('');
    try {
      const r = await axios.post(`${API_URL}/auth/login`, {
        username: authForm.username, password: authForm.password
      });
      localStorage.setItem('sk_token', r.data.token);
      setAuthToken(r.data.token);
      setCurrentUser(r.data.user);
    } catch (err) {
      setAuthError(err.response?.data?.error || 'Login failed');
    } finally { setAuthLoading(false); }
  };

  const handleRegister = async (e) => {
    e && e.preventDefault();
    if (!authForm.name.trim()) { setAuthError('Name is required'); return; }
    if (authForm.password.length < 8) { setAuthError('Password must be at least 8 characters'); return; }
    setAuthLoading(true); setAuthError('');
    try {
      const r = await axios.post(`${API_URL}/auth/register`, {
        name: authForm.name, username: authForm.username,
        password: authForm.password
      });
      localStorage.setItem('sk_token', r.data.token);
      setAuthToken(r.data.token);
      setCurrentUser(r.data.user);
    } catch (err) {
      setAuthError(err.response?.data?.error || 'Registration failed');
    } finally { setAuthLoading(false); }
  };

  const handleLogout = () => {
    localStorage.removeItem('sk_token');
    setAuthToken(null);
    setCurrentUser(null);
    setResults(null);
    setScanHistory([]);
    setAuthForm({ name:'', username:'', password:'' });
    setAuthError('');
  };

  // Add auth header to all API calls
  const authHeaders = authToken ? { Authorization: `Bearer ${authToken}` } : {};
  const [patterns, setPatterns] = useState([]);
  const [loadingPatterns, setLoadingPatterns] = useState(false);
  const [allPatterns, setAllPatterns] = useState([]);
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [emailAddress, setEmailAddress] = useState('');
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [pendingScanResults, setPendingScanResults] = useState(null);

  // AI Fix Suggestions state
  const [showFixModal, setShowFixModal] = useState(false);
  const [fixFinding, setFixFinding] = useState(null);
  const [fixResult, setFixResult] = useState(null);
  const [fixLoading, setFixLoading] = useState(false);
  const [fixError, setFixError] = useState(null);
  const [fixTab, setFixTab] = useState('fix');

  // AI Chat Bot inside Fix modal
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = React.useRef(null);

  // Live Key Validator state
  const [validationResults, setValidationResults] = useState({}); // keyed by secret_hash
  const [validatingKeys, setValidatingKeys] = useState({}); // loading state per finding
  const [supportedPatterns, setSupportedPatterns] = useState([]);
  const [autoValidating, setAutoValidating] = useState(false);

  // NEW: Header scan state
  const [headerScanUrl, setHeaderScanUrl] = useState('');
  const [headerResults, setHeaderResults] = useState(null);
  const [headerLoading, setHeaderLoading] = useState(false);

  // OWASP state
  const [owaspReport, setOwaspReport] = useState(null);
  const [owaspLoading, setOwaspLoading] = useState(false);

  // Severity filter for results
  const [severityFilter, setSeverityFilter] = useState('all');

  const folderInputRef = useRef(null);

  useEffect(() => {
    const savedHistory = localStorage.getItem('scanHistory');
    if (savedHistory) setScanHistory(JSON.parse(savedHistory));
    const savedStats = localStorage.getItem('scanStats');
    if (savedStats) setStats(JSON.parse(savedStats));
    const savedEmail = localStorage.getItem('userEmail');
    if (savedEmail) setEmailAddress(savedEmail);
    const savedEmailEnabled = localStorage.getItem('emailEnabled');
    if (savedEmailEnabled !== null) setEmailEnabled(JSON.parse(savedEmailEnabled));
    const savedNotif = localStorage.getItem('notificationsEnabled');
    if (savedNotif !== null) setNotificationsEnabled(JSON.parse(savedNotif));
    fetchPatterns();
    // Load supported validator patterns
    axios.get(`${API_URL}/validate-key/supported`)
      .then(r => setSupportedPatterns(r.data.supported_patterns || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
    localStorage.setItem('scanStats', JSON.stringify(stats));
  }, [scanHistory, stats]);

  useEffect(() => { localStorage.setItem('emailEnabled', JSON.stringify(emailEnabled)); }, [emailEnabled]);
  useEffect(() => { localStorage.setItem('notificationsEnabled', JSON.stringify(notificationsEnabled)); }, [notificationsEnabled]);

  const fetchPatterns = async () => {
    setLoadingPatterns(true);
    try {
      const response = await axios.get(`${API_URL}/patterns`);
      if (response.data && response.data.patterns) {
        const disabledPatterns = JSON.parse(localStorage.getItem('disabledPatterns') || '[]');
        const transformedPatterns = response.data.patterns.map((p, index) => ({
          id: index + 1,
          name: p.description || p.name,
          pattern: p.pattern,
          severity: p.severity,
          enabled: !disabledPatterns.includes(p.description || p.name),
          category: p.category,
          description: p.description,
          examples: getExampleForPattern(p.name, p.pattern)
        }));
        setPatterns(transformedPatterns);
        setAllPatterns(transformedPatterns);
      }
    } catch (error) {
      console.error('Error fetching patterns:', error);
      setPatterns([]);
      setAllPatterns([]);
    } finally {
      setLoadingPatterns(false);
    }
  };

  const getExampleForPattern = (name, pattern) => {
    const examples = {
      'AWS': 'AKIA...', 'GitHub': 'ghp_...', 'Stripe': 'sk_live_...', 'Google': 'AIza...',
      'Slack': 'xox...', 'Azure': 'DefaultEndpoints...', 'MongoDB': 'mongodb://...',
      'PostgreSQL': 'postgresql://...', 'JWT': 'eyJ...', 'Private Key': '-----BEGIN...',
    };
    for (const [key, example] of Object.entries(examples)) {
      if (name.includes(key)) return example;
    }
    return pattern.substring(0, 30) + '...';
  };

  const sendDesktopNotification = (title, body) => {
    if (!notificationsEnabled) return;
    if ('Notification' in window) {
      if (Notification.permission === 'granted') new Notification(title, { body, icon: '🔐' });
      else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(p => {
          if (p === 'granted') new Notification(title, { body, icon: '🔐' });
        });
      }
    }
  };

  useEffect(() => {
    if (notificationsEnabled && 'Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, [notificationsEnabled]);

  const downloadJSON = (data, filename) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename || `scan-results-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // NEW: Download HTML report
  const downloadHTMLReport = async (scanData) => {
    try {
      const response = await axios.post(`${API_URL}/report/html`, {
        findings: scanData.findings,
        scanTarget: scanData.scanTarget,
        riskScore: scanData.riskScore
      });
      if (response.data.html) {
        const blob = new Blob([response.data.html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = response.data.filename || `securekey-report-${Date.now()}.html`;
        link.click();
        URL.revokeObjectURL(url);
        showNotification('📄 HTML Report downloaded!');
      }
    } catch (e) {
      console.error('HTML report error:', e);
      // Fallback: generate client-side
      const blob = new Blob([`<html><body><h1>SecureKey Report</h1><p>${scanData.findings.length} findings</p></body></html>`], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `securekey-report-${Date.now()}.html`;
      link.click();
      URL.revokeObjectURL(url);
    }
  };

  // AI Fix Suggestion handler
  const handleGetAIFix = async (finding) => {
    setFixFinding(finding);
    setFixResult(null);
    setFixError(null);
    setFixLoading(true);
    setFixTab('fix');
    setShowFixModal(true);
    // Reset chat with context-aware welcome message based on finding type
    const category = finding.category || 'Unknown';
    const credType = finding.type || 'credential';
    const owasp = finding.owasp?.owasp_id || '';
    setChatMessages([{
      role: 'assistant',
      content: `Hi! I'm your AI security assistant 🔐\n\nI have full context about this **${credType}** finding:\n• Severity: **${finding.severity?.toUpperCase()}**\n• Category: ${category}\n• OWASP: ${owasp ? owasp + ' — ' + (finding.owasp?.owasp_name || '') : 'Not mapped'}\n• Source: ${finding.source || 'Unknown'}\n\nI can help you with:\n• Step-by-step rotation guide for this specific credential\n• Secure replacement code in any language\n• Git commands to purge this from commit history\n• Writing an incident report for your team\n• Explaining the real-world risk to a non-technical manager\n\nWhat do you need help with?`
    }]);
    setChatInput('');
    try {
      const response = await axios.post(`${API_URL}/fix-suggestion`, {
        finding,
        context: finding.context || ''
      });
      setFixResult(response.data);
    } catch (err) {
      setFixError(err.response?.data?.error || 'Failed to get AI suggestion. Check backend is running.');
    } finally {
      setFixLoading(false);
    }
  };

  // AI Chat message sender
  const sendChatMessage = async () => {
    const msg = chatInput.trim();
    if (!msg || chatLoading) return;
    setChatInput('');
    setChatMessages(prev => [...prev, { role: 'user', content: msg }]);
    setChatLoading(true);
    setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);

    // Simulate small thinking delay
    await new Promise(r => setTimeout(r, 400 + Math.random() * 300));

    try {
      // First try offline engine (instant, no API needed)
      const offlineReply = generateSecurityResponse(msg, fixFinding, fixResult);

      if (offlineReply !== null) {
        // Offline engine handled it
        setChatMessages(prev => [...prev, { role: 'assistant', content: offlineReply }]);
      } else {
        // Offline engine didn't recognise the question → send to Groq AI
        const groqReply = await sendToGroqChat(msg, fixFinding);
        setChatMessages(prev => [...prev, { role: 'assistant', content: groqReply }]);
      }
    } catch (e) {
      setChatMessages(prev => [...prev, {
        role: 'assistant',
        content: '❌ Something went wrong. Please try again or rephrase your question.'
      }]);
    } finally {
      setChatLoading(false);
      setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    }
  };

  // Smart security response engine — works 100% offline, no API needed
  const generateSecurityResponse = (question, finding, fixData) => {
    const q    = question.toLowerCase().trim();
    const type = (finding?.type || '').toLowerCase();
    const cat  = (finding?.category || '').toLowerCase();
    const sev  = (finding?.severity || 'unknown').toUpperCase();
    const src  = finding?.source || 'your file';
    const owasp = finding?.owasp?.owasp_id || '';

    const any = (...words) => words.some(w => q.includes(w));
    const all = (...words) => words.every(w => q.includes(w));

    const isAws    = type.includes('aws') || cat.includes('aws');
    const isGithub = type.includes('github') || type.includes('gitlab');
    const isStripe = type.includes('stripe') || cat.includes('payment');
    const isDb     = type.includes('database') || type.includes('mongo') || type.includes('mysql') || type.includes('postgres');
    const isJwt    = type.includes('jwt');

    // EXPLAIN
    if (any('what is', 'explain', 'what does', 'what are', 'meaning', 'means', 'tell me about', 'describe')) {
      if (isAws)    return `**AWS IAM Access Key** lets programs access your Amazon Web Services account.\n\nTwo parts:\n• Access Key ID — like a username (starts with AKIA)\n• Secret Access Key — like a password (40 characters)\n\n**Why dangerous:**\n• Attacker spins up EC2 servers for crypto mining (YOUR bill: $10,000+)\n• Reads or deletes all your S3 data\n• Creates backdoor admin accounts`;
      if (isGithub) return `**GitHub Personal Access Token** lets programs use GitHub on your behalf.\n\nStarts with ghp_ — used instead of your password.\n\n**Why dangerous:**\n• Read all your private repositories\n• Push malicious code to your repos\n• Delete branches or repositories\n• Bots scan GitHub every 4 minutes for these tokens`;
      if (isStripe) return `**Stripe Secret Key** gives full access to your payment account.\n\nsk_live_ = real money, sk_test_ = test only.\n\n**Why dangerous:**\n• Access all customer payment data\n• Issue refunds to attacker account (money theft)\n• Cancel customer subscriptions\n• Download your entire customer list`;
      if (isJwt)    return `**JWT (JSON Web Token)** proves a user is logged in.\n\n3 parts: header.payload.signature\n\nPayload contains: User ID, role (admin/user), expiry time.\n\n**Why dangerous:** Attacker uses this token to log in AS THAT USER — no password needed.\n\nPentest note: RS256 tokens may be vulnerable to algorithm confusion attacks.`;
      if (isDb)     return `**Database Connection String** contains everything to connect to a database: server, name, username, password.\n\n**Why dangerous:**\n• Download ALL customer data in minutes\n• Delete or modify any record\n• GDPR violation — fines up to 20 million euros`;
      return null;
    }

    // ATTACKER
    if (any('attacker', 'hacker', 'if they got', 'if stolen', 'if leaked', 'what can they', 'misuse', 'if got this')) {
      if (isAws)    return `**If attacker gets your AWS key:**\n\nStep 1 — Confirm it works:\naws sts get-caller-identity\n(Returns account ID and username)\n\nStep 2 — Enumerate:\naws s3 ls\naws ec2 describe-instances\naws secretsmanager list-secrets\n\nStep 3 — Attack:\n• Launch EC2 servers for crypto mining (your bill)\n• Download all S3 data\n• Create backdoor admin IAM user\n• Delete CloudTrail logs\n\nAverage cost to victim in first 24 hours: $13,000`;
      if (isGithub) return `**If attacker gets your GitHub token:**\n\nStep 1 — Check scopes:\ncurl -H "Authorization: token TOKEN" https://api.github.com/user\n\nStep 2 — Clone all private repos:\ngit clone https://TOKEN@github.com/org/private-repo\n\nStep 3 — Find more secrets in private code, push malicious code, or take over the entire org if admin:org scope exists`;
      if (isStripe) return `**If attacker gets your Stripe key:**\n\nThey run:\ncurl https://api.stripe.com/v1/charges -u sk_live_KEY:\ncurl https://api.stripe.com/v1/customers -u sk_live_KEY:\n\nWhat they do:\n• Download full customer list\n• Issue refunds to their own card (direct money theft)\n• Cancel subscriptions\n• This is the most financially damaging credential type`;
      if (isDb)     return `**If attacker gets your database URI:**\n\nThey connect directly:\nfrom pymongo import MongoClient\nclient = MongoClient("YOUR_URI")\nfor user in db.users.find(): print(user)\n\nWhat they do:\n• Dump entire database in minutes\n• Find hashed passwords and brute force them\n• Delete everything (ransomware)\n• GDPR: you must notify users within 72 hours`;
      if (isJwt)    return `**If attacker gets a JWT token:**\n\nStep 1 — Use it directly:\ncurl -H "Authorization: Bearer TOKEN" https://target.com/api/profile\n(Instant access as that user — no cracking needed)\n\nStep 2 — Try to forge a new token:\n• HS256: try common weak secrets\n• RS256: try algorithm confusion attack\n• alg:none: remove signature entirely\n\nStep 3 — Change role claim to admin, or user_id to access other accounts`;
      return null;
    }

    // PENTESTER
    if (any('pentest', 'pentester', 'how to test', 'how to use', 'how to exploit', 'test this', 'use this key', 'use this token')) {
      if (isAws)    return `**Pentester workflow for AWS key:**\n\nPhase 1 — Validate (SecureKey already did this):\nCheck Live Validation panel for account ID, ARN, username.\n\nPhase 2 — Enumerate with AWS CLI:\naws configure set aws_access_key_id AKIA...\naws configure set aws_secret_access_key SECRET\naws sts get-caller-identity\naws s3 ls\naws ec2 describe-instances\naws secretsmanager list-secrets\naws iam list-attached-user-policies\n\nPhase 3 — Automated tool:\npip install pacu\npacu then run aws__enum_account_info`;
      if (isGithub) return `**Pentester workflow for GitHub token:**\n\nPhase 1 — Read scopes:\ncurl -H "Authorization: token TOKEN" https://api.github.com/user\nCheck X-OAuth-Scopes header in response.\n\nPhase 2 — List all repos:\ncurl -H "Authorization: token TOKEN" https://api.github.com/user/repos?type=all\n\nPhase 3 — Scan private repos:\ngit clone https://TOKEN@github.com/org/private-repo\nThen run SecureKey folder scan on the cloned repo.`;
      if (isJwt)    return `**Pentester workflow for JWT token:**\n\nPhase 1 — Decode (SecureKey already did this):\nCheck Live Validation panel for algorithm, kid, subject, expiry, attack vectors.\n\nPhase 2 — Test algorithm confusion:\npip install jwt_tool\npython3 jwt_tool.py TOKEN -T\n\nPhase 3 — Test kid injection:\nChange kid to: ../../../../dev/null\nSign with empty string as secret.\n\nPhase 4 — Escalate:\nChange sub claim to admin user ID or role to admin.\n\nPortSwigger lab: Your token uses RS256 + kid — perfect for algorithm confusion.`;
      return null;
    }

    // PYTHON FIX
    if (any('python', 'django', 'flask', 'fastapi') && any('fix', 'how', 'code', 'example')) {
      const v = isAws ? 'AWS_ACCESS_KEY_ID' : isGithub ? 'GITHUB_TOKEN' : isStripe ? 'STRIPE_SECRET_KEY' : isDb ? 'DATABASE_URL' : 'SECRET_KEY';
      return `**Fix in Python:**\n\n1. Create .env file (never commit this):\n${v}=your_value_here\n\n2. Install python-dotenv:\npip install python-dotenv\n\n3. Load in your code:\nimport os\nfrom dotenv import load_dotenv\nload_dotenv()\n${v} = os.environ.get("${v}")\nif not ${v}: raise ValueError("${v} not set")\n\n4. Add .env to .gitignore`;
    }

    // NODE FIX
    if (any('node', 'nodejs', 'javascript', 'express') && any('fix', 'how', 'code')) {
      const v = isAws ? 'AWS_ACCESS_KEY_ID' : isStripe ? 'STRIPE_SECRET_KEY' : isGithub ? 'GITHUB_TOKEN' : 'SECRET_KEY';
      return `**Fix in Node.js:**\n\n1. Install dotenv:\nnpm install dotenv\n\n2. Create .env file:\n${v}=your_value_here\n\n3. Load in your app:\nrequire("dotenv").config();\nconst key = process.env.${v};\nif (!key) throw new Error("${v} not set");\n\n4. Add .env to .gitignore`;
    }

    // ROTATE / REVOKE
    if (any('rotate', 'revoke', 'how to fix', 'what do i do', 'fix this', 'remediat')) {
      if (isAws)    return `**Rotate AWS Key:**\n1. AWS Console → IAM → Users → Security credentials\n2. Create new access key\n3. Update .env with new key + secret\n4. Test app works\n5. Deactivate old key\n6. After 24h delete old key\n7. Check CloudTrail for unauthorized usage`;
      if (isGithub) return `**Revoke GitHub Token:**\n1. github.com → Settings → Developer settings → Personal access tokens\n2. Find token → Click Delete\n3. Generate new token with minimum scopes\n4. Update .env file`;
      if (isStripe) return `**Rotate Stripe Key:**\n1. dashboard.stripe.com → Developers → API keys\n2. Click Roll key\n3. Update .env and redeploy\n4. Check Stripe logs for unauthorized calls`;
      return `**Rotate this credential:**\n1. Go to provider dashboard\n2. Create new key FIRST\n3. Update .env with new value\n4. Test everything works\n5. Delete old key\n6. Check logs for unauthorized usage`;
    }

    // IS ACTIVE
    if (all('is', 'live') || all('is', 'active') || all('still', 'working') || all('still', 'valid')) {
      return `Check the **Live Credential Validation** panel above the findings list.\n\n🔴 ACTIVE — rotate immediately\n✅ REVOKED — already dead, safe\n🔍 Format Only — needs secret key to fully test\n\nOr click the Test Live button on the finding card.`;
    }

    // GIT HISTORY
    if (any('git', 'history', 'commit', 'pushed') && any('remove', 'delete', 'clean', 'purge', 'how')) {
      return `**Remove from git history:**\n\ngit filter-branch --force --index-filter "git rm --cached --ignore-unmatch ${src}" --prune-empty --tag-name-filter cat -- --all\ngit push origin --force --all\n\nEasier option: java -jar bfg.jar --delete-files ${src}\n\nIMPORTANT: Also rotate the credential — removing from history does not invalidate active keys.`;
    }

    // SECURE STORAGE
    if (any('store', 'storage', 'safely', 'best practice', 'vault') && any('how', 'where', 'what')) {
      return `**Secure storage options:**\n\n1. .env file — create, add to .gitignore, use python-dotenv\n2. AWS Secrets Manager — for production AWS apps\n3. HashiCorp Vault — open source self-hosted\n4. Doppler — free tier, easy setup\n5. Platform env vars — Heroku, Vercel, Railway\n\nNever hardcode secrets. Never commit .env to git.`;
    }

    // RISK
    if (any('risk', 'worst case', 'what happen', 'what if', 'impact', 'danger', 'serious')) {
      const detail = isAws ? `• Crypto mining on your AWS account ($10,000+ bills)\n• All S3 data stolen or deleted\n• Backdoor admin account created` :
                     isGithub ? `• All private code stolen\n• Malicious code pushed to repos\n• More secrets found in private repos` :
                     isStripe ? `• Customer payment data stolen\n• Fraudulent refunds (direct money theft)\n• GDPR breach notification required` :
                     isDb ? `• Full database dump in minutes\n• All customer PII stolen\n• GDPR fine up to 20 million euros` :
                     isJwt ? `• Attacker logs in as that user\n• Admin token = full application access` :
                     `• Unauthorized API access at your expense\n• Your account may be suspended`;
      return `**Worst case for ${finding?.type || 'this credential'} (${sev}):**\n\n${detail}\n\nBots scan GitHub every 4 minutes. Average exploitation time after exposure: 4 minutes.\n\nRotate NOW and check your access logs.`;
    }

    // INCIDENT REPORT
    if (any('incident', 'report', 'cto', 'manager', 'boss', 'team', 'write', 'template')) {
      const today = new Date().toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric' });
      return `SECURITY INCIDENT REPORT\nDate: ${today} | Severity: ${sev}\n\nSummary: A ${finding?.type || 'credential'} was found exposed in ${src}.\nOWASP: ${owasp}\n\nActions Taken:\n• Credential rotated immediately\n• Git history cleaned\n• Audit logs reviewed\n• .env file created, .gitignore updated\n\nRoot Cause: Credential hardcoded instead of using environment variable.\n\nPrevention: Pre-commit hooks + SecureKey Scanner in CI/CD pipeline.\n\nFill in dates and send to your team.`;
    }

    // WHERE TO RUN
    if (any('where', 'terminal', 'command prompt', 'cmd', 'run this', 'put this command')) {
      return `**Run in your terminal:**\n\nWindows: Press Win+R → type cmd → Enter\ncd C:\\path\\to\\your\\project\n\nMac/Linux: Open Terminal\ncd ~/your-project\n\nVerify git: git --version\nVerify Python: python --version`;
    }

    return null;
  };

  // Send any unrecognised question to Groq via Flask backend
  const sendToGroqChat = async (question, finding) => {
    try {
      const systemPrompt = `You are a cybersecurity expert assistant. The user is asking about a security finding in their code.

FINDING DETAILS:
- Type: ${finding?.type || 'Unknown credential'}
- Severity: ${finding?.severity?.toUpperCase() || 'Unknown'}
- Category: ${finding?.category || 'Unknown'}
- Source: ${finding?.source || 'Unknown'}
- OWASP: ${finding?.owasp?.owasp_id || 'Unknown'} — ${finding?.owasp?.owasp_name || ''}

Answer the user's question clearly and specifically about this credential type.
Use simple language. Give exact steps, commands, or code when relevant.
Keep response under 200 words unless more detail is needed.
Format with bullet points or numbered steps when listing items.`;

      const response = await axios.post(`${API_URL}/chat`, {
        system: systemPrompt,
        messages: [{ role: 'user', content: question }]
      });
      return response.data.reply || 'Sorry, could not get a response. Try rephrasing your question.';
    } catch (e) {
      // Final fallback if Groq also fails
      return `**${finding?.type || 'Credential'} — Quick Answer:**\n\nI couldn't connect to the AI service right now. Here's what I know:\n\n• This is a ${finding?.severity} severity ${finding?.category} credential\n• It was found in: ${finding?.source}\n• OWASP category: ${finding?.owasp?.owasp_id} — ${finding?.owasp?.owasp_name}\n\nFor detailed help, try asking:\n• "How do I rotate this?"\n• "How do I fix this in Python?"\n• "What is the worst case risk?"\n• "Write an incident report"`;
    }
  };

  // Live Key Validator handler
  const handleValidateKey = async (finding) => {
    const hash = finding.secret_hash;
    setValidatingKeys(prev => ({ ...prev, [hash]: true }));
    try {
      const response = await axios.post(`${API_URL}/validate-key`, { finding });
      setValidationResults(prev => ({ ...prev, [hash]: response.data }));
    } catch (err) {
      setValidationResults(prev => ({
        ...prev,
        [hash]: {
          active: null,
          status: 'error',
          message: err.response?.data?.error || 'Validation failed — check backend connection'
        }
      }));
    } finally {
      setValidatingKeys(prev => ({ ...prev, [hash]: false }));
    }
  };

  const isValidatable = (finding) =>
    supportedPatterns.includes(finding.pattern_name) ||
    ['critical','high'].includes(finding.severity);

  // OWASP helpers
  const getOwaspReport = async (findings) => {
    if (!findings || findings.length === 0) { setOwaspReport(null); return; }
    setOwaspLoading(true);
    try {
      const res = await axios.post(`${API_URL}/owasp/summary`, { findings });
      setOwaspReport(res.data);
    } catch (e) {
      console.error('OWASP summary error:', e);
    } finally {
      setOwaspLoading(false);
    }
  };

  const getOwaspBadgeColor = (status) => status === 'FAIL' ? '#ef4444' : '#10b981';
  const getOwaspBg = (status) => status === 'FAIL' ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)';
  const getOwaspBorder = (status) => status === 'FAIL' ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)';

  const getValidationBadge = (result) => {
    if (!result) return null;
    if (result.status === 'active')                return { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.4)',   icon: '🔴', label: 'ACTIVE — ROTATE NOW' };
    if (result.status === 'revoked')               return { color: '#10b981', bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.4)', icon: '✅', label: 'Already Revoked' };
    if (result.status === 'format_only')           return { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', icon: '🔍', label: 'Valid Format' };
    if (result.status === 'no_secret')             return { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.3)',icon: '🔒', label: 'Secret Masked' };
    if (result.status === 'wrong_secret')          return { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', icon: '⚠️', label: 'Key ID Found' };
    if (result.status === 'secret_without_key_id') return { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', icon: '⚠️', label: 'SECRET LEAKED — Rotate immediately' };
    return { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.3)', icon: '❓', label: 'Unknown' };
  };

  const showNotification = (msg) => {
    setCopyNotification(msg);
    setTimeout(() => setCopyNotification(false), 3000);
  };

  const sendEmailNotification = async (email, scanData) => {
    const { findings, totalFindings, scanTarget, riskScore } = scanData;
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high     = findings.filter(f => f.severity === 'high').length;
    const medium   = findings.filter(f => f.severity === 'medium').length;
    const low      = findings.filter(f => f.severity === 'low').length;
    try {
      const response = await axios.post(`${API_URL}/send-email`, {
        to: email, critical, high, medium, low, totalFindings, scanTarget, findings, riskScore,
        timestamp: new Date().toISOString()
      });
      if (response.data.success) showNotification(`📧 Email sent to ${email}`);
      else showNotification(`⚠️ Email not sent: ${response.data.message}`);
    } catch (e) {
      const errMsg = e.response?.data?.error || e.message || 'Unknown error';
      showNotification(`❌ Email failed: ${errMsg}`);
    }
  };

  const handleEmailModalSubmit = async () => {
    if (!emailAddress.trim()) { alert('Please enter a valid email address'); return; }
    localStorage.setItem('userEmail', emailAddress);
    setShowEmailModal(false);
    if (pendingScanResults) {
      await sendEmailNotification(emailAddress, pendingScanResults);
      downloadJSON(pendingScanResults.rawData, `scan-results-${Date.now()}.json`);
      setPendingScanResults(null);
    }
  };

  const handlePostScan = async (responseData, scanTarget) => {
    const findings = responseData.findings || [];
    const totalFindings = responseData.total_findings || 0;
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'low').length;
    const riskScore = responseData.risk_score || { score: 0, level: 'Unknown', color: '#94a3b8', emoji: '' };

    sendDesktopNotification(
      `🔐 SecureKey Scan Complete`,
      `Found ${totalFindings} secrets | Risk: ${riskScore.score}/100 | 🔴${critical} Critical | 🟠${high} High`
    );

    const scanData = { findings, totalFindings, critical, high, medium, low, scanTarget, riskScore, rawData: responseData };

    if (emailEnabled) {
      if (!emailAddress.trim()) {
        setPendingScanResults(scanData);
        setShowEmailModal(true);
      } else {
        await sendEmailNotification(emailAddress, scanData);
        downloadJSON(responseData, `scan-results-${Date.now()}.json`);
      }
    }
  };

  const handleFolderSelect = (e) => {
    const files = Array.from(e.target.files);
    if (files.length === 0) return;
    const folderName = files[0].webkitRelativePath.split('/')[0];
    setUploadedFolder(folderName);
    setFolderFiles(files);
  };

  const handleScan = async () => {
    if (scanType === 'folder' && folderFiles.length === 0) { setError('Please select a folder to scan'); return; }
    if (scanType !== 'folder' && !input.trim()) { setError('Please provide input to scan'); return; }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      let response;
      let scanTarget = '';

      if (scanType === 'text') {
        scanTarget = 'Text Input';
        response = await axios.post(`${API_URL}/scan/text`, { text: input });
      } else if (scanType === 'url') {
        scanTarget = input;
        response = await axios.post(`${API_URL}/scan/url`, { url: input, max_depth: 2, max_pages: 20 });
      } else if (scanType === 'folder') {
        scanTarget = uploadedFolder || 'Folder';
        const textExtensions = ['.txt','.json','.js','.py','.java','.c','.cpp','.h','.env','.config','.yaml','.yml','.xml','.md','.html','.css','.php','.rb','.go','.rs','.ts','.jsx','.tsx','.sh','.bash','.sql','.properties','.conf','.ini','.log'];
        const allFindings = [];
        let filesScanned = 0;

        for (const file of folderFiles) {
          const ext = '.' + file.name.split('.').pop().toLowerCase();
          if (!textExtensions.includes(ext)) continue;
          try {
            const content = await new Promise((resolve, reject) => {
              const reader = new FileReader();
              reader.onload = e => resolve(e.target.result);
              reader.onerror = reject;
              reader.readAsText(file);
            });
            const formData = new FormData();
            formData.append('file', new Blob([content], { type: 'text/plain' }), file.name);
            const fileResponse = await axios.post(`${API_URL}/scan/file`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
            if (fileResponse.data.findings) {
              allFindings.push(...fileResponse.data.findings.map(f => ({ ...f, source: file.webkitRelativePath || file.name })));
            }
            filesScanned++;
          } catch (e) { console.warn(`Could not scan file: ${file.name}`, e); }
        }

        response = { data: { total_findings: allFindings.length, findings: allFindings, files_scanned: filesScanned, folder_name: uploadedFolder, risk_score: null } };
      } else if (scanType === 'github') {
        scanTarget = input;
        response = await axios.post(`${API_URL}/scan/github`, { repo_url: input, max_depth: 2 });
      }

      setResults(response.data);

      const newScan = {
        id: Date.now(), type: scanType,
        target: scanTarget.substring(0, 50) + (scanTarget.length > 50 ? '...' : ''),
        findings: response.data.total_findings,
        riskScore: response.data.risk_score,
        timestamp: new Date().toISOString(), timeAgo: 'Just now',
        severity: response.data.total_findings > 0 ? (response.data.findings?.some(f => f.severity === 'critical') ? 'critical' : 'high') : 'success',
        fullResults: response.data
      };

      setScanHistory(prev => [newScan, ...prev.slice(0, 49)]);
      updateStats(response.data.findings || []);
      await handlePostScan(response.data, scanTarget);
      getOwaspReport(response.data.findings || []);

      // Auto-validate all critical and high findings in background
      const findingsToValidate = (response.data.findings || []).filter(f =>
        ['critical','high'].includes(f.severity) && supportedPatterns.includes(f.pattern_name)
      ).slice(0, 10); // max 10 to avoid rate limiting

      if (findingsToValidate.length > 0) {
        setAutoValidating(true);
        const results = {};
        for (const finding of findingsToValidate) {
          try {
            const vRes = await axios.post(`${API_URL}/validate-key`, { finding });
            results[finding.secret_hash] = vRes.data;
          } catch (e) { /* silent fail per key */ }
          await new Promise(r => setTimeout(r, 300)); // small delay between calls
        }
        setValidationResults(prev => ({ ...prev, ...results }));
        setAutoValidating(false);
      }

      if (scanType === 'folder') { setUploadedFolder(null); setFolderFiles([]); }

    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  // NEW: Header scan handler
  const handleHeaderScan = async () => {
    if (!headerScanUrl.trim()) return;
    setHeaderLoading(true);
    setHeaderResults(null);
    try {
      const response = await axios.post(`${API_URL}/scan/headers`, { url: headerScanUrl });
      setHeaderResults(response.data);
    } catch (err) {
      setHeaderResults({ error: err.response?.data?.error || 'Header scan failed' });
    } finally {
      setHeaderLoading(false);
    }
  };

  const updateStats = (findings) => {
    const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
    setStats(prev => ({ critical: counts.critical || 0, high: counts.high || 0, medium: counts.medium || 0, low: counts.low || 0, totalScans: prev.totalScans + 1 }));
  };

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text).then(() => { showNotification(label); });
  };

  const deleteScan = (id) => setScanHistory(scanHistory.filter(scan => scan.id !== id));
  const clearAllHistory = () => { if (window.confirm('Clear all scan history?')) { setScanHistory([]); localStorage.removeItem('scanHistory'); } };
  const viewScanDetails = (scan) => { setResults(scan.fullResults); setActiveTab('dashboard'); window.scrollTo({ top: 0, behavior: 'smooth' }); };
  const exportResults = () => downloadJSON(results, `scan-results-${Date.now()}.json`);

  // PDF Report download
  const downloadPDFReport = async (scanData) => {
    try {
      const payload = {
        findings:    scanData.findings    || results?.findings    || [],
        scanTarget:  scanData.scanTarget  || 'Scan Results',
        riskScore:   scanData.riskScore   || results?.risk_score  || 0,
        owaspReport: owaspReport          || null,
      };
      showNotification('⏳ Generating PDF report...');
      const response = await axios.post(`${API_URL}/report/pdf`, payload, {
        responseType: 'blob',
        timeout: 30000,
      });
      const url  = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href  = url;
      link.setAttribute('download', `securekey-report-${Date.now()}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      showNotification('✅ PDF Report downloaded!');
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'PDF generation failed';
      if (msg.includes('reportlab')) {
        setError('PDF requires reportlab: run  pip install reportlab  then restart Flask');
      } else {
        setError('PDF download failed: ' + msg);
      }
    }
  };

  const formatTimestamp = (timestamp) => new Date(timestamp).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });

  const getTimeAgo = (timestamp) => {
    const diffMs = new Date() - new Date(timestamp);
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  const getScanTypeIcon = (type) => ({ text: '📝', url: '🌐', github: '🐙', folder: '📁' }[type] || '📄');

  const getSeverityColor = (severity) => ({
    critical: '#ef4444', high: '#f59e0b', medium: '#fbbf24', low: '#10b981', success: '#22c55e'
  }[severity] || '#6b7280');

  const getCategoryIcon = (category) => {
    if (!category) return '📝';
    const cat = category.toLowerCase();
    if (cat.includes('cloud') || cat.includes('aws') || cat.includes('azure') || cat.includes('gcp')) return '☁️';
    if (cat.includes('payment')) return '💳';
    if (cat.includes('database')) return '🗄️';
    if (cat.includes('communication')) return '💬';
    if (cat.includes('version')) return '🔀';
    if (cat.includes('ci/cd')) return '🔧';
    if (cat.includes('auth')) return '🔐';
    if (cat.includes('crypto')) return '🔑';
    if (cat.includes('social')) return '📱';
    if (cat.includes('package')) return '📦';
    if (cat.includes('firebase')) return '🔥';
    return '📄';
  };

  const filterPatternsByCategory = (category) => {
    setPatterns(category === 'all' ? allPatterns : allPatterns.filter(p => p.category?.toLowerCase().includes(category.toLowerCase())));
  };
  const filterPatternsBySeverity = (severity) => {
    setPatterns(severity === 'all' ? allPatterns : allPatterns.filter(p => p.severity === severity));
  };
  const resetPatternFilters = () => setPatterns(allPatterns);

  const getRiskScoreDisplay = (riskScore) => {
    if (!riskScore) return null;
    return (
      <div className="risk-score-display" style={{ borderColor: riskScore.color, background: `${riskScore.color}15` }}>
        <div className="risk-score-number" style={{ color: riskScore.color }}>{riskScore.score}</div>
        <div className="risk-score-info">
          <div className="risk-score-label" style={{ color: riskScore.color }}>{riskScore.emoji} {riskScore.level}</div>
          <div className="risk-score-sub">Risk Score / 100</div>
          <div className="risk-bar-container">
            <div className="risk-bar-fill" style={{ width: `${riskScore.score}%`, background: riskScore.color }}></div>
          </div>
        </div>
      </div>
    );
  };

  // ── AUTH SCREEN — shown when not logged in ──
  if (!currentUser) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="auth-logo">
            <div className="auth-logo-icon">🔐</div>
            <h1 className="auth-logo-title">SecureKey</h1>
            <span className="auth-logo-version">v2.0</span>
          </div>

          <div className="auth-tabs">
            <button className={`auth-tab-btn ${authView==='login' ? 'active':''}`} onClick={()=>{setAuthView('login');setAuthError('');}}>Sign In</button>
            <button className={`auth-tab-btn ${authView==='register' ? 'active':''}`} onClick={()=>{setAuthView('register');setAuthError('');}}>Create Account</button>
          </div>

          {authError && <div className="auth-error">⚠️ {authError}</div>}

          {authView === 'login' ? (
            <form className="auth-form" onSubmit={handleLogin}>
              <div className="auth-field">
                <label className="auth-label">Username</label>
                <input className="auth-input" type="text" placeholder="your_username"
                  value={authForm.username} onChange={e=>setAuthForm(p=>({...p,username:e.target.value.toLowerCase()}))} required autoFocus autoComplete="username" />
              </div>
              <div className="auth-field">
                <label className="auth-label">Password</label>
                <div className="auth-input-wrap">
                  <input className="auth-input" type={showPassword?'text':'password'} placeholder="Your password"
                    value={authForm.password} onChange={e=>setAuthForm(p=>({...p,password:e.target.value}))} required autoComplete="current-password" />
                  <button type="button" className="auth-eye" onClick={()=>setShowPassword(p=>!p)}>{showPassword?'🙈':'👁️'}</button>
                </div>
              </div>
              <button type="submit" className="auth-submit" disabled={authLoading}>
                {authLoading ? <><span className="spinner" style={{width:'14px',height:'14px',marginRight:'8px'}}></span>Signing in...</> : '→ Sign In'}
              </button>
              <p className="auth-hint">Don't have an account? <span className="auth-link" onClick={()=>{setAuthView('register');setAuthError('');}}>Create one →</span></p>
            </form>
          ) : (
            <form className="auth-form" onSubmit={handleRegister}>
              <div className="auth-field">
                <label className="auth-label">Full Name</label>
                <input className="auth-input" type="text" placeholder="John Smith"
                  value={authForm.name} onChange={e=>setAuthForm(p=>({...p,name:e.target.value}))} required autoFocus autoComplete="name" />
              </div>
              <div className="auth-field">
                <label className="auth-label">Username <span style={{color:'var(--text-muted)',fontSize:'0.75rem'}}>(letters, numbers, underscore)</span></label>
                <input className="auth-input" type="text" placeholder="john_smith"
                  value={authForm.username} onChange={e=>setAuthForm(p=>({...p,username:e.target.value.toLowerCase().replace(/[^a-z0-9_]/g,'')}))} required autoComplete="username" />
              </div>
              <div className="auth-field">
                <label className="auth-label">Password <span style={{color:'var(--text-muted)',fontSize:'0.75rem'}}>(min 8 chars)</span></label>
                <div className="auth-input-wrap">
                  <input className="auth-input" type={showPassword?'text':'password'} placeholder="Create strong password"
                    value={authForm.password} onChange={e=>setAuthForm(p=>({...p,password:e.target.value}))} required autoComplete="new-password" />
                  <button type="button" className="auth-eye" onClick={()=>setShowPassword(p=>!p)}>{showPassword?'🙈':'👁️'}</button>
                </div>
              </div>
              <button type="submit" className="auth-submit" disabled={authLoading}>
                {authLoading ? <><span className="spinner" style={{width:'14px',height:'14px',marginRight:'8px'}}></span>Creating account...</> : '→ Create Account'}
              </button>
              <p className="auth-hint">Already have an account? <span className="auth-link" onClick={()=>{setAuthView('login');setAuthError('');}}>Sign in →</span></p>
            </form>
          )}

          <div className="auth-features">
            <div className="auth-feature-item">🔍 104 detection patterns</div>
            <div className="auth-feature-item">🏛️ OWASP API Top 10</div>
            <div className="auth-feature-item">🔴 Live validation</div>
            <div className="auth-feature-item">🤖 AI Fix suggestions</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      {/* Loading Overlay */}
      {loading && (
        <div className="loading-overlay">
          <div className="loading-container">
            <div className="hacker-scene">
              <div className="hacker-avatar">👨‍💻</div>
              <div className="key-stream"><span className="key">🔑</span><span className="key">🔑</span><span className="key">🔑</span></div>
              <div className="firewall">🔥🧱</div>
            </div>
            <div className="loading-text">
              <h3>🔍 Scanning for Exposed Secrets...</h3>
              <div className="loading-steps">
                <div className="step">✓ Analyzing patterns</div>
                <div className="step active">→ Detecting credentials</div>
                <div className="step">○ Validating findings</div>
              </div>
            </div>
            <div className="progress-bar"><div className="progress-fill"></div></div>
          </div>
        </div>
      )}

      {copyNotification && <div className="copy-notification">✓ {copyNotification}</div>}

      {/* Email Modal */}
      {showEmailModal && (
        <div className="modal-overlay" onClick={() => setShowEmailModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>📧 Enter Email Address</h3>
              <button className="modal-close" onClick={() => setShowEmailModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <p style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Enter your email to receive the scan report with findings summary and JSON results.</p>
              {pendingScanResults && (
                <div style={{ background: 'rgba(102,126,234,0.1)', border: '1px solid rgba(102,126,234,0.3)', borderRadius: '8px', padding: '1rem', marginBottom: '1rem' }}>
                  <p style={{ margin: 0, fontWeight: 600 }}>Scan Complete: {pendingScanResults.totalFindings} findings</p>
                  {pendingScanResults.riskScore && (
                    <p style={{ margin: '0.5rem 0 0', fontSize: '0.875rem', color: pendingScanResults.riskScore.color }}>
                      {pendingScanResults.riskScore.emoji} Risk Score: {pendingScanResults.riskScore.score}/100 — {pendingScanResults.riskScore.level}
                    </p>
                  )}
                  <p style={{ margin: '0.5rem 0 0', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                    🔴 {pendingScanResults.critical} Critical &nbsp; 🟠 {pendingScanResults.high} High &nbsp; 🟡 {pendingScanResults.medium} Medium &nbsp; 🟢 {pendingScanResults.low} Low
                  </p>
                </div>
              )}
              <input type="email" className="text-input" placeholder="your@email.com" value={emailAddress}
                onChange={(e) => setEmailAddress(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleEmailModalSubmit()} autoFocus style={{ marginBottom: '0.5rem' }} />
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Your email is saved locally for future scans.</p>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => {
                setShowEmailModal(false);
                if (pendingScanResults) { downloadJSON(pendingScanResults.rawData, `scan-results-${Date.now()}.json`); setPendingScanResults(null); }
              }}>Skip, Just Download</button>
              <button className="btn-primary" onClick={handleEmailModalSubmit}>📧 Send & Download</button>
            </div>
          </div>
        </div>
      )}

            {/* AI Fix Suggestion Modal */}
      {showFixModal && (
        <div className="modal-overlay" onClick={() => setShowFixModal(false)}>
          <div className="modal-content fix-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header fix-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div className="ai-icon-badge">🤖</div>
                <div>
                  <h3>AI Fix Suggestion</h3>
                  {fixFinding && (
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
                      <span className="severity-badge" style={{ backgroundColor: getSeverityColor(fixFinding.severity), color: '#fff', fontSize: '0.65rem', padding: '2px 6px', marginRight: '6px' }}>
                        {fixFinding.severity?.toUpperCase()}
                      </span>
                      {fixFinding.type}
                    </p>
                  )}
                </div>
              </div>
              <button className="modal-close" onClick={() => setShowFixModal(false)}>×</button>
            </div>

            {/* Tab bar */}
            <div className="fix-tabs">
              {[['fix','🔧 Fixed Code'],['rotate','🔄 Rotate Steps'],['prevent','🛡️ Prevention'],['chat','💬 AI Chat']].map(([id,label]) => (
                <button
                  key={id}
                  className={`fix-tab-btn ${fixTab === id ? 'active' : ''}`}
                  onClick={() => setFixTab(id)}
                  disabled={fixLoading && id !== 'chat'}
                >{label}{id === 'chat' && chatMessages.length > 1 && <span style={{ marginLeft: '4px', background: 'var(--accent-purple)', color: '#fff', borderRadius: '10px', padding: '0 5px', fontSize: '0.65rem' }}>{chatMessages.length - 1}</span>}</button>
              ))}
            </div>

            <div className="modal-body fix-modal-body">
              {fixLoading && (
                <div className="fix-loading">
                  <div className="fix-loading-animation">
                    <div className="ai-pulse">🤖</div>
                    <div className="fix-loading-bars">
                      <div className="fix-bar"></div>
                      <div className="fix-bar"></div>
                      <div className="fix-bar"></div>
                    </div>
                  </div>
                  <p>Claude is analyzing your finding and generating a fix...</p>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Checking credential type • Writing rotation steps • Generating fixed code</p>
                </div>
              )}

              {fixError && (
                <div className="alert alert-error" style={{ marginBottom: 0 }}>
                  <span>❌</span>
                  <span>{fixError}</span>
                </div>
              )}

              {fixResult && !fixLoading && (
                <>
                  {/* Risk explanation always visible at top */}
                  {fixResult.risk_explanation && (
                    <div className="fix-risk-banner">
                      <div className="fix-risk-icon">⚠️</div>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '0.85rem', color: '#fca5a5', marginBottom: '0.25rem' }}>What an attacker can do with this credential</div>
                        <p style={{ margin: 0, fontSize: '0.875rem', color: '#fecaca', lineHeight: 1.6 }}>{fixResult.risk_explanation}</p>
                      </div>
                    </div>
                  )}

                  {/* Fixed Code Tab */}
                  {fixTab === 'fix' && (
                    <div className="fix-section">
                      <div className="fix-section-header">
                        <span>🔧 Fixed Code</span>
                        <button className="btn-action" style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                          onClick={() => { copyToClipboard(fixResult.fixed_code, 'Fixed code copied!'); }}>
                          📋 Copy
                        </button>
                      </div>
                      <pre className="fix-code-block">{fixResult.fixed_code}</pre>
                      {fixResult.rotation_url && (
                        <a href={fixResult.rotation_url} target="_blank" rel="noopener noreferrer" className="fix-docs-link">
                          📖 Official rotation docs →
                        </a>
                      )}
                    </div>
                  )}

                  {/* Rotation Steps Tab */}
                  {fixTab === 'rotate' && (
                    <div className="fix-section">
                      <div className="fix-section-header">
                        <span>🔄 Rotation Steps</span>
                        <button className="btn-action" style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                          onClick={() => { copyToClipboard(Array.isArray(fixResult.rotation_steps) ? fixResult.rotation_steps.join('\n') : fixResult.rotation_steps, 'Steps copied!'); }}>
                          📋 Copy All
                        </button>
                      </div>
                      <div className="fix-steps-list">
                        {(Array.isArray(fixResult.rotation_steps) ? fixResult.rotation_steps : [fixResult.rotation_steps]).map((step, i) => (
                          <div key={i} className="fix-step">
                            <div className="fix-step-num">{i + 1}</div>
                            <div className="fix-step-text">{step}</div>
                          </div>
                        ))}
                      </div>
                      {fixResult.rotation_url && (
                        <a href={fixResult.rotation_url} target="_blank" rel="noopener noreferrer" className="fix-docs-link">
                          📖 Official rotation docs →
                        </a>
                      )}
                    </div>
                  )}

                  {/* Prevention Tab */}
                  {fixTab === 'prevent' && (
                    <div className="fix-section">
                      <div className="fix-section-header">
                        <span>🛡️ Prevention Tips</span>
                      </div>
                      <div className="fix-tips-list">
                        {(Array.isArray(fixResult.prevention_tips) ? fixResult.prevention_tips : [fixResult.prevention_tips]).map((tip, i) => (
                          <div key={i} className="fix-tip">
                            <div className="fix-tip-icon">✅</div>
                            <div className="fix-tip-text">{tip}</div>
                          </div>
                        ))}
                      </div>
                      <div className="fix-tools-box">
                        <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--accent-blue)' }}>
                          🔧 Recommended Tools
                        </div>
                        {[
                          { name: 'detect-secrets', desc: 'Pre-commit hook that blocks secret commits', cmd: 'pip install detect-secrets' },
                          { name: 'git-secrets', desc: 'AWS-maintained git hook scanner', cmd: 'brew install git-secrets' },
                          { name: 'python-dotenv', desc: 'Load .env files into environment', cmd: 'pip install python-dotenv' },
                          { name: 'HashiCorp Vault', desc: 'Enterprise-grade secrets manager', cmd: 'vault kv put secret/myapp key=value' },
                        ].map((tool, i) => (
                          <div key={i} className="fix-tool-item">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)' }}>{tool.name}</span>
                              <button className="btn-action" style={{ padding: '2px 8px', fontSize: '0.7rem' }}
                                onClick={() => copyToClipboard(tool.cmd, `${tool.name} command copied!`)}>
                                📋
                              </button>
                            </div>
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '2px' }}>{tool.desc}</div>
                            <code className="fix-tool-cmd">{tool.cmd}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {fixResult.source === 'static_fallback' && (
                    <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.75rem', textAlign: 'center' }}>
                      ⚡ Using static guide (AI service unavailable)
                    </p>
                  )}
                </>
              )}

              {/* AI CHAT TAB — always visible regardless of fixResult */}
              {fixTab === 'chat' && (
                <div className="fix-chat-container">
                  {/* Header with clear button */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                      💬 Ask anything about fixing this {fixFinding?.type || 'issue'}
                    </span>
                    {chatMessages.length > 1 && (
                      <button className="btn-text" style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                        onClick={() => setChatMessages([chatMessages[0]])}>
                        🗑️ Clear
                      </button>
                    )}
                  </div>

                  {/* Dynamic quick suggestion pills based on credential type */}
                  <div className="chat-suggestions">
                    {(() => {
                      const type = (fixFinding?.type || '').toLowerCase();
                      const cat  = (fixFinding?.category || '').toLowerCase();
                      const base = [
                        'Explain this risk to my manager',
                        'Write git command to remove from history',
                        'How to store this securely?',
                        'What is the worst case if not fixed?',
                      ];
                      const specific =
                        type.includes('aws') || cat.includes('aws')       ? ['How to rotate in AWS Console?', 'Check CloudTrail for unauthorized use'] :
                        type.includes('github') || type.includes('gitlab') ? ['How to revoke on GitHub?', 'Scan all my repos for this token'] :
                        type.includes('stripe') || cat.includes('payment') ? ['How to roll Stripe key?', 'Check Stripe logs for fraud'] :
                        type.includes('database') || cat.includes('db')    ? ['How to change DB password?', 'Write connection string with env var'] :
                        type.includes('private key') || type.includes('ssh')? ['How to generate new SSH key?', 'Remove key from all servers'] :
                        type.includes('slack')                             ? ['How to revoke Slack token?', 'Check Slack audit logs'] :
                        type.includes('jwt')                               ? ['How to invalidate all JWTs?', 'Implement token rotation'] :
                        ['How do I fix this in Python?', 'How do I fix this in Node.js?'];
                      return [...specific, ...base].slice(0, 5).map((s, i) => (
                        <button key={i} className="chat-suggestion-pill"
                          onClick={() => {
                            setChatInput(s);
                            setTimeout(() => {
                              const inp = document.querySelector('.chat-input');
                              if (inp) inp.focus();
                            }, 50);
                          }}>
                          {s}
                        </button>
                      ));
                    })()}
                  </div>

                  {/* Messages */}
                  <div className="chat-messages">
                    {chatMessages.map((msg, i) => (
                      <div key={i} className={`chat-bubble ${msg.role}`}>
                        {msg.role === 'assistant' && (
                          <div className="chat-avatar">🤖</div>
                        )}
                        <div className="chat-bubble-content">
                          {msg.content.split('\n').map((line, j) => {
                            if (!line.trim()) return null;
                            // Render inline code
                            const withCode = line.replace(/`([^`]+)`/g,
                              '<code style="background:rgba(0,0,0,0.35);padding:1px 5px;border-radius:4px;font-family:monospace;font-size:0.78rem;color:#22d3ee">$1</code>');
                            // Bold text
                            const withBold = withCode.replace(/\*\*([^*]+)\*\*/g,
                              '<strong>$1</strong>');
                            return (
                              <p key={j} style={{ margin: j === 0 ? 0 : '0.35rem 0 0', fontSize: '0.85rem', lineHeight: 1.6 }}
                                dangerouslySetInnerHTML={{ __html: withBold }} />
                            );
                          })}
                        </div>
                        {msg.role === 'user' && (
                          <div className="chat-avatar user-avatar-chat">U</div>
                        )}
                      </div>
                    ))}
                    {chatLoading && (
                      <div className="chat-bubble assistant">
                        <div className="chat-avatar">🤖</div>
                        <div className="chat-bubble-content">
                          <div className="chat-typing">
                            <span></span><span></span><span></span>
                          </div>
                        </div>
                      </div>
                    )}
                    <div ref={chatEndRef} />
                  </div>

                  {/* Input box */}
                  <div className="chat-input-row">
                    <input
                      className="chat-input"
                      type="text"
                      value={chatInput}
                      onChange={e => setChatInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendChatMessage()}
                      placeholder={`Ask about fixing this ${fixFinding?.type || 'issue'}...`}
                      disabled={chatLoading}
                      autoFocus={fixTab === 'chat'}
                    />
                    <button
                      className="chat-send-btn"
                      onClick={sendChatMessage}
                      disabled={chatLoading || !chatInput.trim()}
                    >
                      {chatLoading
                        ? <span className="spinner" style={{ width: '14px', height: '14px' }}></span>
                        : '➤'}
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowFixModal(false)}>Close</button>
              {fixResult && (
                <button className="btn-primary" onClick={() => {
                  const text = `AI Fix for: ${fixFinding?.type}\n\nFIXED CODE:\n${fixResult.fixed_code}\n\nROTATION STEPS:\n${Array.isArray(fixResult.rotation_steps) ? fixResult.rotation_steps.join('\n') : ''}\n\nPREVENTION:\n${Array.isArray(fixResult.prevention_tips) ? fixResult.prevention_tips.join('\n') : ''}`;
                  copyToClipboard(text, '📋 Full fix guide copied!');
                }}>
                  📋 Copy Full Guide
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">🔐</div>
          <h1>SecureKey</h1>
          <span className="logo-version">v2.0</span>
        </div>

        <nav className="nav">
          {[
            { id: 'dashboard', icon: '📊', label: 'Dashboard' },
            { id: 'owasp', icon: '🛡️', label: 'OWASP Top 10' },
            { id: 'headers', icon: '🔒', label: 'Headers' },
            { id: 'history', icon: '📜', label: 'History', badge: scanHistory.length },
            { id: 'patterns', icon: '🎯', label: 'Patterns', badge: patterns.length },
          ].map(item => (
            <button key={item.id} className={`nav-item ${activeTab === item.id ? 'active' : ''}`} onClick={() => setActiveTab(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              {item.label}
              {item.badge > 0 && <span className="badge">{item.badge}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div style={{ marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>🔔 Desktop Alerts</span>
              <label className="toggle-switch" style={{ transform: 'scale(0.85)' }}>
                <input type="checkbox" checked={notificationsEnabled} onChange={(e) => { setNotificationsEnabled(e.target.checked); if (e.target.checked && 'Notification' in window) Notification.requestPermission(); }} />
                <span className="toggle-slider"></span>
              </label>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>📧 Email Alerts</span>
              <label className="toggle-switch" style={{ transform: 'scale(0.85)' }}>
                <input type="checkbox" checked={emailEnabled} onChange={(e) => { setEmailEnabled(e.target.checked); if (e.target.checked && !emailAddress.trim()) { setPendingScanResults(null); setShowEmailModal(true); } }} />
                <span className="toggle-slider"></span>
              </label>
            </div>
            {emailEnabled && emailAddress && (
              <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem', wordBreak: 'break-all' }}>
                → {emailAddress}
                <span style={{ color: 'var(--accent-blue)', cursor: 'pointer', marginLeft: '0.5rem' }} onClick={() => { setShowEmailModal(true); setPendingScanResults(null); }}>edit</span>
              </p>
            )}
          </div>
          <div className="user-profile">
            <div className="user-avatar">{(currentUser.name || currentUser.username || 'U').charAt(0)}</div>
            <div className="user-info">
              <div className="user-name">{currentUser.name}</div>
              <div className="user-role" style={{textTransform:'capitalize'}}>{currentUser.role}</div>
            </div>
          </div>
          <button className="logout-full-btn" onClick={handleLogout}>
            <span>⏻</span> Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="header">
          <div className="header-left">
            <h2>API Key Exposure Scanner</h2>
            <p className="header-subtitle">Detect exposed secrets • <span style={{color:"var(--accent-orange)",fontWeight:500}}>{patterns.length}</span> active patterns • Real-time scanning</p>
          </div>
          <div className="header-right">
            {results && (
              <>
                <button className="btn-secondary" onClick={exportResults}><span>📥</span> Export JSON</button>
                <button className="btn-secondary" onClick={() => downloadHTMLReport({ findings: results.findings, scanTarget: 'Scan Results', riskScore: results.risk_score })}><span>📄</span> HTML Report</button>
                <button className="btn-secondary" onClick={() => downloadPDFReport({ findings: results.findings, scanTarget: 'Scan Results', riskScore: results.risk_score })} style={{ background: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.4)', color: '#fca5a5' }}><span>📋</span> PDF Report</button>
              </>
            )}
          </div>
        </header>

        {/* DASHBOARD TAB */}
        {activeTab === 'dashboard' && (
          <div className="dashboard">
            <div className="stats-grid">
              {[
                { key: 'critical', icon: '🔴', label: 'Critical', trend: '↑ High priority', cls: 'critical' },
                { key: 'high', icon: '🟠', label: 'High', trend: '→ Needs attention', cls: 'high' },
                { key: 'medium', icon: '🟡', label: 'Medium', trend: '→ Review soon', cls: 'medium' },
                { key: 'low', icon: '🟢', label: 'Low', trend: '→ Monitor', cls: 'low' },
                { key: 'totalScans', icon: '✅', label: 'Total Scans', trend: 'All time', cls: 'success' },
              ].map(({ key, icon, label, trend, cls }) => (
                <div key={key} className={`stat-card ${cls}`}>
                  <div className="stat-icon">{icon}</div>
                  <div className="stat-content">
                    <div className="stat-value">{stats[key]}</div>
                    <div className="stat-label">{label}</div>
                    <div className="stat-trend">{trend}</div>
                  </div>
                </div>
              ))}
            </div>

            <div className="card">
              <div className="card-header-with-actions">
                <h3 className="card-title">New Scan</h3>
                <button className="btn-text" onClick={() => { setInput(''); setUploadedFolder(null); setFolderFiles([]); }}>Clear</button>
              </div>

              <div className="scan-type-selector">
                {[['text','📝 Code/Text'],['url','🌐 Website'],['folder','📁 Folder'],['github','🐙 GitHub']].map(([type,label]) => (
                  <button key={type} className={`scan-type-btn ${scanType === type ? 'active' : ''}`} onClick={() => setScanType(type)}>{label}</button>
                ))}
              </div>

              <div className="scan-input-area">
                {scanType === 'text' ? (
                  <textarea className="scan-textarea" value={input} onChange={(e) => setInput(e.target.value)}
                    placeholder="Paste your code, config files, or any text content here..." rows="10" />
                ) : scanType === 'folder' ? (
                  <div className="file-upload-area">
                    <input type="file" id="folder-upload" ref={folderInputRef} onChange={handleFolderSelect}
                      style={{ display: 'none' }} webkitdirectory="" directory="" multiple />
                    <label htmlFor="folder-upload" className="file-upload-label">
                      {uploadedFolder ? (
                        <>
                          <span className="file-icon">📁</span>
                          <span className="file-name">{uploadedFolder}</span>
                          <span className="file-size">({folderFiles.length} files found)</span>
                        </>
                      ) : (
                        <>
                          <span className="upload-icon">📁</span>
                          <span>Click to select a folder to scan</span>
                          <span className="upload-hint">Recursively scans all text files for secrets</span>
                          <span className="upload-hint">Supports: .js, .py, .env, .json, .yaml, .config and more</span>
                        </>
                      )}
                    </label>
                    {uploadedFolder && <button className="btn-text" onClick={() => { setUploadedFolder(null); setFolderFiles([]); }} style={{ marginTop: '1rem' }}>✕ Remove Folder</button>}
                  </div>
                ) : scanType === 'github' ? (
                  <input className="scan-input" type="text" value={input} onChange={(e) => setInput(e.target.value)} placeholder="https://github.com/username/repository" />
                ) : (
                  <div>
                    <input className="scan-input" type="text" value={input} onChange={(e) => setInput(e.target.value)} placeholder="https://example.com or http://localhost:5500/page.html" />
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>💡 Supports public URLs, localhost, and test environments. JS bundles are scanned automatically.</p>
                  </div>
                )}
              </div>

              <button className="btn-primary btn-scan" onClick={handleScan} disabled={loading || (scanType === 'folder' ? folderFiles.length === 0 : !input)}>
                {loading ? (<><span className="spinner"></span>Scanning...</>) : (<><span>🔍</span>Start Scan</>)}
              </button>
            </div>

            {error && (
              <div className="alert alert-error">
                <span className="alert-icon">❌</span>
                <span>{error}</span>
                <button className="alert-close" onClick={() => setError(null)}>×</button>
              </div>
            )}

            {results && (
              <div className="card">
                <div className="results-header">
                  <div>
                    <h3 className="card-title">Scan Results</h3>
                    <p className="results-time">
                      Completed at {formatTimestamp(new Date())}
                      {results.files_scanned && ` • ${results.files_scanned} files scanned`}
                      {results.total_files && results.total_files !== results.files_scanned && ` (${results.total_files} total)`}
                      {results.pages_scanned && ` • ${results.pages_scanned} pages scanned`}
                      {results.js_bundles_scanned > 0 && ` • ${results.js_bundles_scanned} JS bundles scanned`}
                    </p>
                  </div>
                  <div className="results-stats">
                    {['critical','high','medium','low'].map(sev => (
                      <span key={sev} className={`result-stat ${sev}-stat`}>
                        {{'critical':'🔴','high':'🟠','medium':'🟡','low':'🟢'}[sev]} {results.findings.filter(f => f.severity === sev).length} {sev.charAt(0).toUpperCase()+sev.slice(1)}
                      </span>
                    ))}
                    <button className="btn-secondary" onClick={exportResults} style={{ padding: '0.375rem 0.875rem', fontSize: '0.8rem' }}>📥 JSON</button>
                    <button className="btn-secondary" onClick={() => downloadHTMLReport({ findings: results.findings, scanTarget: 'Scan Results', riskScore: results.risk_score })} style={{ padding: '0.375rem 0.875rem', fontSize: '0.8rem' }}>📄 HTML</button>
                    <button className="btn-secondary" onClick={() => downloadPDFReport({ findings: results.findings, scanTarget: 'Scan Results', riskScore: results.risk_score })} style={{ padding: '0.375rem 0.875rem', fontSize: '0.8rem', background: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.4)', color: '#fca5a5' }}>📋 PDF</button>
                  </div>
                </div>

                {/* Severity Filter Bar */}
                <div className="severity-filter-bar">
                  {[
                    { key: 'all',      label: 'All',      count: results.findings.length,                                      color: 'var(--text-muted)' },
                    { key: 'critical', label: 'Critical', count: results.findings.filter(f => f.severity==='critical').length, color: '#ef4444' },
                    { key: 'high',     label: 'High',     count: results.findings.filter(f => f.severity==='high').length,     color: '#f59e0b' },
                    { key: 'medium',   label: 'Medium',   count: results.findings.filter(f => f.severity==='medium').length,   color: '#fbbf24' },
                    { key: 'low',      label: 'Low',      count: results.findings.filter(f => f.severity==='low').length,      color: '#10b981' },
                  ].map(({ key, label, count, color }) => (
                    <button
                      key={key}
                      className={`sev-filter-btn ${severityFilter === key ? 'active' : ''}`}
                      style={severityFilter === key ? { borderColor: color, color: color, background: `${color}18` } : {}}
                      onClick={() => setSeverityFilter(key)}
                    >
                      {label}
                      <span className="sev-filter-count">{count}</span>
                    </button>
                  ))}
                </div>

                {/* Risk Score Display */}
                {results.risk_score && getRiskScoreDisplay(results.risk_score)}

                {/* OWASP Compliance Summary */}
                {owaspLoading && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.875rem 1rem', background: 'rgba(255,255,255,0.03)', borderRadius: '10px', marginBottom: '1rem' }}>
                    <span className="spinner" style={{ width: '14px', height: '14px' }}></span>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Generating OWASP compliance report...</span>
                  </div>
                )}
                {owaspReport && !owaspLoading && (
                  <div className="owasp-summary-box">
                    <div className="owasp-summary-header">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div className="owasp-score-circle" style={{ background: owaspReport.compliance_score >= 70 ? 'rgba(16,185,129,0.15)' : owaspReport.compliance_score >= 40 ? 'rgba(245,158,11,0.15)' : 'rgba(239,68,68,0.15)', border: `2px solid ${owaspReport.compliance_score >= 70 ? '#10b981' : owaspReport.compliance_score >= 40 ? '#f59e0b' : '#ef4444'}` }}>
                          <span style={{ fontSize: '1.1rem', fontWeight: 800, color: owaspReport.compliance_score >= 70 ? '#10b981' : owaspReport.compliance_score >= 40 ? '#f59e0b' : '#ef4444' }}>
                            {owaspReport.compliance_score}%
                          </span>
                        </div>
                        <div>
                          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>OWASP API Security Top 10 — 2023</div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                            <span style={{ color: '#ef4444', fontWeight: 600 }}>{owaspReport.violations} violated</span>
                            {' · '}
                            <span style={{ color: '#10b981', fontWeight: 600 }}>{owaspReport.passing} passing</span>
                            {' · '}
                            <span style={{ color: 'var(--accent-blue)', cursor: 'pointer' }} onClick={() => setActiveTab('owasp')}>
                              View full report →
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="owasp-mini-grid">
                      {owaspReport.report.map((item, i) => (
                        <div key={i} className="owasp-mini-item"
                          style={{ background: item.status === 'FAIL' ? 'rgba(239,68,68,0.08)' : 'rgba(16,185,129,0.06)', border: `1px solid ${item.status === 'FAIL' ? 'rgba(239,68,68,0.25)' : 'rgba(16,185,129,0.2)'}` }}
                          title={item.name} onClick={() => setActiveTab('owasp')}>
                          <span style={{ fontSize: '0.7rem', fontWeight: 700, color: item.status === 'FAIL' ? '#ef4444' : '#10b981' }}>
                            {item.status === 'FAIL' ? '✗' : '✓'} {item.id?.replace(':2023','') || item.key}
                          </span>
                          {item.count > 0 && <span style={{ fontSize: '0.65rem', color: '#ef4444', marginLeft: '2px' }}>({item.count})</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* NEW: Duplicate Warning */}
                {results.findings.some(f => f.count > 1) && (
                  <div className="duplicate-warning">
                    ⚠️ Some secrets appear in multiple files. Rotating once will fix all occurrences.
                  </div>
                )}

                {/* AUTO VALIDATION SUMMARY PANEL */}
                {(autoValidating || Object.keys(validationResults).length > 0) && (
                  <div className="auto-validation-panel">
                    <div className="auto-val-header">
                      <span style={{ fontWeight: 600, fontSize: '1rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        🔴 Live Credential Validation
                        {autoValidating && <span className="spinner" style={{ width: '12px', height: '12px', borderTopColor: '#ef4444', borderColor: 'rgba(239,68,68,0.3)' }}></span>}
                      </span>
                      <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                        {autoValidating ? 'Testing credentials against real APIs...' : `${Object.keys(validationResults).length} credential(s) tested`}
                      </span>
                    </div>
                    <div className="auto-val-grid">
                      {results.findings.filter(f => validationResults[f.secret_hash]).map((finding, i) => {
                        const vr = validationResults[finding.secret_hash];
                        const isActive = vr.status === 'active';
                        const isRevoked = vr.status === 'revoked';
                        return (
                          <div key={i} className="auto-val-item" style={{
                            background: isActive ? 'rgba(239,68,68,0.1)' : isRevoked ? 'rgba(16,185,129,0.08)' : 'rgba(255,255,255,0.03)',
                            border: `1px solid ${isActive ? 'rgba(239,68,68,0.35)' : isRevoked ? 'rgba(16,185,129,0.3)' : 'rgba(255,255,255,0.08)'}`
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                              <span style={{ fontSize: '0.9rem' }}>{isActive ? '🔴' : isRevoked ? '✅' : '❓'}</span>
                              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: isActive ? '#ef4444' : isRevoked ? '#10b981' : 'var(--text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {finding.type}
                              </span>
                              <span style={{ fontSize: '0.68rem', fontWeight: 700, color: isActive ? '#ef4444' : isRevoked ? '#10b981' : 'var(--text-muted)', textTransform: 'uppercase' }}>
                                {isActive ? 'ACTIVE' : isRevoked ? 'REVOKED' : vr.status}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.72rem', color: isActive ? '#fca5a5' : 'var(--text-muted)', lineHeight: 1.4 }}>
                              {vr.message?.substring(0, 80)}{vr.message?.length > 80 ? '...' : ''}
                            </div>
                            {isActive && vr.username && <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: '2px' }}>👤 {vr.username}</div>}
                            {isActive && vr.account_id && <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: '2px' }}>🏢 AWS Account: {vr.account_id}</div>}
                            {isActive && vr.balance && <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: '2px' }}>💳 Balance: {vr.balance}</div>}
                            {isActive && vr.team && <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: '2px' }}>💬 Workspace: {vr.team}</div>}
                          </div>
                        );
                      })}
                      {autoValidating && (
                        <div className="auto-val-item" style={{ background: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(255,255,255,0.1)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                            <span className="spinner" style={{ width: '10px', height: '10px' }}></span>
                            Testing remaining credentials...
                          </div>
                        </div>
                      )}
                    </div>
                    {Object.values(validationResults).some(v => v.status === 'active') && (
                      <div style={{ marginTop: '0.75rem', padding: '0.625rem 0.875rem', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', fontSize: '0.9rem', color: '#fca5a5', fontWeight: 500 }}>
                        🚨 CRITICAL: {Object.values(validationResults).filter(v => v.status === 'active').length} credential(s) are LIVE and active. Rotate immediately!
                      </div>
                    )}
                    {Object.keys(validationResults).length > 0 && !autoValidating && Object.values(validationResults).every(v => v.status === 'revoked' || v.status === 'no_secret' || v.status === 'format_only') && (
                      <div style={{ marginTop: '0.75rem', padding: '0.625rem 0.875rem', background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: '8px', fontSize: '0.9rem', color: '#6ee7b7' }}>
                        ✅ All tested credentials appear to be revoked or invalid. Good job rotating!
                      </div>
                    )}
                  </div>
                )}

                {results.findings.length === 0 ? (
                  <div className="no-findings">
                    <div className="no-findings-icon">✅</div>
                    <h4>No Secrets Found!</h4>
                    <p>Your code appears to be secure. No exposed API keys or credentials detected.</p>
                  </div>
                ) : (
                  <div className="findings-list">
                    {(() => {
                      const filtered = severityFilter === 'all'
                        ? results.findings
                        : results.findings.filter(f => f.severity === severityFilter);
                      if (filtered.length === 0) return (
                        <div className="no-findings" style={{ padding: '2rem', background: 'rgba(255,255,255,0.02)' }}>
                          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🔍</div>
                          <h4 style={{ fontSize: '1rem' }}>No {severityFilter} findings</h4>
                          <p style={{ fontSize: '0.85rem' }}>No findings match the selected severity filter.</p>
                        </div>
                      );
                      return filtered.map((finding, index) => (
                      <div key={index} className="finding-item">
                        <div className="finding-header">
                          <div className="finding-title">
                            <span className="severity-badge" style={{ backgroundColor: getSeverityColor(finding.severity), color: 'white' }}>
                              {finding.severity.toUpperCase()}
                            </span>
                            <h4>{finding.type}</h4>
                            {/* NEW: Duplicate badge */}
                            {finding.count > 1 && (
                              <span className="duplicate-badge">🔁 {finding.count}x in {finding.occurrences?.length} files</span>
                            )}
                          </div>
                          <span className="finding-number">#{index + 1}</span>
                        </div>

                        <div className="finding-details">
                          <div className="finding-row"><span className="finding-label">📋 Description:</span><span className="finding-value">{finding.description}</span></div>
                          <div className="finding-row"><span className="finding-label">🔑 Preview:</span><code className="finding-code">{finding.secret_preview}</code></div>
                          <div className="finding-row"><span className="finding-label">🔒 Hash:</span><code className="finding-code hash-code">{finding.secret_hash?.substring(0, 16)}...</code></div>
                          <div className="finding-row"><span className="finding-label">📍 Source:</span><span className="finding-value">{finding.source}</span></div>
                          {/* OWASP Badge */}
                          {finding.owasp && (
                            <div className="finding-row">
                              <span className="finding-label">🏛️ OWASP:</span>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                                  <a href={finding.owasp.owasp_url} target="_blank" rel="noopener noreferrer"
                                    style={{ background: `${finding.owasp.owasp_color}20`, border: `1px solid ${finding.owasp.owasp_color}60`,
                                      color: finding.owasp.owasp_color, padding: '3px 10px', borderRadius: '20px',
                                      fontSize: '0.75rem', fontWeight: 700, textDecoration: 'none', letterSpacing: '0.03em' }}>
                                    {finding.owasp.owasp_id}
                                  </a>
                                  <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
                                    {finding.owasp.owasp_name}
                                  </span>
                                </div>
                                {finding.owasp.compliance && finding.owasp.compliance.length > 0 && (
                                  <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                                    {finding.owasp.compliance.map((c, i) => (
                                      <span key={i} style={{ background: 'rgba(96,165,250,0.1)', border: '1px solid rgba(96,165,250,0.25)',
                                        color: '#60a5fa', padding: '1px 7px', borderRadius: '10px', fontSize: '0.7rem', fontWeight: 500 }}>
                                        {c}
                                      </span>
                                    ))}
                                  </div>
                                )}
                                {finding.owasp.impact && (
                                  <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                                    ⚡ {finding.owasp.impact}
                                  </span>
                                )}
                              </div>
                            </div>
                          )}
                          {/* NEW: Show all occurrences */}
                          {finding.count > 1 && finding.occurrences && (
                            <div className="finding-row">
                              <span className="finding-label">📍 All Sources:</span>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                                {finding.occurrences.map((src, i) => <code key={i} className="finding-code" style={{ fontSize: '0.75rem' }}>{src}</code>)}
                              </div>
                            </div>
                          )}
                          {finding.context && (
                            <div className="finding-context"><span className="finding-label">💡 Context:</span><pre className="context-code">{finding.context}</pre></div>
                          )}
                        </div>

                        <div className="finding-actions">
                          <button className="btn-action" onClick={() => copyToClipboard(finding.secret_hash, 'Hash copied')}>📋 Copy Hash</button>
                          <button className="btn-action" onClick={() => copyToClipboard(finding.context, 'Context copied')}>📄 Copy Context</button>
                          <button className="btn-action btn-ai-fix" onClick={() => handleGetAIFix(finding)} title="Get AI-powered fix suggestion">🤖 AI Fix</button>
                          {/* Live Validator Button — shown for supported/critical patterns */}
                          {isValidatable(finding) && !validationResults[finding.secret_hash] && (
                            <button
                              className="btn-action btn-test-live"
                              onClick={() => handleValidateKey(finding)}
                              disabled={validatingKeys[finding.secret_hash]}
                              title="Test if this credential is still active"
                            >
                              {validatingKeys[finding.secret_hash]
                                ? <><span className="spinner" style={{ borderTopColor: '#ef4444', borderColor: 'rgba(239,68,68,0.3)' }}></span> Testing...</>
                                : <>🔴 Test Live</>}
                            </button>
                          )}
                        </div>

                        {/* Validation Result Banner */}
                        {validationResults[finding.secret_hash] && (() => {
                          const vr = validationResults[finding.secret_hash];
                          const badge = getValidationBadge(vr);
                          return (
                            <div className="validation-result" style={{ background: badge.bg, border: `1px solid ${badge.border}`, borderRadius: '10px', padding: '0.875rem 1rem', marginTop: '0.75rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <span style={{ fontSize: '1.1rem' }}>{badge.icon}</span>
                                  <span style={{ fontWeight: 700, color: badge.color, fontSize: '1rem', letterSpacing: '0.03em' }}>{badge.label}</span>
                                </div>
                                <button className="btn-action" style={{ padding: '2px 8px', fontSize: '0.7rem' }}
                                  onClick={() => setValidationResults(prev => { const n = {...prev}; delete n[finding.secret_hash]; return n; })}>
                                  ✕ Clear
                                </button>
                              </div>
                              <p style={{ margin: '0.5rem 0 0', fontSize: '0.9rem', color: badge.color, lineHeight: 1.6 }}>{vr.message}</p>

                              {/* Full pentesting detail panel */}
                              {(vr.active || vr.status === 'expired') && (
                                <div className="validation-details">
                                  {/* Identity fields */}
                                  {vr.account_id   && <div className="vd-row"><span className="vd-label">🏢 AWS Account</span><code className="vd-val">{vr.account_id}</code></div>}
                                  {vr.user_arn     && <div className="vd-row"><span className="vd-label">🔑 IAM ARN</span><code className="vd-val">{vr.user_arn}</code></div>}
                                  {vr.username     && <div className="vd-row"><span className="vd-label">👤 Username</span><code className="vd-val">{vr.username}</code></div>}
                                  {vr.name         && <div className="vd-row"><span className="vd-label">📛 Name</span><code className="vd-val">{vr.name}</code></div>}
                                  {vr.email        && <div className="vd-row"><span className="vd-label">📧 Email</span><code className="vd-val">{vr.email}</code></div>}
                                  {vr.company      && <div className="vd-row"><span className="vd-label">🏬 Company</span><code className="vd-val">{vr.company}</code></div>}
                                  {vr.team         && <div className="vd-row"><span className="vd-label">💬 Slack Team</span><code className="vd-val">{vr.team}</code></div>}
                                  {vr.account_name && <div className="vd-row"><span className="vd-label">📋 Account</span><code className="vd-val">{vr.account_name}</code></div>}
                                  {vr.bot_name     && <div className="vd-row"><span className="vd-label">🤖 Bot Name</span><code className="vd-val">{vr.bot_name}</code></div>}
                                  {vr.guild_count  && <div className="vd-row"><span className="vd-label">🖥️ Discord Servers</span><code className="vd-val">{vr.guild_count}</code></div>}
                                  {vr.balance      && <div className="vd-row"><span className="vd-label">💳 Balance</span><code className="vd-val">{vr.balance}</code></div>}
                                  {vr.total_subscribers && <div className="vd-row"><span className="vd-label">📨 Subscribers</span><code className="vd-val">{vr.total_subscribers.toLocaleString()} contacts</code></div>}
                                  {vr.livemode !== undefined && <div className="vd-row"><span className="vd-label">⚡ Mode</span><code className="vd-val" style={{ color: vr.livemode ? '#ef4444' : '#f59e0b' }}>{vr.livemode ? '🔴 LIVE PRODUCTION' : '🟡 TEST MODE'}</code></div>}

                                  {/* Scopes / Permissions */}
                                  {vr.scopes && (typeof vr.scopes === 'string' ? vr.scopes : vr.scopes.join(', ')) && (
                                    <div className="vd-row"><span className="vd-label">🔐 Scopes</span>
                                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                                        {(typeof vr.scopes === 'string' ? vr.scopes.split(',') : vr.scopes).map((s,i) => (
                                          <code key={i} className="vd-val" style={{ color: ['repo','admin:org','delete_repo','write:packages'].includes(s.trim()) ? '#ef4444' : '#a3a3a3' }}>{s.trim()}</code>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {vr.critical_scopes?.length > 0 && (
                                    <div className="vd-row"><span className="vd-label">🚨 Critical Scopes</span>
                                      <div style={{ display:'flex', flexWrap:'wrap', gap:'3px' }}>
                                        {vr.critical_scopes.map((s,i) => <code key={i} className="vd-val" style={{ color:'#ef4444', fontWeight:700 }}>{s}</code>)}
                                      </div>
                                    </div>
                                  )}

                                  {/* Repo info */}
                                  {vr.private_repos > 0 && <div className="vd-row"><span className="vd-label">📁 Private Repos</span><code className="vd-val" style={{ color:'#f59e0b' }}>{vr.private_repos} accessible</code></div>}
                                  {vr.public_repos  > 0 && <div className="vd-row"><span className="vd-label">📂 Public Repos</span><code className="vd-val">{vr.public_repos}</code></div>}

                                  {/* Admin flags */}
                                  {vr.is_admin      && <div className="vd-row"><span className="vd-label">⚠️ Admin</span><code className="vd-val" style={{ color:'#ef4444', fontWeight:700 }}>YES — Full admin access!</code></div>}
                                  {vr.two_fa_enabled === false && <div className="vd-row"><span className="vd-label">🔓 2FA</span><code className="vd-val" style={{ color:'#f59e0b' }}>DISABLED — Account easier to compromise</code></div>}

                                  {/* Google services */}
                                  {vr.services_accessible?.length > 0 && (
                                    <div className="vd-row"><span className="vd-label">☁️ Google Services</span>
                                      <code className="vd-val" style={{ color:'#ef4444' }}>{vr.services_accessible.join(', ')}</code>
                                    </div>
                                  )}
                                  {vr.billing_risk  && <div className="vd-row"><span className="vd-label">💰 Billing Risk</span><code className="vd-val" style={{ color: vr.billing_risk === 'HIGH' ? '#ef4444' : '#f59e0b' }}>{vr.billing_risk}</code></div>}

                                  {/* JWT specific fields */}
                                  {vr.algorithm     && <div className="vd-row"><span className="vd-label">🔏 Algorithm</span><code className="vd-val" style={{ color: ['none','NONE','HS256'].includes(vr.algorithm) ? '#f59e0b' : vr.algorithm === 'RS256' ? '#60a5fa' : '#a3a3a3' }}>{vr.algorithm}{vr.algorithm === 'RS256' ? ' — check alg confusion' : vr.algorithm === 'HS256' ? ' — forgeable?' : vr.algorithm?.toUpperCase() === 'NONE' ? ' — ⚠️ NO SIGNATURE' : ''}</code></div>}
                                  {vr.kid           && <div className="vd-row"><span className="vd-label">🗝️ Key ID (kid)</span><code className="vd-val" style={{ color:'#f59e0b' }}>{vr.kid} — test injection</code></div>}
                                  {vr.subject       && <div className="vd-row"><span className="vd-label">👤 Subject</span><code className="vd-val">{vr.subject}</code></div>}
                                  {vr.issuer        && <div className="vd-row"><span className="vd-label">🏛️ Issuer</span><code className="vd-val">{vr.issuer}</code></div>}
                                  {vr.expiry        && <div className="vd-row"><span className="vd-label">⏰ Expires</span><code className="vd-val" style={{ color: vr.status === 'expired' ? '#ef4444' : '#10b981' }}>{vr.expiry}{vr.time_left ? ` (${vr.time_left})` : ''}</code></div>}
                                  {vr.roles?.length > 0 && <div className="vd-row"><span className="vd-label">🎭 Roles</span><code className="vd-val">{vr.roles.join(', ')}</code></div>}
                                  {vr.user_id       && <div className="vd-row"><span className="vd-label">🆔 User ID</span><code className="vd-val">{vr.user_id}</code></div>}
                                  {vr.security_issues?.length > 0 && (
                                    <div className="vd-row"><span className="vd-label">⚠️ JWT Issues</span>
                                      <div>{vr.security_issues.map((iss,i) => <div key={i} style={{ color:'#f59e0b', fontSize:'0.84rem', margin:'3px 0', lineHeight:'1.5' }}>{iss}</div>)}</div>
                                    </div>
                                  )}
                                  {vr.attack_vectors?.length > 0 && (
                                    <div style={{ marginTop:'0.5rem', padding:'0.5rem 0.75rem', background:'rgba(245,158,11,0.08)', border:'1px solid rgba(245,158,11,0.2)', borderRadius:'6px' }}>
                                      <div style={{ fontSize:'0.82rem', fontWeight:700, color:'#f59e0b', marginBottom:'5px' }}>⚔️ ATTACK VECTORS</div>
                                      {vr.attack_vectors.map((av,i) => (
                                        <div key={i} style={{ fontSize:'0.84rem', color:'#fcd34d', margin:'3px 0', lineHeight:'1.6' }}>• {av}</div>
                                      ))}
                                    </div>
                                  )}

                                  {/* Blast radius — show for all active findings */}
                                  {vr.blast_radius && (
                                    <div style={{ marginTop:'0.5rem', padding:'0.5rem 0.75rem', background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.2)', borderRadius:'6px' }}>
                                      <div style={{ fontSize:'0.82rem', fontWeight:700, color:'#ef4444', marginBottom:'5px' }}>💣 BLAST RADIUS</div>
                                      {(Array.isArray(vr.blast_radius) ? vr.blast_radius : [vr.blast_radius]).map((b,i) => (
                                        <div key={i} style={{ fontSize:'0.84rem', color:'#fca5a5', lineHeight:'1.6' }}>• {b}</div>
                                      ))}
                                    </div>
                                  )}

                                  {/* Pentest note */}
                                  {vr.pentest_note  && (
                                    <div style={{ marginTop:'0.5rem', padding:'0.5rem 0.75rem', background:'rgba(245,158,11,0.08)', border:'1px solid rgba(245,158,11,0.2)', borderRadius:'6px' }}>
                                      <div style={{ fontSize:'0.82rem', fontWeight:700, color:'#f59e0b', marginBottom:'5px' }}>📋 PENTEST NOTE</div>
                                      <div style={{ fontSize:'0.84rem', color:'#fcd34d', lineHeight:'1.6' }}>{vr.pentest_note}</div>
                                    </div>
                                  )}
                                  {/* Action required — shown for secret_without_key_id */}
                                  {vr.action_required && (
                                    <div style={{ marginTop:'0.5rem', padding:'0.5rem 0.75rem', background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.25)', borderRadius:'6px' }}>
                                      <div style={{ fontSize:'0.82rem', fontWeight:700, color:'#ef4444', marginBottom:'5px' }}>🚨 ACTION REQUIRED</div>
                                      <div style={{ fontSize:'0.84rem', color:'#fca5a5', lineHeight:'1.7' }}>{vr.action_required}</div>
                                    </div>
                                  )}
                                  {/* Secret found confirmation */}
                                  {vr.status === 'secret_without_key_id' && (
                                    <div style={{ marginTop:'0.5rem', padding:'0.5rem 0.75rem', background:'rgba(245,158,11,0.06)', border:'1px solid rgba(245,158,11,0.2)', borderRadius:'6px' }}>
                                      <div style={{ fontSize:'0.82rem', fontWeight:700, color:'#f59e0b', marginBottom:'4px' }}>🔍 WHY CAN'T WE VALIDATE?</div>
                                      <div style={{ fontSize:'0.84rem', color:'#fcd34d', lineHeight:'1.7' }}>
                                        AWS needs <strong>two parts</strong> to authenticate: an <code style={{background:'rgba(0,0,0,0.3)',padding:'1px 5px',borderRadius:'4px',fontSize:'0.78rem'}}>Access Key ID</code> (starts with AKIA...) + this <code style={{background:'rgba(0,0,0,0.3)',padding:'1px 5px',borderRadius:'4px',fontSize:'0.78rem'}}>Secret Key</code> together.
                                        The secret was found but no matching AKIA key was detected nearby. Search the same file for <code style={{background:'rgba(0,0,0,0.3)',padding:'1px 5px',borderRadius:'4px',fontSize:'0.78rem'}}>AKIA</code> to find the pair.
                                        <br/><br/>
                                        <strong>Regardless — this IS a real hardcoded AWS credential. Rotate it NOW.</strong>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                    ));
                    })()}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* NEW: HEADER SECURITY TAB */}
        {activeTab === 'headers' && (
          <div className="card">
            <div className="card-header-with-actions">
              <div>
                <h3 className="card-title">🛡️ HTTP Header Security Analyzer</h3>
                <p className="card-subtitle">Check OWASP security headers, info leakage, and CORS misconfigurations</p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem' }}>
              <input className="scan-input" type="text" value={headerScanUrl} onChange={(e) => setHeaderScanUrl(e.target.value)}
                placeholder="https://example.com" style={{ flex: 1 }}
                onKeyDown={(e) => e.key === 'Enter' && handleHeaderScan()} />
              <button className="btn-primary" onClick={handleHeaderScan} disabled={headerLoading || !headerScanUrl.trim()}>
                {headerLoading ? <><span className="spinner"></span>Checking...</> : <><span>🔍</span>Analyze Headers</>}
              </button>
            </div>

            {headerResults?.error && (
              <div className="alert alert-error"><span>❌</span><span>{headerResults.error}</span></div>
            )}

            {headerResults && !headerResults.error && (
              <>
                {/* Security Score */}
                <div className="security-score-box">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                    <div style={{ fontSize: '2.5rem', fontWeight: 700, color: headerResults.security_score >= 70 ? '#10b981' : headerResults.security_score >= 40 ? '#f59e0b' : '#ef4444' }}>
                      {headerResults.security_score}/100
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '1rem' }}>Header Security Score</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{headerResults.total_issues} issue(s) found for {headerResults.url}</div>
                    </div>
                  </div>
                </div>

                {headerResults.issues.length === 0 ? (
                  <div className="no-findings"><div className="no-findings-icon">✅</div><h4>All Security Headers Present!</h4><p>This URL has excellent security header configuration.</p></div>
                ) : (
                  <div className="findings-list">
                    {headerResults.issues.map((issue, i) => (
                      <div key={i} className="finding-item">
                        <div className="finding-header">
                          <div className="finding-title">
                            <span className="severity-badge" style={{ backgroundColor: getSeverityColor(issue.severity), color: 'white' }}>{issue.severity.toUpperCase()}</span>
                            <h4>{issue.header}</h4>
                            <span className="header-status-badge" style={{ background: issue.status === 'missing' ? 'rgba(239,68,68,0.1)' : 'rgba(245,158,11,0.1)', color: issue.status === 'missing' ? '#ef4444' : '#f59e0b', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>
                              {issue.status === 'missing' ? '⛔ Missing' : issue.status === 'leaking' ? '⚠️ Info Leakage' : '🔧 Misconfigured'}
                            </span>
                          </div>
                        </div>
                        <div className="finding-details">
                          <div className="finding-row"><span className="finding-label">🔍 Issue:</span><span className="finding-value">{issue.issue}</span></div>
                          {issue.value && <div className="finding-row"><span className="finding-label">📄 Value:</span><code className="finding-code">{issue.value}</code></div>}
                          <div className="finding-row"><span className="finding-label">✅ Fix:</span><span className="finding-value" style={{ color: '#10b981' }}>{issue.recommendation}</span></div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Response Headers */}
                <div style={{ marginTop: '1.5rem' }}>
                  <h4 style={{ marginBottom: '0.75rem', color: 'var(--text-secondary)' }}>📋 All Response Headers</h4>
                  <div className="headers-table">
                    {Object.entries(headerResults.headers).map(([key, val]) => (
                      <div key={key} className="header-row">
                        <code className="header-key">{key}</code>
                        <span className="header-value">{val}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

                {/* OWASP TOP 10 TAB */}
        {activeTab === 'owasp' && (
          <div className="card">
            <div className="card-header-with-actions">
              <div>
                <h3 className="card-title">🛡️ OWASP API Security Top 10 — 2023</h3>
                <p className="card-subtitle">Industry-standard compliance report • Run a scan first to see violations</p>
              </div>
              {owaspReport && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '1.5rem', fontWeight: 800, color: owaspReport.compliance_score >= 70 ? '#10b981' : owaspReport.compliance_score >= 40 ? '#f59e0b' : '#ef4444' }}>
                      {owaspReport.compliance_score}%
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Compliance Score</div>
                  </div>
                </div>
              )}
            </div>

            {!owaspReport && !owaspLoading && (
              <div className="empty-state">
                <div className="empty-icon">🛡️</div>
                <h4>No Scan Data Yet</h4>
                <p>Run a scan from the Dashboard tab to generate your OWASP compliance report.</p>
                <button className="btn-primary" onClick={() => setActiveTab('dashboard')} style={{ marginTop: '1rem' }}>
                  → Go to Dashboard
                </button>
              </div>
            )}

            {owaspLoading && (
              <div className="empty-state">
                <div className="spinner" style={{ width: '40px', height: '40px', margin: '0 auto 1rem' }}></div>
                <h4>Generating OWASP Report...</h4>
              </div>
            )}

            {owaspReport && !owaspLoading && (
              <>
                {/* Score bar */}
                <div className="owasp-score-bar">
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Compliance Progress</span>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: owaspReport.compliance_score >= 70 ? '#10b981' : '#ef4444' }}>
                      {owaspReport.passing}/10 categories passing
                    </span>
                  </div>
                  <div style={{ height: '10px', background: 'rgba(255,255,255,0.08)', borderRadius: '10px', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${owaspReport.compliance_score}%`, background: owaspReport.compliance_score >= 70 ? '#10b981' : owaspReport.compliance_score >= 40 ? '#f59e0b' : '#ef4444', borderRadius: '10px', transition: 'width 1s ease' }}></div>
                  </div>
                </div>

                {/* Violations first */}
                {owaspReport.report.filter(r => r.status === 'FAIL').length > 0 && (
                  <div style={{ marginBottom: '1.5rem' }}>
                    <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#ef4444', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
                      ✗ Violations ({owaspReport.report.filter(r => r.status === 'FAIL').length})
                    </div>
                    <div className="owasp-cards-grid">
                      {owaspReport.report.filter(r => r.status === 'FAIL').map((item, i) => (
                        <div key={i} className="owasp-card owasp-card-fail">
                          <div className="owasp-card-header">
                            <a href={item.url} target="_blank" rel="noopener noreferrer" className="owasp-id-badge" style={{ background: `${item.color}20`, borderColor: `${item.color}60`, color: item.color }}>
                              {item.id || item.key}
                            </a>
                            <span className="owasp-count-badge">{item.count} finding{item.count !== 1 ? 's' : ''}</span>
                            <span className={`owasp-sev-badge sev-${item.highest_severity}`}>{item.highest_severity?.toUpperCase()}</span>
                          </div>
                          <div className="owasp-card-name">{item.name}</div>
                          <div className="owasp-card-desc">{item.description}</div>
                          {item.findings && item.findings.length > 0 && (
                            <div className="owasp-findings-list">
                              {[...new Set(item.findings.map(f => f.type))].slice(0, 4).map((type, j) => (
                                <span key={j} className="owasp-finding-chip">{type}</span>
                              ))}
                              {item.findings.length > 4 && <span className="owasp-finding-chip">+{item.findings.length - 4} more</span>}
                            </div>
                          )}
                          {item.findings?.[0]?.compliance?.length > 0 && (
                            <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                              {[...new Set(item.findings.flatMap(f => f.compliance || []))].slice(0, 4).map((c, j) => (
                                <span key={j} style={{ background: 'rgba(96,165,250,0.1)', border: '1px solid rgba(96,165,250,0.2)', color: '#60a5fa', padding: '1px 6px', borderRadius: '8px', fontSize: '0.68rem' }}>{c}</span>
                              ))}
                            </div>
                          )}
                          <a href={item.url} target="_blank" rel="noopener noreferrer" className="owasp-learn-link">📖 OWASP Reference →</a>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Passing categories */}
                {owaspReport.report.filter(r => r.status === 'PASS').length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#10b981', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
                      ✓ Passing ({owaspReport.report.filter(r => r.status === 'PASS').length})
                    </div>
                    <div className="owasp-cards-grid">
                      {owaspReport.report.filter(r => r.status === 'PASS').map((item, i) => (
                        <div key={i} className="owasp-card owasp-card-pass">
                          <div className="owasp-card-header">
                            <a href={item.url} target="_blank" rel="noopener noreferrer" className="owasp-id-badge" style={{ background: 'rgba(16,185,129,0.1)', borderColor: 'rgba(16,185,129,0.3)', color: '#10b981' }}>
                              {item.id || item.key}
                            </a>
                            <span style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>✓ No violations</span>
                          </div>
                          <div className="owasp-card-name" style={{ color: 'var(--text-secondary)' }}>{item.name}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Disclaimer */}
                <div style={{ marginTop: '1.5rem', padding: '0.875rem 1rem', background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.15)', borderRadius: '8px' }}>
                  <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                    ℹ️ This report maps detected credentials to the <strong style={{ color: 'var(--text-secondary)' }}>OWASP API Security Top 10 — 2023</strong> standard.
                    Categories API1, API4, API5, API6, API7 require manual testing and are not covered by static credential scanning.
                    Results reflect findings from the most recent scan only.
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {/* HISTORY TAB */}
        {activeTab === 'history' && (
          <div className="card">
            <div className="card-header-with-actions">
              <div>
                <h3 className="card-title">Scan History</h3>
                <p className="card-subtitle">{scanHistory.length} total scans • Last 50 results</p>
              </div>
              {scanHistory.length > 0 && <button className="btn-danger" onClick={clearAllHistory}>🗑️ Clear All</button>}
            </div>

            {scanHistory.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">📜</div>
                <h4>No Scan History</h4>
                <p>Your scan history will appear here. Start your first scan!</p>
              </div>
            ) : (
              <div className="history-table">
                {scanHistory.map((scan) => (
                  <div key={scan.id} className="history-row">
                    <span className="history-type">{getScanTypeIcon(scan.type)}</span>
                    <div className="history-info">
                      <span className="history-target-full">{scan.target}</span>
                      <span className="history-timestamp">{formatTimestamp(scan.timestamp)} • {getTimeAgo(scan.timestamp)}</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.25rem' }}>
                      <span className="history-findings" style={{ color: getSeverityColor(scan.severity) }}>{scan.findings} findings</span>
                      {scan.riskScore && <span style={{ fontSize: '0.75rem', color: scan.riskScore.color }}>{scan.riskScore.emoji} {scan.riskScore.score}/100</span>}
                    </div>
                    <div className="history-actions">
                      <button className="btn-text" onClick={() => viewScanDetails(scan)}>View</button>
                      <button className="btn-text" onClick={() => downloadJSON(scan.fullResults, `scan-${scan.id}.json`)}>📥</button>
                      <button className="btn-text btn-delete" onClick={() => deleteScan(scan.id)}>Delete</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* PATTERNS TAB */}
        {activeTab === 'patterns' && (
          <div className="patterns-container">
            <div className="card">
              <div className="card-header-with-actions">
                <div>
                  <h3 className="card-title">Detection Patterns</h3>
                  <p className="card-subtitle">{patterns.filter(p => p.enabled).length} active • {patterns.filter(p => !p.enabled).length} disabled • {patterns.length} total</p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <div className="pattern-filters">
                    <select className="filter-select" onChange={(e) => filterPatternsByCategory(e.target.value)}>
                      <option value="all">All Categories ({allPatterns.length})</option>
                      <option value="cloud">Cloud ({allPatterns.filter(p => p.category?.toLowerCase().includes('cloud')).length})</option>
                      <option value="payment">Payment ({allPatterns.filter(p => p.category?.toLowerCase().includes('payment')).length})</option>
                      <option value="database">Database ({allPatterns.filter(p => p.category?.toLowerCase().includes('database')).length})</option>
                      <option value="communication">Communication ({allPatterns.filter(p => p.category?.toLowerCase().includes('communication')).length})</option>
                      <option value="version">Version Control ({allPatterns.filter(p => p.category?.toLowerCase().includes('version')).length})</option>
                      <option value="ci">CI/CD ({allPatterns.filter(p => p.category?.toLowerCase().includes('ci/cd')).length})</option>
                    </select>
                    <select className="filter-select" onChange={(e) => filterPatternsBySeverity(e.target.value)}>
                      <option value="all">All Severities</option>
                      <option value="critical">Critical ({allPatterns.filter(p => p.severity === 'critical').length})</option>
                      <option value="high">High ({allPatterns.filter(p => p.severity === 'high').length})</option>
                      <option value="medium">Medium ({allPatterns.filter(p => p.severity === 'medium').length})</option>
                      <option value="low">Low ({allPatterns.filter(p => p.severity === 'low').length})</option>
                    </select>
                    <button className="btn-secondary" onClick={resetPatternFilters}>🔄 Reset</button>
                  </div>
                  <button className="btn-secondary" onClick={() => {
                    const allEnabled = patterns.every(p => p.enabled);
                    const updated = patterns.map(p => ({ ...p, enabled: !allEnabled }));
                    const updatedAll = allPatterns.map(p => ({ ...p, enabled: !allEnabled }));
                    setPatterns(updated); setAllPatterns(updatedAll);
                    localStorage.setItem('disabledPatterns', JSON.stringify(allEnabled ? updatedAll.map(p => p.name) : []));
                    showNotification(allEnabled ? '⏸️ All patterns disabled' : '✅ All patterns enabled');
                  }}>
                    {patterns.every(p => p.enabled) ? '⏸️ Disable All' : '✅ Enable All'}
                  </button>
                </div>
              </div>

              {loadingPatterns ? (
                <div className="empty-state"><div className="spinner" style={{ width: '40px', height: '40px', margin: '2rem auto' }}></div><h4>Loading Patterns...</h4></div>
              ) : patterns.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">⚠️</div><h4>No Patterns Found</h4>
                  <p>Unable to load patterns. Please check your backend is running on port 5000.</p>
                  <button className="btn-primary" onClick={fetchPatterns} style={{ marginTop: '1rem' }}>🔄 Retry</button>
                </div>
              ) : (
                <div className="patterns-grid">
                  {patterns.map((pattern) => (
                    <div key={pattern.id} className="pattern-card" style={{ opacity: pattern.enabled ? 1 : 0.5, border: pattern.enabled ? '' : '1px dashed var(--border-color)' }}>
                      <div className="pattern-header">
                        <div className="pattern-info">
                          <div className="pattern-name-row">
                            <h4 className="pattern-name" style={{ textDecoration: pattern.enabled ? 'none' : 'line-through' }}>
                              {pattern.name}
                              {!pattern.enabled && <span style={{ marginLeft: '0.5rem', fontSize: '0.75rem' }}>⏸️ Disabled</span>}
                            </h4>
                            <span className="severity-badge" style={{ backgroundColor: getSeverityColor(pattern.severity), color: 'white', opacity: pattern.enabled ? 1 : 0.6 }}>
                              {pattern.severity.toUpperCase()}
                            </span>
                          </div>
                          <span className="pattern-category">{getCategoryIcon(pattern.category)} {pattern.category}</span>
                        </div>
                        <label className="toggle-switch">
                          <input type="checkbox" checked={pattern.enabled} onChange={(e) => {
                            const updated = patterns.map(p => p.id === pattern.id ? { ...p, enabled: e.target.checked } : p);
                            const updatedAll = allPatterns.map(p => p.id === pattern.id ? { ...p, enabled: e.target.checked } : p);
                            setPatterns(updated); setAllPatterns(updatedAll);
                            localStorage.setItem('disabledPatterns', JSON.stringify(updatedAll.filter(p => !p.enabled).map(p => p.name)));
                            showNotification(e.target.checked ? `✅ ${pattern.name} enabled` : `⏸️ ${pattern.name} disabled`);
                          }} />
                          <span className="toggle-slider"></span>
                        </label>
                      </div>
                      <p className="pattern-description">{pattern.description}</p>
                      <div className="pattern-details">
                        <div className="pattern-detail-row">
                          <span className="detail-label">Regex Pattern:</span>
                          <code className="pattern-regex">{pattern.pattern.length > 60 ? pattern.pattern.substring(0, 60) + '...' : pattern.pattern}</code>
                        </div>
                        <div className="pattern-detail-row">
                          <span className="detail-label">Example:</span>
                          <code className="pattern-example">{pattern.examples}</code>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;