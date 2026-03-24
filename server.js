const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_ID = '30388178033-62l5t6mlimokpuge1b4hngct8bnp6rnl.apps.googleusercontent.com';
const OWNER_EMAILS = ['aernatas@gmail.com', 'fhuang@princetonk12.org'];
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'change-this-secret-in-production';

const client = new OAuth2Client(CLIENT_ID);
const WHITELIST_FILE = path.join(__dirname, 'whitelist.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Whitelist ──────────────────────────────────────────────────────────────────
function loadWhitelist() {
  try {
    if (!fs.existsSync(WHITELIST_FILE)) return [];
    return JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf8'));
  } catch { return []; }
}
function saveWhitelist(list) {
  fs.writeFileSync(WHITELIST_FILE, JSON.stringify(list, null, 2));
}

// ── Tokens ─────────────────────────────────────────────────────────────────────
function signToken(email) {
  const payload = Buffer.from(email + '|' + Date.now()).toString('base64');
  const hmac = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  return payload + '.' + hmac;
}
function verifyToken(token) {
  try {
    const [payload, hmac] = token.split('.');
    if (!payload || !hmac) return null;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expected))) return null;
    const decoded = Buffer.from(payload, 'base64').toString('utf8');
    const [email] = decoded.split('|');
    return email ? email.toLowerCase().trim() : null;
  } catch { return null; }
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function requireOwner(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  const email = verifyToken(token);
  if (!email || !OWNER_EMAILS.includes(email)) return res.status(403).json({ error: 'Forbidden' });
  req.userEmail = email;
  next();
}

// ── Routes ─────────────────────────────────────────────────────────────────────

// Google credential → verify + check whitelist → return signed token
app.post('/api/auth', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'No credential' });

    const ticket = await client.verifyIdToken({ idToken: credential, audience: CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase().trim();

    const isOwner = OWNER_EMAILS.includes(email);
    const whitelist = loadWhitelist();
    const isWhitelisted = whitelist.map(e => e.toLowerCase()).includes(email);

    if (!isOwner && !isWhitelisted) {
      return res.status(403).json({ error: 'not_authorized', email });
    }

    const token = signToken(email);
    res.json({ token, email, isOwner });
  } catch (err) {
    console.error('Auth error:', err);
    res.status(401).json({ error: 'Invalid credential' });
  }
});

// Verify a stored token (called on page load to skip Google popup)
app.post('/api/verify', (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'No token' });
    const email = verifyToken(token);
    if (!email) return res.status(401).json({ error: 'Invalid token' });

    const isOwner = OWNER_EMAILS.includes(email);
    const whitelist = loadWhitelist();
    const isWhitelisted = whitelist.map(e => e.toLowerCase()).includes(email);

    if (!isOwner && !isWhitelisted) {
      return res.status(403).json({ error: 'not_authorized', email });
    }

    res.json({ valid: true, email, isOwner });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Get whitelist (owner only)
app.get('/api/whitelist', requireOwner, (req, res) => {
  res.json({ whitelist: loadWhitelist() });
});

// Add to whitelist (owner only)
app.post('/api/whitelist', requireOwner, (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  const list = loadWhitelist();
  const norm = email.toLowerCase().trim();
  if (list.map(e => e.toLowerCase()).includes(norm)) return res.json({ whitelist: list });
  list.push(norm);
  saveWhitelist(list);
  res.json({ whitelist: list });
});

// Remove from whitelist (owner only)
app.delete('/api/whitelist', requireOwner, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Invalid email' });
  const list = loadWhitelist().filter(e => e.toLowerCase() !== email.toLowerCase().trim());
  saveWhitelist(list);
  res.json({ whitelist: list });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
