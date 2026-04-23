const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const stripe = process.env.STRIPE_SECRET_KEY
  ? require('stripe')(process.env.STRIPE_SECRET_KEY)
  : null;

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'viddaassistent-secret-2026';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password TEXT NOT NULL,
      stripe_customer_id TEXT,
      subscription_status TEXT DEFAULT 'trial',
      trial_ends TIMESTAMPTZ DEFAULT NOW() + INTERVAL '14 days',
      claude_api_key TEXT,
      reset_token TEXT,
      reset_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('Database klar');
}
initDB().catch(e => console.error('DB init feil:', e.message));

async function findUser(email) {
  const r = await db.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
  return r.rows[0] || null;
}
async function findUserById(id) {
  const r = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  return r.rows[0] || null;
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Ikke innlogget' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Ugyldig token – logg inn på nytt' }); }
}

app.post('/api/register', async (req, res) => {
  const { email, password, name, claudeApiKey } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Fyll inn alle feltene' });
  if (password.length < 6) return res.status(400).json({ error: 'Passord må være minst 6 tegn' });
  try {
    if (await findUser(email)) return res.status(400).json({ error: 'E-post er allerede registrert' });
    const hashed = await bcrypt.hash(password, 10);
    let stripeCustomerId = null;
    if (stripe) { try { const c = await stripe.customers.create({ email, name }); stripeCustomerId = c.id; } catch(e) {} }
    const r = await db.query(
      'INSERT INTO users (email, name, password, stripe_customer_id, claude_api_key) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [email, name, hashed, stripeCustomerId, claudeApiKey || null]
    );
    const user = r.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, name: user.name, email: user.email, subscriptionStatus: user.subscription_status, trialEnds: user.trial_ends });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Serverfeil ved registrering' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await findUser(email);
    if (!user) return res.status(401).json({ error: 'Feil e-post eller passord' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Feil e-post eller passord' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, name: user.name, email: user.email, subscriptionStatus: user.subscription_status, trialEnds: user.trial_ends });
  } catch(e) { res.status(500).json({ error: 'Serverfeil ved innlogging' }); }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await findUser(email);
    if (!user) return res.json({ ok: true });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 30 * 60 * 1000);
    await db.query('UPDATE users SET reset_token=$1, reset_expires=$2 WHERE id=$3', [code, expires, user.id]);
    if (process.env.RESEND_API_KEY) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: 'ViddaAssistent <noreply@viddaassistent.no>', to: email, subject: 'Tilbakestill passord', html: `<p>Hei ${user.name},</p><p>Din kode er:</p><h2 style="font-size:2rem;letter-spacing:0.2em">${code}</h2><p>Gyldig i 30 minutter.</p>` })
      });
    } else { console.log(`RESET KODE for ${email}: ${code}`); }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Serverfeil' }); }
});

app.post('/api/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!email || !code || !newPassword) return res.status(400).json({ error: 'Mangler felter' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Passord må være minst 6 tegn' });
  try {
    const user = await findUser(email);
    if (!user || user.reset_token !== code) return res.status(400).json({ error: 'Ugyldig kode' });
    if (new Date(user.reset_expires) < new Date()) return res.status(400).json({ error: 'Koden har utløpt. Be om en ny.' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2', [hashed, user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Serverfeil' }); }
});

app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
    res.json({ name: user.name, email: user.email, subscriptionStatus: user.subscription_status, trialEnds: user.trial_ends, hasApiKey: !!user.claude_api_key });
  } catch(e) { res.status(500).json({ error: 'Serverfeil' }); }
});

app.post('/api/apikey', authMiddleware, async (req, res) => {
  try { await db.query('UPDATE users SET claude_api_key=$1 WHERE id=$2', [req.body.claudeApiKey, req.user.id]); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: 'Serverfeil' }); }
});

app.post('/api/create-checkout', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe ikke konfigurert' });
  try {
    const user = await findUserById(req.user.id);
    const session = await stripe.checkout.sessions.create({
      customer: user.stripe_customer_id, payment_method_types: ['card'], mode: 'subscription',
      line_items: [{ price_data: { currency: 'nok', product_data: { name: 'ViddaAssistent – månedlig abonnement' }, unit_amount: 29900, recurring: { interval: 'month' } }, quantity: 1 }],
      success_url: `${process.env.APP_URL || 'http://localhost:3000'}/app.html?payment=success`,
      cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}/app.html?payment=cancelled`
    });
    res.json({ url: session.url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.status(503).end();
  try {
    const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET || '');
    if (event.type === 'checkout.session.completed') await db.query("UPDATE users SET subscription_status='active' WHERE stripe_customer_id=$1", [event.data.object.customer]);
    if (event.type === 'customer.subscription.deleted') await db.query("UPDATE users SET subscription_status='inactive' WHERE stripe_customer_id=$1", [event.data.object.customer]);
    res.json({ received: true });
  } catch(e) { res.status(400).send('Webhook feil: ' + e.message); }
});

app.get('/api/weather', authMiddleware, async (req, res) => {
  const { lat, lon } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'Mangler lat/lon' });
  try {
    const r = await fetch(`https://api.met.no/weatherapi/locationforecast/2.0/compact?lat=${parseFloat(lat).toFixed(4)}&lon=${parseFloat(lon).toFixed(4)}`, { headers: { 'User-Agent': 'ViddaAssistent/1.0 viddaassistent.no' } });
    res.json(await r.json());
  } catch(e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/geocode', authMiddleware, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Mangler søkeord' });
  try {
    const r = await fetch(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q + ', Norway')}&format=json&limit=1`, { headers: { 'User-Agent': 'ViddaAssistent/1.0 viddaassistent.no' } });
    res.json(await r.json());
  } catch(e) { res.status(502).json({ error: e.message }); }
});

app.post('/api/chat', authMiddleware, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
    const now = new Date();
    if (user.subscription_status === 'trial' && new Date(user.trial_ends) < now) return res.status(403).json({ error: 'Prøveperioden er over. Gå til innstillinger for å aktivere abonnement.' });
    if (user.subscription_status === 'inactive') return res.status(403).json({ error: 'Abonnement inaktivt. Gå til innstillinger.' });
    if (!user.claude_api_key) return res.status(400).json({ error: 'Ingen Claude API-nøkkel. Legg inn under innstillinger.' });
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': user.claude_api_key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(req.body)
    });
    res.json(await r.json());
  } catch(e) { res.status(502).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`ViddaAssistent kjører på port ${PORT}`));
