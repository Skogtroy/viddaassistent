const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'viddaassistent-secret-2026';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── ENKEL BRUKERDATABASE (in-memory – holder for MVP) ──
// Brukere lagres her mens serveren kjører.
// For produksjon: bytt ut med en ekte database (f.eks. Railway PostgreSQL).
const users = [];

// ── HJELPEFUNKSJONER ──
function findUser(email) {
  return users.find(u => u.email.toLowerCase() === email.toLowerCase());
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Ikke innlogget' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ugyldig token' });
  }
}

// ── BRUKERREGISTRERING ──
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Fyll inn alle feltene' });

  if (findUser(email))
    return res.status(400).json({ error: 'E-post er allerede registrert' });

  const hashed = await bcrypt.hash(password, 10);

  // Opprett Stripe-kunde
  let stripeCustomerId = null;
  try {
    const customer = await stripe.customers.create({ email, name });
    stripeCustomerId = customer.id;
  } catch (e) {
    console.error('Stripe kunde-feil:', e.message);
  }

  const user = {
    id: Date.now().toString(),
    email,
    name,
    password: hashed,
    stripeCustomerId,
    subscriptionStatus: 'trial', // trial, active, inactive
    trialEnds: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
    claudeApiKey: req.body.claudeApiKey || null
  };

  users.push(user);

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, name: user.name, email: user.email, subscriptionStatus: user.subscriptionStatus, trialEnds: user.trialEnds });
});

// ── INNLOGGING ──
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = findUser(email);
  if (!user) return res.status(401).json({ error: 'Feil e-post eller passord' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Feil e-post eller passord' });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({
    token,
    name: user.name,
    email: user.email,
    subscriptionStatus: user.subscriptionStatus,
    trialEnds: user.trialEnds
  });
});

// ── LAGRE CLAUDE API-NØKKEL ──
app.post('/api/apikey', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
  user.claudeApiKey = req.body.claudeApiKey;
  res.json({ ok: true });
});

// ── HENT BRUKERINFO ──
app.get('/api/me', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
  res.json({
    name: user.name,
    email: user.email,
    subscriptionStatus: user.subscriptionStatus,
    trialEnds: user.trialEnds,
    hasApiKey: !!user.claudeApiKey
  });
});

// ── STRIPE BETALING ──
app.post('/api/create-checkout', authMiddleware, async (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });

  try {
    const session = await stripe.checkout.sessions.create({
      customer: user.stripeCustomerId,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{
        price_data: {
          currency: 'nok',
          product_data: { name: 'ViddaAssistent – månedlig abonnement' },
          unit_amount: 29900, // 299 kr i øre
          recurring: { interval: 'month' }
        },
        quantity: 1
      }],
      success_url: `${process.env.APP_URL || 'http://localhost:3000'}/app.html?payment=success`,
      cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}/app.html?payment=cancelled`
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe checkout feil:', e.message);
    res.status(500).json({ error: 'Kunne ikke opprette betaling: ' + e.message });
  }
});

// ── STRIPE WEBHOOK (oppdater abonnementsstatus) ──
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || '');
  } catch (e) {
    return res.status(400).send('Webhook feil: ' + e.message);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const user = users.find(u => u.stripeCustomerId === session.customer);
    if (user) user.subscriptionStatus = 'active';
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const user = users.find(u => u.stripeCustomerId === sub.customer);
    if (user) user.subscriptionStatus = 'inactive';
  }

  res.json({ received: true });
});

// ── YR VÆRVARSLER (proxy) ──
app.get('/api/weather', authMiddleware, async (req, res) => {
  const { lat, lon } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'Mangler lat/lon' });

  try {
    const yrRes = await fetch(
      `https://api.met.no/weatherapi/locationforecast/2.0/compact?lat=${parseFloat(lat).toFixed(4)}&lon=${parseFloat(lon).toFixed(4)}`,
      { headers: { 'User-Agent': 'ViddaAssistent/1.0 viddaassistent.no' } }
    );
    const data = await yrRes.json();
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'Kunne ikke hente YR-data: ' + e.message });
  }
});

// ── STEDSSØK (proxy for Nominatim) ──
app.get('/api/geocode', authMiddleware, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Mangler søkeord' });

  try {
    const geoRes = await fetch(
      `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q + ', Norway')}&format=json&limit=1`,
      { headers: { 'User-Agent': 'ViddaAssistent/1.0 viddaassistent.no' } }
    );
    const data = await geoRes.json();
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'Stedssøk feilet: ' + e.message });
  }
});

// ── AI CHAT (proxy for Claude API) ──
app.post('/api/chat', authMiddleware, async (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });

  // Sjekk abonnement
  const now = new Date();
  const trialOk = user.subscriptionStatus === 'trial' && new Date(user.trialEnds) > now;
  const activeOk = user.subscriptionStatus === 'active';
  if (!trialOk && !activeOk) {
    return res.status(403).json({ error: 'Abonnement utløpt. Gå til innstillinger for å fornye.' });
  }

  const apiKey = user.claudeApiKey;
  if (!apiKey) return res.status(400).json({ error: 'Ingen Claude API-nøkkel. Legg inn under innstillinger.' });

  try {
    const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await claudeRes.json();
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: 'AI-feil: ' + e.message });
  }
});

app.listen(PORT, () => console.log(`ViddaAssistent kjører på port ${PORT}`));
