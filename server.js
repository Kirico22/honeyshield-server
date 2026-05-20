require('dotenv').config();
const express   = require('express');
const stripe    = require('stripe')(process.env.STRIPE_SECRET_KEY);
const cors      = require('cors');
const crypto    = require('crypto');
const fs        = require('fs');
const path      = require('path');

const app = express();

// ── BASE DE DATOS (JSON en disco — para producción real usa PostgreSQL) ────────
const DB_FILE = path.join(__dirname, 'licenses.json');

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  return { licenses: {}, customers: {} };
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
let db = loadDB();

// ── HELPERS ────────────────────────────────────────────────────────────────────
function generateLicenseKey() {
  const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `HS4-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function signLicense(key, email, plan) {
  const payload = `${key}:${email}:${plan}`;
  return crypto.createHmac('sha256', process.env.LICENSE_SECRET).update(payload).digest('hex');
}

function verifyLicenseSignature(key, email, plan, sig) {
  return signLicense(key, email, plan) === sig;
}

function createLicense({ email, plan, stripeCustomerId, stripeSubscriptionId, stripePriceId }) {
  const key       = generateLicenseKey();
  const createdAt = new Date().toISOString();
  const expiresAt = plan === 'monthly' ? new Date(Date.now() + 30*24*60*60*1000).toISOString()
                  : plan === 'yearly'  ? new Date(Date.now() + 365*24*60*60*1000).toISOString()
                  : null; // lifetime = sin expiración

  const license = {
    key, email, plan, status: 'active',
    createdAt, expiresAt,
    stripeCustomerId, stripeSubscriptionId, stripePriceId,
    activatedOn: null, activatedAt: null,
    sig: signLicense(key, email, plan),
  };

  db.licenses[key] = license;
  if (stripeCustomerId) {
    if (!db.customers[stripeCustomerId]) db.customers[stripeCustomerId] = [];
    db.customers[stripeCustomerId].push(key);
  }
  saveDB(db);
  return license;
}

function getLicenseStatus(lic) {
  if (!lic) return 'not_found';
  if (lic.status === 'revoked') return 'revoked';
  if (lic.expiresAt && new Date(lic.expiresAt) < new Date()) return 'expired';
  return lic.status; // 'active' | 'inactive'
}

function isDevRequest(req) {
  const user = req.headers['x-dev-user'];
  const pass = req.headers['x-dev-pass'];
  return user === process.env.DEV_USERNAME && pass === process.env.DEV_PASSWORD;
}

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
app.use(cors());

// Webhook de Stripe necesita el body RAW (sin parsear)
app.use('/webhook', express.raw({ type: 'application/json' }));

// El resto usa JSON normal
app.use(express.json());

// ── HEALTH CHECK ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'HoneyShield License Server', version: '1.0.0' });
});

// ─────────────────────────────────────────────────────────────────────────────
// RUTAS PÚBLICAS (llamadas desde la app Electron)
// ─────────────────────────────────────────────────────────────────────────────

// 1. Crear sesión de pago Stripe Checkout
app.post('/checkout', async (req, res) => {
  const { plan, email } = req.body;

  const priceMap = {
    monthly:  process.env.STRIPE_PRICE_MONTHLY,
    yearly:   process.env.STRIPE_PRICE_YEARLY,
    lifetime: process.env.STRIPE_PRICE_LIFETIME,
  };

  const priceId = priceMap[plan];
  if (!priceId) return res.status(400).json({ error: 'Plan no válido' });

  try {
    const isRecurring = plan === 'monthly' || plan === 'yearly';

    const session = await stripe.checkout.sessions.create({
      mode: isRecurring ? 'subscription' : 'payment',
      payment_method_types: ['card'],
      customer_email: email || undefined,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.SERVER_URL}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.SERVER_URL}/checkout/cancel`,
      metadata: { plan },
    });

    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 2. Página de éxito tras el pago (el usuario llega aquí desde el navegador)
app.get('/checkout/success', async (req, res) => {
  const { session_id } = req.query;
  try {
    const session  = await stripe.checkout.sessions.retrieve(session_id);
    const licKey   = Object.values(db.licenses).find(l => l.stripeSubscriptionId === session.subscription || l.stripeCustomerId === session.customer)?.key;
    res.send(`
      <!DOCTYPE html><html><head><meta charset="UTF-8">
      <title>Pago completado — HoneyShield AI</title>
      <style>body{font-family:system-ui;background:#080c18;color:#c8d8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px}
      h1{color:#00ff88;font-size:28px}p{color:#4a6a8a;font-size:14px}
      .key{background:#0f1828;border:1px solid #1a3050;border-radius:8px;padding:14px 20px;font-family:'Courier New',monospace;font-size:16px;color:#00d4ff;letter-spacing:2px;margin:10px 0}
      .note{font-size:12px;color:#4a6a8a;margin-top:8px}</style></head>
      <body>
        <div style="font-size:48px">🛡️</div>
        <h1>¡Pago completado!</h1>
        <p>Tu licencia de HoneyShield AI está lista</p>
        ${licKey ? `<div class="key">${licKey}</div><div class="note">Guarda esta clave — la necesitarás para activar la app</div>` : '<p style="color:#ffaa00">Licencia siendo procesada, recibirás un email en breve.</p>'}
        <p style="font-size:12px;color:#4a6a8a;margin-top:20px">Puedes cerrar esta ventana y volver a HoneyShield AI</p>
      </body></html>
    `);
  } catch(e) {
    res.send('<h1>Pago recibido. Recibirás tu licencia por email.</h1>');
  }
});

app.get('/checkout/cancel', (req, res) => {
  res.send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Pago cancelado</title>
    <style>body{font-family:system-ui;background:#080c18;color:#c8d8f0;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:12px}h1{color:#ffaa00}</style></head>
    <body><div style="font-size:48px">⚠️</div><h1>Pago cancelado</h1><p style="color:#4a6a8a">Puedes cerrar esta ventana y volver a HoneyShield AI</p></body></html>
  `);
});

// 3. Verificar/activar licencia (la app llama esto al introducir la clave)
app.post('/license/activate', (req, res) => {
  const { key, machineId } = req.body;
  if (!key) return res.status(400).json({ ok: false, error: 'Clave requerida' });

  const lic = db.licenses[key];
  const status = getLicenseStatus(lic);

  if (status === 'not_found') return res.json({ ok: false, error: 'Licencia no encontrada' });
  if (status === 'revoked')   return res.json({ ok: false, error: 'Licencia revocada' });
  if (status === 'expired')   return res.json({ ok: false, error: 'Licencia expirada. Renueva tu suscripción.' });

  // Si ya está activada en otro equipo, rechazar
  if (lic.activatedOn && lic.activatedOn !== machineId) {
    return res.json({ ok: false, error: 'Esta licencia ya está activada en otro equipo. Desactívala primero.' });
  }

  // Activar
  lic.activatedOn  = machineId;
  lic.activatedAt  = new Date().toISOString();
  lic.status       = 'active';
  saveDB(db);

  res.json({
    ok: true,
    license: {
      key:        lic.key,
      plan:       lic.plan,
      email:      lic.email,
      expiresAt:  lic.expiresAt,
      activatedAt: lic.activatedAt,
      sig:        lic.sig,
    }
  });
});

// 4. Verificar que una licencia sigue válida (la app llama esto al arrancar)
app.post('/license/verify', (req, res) => {
  const { key, sig, machineId } = req.body;
  if (!key) return res.status(400).json({ ok: false, valid: false });

  const lic    = db.licenses[key];
  const status = getLicenseStatus(lic);

  if (status !== 'active') {
    return res.json({ ok: true, valid: false, reason: status, plan: 'free' });
  }

  // Verificar firma y equipo
  const sigOk     = verifyLicenseSignature(key, lic.email, lic.plan, sig || lic.sig);
  const machineOk = !lic.activatedOn || lic.activatedOn === machineId;

  if (!sigOk || !machineOk) {
    return res.json({ ok: true, valid: false, reason: 'invalid_sig', plan: 'free' });
  }

  res.json({
    ok: true, valid: true,
    license: { key: lic.key, plan: lic.plan, email: lic.email, expiresAt: lic.expiresAt }
  });
});

// 5. Desactivar licencia (liberar equipo)
app.post('/license/deactivate', (req, res) => {
  const { key, machineId } = req.body;
  const lic = db.licenses[key];
  if (!lic) return res.json({ ok: false, error: 'No encontrada' });
  if (lic.activatedOn !== machineId) return res.json({ ok: false, error: 'No coincide el equipo' });

  lic.activatedOn = null;
  lic.activatedAt = null;
  saveDB(db);
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// WEBHOOK DE STRIPE (Stripe llama esto automáticamente)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/webhook', (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`[Webhook] ${event.type}`);

  switch (event.type) {

    // Pago único completado (lifetime)
    case 'checkout.session.completed': {
      const session = event.data.object;
      if (session.payment_status === 'paid' && session.mode === 'payment') {
        const plan = session.metadata?.plan || 'lifetime';
        createLicense({
          email:                session.customer_details?.email || session.customer_email,
          plan,
          stripeCustomerId:     session.customer,
          stripeSubscriptionId: null,
          stripePriceId:        null,
        });
        console.log(`[Webhook] Licencia ${plan} creada para ${session.customer_details?.email}`);
      }
      break;
    }

    // Suscripción nueva activada (monthly / yearly)
    case 'customer.subscription.created': {
      const sub  = event.data.object;
      const customer = sub.customer;
      stripe.customers.retrieve(customer).then(cust => {
        const priceId = sub.items.data[0]?.price?.id;
        const plan    = priceId === process.env.STRIPE_PRICE_MONTHLY ? 'monthly'
                      : priceId === process.env.STRIPE_PRICE_YEARLY  ? 'yearly'
                      : 'monthly';
        createLicense({
          email:                cust.email,
          plan,
          stripeCustomerId:     customer,
          stripeSubscriptionId: sub.id,
          stripePriceId:        priceId,
        });
        console.log(`[Webhook] Suscripción ${plan} creada para ${cust.email}`);
      }).catch(console.error);
      break;
    }

    // Suscripción renovada — actualizar expiresAt
    case 'invoice.payment_succeeded': {
      const invoice = event.data.object;
      if (invoice.subscription) {
        const lic = Object.values(db.licenses).find(l => l.stripeSubscriptionId === invoice.subscription);
        if (lic) {
          const days    = lic.plan === 'yearly' ? 365 : 30;
          lic.expiresAt = new Date(Date.now() + days*24*60*60*1000).toISOString();
          lic.status    = 'active';
          saveDB(db);
          console.log(`[Webhook] Renovada licencia ${lic.key} hasta ${lic.expiresAt}`);
        }
      }
      break;
    }

    // Pago fallido — dejar activa pero marcar
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      if (invoice.subscription) {
        const lic = Object.values(db.licenses).find(l => l.stripeSubscriptionId === invoice.subscription);
        if (lic) {
          lic.paymentFailed = true;
          saveDB(db);
          console.log(`[Webhook] Pago fallido para licencia ${lic.key}`);
        }
      }
      break;
    }

    // Suscripción cancelada — vuelve a Free automáticamente
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const lic = Object.values(db.licenses).find(l => l.stripeSubscriptionId === sub.id);
      if (lic) {
        lic.status    = 'cancelled';
        lic.expiresAt = new Date().toISOString(); // expira ahora → app vuelve a Free
        saveDB(db);
        console.log(`[Webhook] Suscripción cancelada → plan Free para ${lic.email}`);
      }
      break;
    }

    // Suscripción actualizada (upgrade/downgrade)
    case 'customer.subscription.updated': {
      const sub = event.data.object;
      const lic = Object.values(db.licenses).find(l => l.stripeSubscriptionId === sub.id);
      if (lic) {
        const priceId = sub.items.data[0]?.price?.id;
        if (priceId === process.env.STRIPE_PRICE_YEARLY)       lic.plan = 'yearly';
        else if (priceId === process.env.STRIPE_PRICE_MONTHLY) lic.plan = 'monthly';
        saveDB(db);
      }
      break;
    }

    default:
      console.log(`[Webhook] Evento no manejado: ${event.type}`);
  }

  res.json({ received: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// RUTAS DE DESARROLLADOR (protegidas por usuario/contraseña en headers)
// ─────────────────────────────────────────────────────────────────────────────
function devAuth(req, res, next) {
  if (!isDevRequest(req)) return res.status(401).json({ ok: false, error: 'No autorizado' });
  next();
}

// Ver todas las licencias
app.get('/dev/licenses', devAuth, (req, res) => {
  res.json({ ok: true, licenses: Object.values(db.licenses) });
});

// Estadísticas
app.get('/dev/stats', devAuth, (req, res) => {
  const all = Object.values(db.licenses);
  const active   = all.filter(l => getLicenseStatus(l) === 'active').length;
  const expired  = all.filter(l => getLicenseStatus(l) === 'expired').length;
  const revoked  = all.filter(l => l.status === 'revoked').length;
  const byPlan   = all.reduce((acc, l) => { acc[l.plan] = (acc[l.plan]||0)+1; return acc; }, {});
  const mrr = all.filter(l=>l.plan==='monthly'&&getLicenseStatus(l)==='active').length * 9.99
            + all.filter(l=>l.plan==='yearly' &&getLicenseStatus(l)==='active').length * (79.99/12);
  res.json({ ok: true, stats: { total: all.length, active, expired, revoked, byPlan, mrr: +mrr.toFixed(2) } });
});

// Crear licencia manual (para probar o regalar)
app.post('/dev/licenses/create', devAuth, (req, res) => {
  const { email, plan } = req.body;
  if (!email || !plan) return res.status(400).json({ ok: false, error: 'email y plan requeridos' });
  const lic = createLicense({ email, plan, stripeCustomerId: null, stripeSubscriptionId: null });
  res.json({ ok: true, license: lic });
});

// Revocar licencia
app.post('/dev/licenses/revoke', devAuth, (req, res) => {
  const { key } = req.body;
  const lic = db.licenses[key];
  if (!lic) return res.json({ ok: false, error: 'No encontrada' });
  lic.status    = 'revoked';
  lic.revokedAt = new Date().toISOString();
  // Cancelar en Stripe si tiene suscripción activa
  if (lic.stripeSubscriptionId) {
    stripe.subscriptions.cancel(lic.stripeSubscriptionId).catch(console.error);
  }
  saveDB(db);
  res.json({ ok: true });
});

// Reactivar licencia
app.post('/dev/licenses/reactivate', devAuth, (req, res) => {
  const { key } = req.body;
  const lic = db.licenses[key];
  if (!lic) return res.json({ ok: false, error: 'No encontrada' });
  lic.status = 'active';
  if (lic.plan !== 'lifetime') {
    const days = lic.plan === 'yearly' ? 365 : 30;
    lic.expiresAt = new Date(Date.now() + days*24*60*60*1000).toISOString();
  }
  delete lic.revokedAt;
  saveDB(db);
  res.json({ ok: true, license: lic });
});

// Buscar licencia por email
app.get('/dev/licenses/search', devAuth, (req, res) => {
  const { email } = req.query;
  const results = Object.values(db.licenses).filter(l => l.email?.toLowerCase().includes(email?.toLowerCase()));
  res.json({ ok: true, licenses: results });
});

// ── ARRANCAR ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛡️  HoneyShield License Server v1.0`);
  console.log(`📡 Escuchando en puerto ${PORT}`);
  console.log(`🔑 Licencias en base de datos: ${Object.keys(db.licenses).length}`);
  console.log(`💳 Stripe: ${process.env.STRIPE_SECRET_KEY?.startsWith('sk_live') ? '✅ PRODUCCIÓN' : '⚠️  MODO TEST'}`);
  console.log(`\nEndpoints disponibles:`);
  console.log(`  POST /checkout           → Crear sesión de pago`);
  console.log(`  POST /license/activate   → Activar licencia`);
  console.log(`  POST /license/verify     → Verificar licencia`);
  console.log(`  POST /license/deactivate → Desactivar licencia`);
  console.log(`  POST /webhook            → Webhook Stripe`);
  console.log(`  GET  /dev/licenses       → [DEV] Ver todas`);
  console.log(`  GET  /dev/stats          → [DEV] Estadísticas\n`);
});
