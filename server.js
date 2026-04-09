const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const storeApi = require('./lib/api');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════
// cbay — computational instruments marketplace
// Route-aware security hardening
// ═══════════════════════════════════════════════════════════

const PAGES = {
  '/':         { file: 'index.html',    security: 'strict' },
  '/store':    { file: 'store.html',    security: 'strict' },
  '/pay':      { file: 'pay.html',      security: 'strict' },
  '/unlock':   { file: 'unlock.html',   security: 'strict' },
  '/spectra':        { file: 'spectra.html',        security: 'camera' },
  '/artifact':       { file: 'artifact.html',       security: 'camera' },
  '/take':           { file: 'take.html',           security: 'camera' },
  '/map':            { file: 'map.html',            security: 'map' },
  '/report':         { file: 'report.html',         security: 'strict' },
  '/countermeasures': { file: 'countermeasures.html', security: 'camera' },
  '/tones-healing':  { file: 'tones-healing.html',  security: 'camera' },
  '/tones-shield':   { file: 'tones-shield.html',   security: 'camera' },
  '/tones-instrument': { file: 'tones-instrument.html', security: 'camera' },
  '/tones-multipack': { file: 'tones-multipack.html', security: 'camera' },
  '/tones-protective': { file: 'tones-protective.html', security: 'camera' },
  '/tones-shield-guide': { file: 'tones-shield-guide.html', security: 'strict' },
  '/ai-attack-vector-analysis': { file: 'ai-attack-vector-analysis.html', security: 'strict' },
};

// Pre-load HTML templates at startup
const TEMPLATES = {};
for (const [route, cfg] of Object.entries(PAGES)) {
  const fp = path.join(__dirname, 'public', cfg.file);
  if (fs.existsSync(fp)) TEMPLATES[route] = fs.readFileSync(fp, 'utf8');
}

const STATIC_FILES = new Set([
  '/favicon.svg', '/favicon.png', '/icon-transparent.svg',
  '/icon-spectra.svg', '/icon-artifact.svg', '/icon-take.svg',
  '/preview-spectra.svg', '/preview-artifact.svg', '/preview-take.svg',
]);

const ALLOWED = new Set([
  ...Object.keys(PAGES),
  ...STATIC_FILES,
  '/index.html', '/spectra.html', '/artifact.html', '/take.html',
  '/store.html', '/pay.html', '/unlock.html',
  '/map.html', '/report.html', '/countermeasures.html',
  '/tones-healing.html', '/tones-shield.html', '/tones-instrument.html',
  '/tones-multipack.html', '/tones-protective.html', '/tones-shield-guide.html',
  '/ai-attack-vector-analysis.html',
  '/cm-engine.js', '/i18n.js', '/sw.js',
  '/manifest-healing.json', '/manifest-instrument.json',
  '/manifest-multipack.json', '/manifest-protective.json', '/manifest-shield.json',
]);

// API routes bypass the static allowlist
const API_PREFIX = '/api/';

// ── Fingerprint removal ──
app.disable('x-powered-by');
app.disable('etag');
app.set('trust proxy', 1);

// ── Rate limiting ──
app.use(rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: '',
  statusCode: 429,
}));

// ── HTTPS enforcement ──
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV !== 'development') {
    return res.redirect(301, 'https://' + req.hostname + req.url);
  }
  next();
});

// ── Nonce generation ──
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// ── CSP directives by security level ──
function csp(nonce, level) {
  const d = {
    defaultSrc: ["'none'"],
    scriptSrc: [`'nonce-${nonce}'`],
    styleSrc: ["'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'],
    fontSrc: ["'none'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    frameAncestors: ["'none'"],
    formAction: ["'self'"],
    baseUri: ["'self'"],
    upgradeInsecureRequests: [],
  };
  if (level === 'camera') {
    d.connectSrc = ["'self'", 'blob:'];
    d.mediaSrc = ["'self'", 'blob:', 'mediastream:'];
    d.workerSrc = ["'self'", 'blob:'];
    d.childSrc = ["'self'", 'blob:'];
    d.imgSrc.push('blob:');
  } else if (level === 'map') {
    d.scriptSrc.push('https://unpkg.com');
    d.styleSrc.push('https://unpkg.com');
    d.connectSrc = ["'self'", 'https://earthquake.usgs.gov', 'https://eonet.gsfc.nasa.gov', 'https://firms.modaps.eosdis.nasa.gov', 'https://opensky-network.org', 'https://www.gdacs.org', 'https://api.wheretheiss.at', 'https://native-land.ca'];
    d.imgSrc = ["'self'", 'data:', 'https://*.basemaps.cartocdn.com', 'https://*.tile.openstreetmap.org', 'https://server.arcgisonline.com', 'https://*.tile.opentopomap.org', 'https://tiles.stadiamaps.com'];
    d.mediaSrc = ["'none'"];
    d.workerSrc = ["'none'"];
    d.childSrc = ["'none'"];
  } else {
    d.connectSrc = ["'self'"];
    d.mediaSrc = ["'none'"];
    d.workerSrc = ["'none'"];
    d.childSrc = ["'none'"];
  }
  return d;
}

function permissions(level) {
  const cam = level === 'camera' ? '(self)' : '()';
  const mic = level === 'camera' ? '(self)' : '()';
  return [
    `accelerometer=()`, `camera=${cam}`, `geolocation=()`,
    `gyroscope=()`, `magnetometer=()`, `microphone=${mic}`,
    `payment=()`, `usb=()`, `interest-cohort=()`,
    `browsing-topics=()`, `display-capture=()`, `document-domain=()`,
    `encrypted-media=()`, `fullscreen=(self)`, `picture-in-picture=()`
  ].join(', ');
}

// ── Security headers (route-aware) ──
app.use((req, res, next) => {
  const pg = PAGES[req.path];
  const level = pg ? pg.security : 'strict';
  helmet({
    contentSecurityPolicy: { directives: csp(res.locals.nonce, level) },
    strictTransportSecurity: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'no-referrer' },
    dnsPrefetchControl: { allow: false },
    ieNoOpen: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  })(req, res, () => {
    res.setHeader('Permissions-Policy', permissions(level));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    if (level === 'camera') {
      // Remove COOP/CORP — they break getUserMedia permission prompts
      res.removeHeader('Cross-Origin-Opener-Policy');
      res.removeHeader('Cross-Origin-Resource-Policy');
      res.removeHeader('Cross-Origin-Embedder-Policy');
    }
    res.removeHeader('X-Powered-By');
    next();
  });
});

// ── Path allowlist ──
app.use((req, res, next) => {
  const p = req.path.split('?')[0].split('#')[0].toLowerCase();
  if (p.includes('..') || p.includes('%2e') || p.includes('%00')) return res.status(400).end();
  // API routes have their own routing
  if (p.startsWith('/api/')) return next();
  if (!ALLOWED.has(p)) return res.status(404).end();
  next();
});

// ── Serve pages with nonce injection ──
function serve(route) {
  return (req, res) => {
    const t = TEMPLATES[route];
    if (!t) return res.status(404).end();
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.send(t.replace(/<script>/g, `<script nonce="${res.locals.nonce}">`));
  };
}

app.get('/', serve('/'));
app.get('/store', serve('/store'));
app.get('/pay', serve('/pay'));
app.get('/unlock', serve('/unlock'));
app.get('/spectra', serve('/spectra'));
app.get('/artifact', serve('/artifact'));
app.get('/take', serve('/take'));
app.get('/map', serve('/map'));
app.get('/report', serve('/report'));
app.get('/countermeasures', serve('/countermeasures'));
app.get('/tones-healing', serve('/tones-healing'));
app.get('/tones-shield', serve('/tones-shield'));
app.get('/tones-instrument', serve('/tones-instrument'));
app.get('/tones-multipack', serve('/tones-multipack'));
app.get('/tones-protective', serve('/tones-protective'));
app.get('/tones-shield-guide', serve('/tones-shield-guide'));
app.get('/ai-attack-vector-analysis', serve('/ai-attack-vector-analysis'));

// ── Clean URL redirects ──
app.get('/index.html', (_, res) => res.redirect(301, '/'));
app.get('/spectra.html', (_, res) => res.redirect(301, '/spectra'));
app.get('/artifact.html', (_, res) => res.redirect(301, '/artifact'));
app.get('/take.html', (_, res) => res.redirect(301, '/take'));
app.get('/store.html', (_, res) => res.redirect(301, '/store'));
app.get('/pay.html', (_, res) => res.redirect(301, '/pay'));
app.get('/unlock.html', (_, res) => res.redirect(301, '/unlock'));
app.get('/map.html', (_, res) => res.redirect(301, '/map'));
app.get('/report.html', (_, res) => res.redirect(301, '/report'));
app.get('/countermeasures.html', (_, res) => res.redirect(301, '/countermeasures'));
app.get('/tones-healing.html', (_, res) => res.redirect(301, '/tones-healing'));
app.get('/tones-shield.html', (_, res) => res.redirect(301, '/tones-shield'));
app.get('/tones-instrument.html', (_, res) => res.redirect(301, '/tones-instrument'));
app.get('/tones-multipack.html', (_, res) => res.redirect(301, '/tones-multipack'));
app.get('/tones-protective.html', (_, res) => res.redirect(301, '/tones-protective'));
app.get('/tones-shield-guide.html', (_, res) => res.redirect(301, '/tones-shield-guide'));
app.get('/ai-attack-vector-analysis.html', (_, res) => res.redirect(301, '/ai-attack-vector-analysis'));

// ── Store API ──
app.use('/api', storeApi);

// ── Static assets ──
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  dotfiles: 'deny',
  index: false,
}));

// ── 404 ──
app.use((req, res) => res.status(404).end());

// ── Error handler ──
app.use((err, req, res, next) => res.status(500).end());

// Start server only when run directly (not on Vercel)
if (!process.env.VERCEL) {
  app.listen(PORT, () => console.log(`[cbay] port ${PORT}`));
}

module.exports = app;
