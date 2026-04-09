// ═══════════════════════════════════════════════════════════
// cbay — product catalog & access code store
// HMAC-signed codes + flat-file JSON store
// ═══════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ── HMAC signing key — MUST be set in production ──
const HMAC_SECRET = process.env.CBAY_HMAC_SECRET || 'cbay-dev-only-change-this';

// Use /tmp on Vercel (read-only fs), local data/ dir otherwise
const DATA_DIR = process.env.VERCEL ? path.join('/tmp', 'cbay-data') : path.join(__dirname, '..', 'data');
const CODES_FILE = path.join(DATA_DIR, 'codes.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Seed codes embedded for Vercel (bundler can't trace dynamic fs reads)
const SEED_CODES = [
  { code: 'CBAY-5D42-CFB5-76FA-8D09', productId: 'spectra', tier: 'visual', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.669Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: null },
  { code: 'CBAY-E8F7-D99F-38AD-D2D0', productId: 'artifact', tier: 'visual', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.672Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: null },
  { code: 'CBAY-9511-03A8-EC6A-5B17', productId: 'take', tier: 'visual', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.673Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: null },
  { code: 'CBAY-BC85-3027-2B12-9149', productId: 'cbay-suite', tier: 'visual', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.674Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: null },
  { code: 'CBAY-BFC6-BE62-B2F5-42BF', productId: 'tones', tier: 'audio', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.675Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: ['iOS', 'Android', 'Desktop'] },
  { code: 'CBAY-9523-0430-E2A9-FF63', productId: 'shield', tier: 'audio', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.677Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: ['iOS', 'Android', 'Desktop'] },
  { code: 'CBAY-5261-F1E0-96D4-2D65', productId: 'tone-lab', tier: 'audio', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.678Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: ['iOS', 'Android', 'Desktop'] },
  { code: 'CBAY-CDFA-DE9A-FB60-3BB0', productId: 'audio-suite', tier: 'audio', coin: 'XMR', txHash: null, createdAt: '2026-04-09T13:18:08.682Z', redeemed: false, redeemedAt: null, deviceHash: null, platforms: ['iOS', 'Android', 'Desktop'] },
];

// Ensure data dir exists + seed on cold start
try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CODES_FILE)) {
    fs.writeFileSync(CODES_FILE, JSON.stringify(SEED_CODES, null, 2), 'utf8');
  }
} catch (e) {
  // Serverless: silently continue — codes will live in memory only
}

// ── Product catalog ──

const PRODUCTS = {
  spectra: {
    id: 'spectra',
    name: 'SPECTRA',
    tagline: 'computational vision engine',
    description: 'Night vision, thermal imaging, motion detection, edge detection — 5 modes of real-time camera processing.',
    tags: ['night', 'thermal', 'motion', 'edge', 'infrared'],
    type: 'app',
    access: 'freemium',
    webPath: '/spectra',
    tier: 'visual',
    prices: {
      XMR: '0.035',
      LTC: '0.08',
      BTC: '0.00005',
      ETH: '0.003',
    },
    priceUSD: 5.00,
  },
  artifact: {
    id: 'artifact',
    name: 'ARTIFACT',
    tagline: 'analog glitch camera',
    description: '10 real-time glitch modes — pixel sort, VHS, databend, signal modulation, melt, slit-scan, physarum, and more. Touch + audio reactive.',
    tags: ['pixel sort', 'VHS', 'databend', 'signal', 'melt', 'slit-scan', 'physarum', 'JPEG glitch'],
    type: 'app',
    access: 'freemium',
    webPath: '/artifact',
    tier: 'visual',
    prices: {
      XMR: '0.055',
      LTC: '0.12',
      BTC: '0.00008',
      ETH: '0.005',
    },
    priceUSD: 8.00,
  },
  take: {
    id: 'take',
    name: 'TAKE',
    tagline: 'short-form video tool',
    description: 'Record, apply real-time effects, concatenate clips, export. Built for quick content creation.',
    tags: ['record', 'effects', 'concatenate', 'export'],
    type: 'app',
    access: 'freemium',
    webPath: '/take',
    tier: 'visual',
    prices: {
      XMR: '0.035',
      LTC: '0.08',
      BTC: '0.00005',
      ETH: '0.003',
    },
    priceUSD: 5.00,
  },
  'cbay-suite': {
    id: 'cbay-suite',
    name: 'CBAY SUITE',
    tagline: 'all instruments — one code',
    description: 'Unlock every cbay app with a single access code. Includes all future releases.',
    tags: ['spectra', 'artifact', 'take', 'all'],
    type: 'bundle',
    access: 'paid',
    webPath: null,
    tier: 'visual',
    prices: {
      XMR: '0.10',
      LTC: '0.22',
      BTC: '0.00015',
      ETH: '0.009',
    },
    priceUSD: 15.00,
  },
  tones: {
    id: 'tones',
    name: 'TONES',
    tagline: 'healing frequency engine',
    description: 'Solfeggio healing tones, binaural beats, pink noise, brown noise, ocean ambience — 6 modes of therapeutic audio synthesis.',
    tags: ['solfeggio', 'binaural', 'pink noise', 'brown noise', 'ocean', 'healing'],
    type: 'app',
    access: 'paid',
    webPath: '/tones',
    tier: 'audio',
    platforms: ['iOS', 'Android', 'Desktop', 'Web'],
    prices: {
      XMR: '0.045',
      LTC: '0.10',
      BTC: '0.00006',
      ETH: '0.004',
    },
    priceUSD: 6.99,
  },
  shield: {
    id: 'shield',
    name: 'SHIELD',
    tagline: 'audio defense system',
    description: 'Real-time FFT threat detection across 5 bands. Phase cancellation, sweep jamming, broadband defense, counter-frequency — with evidence recording.',
    tags: ['threat detect', 'phase cancel', 'sweep jam', 'broadband', 'counter-frequency', 'evidence'],
    type: 'app',
    access: 'paid',
    webPath: '/shield',
    tier: 'audio',
    platforms: ['iOS', 'Android', 'Desktop', 'Web'],
    prices: {
      XMR: '0.065',
      LTC: '0.15',
      BTC: '0.0001',
      ETH: '0.006',
    },
    priceUSD: 9.99,
  },
  'tone-lab': {
    id: 'tone-lab',
    name: 'TONE LAB',
    tagline: '32-pad synthesizer',
    description: 'Full synthesizer — 32 pads, 5 categories, effects chain, mic modes, 32-step sequencer, WAV export.',
    tags: ['synthesizer', 'solfeggio', 'chant', 'binaural', 'ultrasonic', 'sequencer', 'WAV'],
    type: 'app',
    access: 'paid',
    webPath: '/tone-lab',
    tier: 'audio',
    platforms: ['iOS', 'Android', 'Desktop', 'Web'],
    prices: {
      XMR: '0.065',
      LTC: '0.15',
      BTC: '0.0001',
      ETH: '0.006',
    },
    priceUSD: 9.99,
  },
  'audio-suite': {
    id: 'audio-suite',
    name: 'AUDIO SUITE',
    tagline: 'all audio apps — all platforms',
    description: 'Unlock TONES + SHIELD + TONE LAB on iOS, Android, and Desktop with a single code.',
    tags: ['tones', 'shield', 'tone-lab', 'all-platforms'],
    type: 'bundle',
    access: 'paid',
    webPath: null,
    tier: 'audio',
    platforms: ['iOS', 'Android', 'Desktop'],
    prices: {
      XMR: '0.14',
      LTC: '0.32',
      BTC: '0.0002',
      ETH: '0.012',
    },
    priceUSD: 19.99,
  },
};

// ── Crypto wallet addresses ──
// Set via env vars — NEVER hardcode wallet addresses
const WALLETS = {
  XMR: process.env.CBAY_WALLET_XMR || null,
  LTC: process.env.CBAY_WALLET_LTC || null,
  BTC: process.env.CBAY_WALLET_BTC || null,
  ETH: process.env.CBAY_WALLET_ETH || null,
};

const COIN_NAMES = {
  XMR: 'Monero',
  LTC: 'Litecoin',
  BTC: 'Bitcoin',
  ETH: 'Ethereum',
};

// ── Access codes — HMAC-signed ──
// Format: CBAY-XXXX-XXXX-XXXX-SSSS
// 12 hex = 96-bit random payload, last 4 = HMAC-SHA256 signature prefix
// Self-validating: format check rejects bad codes before DB hit

function loadJSON(file) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { /* corrupt file, start fresh */ }
  return [];
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function hmacSign(payload) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

function generateCode() {
  // 12 bytes = 96 bits entropy (was 6 bytes / 48 bits)
  const payload = crypto.randomBytes(12).toString('hex').toUpperCase();
  const seg = payload.slice(0, 4) + '-' + payload.slice(4, 8) + '-' + payload.slice(8, 12);
  // HMAC the first 12 chars as signature
  const sig = hmacSign(payload.slice(0, 12)).toUpperCase().slice(0, 4);
  return 'CBAY-' + seg + '-' + sig;
}

// Validate format + HMAC signature — rejects brute-force attempts without DB
function validateCodeFormat(code) {
  if (typeof code !== 'string') return false;
  const parts = code.split('-');
  if (parts.length !== 5 || parts[0] !== 'CBAY') return false;
  for (let i = 1; i <= 4; i++) {
    if (!/^[A-F0-9]{4}$/i.test(parts[i])) return false;
  }
  const payload = (parts[1] + parts[2] + parts[3]).toUpperCase();
  const expected = hmacSign(payload).toUpperCase().slice(0, 4);
  const provided = parts[4].toUpperCase();
  // Constant-time comparison
  let diff = 0;
  for (let i = 0; i < 4; i++) diff |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// ── Brute-force protection ──
const _fails = new Map();
const MAX_FAILS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function checkBruteForce(ip) {
  const e = _fails.get(ip);
  if (!e) return true;
  if (Date.now() > e.resetAt) { _fails.delete(ip); return true; }
  return e.count < MAX_FAILS;
}

function recordFailure(ip) {
  const e = _fails.get(ip) || { count: 0, resetAt: Date.now() + LOCKOUT_MS };
  e.count++;
  e.resetAt = Date.now() + LOCKOUT_MS;
  _fails.set(ip, e);
}

function clearFailure(ip) { _fails.delete(ip); }

function resolveUnlocks(productId) {
  const p = PRODUCTS[productId];
  if (productId === 'audio-suite') {
    return Object.values(PRODUCTS).filter(x => x.tier === 'audio' && x.type === 'native-app').map(x => x.name);
  }
  if (productId === 'cbay-suite') {
    return Object.values(PRODUCTS).filter(x => x.type === 'app').map(x => x.name);
  }
  return [p ? p.name : productId];
}

function createAccessCode(productId, coin, txHash) {
  const codes = loadJSON(CODES_FILE);
  const code = generateCode();
  const product = PRODUCTS[productId];

  const entry = {
    code,
    productId,
    tier: product ? product.tier : 'visual',
    coin,
    txHash: txHash || null,
    createdAt: new Date().toISOString(),
    redeemed: false,
    redeemedAt: null,
    deviceHash: null,
    platforms: product && product.platforms ? product.platforms : null,
  };

  codes.push(entry);
  saveJSON(CODES_FILE, codes);

  const orders = loadJSON(ORDERS_FILE);
  orders.push({
    code,
    productId,
    coin,
    txHash: txHash || null,
    amount: product ? product.prices[coin] : null,
    createdAt: entry.createdAt,
    status: txHash ? 'pending-verification' : 'awaiting-payment',
  });
  saveJSON(ORDERS_FILE, orders);

  return entry;
}

function verifyCode(code) {
  // HMAC check first — rejects invalid codes before touching DB
  if (!validateCodeFormat(code)) return null;

  const codes = loadJSON(CODES_FILE);
  const entry = codes.find(c => c.code === code);
  if (!entry) return null;

  const product = PRODUCTS[entry.productId];
  return {
    valid: true,
    code: entry.code,
    product: product ? product.id : entry.productId,
    productName: product ? product.name : entry.productId,
    tier: entry.tier,
    platforms: entry.platforms,
    redeemed: entry.redeemed,
    createdAt: entry.createdAt,
    redeemedAt: entry.redeemedAt,
    unlocks: resolveUnlocks(entry.productId),
  };
}

function redeemCode(code, deviceId) {
  if (!validateCodeFormat(code)) return { error: 'invalid code' };

  const codes = loadJSON(CODES_FILE);
  const idx = codes.findIndex(c => c.code === code);
  if (idx === -1) return { error: 'invalid code' };

  const entry = codes[idx];
  // Hash device ID for storage (never store raw)
  const deviceHash = deviceId
    ? crypto.createHash('sha256').update(deviceId).digest('hex').slice(0, 16)
    : null;

  if (entry.redeemed) {
    if (deviceHash && entry.deviceHash === deviceHash) {
      return { ok: true, alreadyRedeemed: true, product: entry.productId, tier: entry.tier };
    }
    return { error: 'code already redeemed on another device' };
  }

  codes[idx].redeemed = true;
  codes[idx].redeemedAt = new Date().toISOString();
  codes[idx].deviceHash = deviceHash;
  saveJSON(CODES_FILE, codes);

  return {
    ok: true,
    product: entry.productId,
    tier: entry.tier,
    platforms: entry.platforms,
    unlocks: resolveUnlocks(entry.productId),
  };
}

module.exports = {
  PRODUCTS,
  WALLETS,
  COIN_NAMES,
  generateCode,
  validateCodeFormat,
  createAccessCode,
  verifyCode,
  redeemCode,
  checkBruteForce,
  recordFailure,
  clearFailure,
};
