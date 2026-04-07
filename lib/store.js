// ═══════════════════════════════════════════════════════════
// cbay — product catalog & access code store
// Flat-file JSON store (upgradeable to DB later)
// ═══════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Use /tmp on Vercel (read-only fs), local data/ dir otherwise
const DATA_DIR = process.env.VERCEL ? path.join('/tmp', 'cbay-data') : path.join(__dirname, '..', 'data');
const CODES_FILE = path.join(DATA_DIR, 'codes.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Ensure data dir exists
try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
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
    type: 'app',        // app | tool | bundle
    access: 'freemium', // free | freemium | paid
    webPath: '/spectra',
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
    prices: {
      XMR: '0.10',
      LTC: '0.22',
      BTC: '0.00015',
      ETH: '0.009',
    },
    priceUSD: 15.00,
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

// ── Access codes ──

function loadJSON(file) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { /* corrupt file, start fresh */ }
  return [];
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

/**
 * Generate access code: CBAY-XXXX-XXXX-XXXX
 * Cryptographically random, 12 hex chars in groups
 */
function generateCode() {
  const hex = crypto.randomBytes(6).toString('hex').toUpperCase();
  return 'CBAY-' + hex.slice(0, 4) + '-' + hex.slice(4, 8) + '-' + hex.slice(8, 12);
}

/**
 * Create a new access code for a product purchase
 */
function createAccessCode(productId, coin, txHash) {
  const codes = loadJSON(CODES_FILE);
  const code = generateCode();

  const entry = {
    code,
    productId,
    coin,
    txHash: txHash || null,
    createdAt: new Date().toISOString(),
    redeemed: false,
    redeemedAt: null,
    deviceId: null,
  };

  codes.push(entry);
  saveJSON(CODES_FILE, codes);

  // Also log to orders
  const orders = loadJSON(ORDERS_FILE);
  orders.push({
    code,
    productId,
    coin,
    txHash: txHash || null,
    amount: PRODUCTS[productId] ? PRODUCTS[productId].prices[coin] : null,
    createdAt: entry.createdAt,
    status: txHash ? 'pending-verification' : 'awaiting-payment',
  });
  saveJSON(ORDERS_FILE, orders);

  return entry;
}

/**
 * Verify an access code — returns product info or null
 */
function verifyCode(code) {
  const codes = loadJSON(CODES_FILE);
  const entry = codes.find(c => c.code === code);
  if (!entry) return null;

  const product = PRODUCTS[entry.productId];
  return {
    valid: true,
    code: entry.code,
    product: product ? product.id : entry.productId,
    productName: product ? product.name : entry.productId,
    redeemed: entry.redeemed,
    createdAt: entry.createdAt,
    redeemedAt: entry.redeemedAt,
    // Suite codes unlock everything
    unlocks: entry.productId === 'cbay-suite'
      ? Object.keys(PRODUCTS).filter(k => PRODUCTS[k].type === 'app').map(k => PRODUCTS[k].name)
      : [product ? product.name : entry.productId],
  };
}

/**
 * Redeem an access code (mark as used, bind to device)
 */
function redeemCode(code, deviceId) {
  const codes = loadJSON(CODES_FILE);
  const idx = codes.findIndex(c => c.code === code);
  if (idx === -1) return { error: 'invalid code' };

  const entry = codes[idx];
  if (entry.redeemed) {
    // Allow re-verification from same device
    if (entry.deviceId === deviceId) {
      return { ok: true, alreadyRedeemed: true, product: entry.productId };
    }
    return { error: 'code already redeemed on another device' };
  }

  codes[idx].redeemed = true;
  codes[idx].redeemedAt = new Date().toISOString();
  codes[idx].deviceId = deviceId || null;
  saveJSON(CODES_FILE, codes);

  const product = PRODUCTS[entry.productId];
  return {
    ok: true,
    product: entry.productId,
    unlocks: entry.productId === 'cbay-suite'
      ? Object.keys(PRODUCTS).filter(k => PRODUCTS[k].type === 'app').map(k => PRODUCTS[k].name)
      : [product ? product.name : entry.productId],
  };
}

module.exports = {
  PRODUCTS,
  WALLETS,
  COIN_NAMES,
  generateCode,
  createAccessCode,
  verifyCode,
  redeemCode,
};
