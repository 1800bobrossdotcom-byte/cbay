// ═══════════════════════════════════════════════════════════
// cbay — store API routes
// HMAC-verified codes + brute-force protection
// ═══════════════════════════════════════════════════════════

const express = require('express');
const rateLimit = require('express-rate-limit');
const {
  PRODUCTS, WALLETS, COIN_NAMES,
  createAccessCode, verifyCode, redeemCode,
  validateCodeFormat, checkBruteForce, recordFailure, clearFailure,
} = require('./store');

const router = express.Router();

router.use(express.json({ limit: '16kb' }));

// ── Endpoint-specific rate limits for sensitive routes ──
const codeRateLimit = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts — try again later' },
  statusCode: 429,
  keyGenerator: (req) => req.ip,
});

// ── GET /api/products — public catalog ──
router.get('/products', (req, res) => {
  const catalog = Object.values(PRODUCTS).map(p => ({
    id: p.id,
    name: p.name,
    tagline: p.tagline,
    description: p.description,
    tags: p.tags,
    type: p.type,
    access: p.access,
    webPath: p.webPath,
    tier: p.tier,
    platforms: p.platforms || null,
    priceUSD: p.priceUSD,
    prices: p.prices,
  }));
  res.json({ products: catalog });
});

// ── GET /api/wallets — payment addresses ──
router.get('/wallets', (req, res) => {
  const available = {};
  for (const [coin, addr] of Object.entries(WALLETS)) {
    if (addr) {
      available[coin] = {
        address: addr,
        name: COIN_NAMES[coin],
      };
    }
  }
  res.json({ wallets: available });
});

// ── POST /api/order — create order + access code ──
router.post('/order', (req, res) => {
  const { productId, coin, txHash } = req.body || {};

  if (!productId || !PRODUCTS[productId]) {
    return res.status(400).json({ error: 'invalid product' });
  }
  if (!coin || !['XMR', 'LTC', 'BTC', 'ETH'].includes(coin)) {
    return res.status(400).json({ error: 'invalid coin — must be XMR, LTC, BTC, or ETH' });
  }

  const safeTxHash = typeof txHash === 'string' ? txHash.replace(/[^a-fA-F0-9]/g, '').slice(0, 128) : null;

  const entry = createAccessCode(productId, coin, safeTxHash);
  const product = PRODUCTS[productId];

  res.json({
    code: entry.code,
    product: product.name,
    coin,
    amount: product.prices[coin],
    wallet: WALLETS[coin] || null,
    status: safeTxHash ? 'pending-verification' : 'awaiting-payment',
    message: safeTxHash
      ? 'Code generated. Payment will be verified.'
      : `Send ${product.prices[coin]} ${coin} to the wallet address, then submit your tx hash to confirm.`,
  });
});

// ── POST /api/verify — check an access code ──
// Brute-force protected: HMAC check rejects bad format before DB hit
router.post('/verify', codeRateLimit, (req, res) => {
  const { code } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'missing code' });
  }

  const ip = req.ip;
  if (!checkBruteForce(ip)) {
    return res.status(429).json({ error: 'too many failed attempts — locked for 15 minutes' });
  }

  const clean = code.trim().toUpperCase();
  const result = verifyCode(clean);

  if (!result) {
    recordFailure(ip);
    return res.json({ valid: false, error: 'invalid or unregistered code' });
  }

  clearFailure(ip);
  res.json(result);
});

// ── POST /api/redeem — redeem code on a device ──
// Brute-force protected + device-bound
router.post('/redeem', codeRateLimit, (req, res) => {
  const { code, deviceId } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'missing code' });
  }

  const ip = req.ip;
  if (!checkBruteForce(ip)) {
    return res.status(429).json({ error: 'too many failed attempts — locked for 15 minutes' });
  }

  const clean = code.trim().toUpperCase();
  const safeDeviceId = typeof deviceId === 'string' ? deviceId.slice(0, 128) : null;
  const result = redeemCode(clean, safeDeviceId);

  if (result.error) {
    recordFailure(ip);
    return res.status(400).json(result);
  }

  clearFailure(ip);
  res.json(result);
});

module.exports = router;
