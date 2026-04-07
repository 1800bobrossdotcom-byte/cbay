// ═══════════════════════════════════════════════════════════
// cbay — store API routes
// /api/products, /api/verify, /api/redeem, /api/order
// ═══════════════════════════════════════════════════════════

const express = require('express');
const crypto = require('crypto');
const { PRODUCTS, WALLETS, COIN_NAMES, createAccessCode, verifyCode, redeemCode } = require('./store');

const router = express.Router();

router.use(express.json({ limit: '16kb' }));

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
    priceUSD: p.priceUSD,
    prices: p.prices,
  }));
  res.json({ products: catalog });
});

// ── GET /api/wallets — payment addresses ──
router.get('/wallets', (req, res) => {
  // Only return wallets that are configured
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
// Body: { productId, coin, txHash? }
router.post('/order', (req, res) => {
  const { productId, coin, txHash } = req.body || {};

  if (!productId || !PRODUCTS[productId]) {
    return res.status(400).json({ error: 'invalid product' });
  }
  if (!coin || !['XMR', 'LTC', 'BTC', 'ETH'].includes(coin)) {
    return res.status(400).json({ error: 'invalid coin — must be XMR, LTC, BTC, or ETH' });
  }

  // Sanitize txHash 
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
// Body: { code }
router.post('/verify', (req, res) => {
  const { code } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'missing code' });
  }

  // Normalize: uppercase, trim
  const clean = code.trim().toUpperCase();
  const result = verifyCode(clean);

  if (!result) {
    return res.json({ valid: false });
  }

  res.json(result);
});

// ── POST /api/redeem — redeem code on a device ──
// Body: { code, deviceId }
router.post('/redeem', (req, res) => {
  const { code, deviceId } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'missing code' });
  }

  const clean = code.trim().toUpperCase();
  const safeDeviceId = typeof deviceId === 'string' ? deviceId.slice(0, 128) : null;
  const result = redeemCode(clean, safeDeviceId);

  if (result.error) {
    return res.status(400).json(result);
  }

  res.json(result);
});

module.exports = router;
