// ═══════════════════════════════════════════════════════════
// cbay — email service
// Gmail SMTP via Nodemailer (App Password)
// Route: support@clasp.codes → 1800bobrossdotcom@gmail.com
// ═══════════════════════════════════════════════════════════

const nodemailer = require('nodemailer');

// ── Gmail App Password config ──
// Generate at: https://myaccount.google.com/apppasswords
// Set env vars: GMAIL_USER, GMAIL_APP_PASSWORD
// Optional: SUPPORT_EMAIL for the "from" display address

const GMAIL_USER = process.env.GMAIL_USER || '1800bobrossdotcom@gmail.com';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || null;
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@clasp.codes';

let transporter = null;

if (GMAIL_APP_PASSWORD) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD,
    },
  });

  // Verify connection on startup
  transporter.verify().then(() => {
    console.log('[mailer] gmail SMTP ready');
  }).catch((err) => {
    console.error('[mailer] gmail SMTP failed:', err.message);
    transporter = null;
  });
} else {
  console.log('[mailer] no GMAIL_APP_PASSWORD set — email disabled');
}

// ── HTML entity escaping for user content in emails ──
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Send access code to buyer ──
async function sendAccessCode({ to, code, productName, coin, amount }) {
  if (!transporter || !to) return { sent: false, reason: 'email not configured' };

  const html = `
    <div style="font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:0 auto;background:#0a0a14;color:#b0d0e0;padding:32px 24px;border-radius:12px;">
      <h1 style="font-size:28px;letter-spacing:8px;color:#fff;text-align:center;margin:0 0 8px;">CBAY</h1>
      <p style="font-size:10px;letter-spacing:3px;color:#8888aa;text-align:center;margin:0 0 24px;">computational instruments</p>
      <hr style="border:none;border-top:1px solid #1e1e3a;margin:0 0 24px;">
      <p style="font-size:12px;color:#8888aa;letter-spacing:1px;">your access code for <strong style="color:#00E5FF;">${productName}</strong></p>
      <div style="background:#12122a;border:1px solid #1e1e3a;border-radius:8px;padding:16px;text-align:center;margin:12px 0 20px;">
        <code style="font-size:18px;letter-spacing:3px;color:#00E5FF;font-family:'SF Mono',Menlo,monospace;">${code}</code>
      </div>
      <p style="font-size:11px;color:#8888aa;line-height:1.6;">
        payment: <strong>${amount} ${coin}</strong><br>
        redeem at <a href="https://cbay.ing/unlock" style="color:#00E5FF;">cbay.ing/unlock</a>
      </p>
      <hr style="border:none;border-top:1px solid #1e1e3a;margin:24px 0 16px;">
      <p style="font-size:9px;color:#555577;text-align:center;letter-spacing:2px;">
        keep this code safe — it cannot be recovered<br>
        support: <a href="mailto:${SUPPORT_EMAIL}" style="color:#8888aa;">${SUPPORT_EMAIL}</a>
      </p>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"cbay" <${GMAIL_USER}>`,
      replyTo: SUPPORT_EMAIL,
      to,
      subject: `Your ${productName} access code`,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] send failed:', err.message);
    return { sent: false, reason: err.message };
  }
}

// ── Send bug report notification ──
async function sendBugReport({ from, subject, body, userAgent, page }) {
  if (!transporter) return { sent: false, reason: 'email not configured' };

  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:24px;">
      <h2 style="margin:0 0 16px;">Bug Report — cbay</h2>
      <table style="font-size:13px;border-collapse:collapse;width:100%;">
        <tr><td style="padding:4px 8px;color:#888;">From</td><td style="padding:4px 8px;">${esc(from || 'anonymous')}</td></tr>
        <tr><td style="padding:4px 8px;color:#888;">Page</td><td style="padding:4px 8px;">${esc(page || 'unknown')}</td></tr>
        <tr><td style="padding:4px 8px;color:#888;">UA</td><td style="padding:4px 8px;font-size:11px;">${esc(userAgent || 'n/a')}</td></tr>
      </table>
      <hr style="margin:16px 0;">
      <p style="font-size:13px;white-space:pre-wrap;">${esc(body)}</p>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"cbay bug" <${GMAIL_USER}>`,
      replyTo: from || SUPPORT_EMAIL,
      to: GMAIL_USER,
      subject: `[BUG] ${subject || 'Bug report'}`,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] bug report send failed:', err.message);
    return { sent: false, reason: err.message };
  }
}

module.exports = { sendAccessCode, sendBugReport, SUPPORT_EMAIL };
