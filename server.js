require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Handle invalid JSON bodies gracefully
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON payload' });
  }
  return next(err);
});

// MongoDB Connection
if (process.env.MONGODB_URI) {
  console.log('🔄 Attempting MongoDB connection...');
  mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB connected successfully'))
    .catch(e => console.error('❌ MongoDB connection failed:', e.message || e));
} else {
  console.log('⚠️  MONGODB_URI not set in .env');
}

// User Schema
const userSchema = new mongoose.Schema({
  phone: { type: String, unique: true, required: true },
  firstLoginAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: Date.now },
  loginCount: { type: Number, default: 1 },
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

const Redis = require('ioredis');

let redisClient = null;
if (process.env.REDIS_URL) {
  try {
    redisClient = new Redis(process.env.REDIS_URL);
    redisClient.on('error', e => console.error('Redis error', e));
    console.log('Using Redis for OTP storage');
  } catch (e) {
    console.error('Failed to initialize Redis, falling back to memory store', e);
    redisClient = null;
  }
}

const otpStore = redisClient ? null : new Map();

function normalize(phone) {
  if (!phone) return null;
  const s = String(phone).trim();
  const p = s.replace(/\D/g, '');
  if (p.length === 10) return '+91' + p;
  if (p.length === 12 && p.startsWith('91')) return '+' + p;
  if (p.length === 11 && p.startsWith('0')) return '+91' + p.slice(1);
  if (s.startsWith('+')) return s;
  return null;
}

async function storeOtp(normalized, code, ttlMs = 5 * 60 * 1000) {
  if (redisClient) {
    await redisClient.set(normalized, code, 'PX', ttlMs);
  } else {
    otpStore.set(normalized, { code, expiresAt: Date.now() + ttlMs });
  }
}

async function fetchOtp(normalized) {
  if (redisClient) {
    const code = await redisClient.get(normalized);
    if (!code) return null;
    return { code, expiresAt: Date.now() + 1 };
  }
  return otpStore.get(normalized) || null;
}

async function deleteOtp(normalized) {
  if (redisClient) await redisClient.del(normalized);
  else otpStore.delete(normalized);
}

app.post('/api/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    const normalized = normalize(phone);
    if (!normalized) return res.status(400).json({ error: 'Invalid phone' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await storeOtp(normalized, code);

    const {
      TWILIO_VERIFY_SERVICE_SID, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM, NODE_ENV,
      FAST2SMS_API_KEY, MSG91_AUTHKEY, MSG91_SENDER
    } = process.env;

    let providerUsed = 'debug';
    let providerError = null;

    // Twilio Verify
    if (TWILIO_VERIFY_SERVICE_SID && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
      providerUsed = 'twilio-verify';
      const url = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/Verifications`;
      const body = new URLSearchParams({ To: normalized, Channel: 'sms' });
      const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64');
      try {
        const r = await fetch(url, { method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
        if (!r.ok) {
          const text = await r.text();
          providerError = `Twilio Verify: ${r.status} ${text}`;
          console.error('Twilio Verify error', r.status, text);
        }
      } catch (e) {
        providerError = `Twilio Verify exception: ${e.message || e}`;
        console.error('Twilio Verify send failed', e.message || e);
      }
    } else if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM) {
      // Twilio REST SMS fallback
      providerUsed = 'twilio-sms';
      const url = `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`;
      const body = new URLSearchParams({ To: normalized, From: TWILIO_FROM, Body: `Your OTP is ${code}.` });
      const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64');
      try {
        const r = await fetch(url, { method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
        if (!r.ok) {
          const text = await r.text();
          providerError = `Twilio SMS: ${r.status} ${text}`;
          console.error('Twilio SMS error', r.status, text);
        }
      } catch (e) {
        providerError = `Twilio SMS exception: ${e.message || e}`;
        console.error('Twilio send failed', e.message || e);
      }
    }

    // Fast2SMS (India) fallback
    if (FAST2SMS_API_KEY) {
      providerUsed = providerUsed === 'debug' ? 'fast2sms' : providerUsed;
      try {
        const fastUrl = 'https://www.fast2sms.com/dev/bulkV2';
        const numbers = normalized.replace('+91', '');
        const payload = { message: `Your OTP is ${code}.`, language: 'english', route: 'v3', numbers };
        const r2 = await fetch(fastUrl, { method: 'POST', headers: { authorization: FAST2SMS_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        if (!r2.ok) {
          const text = await r2.text();
          providerError = providerError || `Fast2SMS: ${r2.status} ${text}`;
          console.error('Fast2SMS error', r2.status, text);
        }
      } catch (e) {
        providerError = providerError || `Fast2SMS exception: ${e.message || e}`;
        console.error('Fast2SMS send failed', e.message || e);
      }
    }

    // MSG91 fallback
    if (MSG91_AUTHKEY) {
      providerUsed = providerUsed === 'debug' ? 'msg91' : providerUsed;
      try {
        const msgUrl = 'https://api.msg91.com/api/v2/sendsms';
        const numbers = [normalized.replace('+91', '')];
        const bodyMsg = { sender: MSG91_SENDER || 'MSGIND', route: '4', country: '91', sms: numbers.map(num => ({ message: `Your OTP is ${code}.`, to: [num] })) };
        const r3 = await fetch(msgUrl, { method: 'POST', headers: { authkey: MSG91_AUTHKEY, 'Content-Type': 'application/json' }, body: JSON.stringify(bodyMsg) });
        if (!r3.ok) {
          const text = await r3.text();
          providerError = providerError || `MSG91: ${r3.status} ${text}`;
          console.error('MSG91 error', r3.status, text);
        }
      } catch (e) {
        providerError = providerError || `MSG91 exception: ${e.message || e}`;
        console.error('MSG91 send failed', e.message || e);
      }
    }

    const debugCode = process.env.NODE_ENV === 'production' ? undefined : code;
    return res.json({ success: true, debugCode, provider: providerUsed, providerError });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.status(400).json({ error: 'Missing params' });
    const normalized = normalize(phone);
    if (!normalized) return res.status(400).json({ error: 'Invalid phone' });

    const { TWILIO_VERIFY_SERVICE_SID, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN } = process.env;
    // Prefer Twilio Verify check when configured
    if (TWILIO_VERIFY_SERVICE_SID && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
      const url = `https://verify.twilio.com/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/VerificationCheck`;
      const body = new URLSearchParams({ To: normalized, Code: String(otp) });
      const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64');
      try {
        const r = await fetch(url, { method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
        const j = await r.json();
        if (r.ok && j.status === 'approved') {
          await deleteOtp(normalized);
          let dbUser = null;
          if (mongoose.connection.readyState === 1) {
            dbUser = await User.findOneAndUpdate(
              { phone: normalized },
              { $set: { lastLoginAt: new Date() }, $inc: { loginCount: 1 }, $setOnInsert: { firstLoginAt: new Date() } },
              { upsert: true, new: true }
            );
          }
          const token = jwt.sign(
            { phone: normalized, id: dbUser?._id },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '7d' }
          );
          return res.json({ success: true, token, provider: 'twilio-verify' });
        }
        return res.status(400).json({ error: j && j.status ? j.status : 'Invalid OTP', provider: 'twilio-verify' });
      } catch (e) {
        console.error('Twilio Verify check failed', e.message || e);
        return res.status(500).json({ error: 'Verify failed', provider: 'twilio-verify' });
      }
    }

    // Fallback: check local store (or Redis)
    const rec = await fetchOtp(normalized);
    if (!rec) return res.status(400).json({ error: 'No OTP found', provider: 'local' });
    if (rec.expiresAt && Date.now() > rec.expiresAt) {
      await deleteOtp(normalized);
      return res.status(400).json({ error: 'OTP expired', provider: 'local' });
    }
    if (String(otp) === String(rec.code)) {
      await deleteOtp(normalized);
      let dbUser = null;
      if (mongoose.connection.readyState === 1) {
        dbUser = await User.findOneAndUpdate(
          { phone: normalized },
          { $set: { lastLoginAt: new Date() }, $inc: { loginCount: 1 }, $setOnInsert: { firstLoginAt: new Date() } },
          { upsert: true, new: true }
        );
      }
      const token = jwt.sign(
        { phone: normalized, id: dbUser?._id },
        process.env.JWT_SECRET || 'fallback_secret',
        { expiresIn: '7d' }
      );
      return res.json({ success: true, token, provider: 'local' });
    }
    return res.status(400).json({ error: 'Invalid OTP', provider: 'local' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    const { secret } = req.query;
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database not connected' });
    }
    const users = await User.find({}).sort({ lastLoginAt: -1 });
    return res.json({ users });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token' });
    }
    const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET || 'fallback_secret');
    return res.json({ phone: decoded.phone });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// Serve React build in production
if (process.env.NODE_ENV === 'production') {
  const buildPath = path.join(__dirname, 'build');
  app.use(express.static(buildPath));
  app.get('*', (req, res) => res.sendFile(path.join(buildPath, 'index.html')));
}

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
