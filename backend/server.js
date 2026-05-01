'use strict'

const express        = require('express')
const cors           = require('cors')
const axios          = require('axios')
const path           = require('path')
const helmet         = require('helmet')
const rateLimit      = require('express-rate-limit')
const slowDown       = require('express-slow-down')
const jwt            = require('jsonwebtoken')
const bcrypt         = require('bcryptjs')
const { v4: uuidv4 } = require('uuid')
const validator      = require('validator')
const xss            = require('xss')
const hpp            = require('hpp')
const morgan         = require('morgan')
const crypto         = require('crypto')
require('dotenv').config()

// ─── ENV VALIDATION ───────────────────────────────────────────────────────────
const REQUIRED_ENV = [
  'MPESA_CONSUMER_KEY','MPESA_CONSUMER_SECRET',
  'MPESA_SHORTCODE','MPESA_PASSKEY',
  'JWT_SECRET','JWT_REFRESH_SECRET',
  'PAYPAL_CLIENT_ID','PAYPAL_SECRET',
  'PAYSTACK_SECRET_KEY',
]
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k])
if (missingEnv.length) {
  console.error('[FATAL] Missing required environment variables:', missingEnv.join(', '))
  process.exit(1)
}

const JWT_SECRET         = process.env.JWT_SECRET
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET
const JWT_EXPIRY         = process.env.JWT_EXPIRY         || '15m'
const JWT_REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d'
const PORT               = parseInt(process.env.PORT, 10) || 3000
const NODE_ENV           = process.env.NODE_ENV || 'production'
const BUILD_PATH         = process.env.BUILD_PATH ||
  path.join(__dirname, '../frontend/build')
const ALLOWED_ORIGINS    = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:3001').split(',').map(s => s.trim())
const MPESA_ENV          = process.env.MPESA_ENVIRONMENT || 'sandbox'
const MPESA_BASE         = MPESA_ENV === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke'
const PAYPAL_BASE        = process.env.PAYPAL_ENVIRONMENT === 'production'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com'

const app = express()

// ─── TRUST PROXY (Heroku / Railway / Nginx) ───────────────────────────────────
app.set('trust proxy', 1)

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", 'js.paystack.co', 'www.paypal.com'],
      styleSrc:       ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      fontSrc:        ["'self'", 'fonts.gstatic.com'],
      imgSrc:         ["'self'", 'data:', 'https:'],
      connectSrc:     ["'self'", 'api.paystack.co', 'api-m.paypal.com', 'api-m.sandbox.paypal.com', 'sandbox.safaricom.co.ke', 'api.safaricom.co.ke'],
      frameSrc:       ["'self'", 'js.paystack.co', 'www.paypal.com'],
      objectSrc:      ["'none'"],
      upgradeInsecureRequests: NODE_ENV === 'production' ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}))

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true)
    cb(new Error(`CORS: Origin ${origin} not allowed`))
  },
  methods:            ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders:     ['Content-Type','Authorization','X-Request-ID'],
  credentials:        true,
  maxAge:             86400,
}))

// ─── BODY PARSING ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }))
app.use(express.urlencoded({ extended: false, limit: '50kb' }))

// ─── PARAMETER POLLUTION PROTECTION ──────────────────────────────────────────
app.use(hpp())

// ─── REQUEST ID ───────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4()
  next()
})

// ─── LOGGING ──────────────────────────────────────────────────────────────────
if (NODE_ENV !== 'test') {
  app.use(morgan(NODE_ENV === 'production'
    ? ':remote-addr - :method :url :status :res[content-length] - :response-time ms'
    : 'dev'
  ))
}

// ─── IN-MEMORY STORES ─────────────────────────────────────────────────────────
const tokenBlacklist  = new Set()            // revoked JWTs
const refreshTokens   = new Map()            // { token -> { userId, expiresAt } }
const mpesaTransactions = new Map()          // { checkoutId -> status }
const authAttempts    = new Map()            // { ip:username -> { count, resetAt } }
const auditLog        = []                   // [{time,userId,action,ip,meta}]

// ─── RATE LIMITERS ────────────────────────────────────────────────────────────
const makeLimiter = (max, windowMs, message) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders:   false,
    message: { success: false, error: message },
    keyGenerator: req => req.ip,
    skip: req => NODE_ENV === 'test',
  })

// General API — 100 req / 15 min
const apiLimiter = makeLimiter(100, 15 * 60 * 1000, 'Too many requests. Try again in 15 minutes.')

// Auth — 5 attempts / 15 min
const authLimiter = makeLimiter(5, 15 * 60 * 1000, 'Too many login attempts. Try again in 15 minutes.')

// Payment endpoints — 10 req / 1 min
const paymentLimiter = makeLimiter(10, 60 * 1000, 'Too many payment requests. Try again in 1 minute.')

// M-Pesa specifically — 5 req / 1 min
const mpesaLimiter = makeLimiter(5, 60 * 1000, 'Too many M-Pesa requests. Try again in 1 minute.')

// Slow-down after 50 requests
const speedLimiter = slowDown({
  windowMs:         15 * 60 * 1000,
  delayAfter:       50,
  delayMs: () => 500,
  skip: req => NODE_ENV === 'test',
})

app.use('/api', apiLimiter)
app.use('/api', speedLimiter)

// ─── INPUT SANITIZATION ───────────────────────────────────────────────────────
const sanitizeValue = v => {
  if (typeof v === 'string') {
    return xss(v.trim(), {
      whiteList:         {},
      stripIgnoreTag:    true,
      stripIgnoreTagBody: ['script','style','iframe','object','embed'],
    })
  }
  if (Array.isArray(v)) return v.map(sanitizeValue)
  if (v && typeof v === 'object') return sanitizeObject(v)
  return v
}
const sanitizeObject = obj => {
  const out = {}
  for (const [k, v] of Object.entries(obj)) {
    out[sanitizeValue(k)] = sanitizeValue(v)
  }
  return out
}

const sanitize = (req, res, next) => {
  if (req.body)   req.body   = sanitizeObject(req.body)
  if (req.query)  req.query  = sanitizeObject(req.query)
  if (req.params) req.params = sanitizeObject(req.params)
  next()
}

app.use('/api', sanitize)

// ─── PAYLOAD SIZE CHECK ───────────────────────────────────────────────────────
app.use('/api', (req, res, next) => {
  const cl = parseInt(req.headers['content-length'] || '0', 10)
  if (cl > 50 * 1024) return res.status(413).json({ success: false, error: 'Payload too large.' })
  next()
})

// ─── JWT HELPERS ──────────────────────────────────────────────────────────────
const signAccess  = payload => jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY, issuer: 'berylbytes-pos', jwtid: uuidv4() })
const signRefresh = payload => jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRY, issuer: 'berylbytes-pos', jwtid: uuidv4() })

const verifyAccess = token => {
  if (tokenBlacklist.has(token)) throw new Error('Token revoked')
  return jwt.verify(token, JWT_SECRET, { issuer: 'berylbytes-pos' })
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
const ROLE_PERMISSIONS = {
  superadmin: ['*'],
  manager:    ['pos','dashboard','crm','orders','add','settings','reports'],
  cashier:    ['pos','settings'],
  inventory:  ['orders','add','dashboard'],
  accountant: ['dashboard'],
  audit:      ['dashboard','crm','orders'],
  support:    ['crm','pos'],
}

const requireAuth = (req, res, next) => {
  try {
    const hdr = req.headers.authorization
    if (!hdr || !hdr.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Missing authorization header.' })
    }
    const token = hdr.slice(7)
    const payload = verifyAccess(token)
    req.user = payload
    next()
  } catch (e) {
    const msg = e.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token.'
    return res.status(401).json({ success: false, error: msg })
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: 'Unauthenticated.' })
  const perms = ROLE_PERMISSIONS[req.user.role] || []
  const ok = perms.includes('*') || roles.some(r => perms.includes(r))
  if (!ok) return res.status(403).json({ success: false, error: 'Insufficient permissions.' })
  next()
}

// ─── AUDIT LOGGER ─────────────────────────────────────────────────────────────
const logAudit = (userId, action, ip, meta = {}) => {
  const entry = { time: new Date().toISOString(), userId, action, ip, meta }
  auditLog.unshift(entry)
  if (auditLog.length > 5000) auditLog.length = 5000
}

// ─── VALIDATION HELPERS ───────────────────────────────────────────────────────
const isValidPhone = p => /^254[0-9]{9}$/.test(String(p))
const isPositiveInt = n => Number.isInteger(Number(n)) && Number(n) > 0
const isValidEmail  = e => validator.isEmail(String(e || ''))

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
app.use(express.static(BUILD_PATH, {
  etag:         true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
    } else if (/\.(js|css|woff2?|png|ico)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
    }
  },
}))

// ─── HEALTH ENDPOINT ──────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    success:   true,
    status:    'healthy',
    version:   '4.4.0',
    timestamp: new Date().toISOString(),
    uptime:    Math.floor(process.uptime()) + 's',
    env:       NODE_ENV,
    services: {
      mpesa:    { configured: !!(process.env.MPESA_CONSUMER_KEY), mode: MPESA_ENV },
      paystack: { configured: !!(process.env.PAYSTACK_SECRET_KEY) },
      paypal:   { configured: !!(process.env.PAYPAL_CLIENT_ID), mode: process.env.PAYPAL_ENVIRONMENT || 'sandbox' },
    },
  })
})

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { userId, pin } = req.body
    const ip = req.ip

    // Validate input
    if (!userId || !pin) return res.status(400).json({ success: false, error: 'userId and pin are required.' })
    if (typeof pin !== 'string' || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ success: false, error: 'PIN must be exactly 4 digits.' })
    }

    // Brute-force tracking
    const attemptKey = `${ip}:${userId}`
    const attempt = authAttempts.get(attemptKey) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 }
    if (Date.now() > attempt.resetAt) { attempt.count = 0; attempt.resetAt = Date.now() + 15 * 60 * 1000 }
    if (attempt.count >= 5) {
      const waitSec = Math.ceil((attempt.resetAt - Date.now()) / 1000)
      return res.status(429).json({ success: false, error: `Too many failed attempts. Try again in ${waitSec}s.` })
    }

    // Look up user (in real app: database lookup)
    const SYSTEM_USERS = getSystemUsers()
    const user = SYSTEM_USERS.find(u => u.id === parseInt(userId, 10))

    // Constant-time comparison to prevent timing attacks
    const hashMatch = user ? await bcrypt.compare(pin, user.pinHash) : await bcrypt.compare(pin, '$2a$10$invalidhashpadding000000000000000000000000000000000000000')

    if (!user || !hashMatch) {
      attempt.count++
      authAttempts.set(attemptKey, attempt)
      logAudit(userId, 'LOGIN_FAILED', ip, { reason: 'invalid_credentials' })
      // Generic message — do not reveal which is wrong
      return res.status(401).json({ success: false, error: 'Invalid credentials.' })
    }

    // Reset attempt counter on success
    authAttempts.delete(attemptKey)

    const payload = { sub: user.id, role: user.role, name: user.name }
    const accessToken  = signAccess(payload)
    const refreshToken = signRefresh(payload)

    refreshTokens.set(refreshToken, {
      userId:    user.id,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    })

    logAudit(user.id, 'LOGIN_SUCCESS', ip, { role: user.role })

    res.json({
      success:      true,
      accessToken,
      refreshToken,
      user: {
        id:      user.id,
        name:    user.name,
        role:    user.role,
        initial: user.initial,
        email:   user.email,
      },
    })
  } catch (e) {
    console.error('[auth/login]', e.message)
    res.status(500).json({ success: false, error: 'Authentication failed.' })
  }
})

// Refresh token
app.post('/api/auth/refresh', authLimiter, (req, res) => {
  try {
    const { refreshToken } = req.body
    if (!refreshToken) return res.status(400).json({ success: false, error: 'Refresh token required.' })

    const record = refreshTokens.get(refreshToken)
    if (!record || Date.now() > record.expiresAt) {
      refreshTokens.delete(refreshToken)
      return res.status(401).json({ success: false, error: 'Invalid or expired refresh token.' })
    }

    let payload
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET, { issuer: 'berylbytes-pos' })
    } catch {
      refreshTokens.delete(refreshToken)
      return res.status(401).json({ success: false, error: 'Invalid refresh token.' })
    }

    const newAccess  = signAccess({ sub: payload.sub, role: payload.role, name: payload.name })
    const newRefresh = signRefresh({ sub: payload.sub, role: payload.role, name: payload.name })

    refreshTokens.delete(refreshToken)
    refreshTokens.set(newRefresh, { userId: payload.sub, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 })

    res.json({ success: true, accessToken: newAccess, refreshToken: newRefresh })
  } catch (e) {
    res.status(500).json({ success: false, error: 'Token refresh failed.' })
  }
})

// Logout — revoke tokens
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers.authorization?.slice(7)
  if (token) tokenBlacklist.add(token)

  const { refreshToken } = req.body
  if (refreshToken) refreshTokens.delete(refreshToken)

  logAudit(req.user.sub, 'LOGOUT', req.ip, {})
  res.json({ success: true, message: 'Logged out.' })
})

// 2FA — generate code (in production: send via SMS/TOTP)
app.post('/api/auth/2fa/send', authLimiter, requireAuth, (req, res) => {
  const code = crypto.randomInt(100000, 999999).toString()
  // TODO: send via SMS (Twilio / Africa's Talking)
  // In production NEVER return the code in the response
  logAudit(req.user.sub, '2FA_SENT', req.ip, {})
  res.json({
    success: true,
    message: 'Verification code sent.',
    // REMOVE in production:
    ...(NODE_ENV !== 'production' && { _devCode: code }),
  })
})

// ═══════════════════════════════════════════════════════════════════════════════
// MPESA
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/mpesa/stkpush', mpesaLimiter, requireAuth, requireRole('pos'), async (req, res) => {
  try {
    const { phone, amount } = req.body

    // Validate
    if (!isValidPhone(phone)) return res.status(400).json({ success: false, error: 'Invalid phone. Use format 254XXXXXXXXX.' })
    if (!isPositiveInt(amount) || Number(amount) < 1 || Number(amount) > 500000) {
      return res.status(400).json({ success: false, error: 'Amount must be between 1 and 500,000 KES.' })
    }

    const auth = Buffer.from(
      `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
    ).toString('base64')

    const tokenRes = await axios.get(
      `${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`,
      { headers: { Authorization: `Basic ${auth}` }, timeout: 10000 }
    )
    const mpesaToken = tokenRes.data.access_token

    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14)
    const password  = Buffer.from(
      `${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`
    ).toString('base64')

    const callbackUrl = `${process.env.CALLBACK_BASE_URL || process.env.NEXT_PUBLIC_API_URL || 'https://yourapp.com'}/api/mpesa/callback`

    const response = await axios.post(
      `${MPESA_BASE}/mpesa/stkpush/v1/processrequest`,
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password:          password,
        Timestamp:         timestamp,
        TransactionType:   'CustomerPayBillOnline',
        Amount:            parseInt(amount, 10),
        PartyA:            phone,
        PartyB:            process.env.MPESA_SHORTCODE,
        PhoneNumber:       phone,
        CallBackURL:       callbackUrl,
        AccountReference:  'BerylBytes',
        TransactionDesc:   'POS Payment',
      },
      { headers: { Authorization: `Bearer ${mpesaToken}` }, timeout: 15000 }
    )

    if (response.data.CheckoutRequestID) {
      mpesaTransactions.set(response.data.CheckoutRequestID, {
        status:    'pending',
        amount:    parseInt(amount, 10),
        phone,
        userId:    req.user.sub,
        createdAt: Date.now(),
      })
    }

    logAudit(req.user.sub, 'MPESA_STK_PUSH', req.ip, { phone: phone.slice(0,-4)+'XXXX', amount })

    res.json({ success: true, ...response.data })
  } catch (e) {
    console.error('[mpesa/stkpush]', e.response?.data || e.message)
    res.status(502).json({ success: false, error: 'M-Pesa request failed. Try again.' })
  }
})

// M-Pesa callback — no auth required (called by Safaricom)
app.post('/api/mpesa/callback', (req, res) => {
  try {
    const cb = req.body?.Body?.stkCallback
    if (cb?.CheckoutRequestID) {
      const existing = mpesaTransactions.get(cb.CheckoutRequestID) || {}
      mpesaTransactions.set(cb.CheckoutRequestID, {
        ...existing,
        status:    cb.ResultCode === 0 ? 'success' : 'failed',
        resultDesc: String(cb.ResultDesc || '').slice(0, 200),
        receipt:   cb.CallbackMetadata?.Item?.find(i => i.Name === 'MpesaReceiptNumber')?.Value,
        updatedAt: Date.now(),
      })
    }
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch {
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  }
})

// M-Pesa status poll
app.get('/api/mpesa/status/:checkoutId', requireAuth, requireRole('pos'), (req, res) => {
  const { checkoutId } = req.params
  if (!/^[a-zA-Z0-9_-]{10,100}$/.test(checkoutId)) {
    return res.status(400).json({ success: false, error: 'Invalid checkout ID format.' })
  }
  const txn = mpesaTransactions.get(checkoutId)
  if (!txn) return res.json({ success: true, status: 'pending' })
  // Only return to the user who initiated
  if (txn.userId !== req.user.sub && req.user.role !== 'superadmin') {
    return res.status(403).json({ success: false, error: 'Not authorized to view this transaction.' })
  }
  res.json({ success: true, status: txn.status, receipt: txn.receipt })
})

// ═══════════════════════════════════════════════════════════════════════════════
// PAYSTACK
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/paystack/verify', paymentLimiter, requireAuth, requireRole('pos'), async (req, res) => {
  try {
    const { reference } = req.body
    if (!reference || typeof reference !== 'string' || !/^[a-zA-Z0-9_-]{5,100}$/.test(reference)) {
      return res.status(400).json({ success: false, error: 'Invalid transaction reference.' })
    }

    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }, timeout: 15000 }
    )

    logAudit(req.user.sub, 'PAYSTACK_VERIFY', req.ip, { reference })
    res.json({ success: true, data: response.data })
  } catch (e) {
    console.error('[paystack/verify]', e.response?.data || e.message)
    res.status(502).json({ success: false, error: 'Paystack verification failed.' })
  }
})

// Paystack webhook — verify signature
app.post('/api/paystack/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig    = req.headers['x-paystack-signature']
  const secret = process.env.PAYSTACK_WEBHOOK_SECRET || process.env.PAYSTACK_SECRET_KEY

  if (sig && secret) {
    const hash = crypto.createHmac('sha512', secret).update(req.body).digest('hex')
    if (hash !== sig) {
      console.warn('[paystack/webhook] Invalid signature')
      return res.status(401).json({ error: 'Invalid signature' })
    }
  }

  try {
    const event = JSON.parse(req.body)
    if (event.event === 'charge.success') {
      logAudit('system', 'PAYSTACK_WEBHOOK_SUCCESS', 'paystack', {
        reference: event.data?.reference,
        amount:    event.data?.amount,
      })
    }
    res.sendStatus(200)
  } catch {
    res.sendStatus(200)
  }
})

// ═══════════════════════════════════════════════════════════════════════════════
// PAYPAL
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/paypal/verify', paymentLimiter, requireAuth, requireRole('pos'), async (req, res) => {
  try {
    const { orderID } = req.body
    if (!orderID || typeof orderID !== 'string' || !/^[A-Z0-9]{10,30}$/.test(orderID)) {
      return res.status(400).json({ success: false, error: 'Invalid PayPal order ID.' })
    }

    const auth = Buffer.from(
      `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`
    ).toString('base64')

    const tokenRes = await axios.post(
      `${PAYPAL_BASE}/v1/oauth2/token`,
      'grant_type=client_credentials',
      { headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
    )

    const verifyRes = await axios.get(
      `${PAYPAL_BASE}/v2/checkout/orders/${encodeURIComponent(orderID)}`,
      { headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }, timeout: 10000 }
    )

    logAudit(req.user.sub, 'PAYPAL_VERIFY', req.ip, { orderID })
    res.json({ success: true, data: verifyRes.data })
  } catch (e) {
    console.error('[paypal/verify]', e.response?.data || e.message)
    res.status(502).json({ success: false, error: 'PayPal verification failed.' })
  }
})

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT LOG (superadmin only)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/audit', requireAuth, requireRole('dashboard'), (req, res) => {
  if (req.user.role !== 'superadmin' && req.user.role !== 'audit') {
    return res.status(403).json({ success: false, error: 'Insufficient permissions.' })
  }
  const page  = Math.max(1, parseInt(req.query.page  || '1',  10))
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10)))
  const start = (page - 1) * limit
  res.json({
    success: true,
    total:   auditLog.length,
    page,
    limit,
    data:    auditLog.slice(start, start + limit),
  })
})

// ═══════════════════════════════════════════════════════════════════════════════
// SYSTEM USERS (hashed PINs — demo only, use DB in production)
// ═══════════════════════════════════════════════════════════════════════════════

function getSystemUsers() {
  // In production these come from a database with bcrypt-hashed PINs
  // PINs are loaded from env as bcrypt hashes, NOT plaintext
  return [
    { id:1, name:'Beryl Munyao',  email:'beryl@berylbytes.co.ke',    pinHash: process.env.PIN_HASH_1 || '$2a$10$hashedpin1placeholder000000', role:'superadmin', initial:'B' },
    { id:2, name:'Admin User',    email:'admin@berylbytes.co.ke',    pinHash: process.env.PIN_HASH_2 || '$2a$10$hashedpin2placeholder000000', role:'manager',    initial:'A' },
    { id:3, name:'Cashier One',   email:'cashier1@berylbytes.co.ke', pinHash: process.env.PIN_HASH_3 || '$2a$10$hashedpin3placeholder000000', role:'cashier',    initial:'C' },
    { id:4, name:'Cashier Two',   email:'cashier2@berylbytes.co.ke', pinHash: process.env.PIN_HASH_4 || '$2a$10$hashedpin4placeholder000000', role:'cashier',    initial:'D' },
    { id:5, name:'Stock Manager', email:'stock@berylbytes.co.ke',    pinHash: process.env.PIN_HASH_5 || '$2a$10$hashedpin5placeholder000000', role:'inventory',  initial:'S' },
    { id:6, name:'Mary Accounts', email:'accounts@berylbytes.co.ke', pinHash: process.env.PIN_HASH_6 || '$2a$10$hashedpin6placeholder000000', role:'accountant', initial:'M' },
    { id:7, name:'Audit Officer', email:'audit@berylbytes.co.ke',    pinHash: process.env.PIN_HASH_7 || '$2a$10$hashedpin7placeholder000000', role:'audit',      initial:'U' },
    { id:8, name:'Support Agent', email:'support@berylbytes.co.ke',  pinHash: process.env.PIN_HASH_8 || '$2a$10$hashedpin8placeholder000000', role:'support',    initial:'P' },
  ]
}

// ─── UTILITY: Generate hashed PINs (run once, store hashes in .env) ───────────
app.post('/api/admin/hash-pin', (req, res) => {
  if (NODE_ENV === 'production') return res.status(404).end()
  const { pin } = req.body
  if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 4 digits' })
  bcrypt.hash(pin, 12).then(hash => res.json({ hash }))
})

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

// 404
app.use('/api', (req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found.' })
})

// Global error handler — never leak stack traces
app.use((err, req, res, _next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'Request payload too large.' })
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Malformed JSON body.' })
  }
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message)
  res.status(500).json({ success: false, error: 'Internal server error.' })
})

// React SPA catch-all
app.get('/{*path}', (_req, res) => {
  res.sendFile(path.join(BUILD_PATH, 'index.html'))
})

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[BerylBytes] Server running — http://localhost:${PORT}`)
  console.log(`[BerylBytes] Environment: ${NODE_ENV} | M-Pesa: ${MPESA_ENV}`)
})

module.exports = app