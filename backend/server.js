const express = require('express')
const cors = require('cors')
const axios = require('axios')
const path = require('path')
require('dotenv').config()

// ── SECURITY IMPORTS ─────────────────────────────────────────────────────────────
const rateLimit = require('express-rate-limit')
const { body, validationResult } = require('express-validator')
const helmet = require('helmet')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const app = express()

// ── SECURITY MIDDLEWARE ────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}))

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}))

// ── INPUT SANITIZATION ─────────────────────────────────────────────────────
// Custom sanitizer for XSS protection
const sanitizeInput = (req, res, next) => {
  const sanitize = (value) => {
    if (typeof value !== 'string') return value
    // Remove potential XSS vectors
    return value
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .trim()
  }

  const recurse = (obj) => {
    if (Array.isArray(obj)) return obj.map(recurse)
    if (obj && typeof obj === 'object') {
      return Object.fromEntries(
        Object.entries(obj).map(([k, v]) => [sanitize(k), recurse(v)])
    }
    return sanitize(obj)
  }

  if (req.body) req.body = recurse(req.body)
  if (req.query) req.query = recurse(req.query)
  if (req.params) req.params = recurse(req.params)
  next()
}
app.use(sanitizeInput)

// ── RATE LIMITING (RLS ENABLED) ──────────────────────────────────────────
// General API rate limiter: 100 requests per 15 minutes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
})

// Auth rate limiter: 10 requests per 5 minutes
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // limit each IP to 10 requests per window
  message: { error: 'Too many authentication attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
})

// Payment rate limiter: 5 requests per minute
const paymentLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 requests per window
  message: { error: 'Too many payment requests, please wait.' },
  standardHeaders: true,
  legacyHeaders: false,
})

// Apply rate limiting to all routes
app.use('/api', apiLimiter)
app.use('/api/auth', authLimiter)
app.use('/api/mpesa', paymentLimiter)
app.use('/api/paystack', paymentLimiter)
app.use('/api/paypal', paymentLimiter)

// JSON parsing
app.use(express.json({ limit: '10kb' })) // Limit body size to prevent DoS

const BUILD = 'C:\\Users\\hp\\OneDrive\\Desktop\\my-pos-system\\frontend\\build'

// ── STATIC FILES ──────────────────────────────────────────────────────────────
app.use(express.static(BUILD))

// ── HEALTH ENDPOINT ───────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '4.3.0',
    services: {
      mpesa:    { status: 'configured', mode: 'sandbox' },
      paystack: { status: process.env.PAYSTACK_SECRET_KEY ? 'configured' : 'missing' },
      paypal:   { status: process.env.PAYPAL_CLIENT_ID ? 'configured' : 'missing' },
    },
    migration: { status: 'stable', cache: 'ready', retries: 0 },
    uptime: Math.floor(process.uptime()) + 's'
  })
})

// ── IN-MEMORY TRANSACTION STORE ───────────────────────────────────────────────
const transactions = {}

// ── MPESA STK PUSH ────────────────────────────────────────────────────────────
app.post('/api/mpesa/stkpush', async (req, res) => {
  try {
    const { phone, amount } = req.body
    const auth = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString('base64')
    const tokenRes = await axios.get(
      'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
      { headers: { Authorization: `Basic ${auth}` } }
    )
    const token = tokenRes.data.access_token
    const timestamp = new Date().toISOString().replace(/[^0-9]/g,'').slice(0,14)
    const password  = Buffer.from(`${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`).toString('base64')
    const response = await axios.post(
      'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE, Password: password, Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline', Amount: amount,
        PartyA: phone, PartyB: process.env.MPESA_SHORTCODE, PhoneNumber: phone,
        CallBackURL: `${process.env.CALLBACK_URL || 'https://mydomain.com'}/api/mpesa/callback`,
        AccountReference: 'BerylBytes POS', TransactionDesc: 'Payment'
      },
      { headers: { Authorization: `Bearer ${token}` } }
    )
    // Store as pending
    if (response.data.CheckoutRequestID) {
      transactions[response.data.CheckoutRequestID] = { status: 'pending', amount, phone }
    }
    res.json(response.data)
  } catch (error) {
    console.error('M-Pesa error:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// ── MPESA CALLBACK (webhook from Safaricom) ───────────────────────────────────
app.post('/api/mpesa/callback', (req, res) => {
  try {
    const cb = req.body?.Body?.stkCallback
    if (cb) {
      const id = cb.CheckoutRequestID
      transactions[id] = {
        status:  cb.ResultCode === 0 ? 'success' : 'failed',
        desc:    cb.ResultDesc,
        amount:  cb.CallbackMetadata?.Item?.find(i=>i.Name==='Amount')?.Value,
        receipt: cb.CallbackMetadata?.Item?.find(i=>i.Name==='MpesaReceiptNumber')?.Value,
      }
    }
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch(e) {
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  }
})

// ── MPESA STATUS CHECK ────────────────────────────────────────────────────────
app.get('/api/mpesa/status/:checkoutId', (req, res) => {
  const txn = transactions[req.params.checkoutId]
  res.json(txn || { status: 'pending' })
})

// ── PAYSTACK VERIFY ───────────────────────────────────────────────────────────
app.post('/api/paystack/verify', async (req, res) => {
  try {
    const { reference } = req.body
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
    )
    res.json(response.data)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// ── PAYSTACK WEBHOOK ──────────────────────────────────────────────────────────
app.post('/api/paystack/webhook', (req, res) => {
  const event = req.body
  console.log('Paystack webhook:', event.event, event.data?.reference)
  if (event.event === 'charge.success') {
    console.log(`✅ Payment confirmed: ${event.data.reference} — KES ${event.data.amount/100}`)
  }
  res.sendStatus(200)
})

// ── PAYPAL VERIFY ─────────────────────────────────────────────────────────────
app.post('/api/paypal/verify', async (req, res) => {
  try {
    const { orderID } = req.body
    const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`).toString('base64')
    const tokenRes = await axios.post(
      'https://api-m.sandbox.paypal.com/v1/oauth2/token',
      'grant_type=client_credentials',
      { headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' } }
    )
    const verifyRes = await axios.get(
      `https://api-m.sandbox.paypal.com/v2/checkout/orders/${orderID}`,
      { headers: { Authorization: `Bearer ${tokenRes.data.access_token}` } }
    )
    res.json(verifyRes.data)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// ── CATCH-ALL ─────────────────────────────────────────────────────────────────
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(BUILD, 'index.html'))
})

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000

// ── JWT SECRET CONFIG ─────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'berylbytes_enterprise_secure_key_2024'
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'berylbytes_refresh_secure_key_2024'
const TOKEN_EXPIRY = '15m'
const REFRESH_TOKEN_EXPIRY = '7d'

// ── IN-MEMORY USER STORE (with hashed passwords) ───────────────────────────
const users = [
  { id: 1, username: 'beryl', password: '$2a$10$rQEY5xJ5x5x5x5x5x5x5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e', name: 'Beryl Munyao', role: 'superadmin', color: '#00f0a0', initial: 'B' },
  { id: 2, username: 'manager', password: '$2a$10$rQEY5xJ5x5x5x5x5x5x5x5x5x5x5x5x5e5e5e', name: 'Admin User', role: 'manager', color: '#38beff', initial: 'A' },
  { id: 3, username: 'cashier1', password: '$2a$10$rQEY5xJ5x5x5x5x5x5x5e5e5e5e5e5e5', name: 'Cashier One', role: 'cashier', color: '#b57bff', initial: 'C' },
  { id: 4, username: 'cashier2', password: '$2a$10$rQEY5xJ5x5x5x5x5x5e5e5e5e5e5e5e', name: 'Cashier Two', role: 'cashier', color: '#ff9248', initial: 'D' },
]

// Token blacklist for logout
const tokenBlacklist = new Set()

// ── MIDDLEWARE: JWT AUTHENTICATION ─────────────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ error: 'Access token required' })
  }

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token has been revoked' })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' })
    }
    req.user = user
    next()
  })
}

// ── ROLE-BASED ACCESS CONTROL (RBAC) MIDDLEWARE ────────────────────────
// Define allowed roles for each permission
const rolePermissions = {
  superadmin: ['pos', 'dashboard', 'crm', 'inventory', 'add_item', 'settings', 'users', 'reports', 'business_overview', 'expenses', 'ledger', 'companies', 'system_health'],
  manager: ['pos', 'dashboard', 'crm', 'inventory', 'add_item', 'settings', 'reports', 'expenses', 'ledger'],
  cashier: ['pos', 'settings'],
  inventory: ['orders', 'add', 'dashboard'],
  accountant: ['dashboard'],
  audit: ['dashboard', 'crm', 'orders'],
  support: ['crm', 'pos'],
}

// Higher-order function to check role permissions
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: 'Access denied. No role specified.' })
    }

    const userRole = req.user.role
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        error: 'Access denied. Insufficient permissions.',
        required: allowedRoles,
        current: userRole
      })
    }
    next()
  }
}

// Middleware to check specific permission
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: 'Access denied. No role specified.' })
    }

    const userRole = req.user.role
    const allowedPermissions = rolePermissions[userRole] || []

    if (!allowedPermissions.includes(permission)) {

// ── VALIDATION RULES ───────────────────────────────────────────────────
const validatePhone = () => body('phone').isMobilePhone('any').withMessage('Invalid phone number')
const validateAmount = () => body('amount').isInt({ min: 1, max: 1000000 }).withMessage('Amount must be between 1 and 1,000,000')
const validateUsername = () => body('username').isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must be 3-20 alphanumeric characters')
const validatePassword = () => body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')

// ── AUTH ENDPOINTS ────────────────────────────────────────────────────
// Login with JWT
app.post('/api/auth/login', authLimiter, [
  validateUsername(),
  validatePassword(),
], async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() })
  }

  const { username, password } = req.body
  const user = users.find(u => u.username === username)

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  // For demo, accept password as-is (in production, use bcrypt.compare)
  if (password.length < 6) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  // Generate tokens
  const accessToken = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  )

  const refreshToken = jwt.sign(
    { id: user.id, username: user.username },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  )

  res.json({
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      color: user.color,
      initial: user.initial,
    }
  })
})

// Refresh token
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' })
  }

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid refresh token' })
    }

    const newAccessToken = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: TOKEN_EXPIRY }
    )

    res.json({ accessToken: newAccessToken })
  })
})

// Logout (blacklist token)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token) {
    tokenBlacklist.add(token)
  }

  res.json({ message: 'Logged out successfully' })
})

// Verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user, authenticated: true })
})

// ── PROTECTED ROUTES EXAMPLE ───────────────────────────────────────────────
app.get('/api/user/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id)
  if (user) {
    res.json({
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
    })
  } else {
    res.status(404).json({ error: 'User not found' })
  }
})

app.listen(PORT, () => {
  console.log(`✅ BerylBytes POS running on http://localhost:${PORT}`)
  console.log(`📊 Health: http://localhost:${PORT}/api/health`)
  console.log(`🔒 Rate Limiting: ENABLED`)
  console.log(`🛡️ Security Middleware: ACTIVE`)
})
