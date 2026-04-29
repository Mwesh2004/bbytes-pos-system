const express = require('express')
const cors    = require('cors')
const axios   = require('axios')
const path    = require('path')
require('dotenv').config()

const app = express()
app.use(cors())
app.use(express.json())

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
app.listen(PORT, () => {
  console.log(`✅ BerylBytes POS running on http://localhost:${PORT}`)
  console.log(`📊 Health: http://localhost:${PORT}/api/health`)
})