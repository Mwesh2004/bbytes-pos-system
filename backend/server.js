const express = require('express')
const cors = require('cors')
const axios = require('axios')
require('dotenv').config()

const app = express()
app.use(cors())
app.use(express.json())

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000'

app.get('/', (req, res) => {
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>BBytes POS System - Backend API</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .container { text-align: center; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 500px; }
            h1 { color: #333; margin: 0 0 10px 0; }
            p { color: #666; margin: 10px 0; }
            .status { background: #e8f5e9; color: #2e7d32; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #2e7d32; }
            a { display: inline-block; margin-top: 20px; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; transition: background 0.3s; }
            a:hover { background: #764ba2; }
            .api-info { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; text-align: left; font-size: 14px; }
            code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🎉 BBytes POS System</h1>
            <p>Backend API is running!</p>
            <div class="status">
              <strong>✓ API Server Active</strong><br>
              Backend is ready to accept requests
            </div>
            <p>To access the POS System UI, go to:</p>
            <a href="${FRONTEND_URL}">${FRONTEND_URL}</a>
            <div class="api-info">
              <strong>API Endpoints:</strong><br>
              POST <code>/api/mpesa/stkpush</code> - M-Pesa payment<br>
              POST <code>/api/paystack/verify</code> - Paystack verification<br>
              POST <code>/api/paypal/verify</code> - PayPal verification
            </div>
          </div>
        </body>
      </html>
    `)
  }
  res.json({ message: 'POS System is running!', frontend: FRONTEND_URL })
})

app.post('/api/mpesa/stkpush', async (req, res) => {
  try {
    const { phone, amount } = req.body

    const auth = Buffer.from(
      `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
    ).toString('base64')

    const tokenRes = await axios.get(
      'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
      { headers: { Authorization: `Basic ${auth}` } }
    )
    const token = tokenRes.data.access_token

    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14)
    const password = Buffer.from(
      `${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`
    ).toString('base64')

    const response = await axios.post(
      'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: amount,
        PartyA: phone,
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: phone,
        CallBackURL: 'https://mydomain.com/callback',
        AccountReference: 'POS System',
        TransactionDesc: 'Payment'
      },
      { headers: { Authorization: `Bearer ${token}` } }
    )

    res.json(response.data)

  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Paystack Payment Verification
app.post('/api/paystack/verify', async (req, res) => {
  try {
    const { reference } = req.body
    
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    )
    
    res.json(response.data)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// PayPal Payment Verification
app.post('/api/paypal/verify', async (req, res) => {
  try {
    const { orderID } = req.body
    
    // Get PayPal access token
    const auth = Buffer.from(
      `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`
    ).toString('base64')
    
    const tokenRes = await axios.post(
      'https://api-m.sandbox.paypal.com/v1/oauth2/token',
      'grant_type=client_credentials',
      {
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    )
    
    const accessToken = tokenRes.data.access_token
    
    // Verify order
    const verifyRes = await axios.get(
      `https://api-m.sandbox.paypal.com/v2/checkout/orders/${orderID}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    )
    
    res.json(verifyRes.data)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

const PORT = process.env.PORT || 3002
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Frontend redirect URL: ${FRONTEND_URL}`)
})