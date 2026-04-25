const express = require('express')
const cors = require('cors')
const axios = require('axios')
require('dotenv').config()

const app = express()
app.use(cors())
app.use(express.json())

app.get('/', (req, res) => {
  res.json({ message: 'POS System is running!' })
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

const PORT = 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})