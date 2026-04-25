#  B.Bytes POS System

A full-stack Point of Sale (POS) system built for Kenyan businesses, with M-Pesa STK Push integration, multi-category product management, and a clean modern interface.

## ✨ Features

- 💊 **Pharmacy Module** — OTC & POM products with prescription warnings
- 🛒 **General Shop** — Everyday retail products
- 🏠 **Airbnb Module** — Room bookings and hospitality services
- 📱 **M-Pesa STK Push** — Real-time mobile payments via Safaricom Daraja API
- 🔍 **Product Search** — Instant search across all categories
- 🧾 **Cart & VAT** — Automatic 16% VAT calculation
- 📊 **Admin Panel** — Coming soon
- 🧾 **Invoice Generation** — Coming soon
- 💳 **Card Payments** — Coming soon

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React.js |
| Backend | Node.js + Express |
| Payments | Safaricom Daraja API (M-Pesa) |
| Styling | CSS3 |
| Version Control | Git + GitHub |

## 🚀 Getting Started

### Prerequisites
- Node.js v18+
- npm
- Safaricom Daraja API credentials

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/Mwesh2004/bbytes-pos-system.git
cd bbytes-pos-system
```

**2. Set up the backend**
```bash
cd backend
npm install
```

**3. Create your .env file inside the backend folder**
```bash
PORT=3000
MPESA_CONSUMER_KEY=your_key_here
MPESA_CONSUMER_SECRET=your_secret_here
MPESA_SHORTCODE=174379
MPESA_PASSKEY=your_passkey_here
```

**4. Start the backend server**
```bash
node server.js
```

**5. Set up the frontend**
```bash
cd ../frontend
npm install
npm start
```

**6. Open your browser at**
http://localhost:3000

## 📱 M-Pesa Integration

This system uses the Safaricom Daraja API to trigger STK Push payments. When a customer pays:

1. Cashier enters customer phone number
2. System sends STK Push request to Safaricom
3. Customer receives PIN prompt on their phone
4. Customer enters M-Pesa PIN
5. Payment confirmed instantly ✅

## 📁 Project Structure
bbytes-pos-system/
├── backend/
│   ├── server.js        # Main server & M-Pesa routes
│   ├── .env             # Secret keys (not uploaded)
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── App.js       # Main POS interface
│   │   └── App.css      # Styling
│   └── public/
│       └── logo.png     # BBytes logo
└── README.md

## 🔐 Security

- All API keys stored in `.env` file
- `.env` is excluded from version control via `.gitignore`
- Prescription medicine flagged as POM for pharmacist verification

## 🗺️ Roadmap

- [x] M-Pesa STK Push
- [x] Multi-category POS
- [x] Product search
- [x] VAT calculation
- [ ] Admin panel & user roles
- [ ] Flutterwave card payments
- [ ] PDF invoice generation
- [ ] Sales dashboard & reports
- [ ] Mobile app (React Native)
- [ ] Cloud deployment

## 👩‍💻 Developer

**Beryl Munyao** — B.Bytes System
Built with ❤️ in Nairobi, Kenya 🇰🇪

## 📄 License

This project is private and proprietary.
© 2026 B.Bytes System. All rights reserved.
