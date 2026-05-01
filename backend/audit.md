# BerylBytes POS — Security Audit Report

## Implemented

### Rate Limiting
- General API: 100 req / 15 min
- Auth routes: 5 attempts / 15 min (+ brute-force lockout)
- Payment routes: 10 req / 1 min
- M-Pesa specifically: 5 req / 1 min
- Speed throttle: delay added after 50 req / 15 min

### Authentication & Authorization
- JWT access tokens (15 min expiry)
- JWT refresh tokens (7 days, rotated on use)
- Token blacklist on logout (in-memory; use Redis in production)
- Brute-force protection: 5 failed attempts locks IP:userId for 15 min
- Constant-time bcrypt comparison prevents timing attacks
- RBAC on every protected route
- 2FA code generation (SMS delivery TODO)

### Input Sanitization
- XSS library strips all script/event-handler injection
- validator.js used for phone, email, reference validation
- Body size limited to 50 KB
- Malformed JSON returns 400 not 500
- HPP middleware blocks HTTP Parameter Pollution
- Regex validation on all IDs and references

### Security Headers (Helmet)
- Content-Security-Policy configured
- HSTS enforced in production
- X-Frame-Options, X-Content-Type-Options set
- Referrer-Policy set

### Secret Management
- All secrets in .env (never hardcoded)
- .env validated at startup — server exits if missing
- .env.example is the only file committed
- PIN hashes generated with bcrypt cost 12

### Webhook Security
- Paystack webhook verifies HMAC-SHA512 signature
- M-Pesa callback accepts all (Safaricom requirement) but logs all events

### Audit Logging
- Every auth event, payment event logged with userId, IP, timestamp
- Log capped at 5000 entries in-memory
- Accessible to superadmin and auditor roles only

---

## Remaining Items (Production Checklist)

| Priority | Item | Action |
|----------|------|--------|
| CRITICAL | In-memory token blacklist | Replace with Redis — restarts clear it |
| CRITICAL | In-memory user store | Move to PostgreSQL with parameterised queries |
| CRITICAL | HTTPS only | Force TLS on server or reverse proxy |
| HIGH | PIN hashes in .env | Move to database rows, one hash per user |
| HIGH | M-Pesa callback verification | Add IP allowlist for Safaricom callback IPs |
| HIGH | CSRF protection | Add csurf for non-SPA forms |
| HIGH | Secrets rotation | Rotate JWT secrets, API keys every 90 days |
| MEDIUM | Log sensitive data | Ensure phone numbers/emails are masked in logs |
| MEDIUM | Dependency audit | Run `npm audit` weekly in CI |
| MEDIUM | Refresh token storage | Store hash in DB not plaintext in-memory Map |
| MEDIUM | PayPal webhook sig | Implement PayPal webhook signature verification |
| LOW | 2FA SMS delivery | Integrate Africa's Talking or Twilio |
| LOW | TOTP passkey | Implement WebAuthn + TOTP for hardware keys |
| LOW | Security scan | Run OWASP ZAP against staging before launch |
| LOW | Penetration test | Engage a third party before going live |