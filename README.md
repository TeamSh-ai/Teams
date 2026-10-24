# TeamSh — starter project (Node.js + Express)

This is a learning starter, not a production-ready streaming/payment service.

## Requirements
- Node.js 20 or newer
- Internet connection for installing packages

## Run on Windows
1. Install Node.js LTS from the official Node.js website.
2. Extract this ZIP into a folder, e.g. `C:\vista-server`.
3. Open that folder in Terminal / PowerShell.
4. Copy `.env.example` to a new file named `.env`.
5. In `.env`, set `JWT_SECRET` to a long random secret (32+ characters). Keep `.env private.
6. Run:
   ```powershell
   npm install
   npm start
   ```
7. Open `http://localhost:3000`.

## What works locally
- Email/password registration and login (passwords are hashed with bcrypt).
- HttpOnly session cookie containing a signed JWT.
- SQLite database for users, videos, likes, subscriptions, and purchases.
- Video list and preview endpoint.
- Server-side check before returning the full-video URL.
- Optional Stripe Checkout route and webhook code (disabled unless configured).
- Upload price quote only (actual uploads are intentionally not implemented).

## Important limitations before production
1. **Payment provider availability:** Do not assume Stripe can onboard a business in every country. Confirm that your legal business country, bank account, currency, and product category are supported before choosing a provider. Never try to bypass provider eligibility.
2. **Card data:** Do not collect or store card numbers/CVV yourself. Use a compliant provider-hosted checkout or tokenized payment fields.
3. **Stripe webhook:** Configure an HTTPS endpoint `/api/payments/webhook` in the provider dashboard and set `STRIPE_WEBHOOK_SECRET`. Test using provider test mode. Do not grant access based only on a success redirect.
4. **Preview rule:** For a true 20-second preview, upload/generate a separate 20-second preview file. The browser-side timer is only a convenience and can be bypassed if the full source URL is public.
5. **Video security:** `full_url` must not be a public permanent URL. Use private object storage and short-lived signed URLs or a DRM streaming provider. This demo does not implement DRM.
6. **Production hardening:** Add email verification, password reset, CSRF protection, stronger validation, moderation/reporting, copyright takedown workflow, audit logs, backups, HTTPS, and monitoring.
7. **Creator subscriptions:** The schema includes subscriptions, but this starter does not yet provide a creator directory or UI for subscribing to a creator.
8. **Paid uploads:** Only a price quote endpoint exists. Actual file upload/storage and payment enforcement must be implemented before launch.
9. **Currency:** Demo checkout uses USD and a sample $1.99 price. Change this only after confirming your provider and business setup.

Never commit `.env` or real keys to a public repository.
