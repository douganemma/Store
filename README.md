# MarketMate — conversational store

A single-business conversational shopping experience for food, clothing and everyday health essentials. This repository contains the first backend milestone and the customer/admin interface.

## Implemented

- Full-screen chat-style shopping interface.
- D1-backed catalogue with food, clothing and health essentials categories.
- Public product/category listing and basic keyword product matching.
- Admin account bootstrap protected by a Cloudflare Worker secret.
- Password hashing with PBKDF2-HMAC-SHA-256 and random salts.
- Opaque, random admin sessions stored as SHA-256 hashes in D1; HttpOnly, SameSite=Strict cookies.
- Login throttling by hashed client IP.
- Admin product create, edit and delete.
- Category create and delete (categories with products cannot be deleted).
- R2 product image uploads (JPG, PNG, WebP and AVIF; maximum 5 MB) with signature checks.
- Sample catalogue rows in the initial D1 migration.
- Persistent customer carts stored in D1 and associated with a secure, HTTP-only guest cart cookie.
- Cash-on-delivery checkout with Ghana phone validation, server-side price calculation, stock checks and stock deduction.
- Order records and item snapshots in D1, with an admin order list and fulfilment status updates.

## Live deployment

The first Worker deployment is live at:

- Storefront: https://conversational-store.edougan.workers.dev
- GitHub source: https://github.com/douganemma/Store
- Automatic production builds: enabled for pushes to `main`

The Worker is connected to GitHub through Cloudflare Workers Builds. Each push to `main` builds and deploys the project.

## Cloudflare resources already created

The resources were created in the connected Cloudflare account:

- D1 database: `marketmate-store`
- D1 database ID: `36d18154-3787-4b47-8a9b-81d085a172af`
- R2 bucket: `marketmate-store-images`

The initial schema and sample catalogue have already been applied to D1. The Worker is bound to these resources in `cloudflare.config.ts`.

## First-time admin setup

The live Worker already has an `ADMIN_SETUP_TOKEN` secret configured. Use the one-time token shared separately in the setup instructions to create your admin account.

1. Open the live storefront.
2. Select **Admin login**.
3. Choose **First time? Set up the admin account**.
4. Enter the one-time setup token, your admin email and a password of at least 12 characters.

The first admin account is created once; the setup endpoint refuses subsequent setup attempts. Keep the token private and never commit it to GitHub. To rotate it later, open Cloudflare Dashboard → Workers & Pages → `conversational-store` → Settings → Variables and Secrets.

## Local development and deployment

This project uses Cloudflare's `cf` CLI and `cloudflare.config.ts` project format.

1. Install a current Node.js LTS release.
2. Install dependencies: `npm install`.
3. Install the Cloudflare CLI if needed: `npm install --global cf`.
4. Sign in: `cf auth login`.
5. Generate Worker binding types: `cf workers types`.
6. Run locally: `npm run dev`.
7. Build: `npm run build`.
8. Deploy: `npm run deploy`.

Connect this GitHub repository to Cloudflare Workers Builds for automatic deployments from the default branch. Verify the build command and output settings in the Cloudflare dashboard before enabling automatic production deploys.

## Important security and launch notes

- Admin API routes require a valid server-side session. Never expose admin credentials or setup tokens in frontend code.
- Product prices are stored as integer pesewas to avoid floating-point money errors. The API returns Ghana cedi amounts for display; all future checkout totals must be recalculated server-side.
- Product images are checked for allowed formats and file signatures, and are stored in a private R2 bucket served through the Worker.
- Cash-on-delivery ordering is implemented, but delivery fees are currently zero and must be configured before launch. Confirm every COD order with the customer and verify the delivery address.
- Online payments (Paystack/Hubtel), order tracking for customers, customer accounts, WhatsApp and the real AI shopping assistant are not implemented yet. The chat matching is still keyword-based.
- Prescription-required products are blocked from online cart checkout until appropriate verification and dispensing controls are implemented.
- Medicine products must comply with applicable Ghana FDA and Pharmacy Council rules. The assistant must not diagnose, prescribe or recommend treatment. Prescription products require the correct verification and dispensing controls before sale.
- Before public launch, add a privacy notice, delivery/refund policies, additional security review, automated tests, backups and monitoring.

## Next milestone

Next: connect Workers AI to safe catalogue and cart tools, then add customer order tracking and configurable delivery fees. Integrate Paystack/Hubtel after the cash-on-delivery flow has been tested. WhatsApp will use the same backend later.
