# MarketMate — conversational store

A single-business conversational shopping experience for food, clothing and everyday health essentials. The first commit is a **UI/API prototype**, not a production-ready shop.

## Current prototype

- Full-screen chat-style shopping interface
- Sample products across the three categories, priced in Ghana cedis
- Basic keyword matching through the Worker API
- Add-to-cart interaction in the browser
- Admin dashboard layout preview

The catalogue, cart and admin view currently use sample/demo data. There is no real checkout, database persistence, admin authentication, AI model connection, payment processing, or WhatsApp integration yet.

## Cloudflare project

This project uses Cloudflare's current `cf` CLI and `cloudflare.config.ts` project format (not Wrangler).

1. Install a current Node.js LTS release.
2. Install dependencies: `npm install`.
3. Install the Cloudflare CLI if needed: `npm install --global cf`.
4. Sign in: `cf auth login`.
5. Run locally: `npm run dev`.
6. Build: `npm run build`.
7. Deploy when the account resources and secrets have been configured: `npm run deploy`.

Connect this GitHub repository to Cloudflare Workers Builds for automatic deployments after the initial manual setup. Review the Cloudflare build settings against the current CLI documentation before enabling production deploys.

## Planned production architecture

- **Workers + Static Assets:** storefront and API
- **D1:** products, categories, customers, carts, orders and order events
- **R2:** product image uploads
- **Workers AI or a separately configured model provider:** conversational product discovery, with tool-based access to the real catalogue and cart
- **Admin authentication:** protected admin routes and role checks
- **Payments:** select a Ghana-supported provider and verify its current merchant requirements before integration
- **WhatsApp:** Meta WhatsApp Cloud API later, sharing the same catalogue and order services

## Safety and launch requirements

- Do not use the assistant to diagnose, prescribe, or replace a pharmacist. Medicine listings must follow applicable Ghana FDA and Pharmacy Council requirements; prescription-only products need the required verification and dispensing controls.
- Keep API credentials in Cloudflare secrets, never in Git.
- Validate all prices, stock, discounts and order totals on the server.
- Do not accept payment details directly in chat.
- Add rate limits, abuse protection, privacy notices, order cancellation/refund rules and delivery policies before launch.

## Next implementation milestone

Replace the demo catalogue with D1-backed product/category management, secure admin sign-in, image uploads to R2, and persistent carts/orders. Then connect the AI assistant to safe, server-side store tools.
