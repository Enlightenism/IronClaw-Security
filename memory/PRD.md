# IronClaw-Security — PRD

## Original Problem Statement
Cybersecurity SaaS protecting AI agents from prompt injection, unsafe tool execution, data exfiltration, trust collapse. Two views: public landing page + JWT-protected dashboard. Luxury "battle-hardened" gold/platinum/sky-blue glassmorphism aesthetic on deep black. Stack: React + FastAPI + MongoDB + Stripe.

## User Choices (Feb 2026)
- Auth: JWT email + password
- Payments: Stripe Checkout (hosted redirect)
- Dashboard data: seeded simulated security events + live simulate endpoint
- AI Brain: marketing/UI only (no LLM this phase)
- Saved card: display via Stripe

## Architecture
- Backend `/app/backend/server.py` — FastAPI, all routes `/api` prefixed. Collections: `users`, `security_events`, `payment_transactions`. bcrypt + PyJWT auth. Stripe via emergentintegrations StripeCheckout. Fixed server-side PACKAGES. Idempotent unit crediting (`credit_units_once`).
- Frontend `/app/frontend/src` — React 19 + react-router. AuthContext (JWT in localStorage `ironclaw_token`), axios instance `lib/api.js`. Pages: Landing, Dashboard. Custom canvas ParticleField, framer-motion animations, Recharts bar chart, sonner toasts, custom useCountUp hook.

## Endpoints
- POST /api/auth/signup (seeds ~48 events, creates user_token, wallet 0)
- POST /api/auth/signin, GET /api/auth/me
- GET /api/dashboard (wallet, usage today/week, 7-day daily_usage, attacks[30], blocked total)
- GET /api/integrations/token (claude-code + openclaw install commands)
- POST /api/payments/create-checkout, GET /api/payments/status/{id}, POST /api/webhook/stripe
- POST /api/events/simulate (live events + wallet draw-down)

## Implemented (2026-06-01)
- Landing: particle constellation bg, gold-shimmer hero headline, animated live threat counter, 6 glassmorphism feature cards w/ gold hover sweep, platinum credits card, footer CTA.
- Dashboard: platinum Wallet card (count-up balance, 3 Stripe purchase tiers, saved payment method section), blue Security Analysis card (today/week stats, sky-blue Recharts bar chart, animated attack log w/ verdict chips), gold Claude Code + platinum OpenClaw install cards w/ copy-to-clipboard.
- Full Stripe Checkout flow with frontend polling + webhook crediting. JWT-protected dashboard with redirect.
- Tested: backend 18/18; frontend signup/signin/dashboard/purchase/signout verified.

## Backlog / Next
- P1: Real saved-card last4/expiry (needs production Stripe Customer + SetupIntent; emergent test key returns no PM details).
- P1: Audit-trail CSV export for compliance.
- P2: Real "AI Brain" LLM semantic scoring endpoint (Emergent LLM key / Claude Sonnet 4.5).
- P2: Gate the 20s live-simulate poll behind document.visibilityState.
- P2: Per-platform usage breakdown (claude-code vs openclaw).
