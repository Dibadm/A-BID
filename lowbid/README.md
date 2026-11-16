# LowBid: white-label Lowest Unique Bid Auction

FastAPI + Redis (live game state) + PostgreSQL (ledger) + single-file Tailwind player app (English / Amharic) + admin panel.

## Quick start (development)
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env            # defaults work for local dev (needs Postgres and Redis running)
    python seed.py --reset          # tables, 6 test players, 3 rooms
    python create_admin.py yourname # first superadmin (hidden password prompt)
    uvicorn main:app --env-file .env --port 8000

- Players: http://localhost:8000/   (sign in with 0911000001; dev code is filled in automatically)
- Admin:   http://localhost:8000/admin

## Files
| File | Purpose |
|---|---|
| main.py | API, Redis atomic bidding (Lua), WebSockets, room finalization |
| database.py | SQLAlchemy models (users, rooms, bid ledger, wallet ledger, payments, admin tables) |
| auth.py | Player session tokens (phone OTP -> JWT), suspended-player enforcement |
| payments.py | Chapa deposits: initialize, signed webhook, callback, status polling, reconciliation |
| admin.py / admin.html | Back-office API and UI (roles, audit log, refunds, ledger, reports) |
| create_admin.py | Create or reset staff accounts from the command line |
| seed.py | Test data |
| index.html | Player app |
| tests/test_e2e.py | End-to-end test (SQLite + fake Redis): `pip install -r requirements-dev.txt && python tests/test_e2e.py` |

## Before production
Set DEV_MODE=0, AUTH_SECRET, ADMIN_AUTH_SECRET (>=32 chars, different from each other), serve over HTTPS,
connect an SMS provider in `send_user_otp` (main.py), add the Chapa key and register the webhook
`PUBLIC_BASE_URL/api/webhooks/chapa`, restrict the admin panel with ADMIN_IP_ALLOWLIST, and run behind
`uvicorn --proxy-headers` if you use a reverse proxy.
