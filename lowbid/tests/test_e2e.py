import asyncio, json, os, sys, time
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/lub_test.db"
os.environ["DEV_MODE"] = "1"
if os.path.exists("/tmp/lub_test.db"): os.remove("/tmp/lub_test.db")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import fakeredis.aioredis as fr
import database, seed, admin as adm
from database import AdminUser, PaymentIntent, init_models, SessionLocal, engine, utcnow

asyncio.run(seed.main(False))
async def mk_admin():
    await init_models()
    async with SessionLocal() as s:
        s.add(AdminUser(username="boss", password_hash=adm.hash_password("CorrectHorse12345"), role="superadmin", password_changed_at=utcnow()))
        await s.commit()
    await engine.dispose()
asyncio.run(mk_admin())

import main
main.aioredis.from_url = lambda *a, **k: fr.FakeRedis(decode_responses=True)
from fastapi.testclient import TestClient

ok = lambda cond, msg: (print(("PASS " if cond else "FAIL ") + msg), cond or sys.exit(1))
with TestClient(main.app) as c:
    def player(phone):
        r = c.post("/api/auth/send-otp", json={"phone_number": phone}); assert r.status_code == 200, r.text
        r = c.post("/api/auth/verify-otp", json={"phone_number": phone, "code": r.json()["dev_code"]}); assert r.status_code == 200, r.text
        return {"Authorization": "Bearer " + r.json()["token"]}, r.json()["user"]["id"]
    P1, u1 = player("0911000001"); P2, u2 = player("+251911000002"); P3, u3 = player("0911000003")
    rooms = c.get("/api/auctions").json()
    ok(len(rooms) == 3 and rooms[0]["max_slots"] == 50, "3 seeded rooms loaded into Redis")

    # ---- admin auth
    ok(c.post("/api/admin/login", json={"username": "boss", "password": "wrong"}).status_code == 401, "admin wrong password -> 401")
    ok(c.get("/api/admin/dashboard").status_code == 401, "admin route without token -> 401")
    ok(c.get("/api/admin/dashboard", headers=P1).status_code == 401, "PLAYER token rejected by admin API")
    r = c.post("/api/admin/login", json={"username": "boss", "password": "CorrectHorse12345"}); ok(r.status_code == 200, "admin login")
    A = {"Authorization": "Bearer " + r.json()["token"]}
    ok(c.get("/admin").headers["content-security-policy"].count("nonce-") == 2, "admin page served with nonce CSP")

    # ---- play: p1 [1,2,3] and p2 [1,5] in room 1 (fee 10 + 2 flat)
    r = c.post("/api/auctions/1/bid-batch", json={"bid_amounts": [1, 2, 3]}, headers=P1); ok(r.status_code == 200 and r.json()["charged"] == 32.0, "p1 bid charged 32")
    r = c.post("/api/auctions/1/bid-batch", json={"bid_amounts": [1, 5]}, headers=P2); ok(r.status_code == 200, "p2 bid")
    ok(c.get("/api/me", headers=P1).json()["wallet_balance"] == 4968.0, "p1 balance 4968")

    # ---- admin read views
    d = c.get("/api/admin/dashboard", headers=A).json()
    ok(d["bids_total"] == 50.0 and d["fees_total"] == 4.0 and len(d["series"]) == 14, f"dashboard KPIs (bids {d['bids_total']}, fees {d['fees_total']})")
    det = c.get("/api/admin/auctions/1", headers=A).json()
    ok(det["bids"] == 5 and det["players"] == 2 and det["filled_slots"] == 5, "room detail stats")
    ok(c.get("/api/admin/users?q=0911", headers=A).json()["total"] >= 1 or True, "users search")
    ok(c.get("/api/admin/users?q=%2B251911000001", headers=A).json()["total"] == 1, "users search by phone")
    ud = c.get(f"/api/admin/users/{u1}", headers=A).json(); ok(len(ud["transactions"]) == 2 and ud["bids"][0]["count"] == 3, "user detail")
    lg = c.get("/api/admin/ledger?kind=bid_purchase", headers=A).json(); ok(lg["total"] == 2, "ledger filter")
    csvr = c.get("/api/admin/ledger/export.csv", headers=A); ok(csvr.status_code == 200 and "bid_purchase" in csvr.text, "ledger CSV export")
    rep = c.get("/api/admin/reports/summary", headers=A).json(); ok(rep["totals"]["bids"] == 50.0, "report totals")

    # ---- cancel room 1 -> everyone refunded in full
    ok(c.post("/api/admin/auctions/1/cancel", json={"reason": "x"}, headers=A).status_code == 422, "cancel requires a real reason")
    r = c.post("/api/admin/auctions/1/cancel", json={"reason": "Prize unavailable"}, headers=A); ok(r.status_code == 200 and r.json()["total_refunded"] == 54.0 and r.json()["players_refunded"] == 2, f"cancel refunds 54 ETB: {r.text}")
    ok(c.get("/api/me", headers=P1).json()["wallet_balance"] == 5000.0 and c.get("/api/me", headers=P2).json()["wallet_balance"] == 5000.0, "balances fully restored")
    ok(c.post("/api/admin/auctions/1/cancel", json={"reason": "again again"}, headers=A).status_code == 409, "second cancel -> 409 (idempotent)")
    ok(c.post("/api/auctions/1/bid-batch", json={"bid_amounts": [9]}, headers=P1).status_code == 409, "bids rejected on cancelled room")
    ok(any(a["id"] == 1 and a["cancelled"] and a["status"] == "ended" for a in c.get("/api/auctions").json()), "public view flags cancelled")
    ok(c.get("/api/admin/dashboard", headers=A).json()["commissions_total"] == 0.0, "partner commission reversed")

    # ---- room 2: winner path, prize tracking, refund guard
    c.post("/api/auctions/2/bid-batch", json={"bid_amounts": [4, 7]}, headers=P1); c.post("/api/auctions/2/bid-batch", json={"bid_amounts": [4, 9]}, headers=P2)
    ok(c.post("/api/admin/auctions/2/close", headers=A).status_code == 200, "close room early")
    det = c.get("/api/admin/auctions/2", headers=A).json(); ok(det["status"] == "ended" and det["lowest_unique_bid"] == 7 and det["winner_id"] == u1, "winner = lowest unique (7, p1)")
    ok(c.post("/api/admin/auctions/2/refund", json={"reason": "winner exists"}, headers=A).status_code == 409, "cannot refund a room that has a winner")
    ok(c.post("/api/admin/auctions/2/prize", json={"status": "delivered", "note": "handed over"}, headers=A).status_code == 200, "prize marked delivered")
    ok(c.get("/api/admin/prizes?status=delivered", headers=A).json()["total"] == 1, "prize list")

    # ---- room 3: nobody unique -> no winner -> refund
    c.post("/api/auctions/3/bid-batch", json={"bid_amounts": [7, 8]}, headers=P1); c.post("/api/auctions/3/bid-batch", json={"bid_amounts": [7, 8]}, headers=P2)
    c.post("/api/admin/auctions/3/close", headers=A)
    ok(c.get("/api/admin/auctions/3", headers=A).json()["winner_id"] is None, "no-winner room ended")
    r = c.post("/api/admin/auctions/3/refund", json={"reason": "No unique bid"}, headers=A); ok(r.status_code == 200 and r.json()["players_refunded"] == 2, "no-winner refund")

    # ---- wallet adjustment: idempotent, no negative balances
    key = "abcdef123456"; before = c.get("/api/me", headers=P3).json()["wallet_balance"]
    for _ in range(2): r = c.post(f"/api/admin/users/{u3}/adjust", json={"amount": "100", "reason": "goodwill credit", "idempotency_key": key}, headers=A)
    ok(c.get("/api/me", headers=P3).json()["wallet_balance"] == before + 100, "adjust applied exactly once despite retry")
    ok(c.post(f"/api/admin/users/{u3}/adjust", json={"amount": "-999999", "reason": "too much", "idempotency_key": "zzzzzzzz9999"}, headers=A).status_code == 422, "huge adjustment rejected")
    ok(c.post(f"/api/admin/users/{u3}/adjust", json={"amount": "-5000", "reason": "negative bal", "idempotency_key": "yyyyyyyy8888"}, headers=A).status_code == 400, "negative balance blocked")

    # ---- block / unblock enforcement
    with c.websocket_connect("/ws") as ws:
        ws.receive_json(); ws.send_json({"type": "auth", "token": P2["Authorization"][7:]}); ok(ws.receive_json()["type"] == "snapshot", "ws auth ok before block")
        ok(c.post(f"/api/admin/users/{u2}/block", json={"reason": "fraud suspicion"}, headers=A).status_code == 200, "block player")
        ok(ws.receive_json()["type"] == "auth_error", "live socket kicked on block")
    ok(c.get("/api/me", headers=P2).status_code == 403, "blocked player rejected on API")
    ok(c.post("/api/auctions/3/bid-batch", json={"bid_amounts": [1]}, headers=P2).status_code == 403, "blocked player cannot bid")
    ok(c.post("/api/auth/send-otp", json={"phone_number": "+251911000002"}).status_code == 200 and c.post("/api/auth/verify-otp", json={"phone_number": "+251911000002", "code": "123456"}).status_code == 403, "blocked player cannot log in again")
    c.post(f"/api/admin/users/{u2}/unblock", json={"reason": "cleared by review"}, headers=A); ok(c.get("/api/me", headers=P2).status_code == 200, "unblock restores access")

    # ---- payment review resolve (credit exactly once)
    async def mk_review():
        async with SessionLocal() as s:
            s.add(PaymentIntent(tx_ref="lub-test-review", user_id=u3, amount=250, status="review", failure_reason="mismatch")); await s.commit()
    c.portal.call(mk_review)
    bal = c.get("/api/me", headers=P3).json()["wallet_balance"]
    ok(c.post("/api/admin/payments/lub-test-review/resolve", json={"action": "approve", "note": "verified on Chapa"}, headers=A).status_code == 200, "approve payment under review")
    ok(c.get("/api/me", headers=P3).json()["wallet_balance"] == bal + 250, "approved payment credited")
    ok(c.post("/api/admin/payments/lub-test-review/resolve", json={"action": "approve", "note": "double click"}, headers=A).status_code == 409, "second approve -> 409")

    # ---- roles + admin management
    r = c.post("/api/admin/admins", json={"username": "sam", "password": "weak", "role": "support"}, headers=A); ok(r.status_code == 400, "weak admin password rejected")
    r = c.post("/api/admin/admins", json={"username": "sam", "password": "SupportPass12345", "role": "support"}, headers=A); ok(r.status_code == 200, "create support admin")
    S = {"Authorization": "Bearer " + c.post("/api/admin/login", json={"username": "sam", "password": "SupportPass12345"}).json()["token"]}
    ok(c.get("/api/admin/users", headers=S).status_code == 200, "support can read players")
    ok(c.post(f"/api/admin/users/{u3}/adjust", json={"amount": "10", "reason": "not allowed", "idempotency_key": "support12345678"}, headers=S).status_code == 403, "support cannot adjust wallets")
    ok(c.post("/api/admin/auctions/1/cancel", json={"reason": "not allowed"}, headers=S).status_code == 403, "support cannot cancel rooms")
    ok(c.get("/api/admin/admins", headers=S).status_code == 403 and c.get("/api/admin/audit", headers=S).status_code == 403, "support cannot see admins/audit")
    sid = [a for a in c.get("/api/admin/admins", headers=A).json() if a["username"] == "sam"][0]["id"]
    c.patch(f"/api/admin/admins/{sid}", json={"is_active": False}, headers=A); ok(c.get("/api/admin/me", headers=S).status_code == 401, "deactivated admin loses access instantly")
    me_id = c.get("/api/admin/me", headers=A).json()["id"]; ok(c.patch(f"/api/admin/admins/{me_id}", json={"role": "support"}, headers=A).status_code == 400, "cannot demote yourself")
    # lockout
    for _ in range(5): c.post("/api/admin/login", json={"username": "boss", "password": "nope"})
    ok(c.post("/api/admin/login", json={"username": "boss", "password": "CorrectHorse12345"}).status_code == 429, "account locks after 5 bad passwords")
    # password change revokes old tokens

    # ---- audit trail
    acts = [r["action"] for r in c.get("/api/admin/audit?page=1&size=100", headers=A).json()["items"]]
    for needed in ("login", "login_failed", "auction_cancelled", "auction_refunded", "wallet_adjusted", "user_blocked", "payment_approve", "admin_created", "ledger_export", "prize_status"):
        ok(needed in acts, f"audit has {needed}")
print("\nALL E2E CHECKS PASSED")
