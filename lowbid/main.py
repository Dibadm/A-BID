"""
main.py - FastAPI real-time engine for the white-label Lowest Unique Bid Auction platform.

Run:  uvicorn main:app --host 0.0.0.0 --port 8000

Architecture
  * Redis  = live state. Per auction:
        auction:{id}            HASH  status, max_slots, filled_slots, pending, + static display fields
        auction:{id}:bids       ZSET  member = zero-padded bid value, score = times chosen
        auction:{id}:user:{uid} HASH  bid value -> how many times this user chose it
    Slot check + increments run inside ONE Lua script => atomic, no race conditions.
  * Postgres = wallet ledger, bid audit rows, final results (no SQL aggregates for live play).

White-label integration points (search for "STUB"):
    send_user_otp, verify_user_otp, process_wallet_deposit, verify_webhook_signature
"""
import asyncio
import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from decimal import Decimal
from typing import Optional

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    Auction, AuctionOutcome, AuctionStatus, BidLedger, PartnerCommission, SessionLocal, User, UserFlag,
    WalletTransaction, engine, get_db, init_models, utcnow,
)
import admin
import auth
import payments

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("lub")

# ----------------------------------------------------------------------------- config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DEV_MODE = os.getenv("DEV_MODE", "1") == "1"  # DEV_MODE accepts OTP 123456 and exposes /api/users
PLATFORM_FEE_FLAT = Decimal(os.getenv("PLATFORM_FEE_FLAT", "2.00"))  # flat fee per bid transaction
PARTNER_COMMISSION_RATE = Decimal(os.getenv("PARTNER_COMMISSION_RATE", "0.10"))  # of bid cost
BID_MAX_VALUE = int(os.getenv("BID_MAX_VALUE", "100000"))
OTP_TTL_SECONDS = 300
MONEY = Decimal("0.01")

R: aioredis.Redis = None  # set in lifespan
_bg_tasks: set = set()


def spawn(coro):
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


# ----------------------------------------------------------------------------- redis key helpers
def akey(aid: int) -> str:
    return f"auction:{aid}"


def bkey(aid: int) -> str:
    return f"auction:{aid}:bids"


def ukey(aid: int, uid: int) -> str:
    return f"auction:{aid}:user:{uid}"


def member(value: int) -> str:
    """Zero-padded so lexicographic order == numeric order for equal scores."""
    return f"{int(value):08d}"


RESERVE_LUA = """
local st = redis.call('HGET', KEYS[1], 'status')
if not st then return {-3, 0} end
if st ~= 'active' then return {-1, 0} end
local filled = tonumber(redis.call('HGET', KEYS[1], 'filled_slots'))
local maxs = tonumber(redis.call('HGET', KEYS[1], 'max_slots'))
local n = #ARGV
if filled + n > maxs then return {-2, maxs - filled} end
for i = 1, n do
  redis.call('ZINCRBY', KEYS[2], 1, ARGV[i])
  redis.call('HINCRBY', KEYS[3], ARGV[i], 1)
end
filled = redis.call('HINCRBY', KEYS[1], 'filled_slots', n)
redis.call('HINCRBY', KEYS[1], 'pending', 1)
if filled >= maxs then redis.call('HSET', KEYS[1], 'status', 'calculating') end
return {filled, maxs}
"""

SETTLE_LUA = """
local mode = ARGV[1]
if mode == 'rollback' then
  local n = #ARGV - 1
  for i = 2, #ARGV do
    redis.call('ZINCRBY', KEYS[2], -1, ARGV[i])
    local c = redis.call('HINCRBY', KEYS[3], ARGV[i], -1)
    if c <= 0 then redis.call('HDEL', KEYS[3], ARGV[i]) end
  end
  redis.call('HINCRBY', KEYS[1], 'filled_slots', -n)
  if redis.call('HGET', KEYS[1], 'status') == 'calculating' then
    redis.call('HSET', KEYS[1], 'status', 'active')
  end
end
redis.call('HINCRBY', KEYS[1], 'pending', -1)
return 1
"""


async def lowest_unique(aid: int) -> Optional[int]:
    """Smallest bid value chosen exactly once (score==1). O(log N) thanks to zero-padded members."""
    res = await R.zrangebyscore(bkey(aid), 1, 1, start=0, num=1)
    return int(res[0]) if res else None


# ----------------------------------------------------------------------------- views / loading
def public_view(h: dict) -> dict:
    """Public auction payload. The leading number is NEVER exposed until the room has ended."""
    ended = h.get("status") == "ended"
    win = int(h.get("lowest_unique_bid", 0) or 0)
    return {
        "id": int(h["id"]),
        "title": h["title"],
        "description": h.get("description", ""),
        "market_value": float(h["market_value"]),
        "bid_fee": float(h["bid_fee"]),
        "max_slots": int(h["max_slots"]),
        "filled_slots": int(h["filled_slots"]),
        "status": h["status"],
        "ends_at": h.get("ends_at"),
        "winning_bid": win if (ended and win > 0) else None,
        "cancelled": h.get("cancelled") == "1",
    }


async def load_auction_into_redis(a: Auction, session: AsyncSession) -> None:
    """Hydrate Redis from Postgres if the auction is not already there (startup / new rooms)."""
    key = akey(a.id)
    if await R.exists(key):
        await R.sadd("auctions:index", a.id)
        return
    rows = (
        await session.execute(
            select(BidLedger.user_id, BidLedger.bid_amount).where(BidLedger.auction_id == a.id)
        )
    ).all()
    outcome = await session.get(AuctionOutcome, a.id)
    pipe = R.pipeline()
    for uid, amount in rows:
        pipe.zincrby(bkey(a.id), 1, member(int(amount)))
        pipe.hincrby(ukey(a.id, uid), member(int(amount)), 1)
    pipe.hset(key, mapping={
        "id": a.id, "title": a.title, "description": a.description or "",
        "market_value": str(a.market_value), "bid_fee": str(a.bid_fee),
        "max_slots": a.max_slots, "filled_slots": len(rows), "pending": 0,
        "status": a.status.value, "ends_at": a.ends_at.isoformat(),
        "winner_id": a.winner_id or 0, "cancelled": "1" if (outcome and outcome.outcome == "cancelled") else "0",
        "lowest_unique_bid": int(a.lowest_unique_bid) if a.lowest_unique_bid is not None else 0,
    })
    pipe.sadd("auctions:index", a.id)
    await pipe.execute()


async def all_public_auctions() -> list:
    ids = sorted(int(i) for i in await R.smembers("auctions:index"))
    pipe = R.pipeline()
    for i in ids:
        pipe.hgetall(akey(i))
    return [public_view(h) for h in await pipe.execute() if h]


# ----------------------------------------------------------------------------- websocket manager
class ConnectionManager:
    """Dynamic pool of live sockets. user_id 0 = anonymous spectator."""

    def __init__(self):
        self.active: dict[WebSocket, int] = {}

    async def connect(self, ws: WebSocket, user_id: int):
        await ws.accept()
        self.active[ws] = user_id

    def disconnect(self, ws: WebSocket):
        self.active.pop(ws, None)

    async def _send(self, ws: WebSocket, text: str):
        try:
            await ws.send_text(text)
        except Exception:
            self.disconnect(ws)

    async def broadcast(self, message: dict):
        text = json.dumps(message)
        await asyncio.gather(*[self._send(ws, text) for ws in list(self.active)])

    async def send_user(self, user_id: int, message: dict):
        text = json.dumps(message)
        await asyncio.gather(*[self._send(ws, text) for ws, uid in list(self.active.items()) if uid == user_id])

    def user_ids(self) -> set:
        return {u for u in self.active.values() if u}


manager = ConnectionManager()


async def broadcast_auction(aid: int):
    h = await R.hgetall(akey(aid))
    if h:
        await manager.broadcast({"type": "auction_update", "auction": public_view(h)})


async def compute_user_statuses(aid: int, user_ids: list) -> dict:
    """Personal status per user: winning (green) / clashing (yellow) / unique / closed (red)."""
    status = await R.hget(akey(aid), "status")
    lowest = await lowest_unique(aid)
    pipe = R.pipeline()
    for uid in user_ids:
        pipe.hgetall(ukey(aid, uid))
    holdings = await pipe.execute()
    order = []
    pipe = R.pipeline()
    for uid, held in zip(user_ids, holdings):
        for m in held:
            pipe.zscore(bkey(aid), m)
            order.append((uid, m))
    scores = await pipe.execute() if order else []
    per_user: dict = {}
    for (uid, m), sc in zip(order, scores):
        per_user.setdefault(uid, []).append((int(m), int(sc or 0)))
    out = {}
    for uid, items in per_user.items():
        numbers = [n for n, _ in items]
        unique = [n for n, s in items if s == 1]
        clashing = [n for n, s in items if s > 1]
        if status != "active":
            st = "winning" if (status == "ended" and lowest in numbers) else "closed"
        elif lowest is not None and lowest in numbers:
            st = "winning"
        elif unique:
            st = "unique"
        else:
            st = "clashing"
        out[uid] = {
            "status": st, "final": status == "ended",
            "total_bids": len(items), "unique_count": len(unique), "clashing_count": len(clashing),
        }
    return out


async def push_user_statuses(aid: int):
    uids = list(manager.user_ids())
    if not uids:
        return
    statuses = await compute_user_statuses(aid, uids)
    for uid, st in statuses.items():
        await manager.send_user(uid, {"type": "bid_status", "auction_id": aid, **st})


async def push_wallet(user_id: int, balance):
    await manager.send_user(user_id, {"type": "wallet_update", "balance": float(balance)})


async def kick_user(user_id: int):
    """Disconnect every live socket of a suspended player."""
    for ws, uid in list(manager.active.items()):
        if uid == user_id:
            try:
                await ws.send_text(json.dumps({"type": "auth_error"}))
                await ws.close(code=4403)
            except Exception:
                pass
            manager.disconnect(ws)


# ----------------------------------------------------------------------------- finalization
async def sync_auction_to_db(aid: int):
    """Async write-behind of live metrics to Postgres (monotonic, never overwrites an ended room)."""
    h = await R.hgetall(akey(aid))
    if not h:
        return
    values = {"filled_slots": int(h["filled_slots"])}
    if h["status"] == "calculating":
        values["status"] = AuctionStatus.calculating
    async with SessionLocal() as s:
        await s.execute(
            update(Auction)
            .where(Auction.id == aid, Auction.status != AuctionStatus.ended,
                   Auction.filled_slots <= values["filled_slots"])
            .values(**values)
        )
        await s.commit()


async def finalize_auction(aid: int, force: bool = False):
    """Freeze the room, find lowest unique bid, write the audit result, notify everyone."""
    lock = f"auction:{aid}:finalizing"
    if not await R.set(lock, "1", nx=True, ex=60):
        return
    try:
        key = akey(aid)
        if force:
            await R.hset(key, "status", "calculating")
        for _ in range(100):  # wait for in-flight bids to settle (max ~5s)
            if int(await R.hget(key, "pending") or 0) <= 0:
                break
            await asyncio.sleep(0.05)
        h = await R.hgetall(key)
        if not h or h["status"] == "ended":
            return
        if h["status"] == "active" and not force:
            return  # a rollback re-opened the room
        await broadcast_auction(aid)
        lowest = await lowest_unique(aid)
        winner_id = None
        async with SessionLocal() as s:
            if lowest is not None:
                winner_id = (await s.execute(
                    select(BidLedger.user_id)
                    .where(BidLedger.auction_id == aid, BidLedger.bid_amount == Decimal(lowest))
                    .order_by(BidLedger.id).limit(1)
                )).scalar_one_or_none()
            await s.execute(update(Auction).where(Auction.id == aid).values(
                status=AuctionStatus.ended,
                lowest_unique_bid=Decimal(lowest) if lowest is not None else None,
                winner_id=winner_id, filled_slots=int(h["filled_slots"]),
            ))
            await s.commit()
        await R.hset(key, mapping={"status": "ended", "winner_id": winner_id or 0, "lowest_unique_bid": lowest or 0})
        await broadcast_auction(aid)
        await push_user_statuses(aid)
        log.info("auction %s ended: lowest_unique=%s winner=%s", aid, lowest, winner_id)
    finally:
        await R.delete(lock)


async def post_bid_tasks(aid: int):
    try:
        await sync_auction_to_db(aid)
        if await R.hget(akey(aid), "status") == "calculating":
            await finalize_auction(aid)
    except Exception:
        log.exception("post_bid_tasks failed for auction %s", aid)


async def expiry_loop():
    """Closes rooms whose ends_at has passed."""
    while True:
        try:
            for aid in sorted(int(i) for i in await R.smembers("auctions:index")):
                h = await R.hgetall(akey(aid))
                if h and h["status"] == "active" and datetime.fromisoformat(h["ends_at"]) <= utcnow():
                    await finalize_auction(aid, force=True)
        except Exception:
            log.exception("expiry_loop error")
        await asyncio.sleep(5)


# ----------------------------------------------------------------------------- white-label STUBS
async def send_user_otp(phone_number: str) -> Optional[str]:
    """
    STUB - replace the body with your SMS provider call (e.g. partner SMS gateway HTTP request).
    Stores the code in Redis with a TTL. In DEV_MODE the fixed code 123456 is used and returned.
    """
    code = "123456" if DEV_MODE else f"{secrets.randbelow(10 ** 6):06d}"
    await R.set(f"otp:{phone_number}", code, ex=OTP_TTL_SECONDS)
    # >>> DROP-IN: await sms_gateway.send(phone_number, f"Your code is {code}")
    log.info("[STUB] OTP for %s generated (no SMS sent)", phone_number)
    return code if DEV_MODE else None


async def verify_user_otp(phone_number: str, code: str) -> bool:
    """STUB - swap for the provider's verify API if the SMS partner manages codes; default checks Redis."""
    stored = await R.get(f"otp:{phone_number}")
    if stored and secrets.compare_digest(stored, code):
        await R.delete(f"otp:{phone_number}")
        return True
    return False


async def process_wallet_deposit(db: AsyncSession, user: User, amount: Decimal,
                                 provider: str, reference: str) -> dict:
    """
    STUB - mobile money deposit (telebirr / CBE / Ebirr).
    Production flow: initiate the gateway charge here (merchant key + endpoint), then credit the wallet
    ONLY from the gateway's confirmed webhook. This stub treats the deposit as already confirmed.
    Idempotent on `reference`, so repeated webhook deliveries never double-credit.
    """
    # >>> DROP-IN: await gateway.initiate_charge(provider, user.phone_number, amount, reference)
    existing = (await db.execute(
        select(WalletTransaction).where(WalletTransaction.reference == reference)
    )).scalar_one_or_none()
    if existing:
        return {"duplicate": True, "balance": float(user.wallet_balance), "reference": reference}
    locked = (await db.execute(select(User).where(User.id == user.id).with_for_update())).scalar_one()
    locked.wallet_balance = Decimal(locked.wallet_balance) + amount
    db.add(WalletTransaction(user_id=locked.id, kind="deposit", amount=amount,
                             balance_after=locked.wallet_balance, reference=reference, provider=provider))
    await db.commit()
    await push_wallet(locked.id, locked.wallet_balance)
    return {"duplicate": False, "balance": float(locked.wallet_balance), "reference": reference}


def verify_webhook_signature(provider: str, raw_body: bytes, signature: Optional[str]) -> bool:
    """STUB - verify the gateway's HMAC/signature with the partner's secret before trusting a webhook."""
    # >>> DROP-IN: return hmac.compare_digest(expected_signature, signature or "")
    return DEV_MODE


# ----------------------------------------------------------------------------- schemas
PHONE_RE = re.compile(r"^\+?\d{9,15}$")


def clean_phone(v: str) -> str:
    v = re.sub(r"[\s\-]", "", v)
    if re.fullmatch(r"0[79]\d{8}", v):  # 0911000001 -> +251911000001
        v = "+251" + v[1:]
    elif re.fullmatch(r"251[79]\d{8}", v):
        v = "+" + v
    if not PHONE_RE.match(v):
        raise ValueError("invalid phone number")
    return v


class OtpRequest(BaseModel):
    phone_number: str

    @field_validator("phone_number")
    @classmethod
    def _p(cls, v):
        return clean_phone(v)


class OtpVerify(OtpRequest):
    code: str = Field(min_length=4, max_length=8)


class DepositRequest(BaseModel):
    user_id: Optional[int] = None  # ignored: identity comes from the token
    amount: Decimal = Field(gt=0, le=1000000)
    provider: str = Field(default="mock", pattern="^(telebirr|cbe|ebirr|mock)$")
    reference: Optional[str] = Field(default=None, max_length=80)


class BatchBidRequest(BaseModel):
    user_id: Optional[int] = None  # ignored: identity comes from the token
    bid_amounts: list[int] = Field(min_length=1, max_length=100)

    @field_validator("bid_amounts")
    @classmethod
    def _b(cls, v):
        if any(b < 1 or b > BID_MAX_VALUE for b in v):
            raise ValueError(f"each bid must be between 1 and {BID_MAX_VALUE}")
        if len(set(v)) != len(v):
            raise ValueError("duplicate numbers inside one batch are not allowed")
        return v


def user_dict(u: User) -> dict:
    return {"id": u.id, "phone_number": u.phone_number,
            "wallet_balance": float(u.wallet_balance), "is_verified": u.is_verified}


# ----------------------------------------------------------------------------- app
@asynccontextmanager
async def lifespan(app: FastAPI):
    global R
    R = aioredis.from_url(REDIS_URL, decode_responses=True)
    auth.set_redis(R)
    await init_models()
    async with SessionLocal() as s:
        for a in (await s.execute(select(Auction))).scalars().all():
            await load_auction_into_redis(a, s)
    async with SessionLocal() as s:  # rebuild the suspended-players set from the database on every start
        blocked = (await s.execute(select(UserFlag.user_id).where(UserFlag.blocked.is_(True)))).scalars().all()
    await R.delete("blocked_users")
    if blocked:
        await R.sadd("blocked_users", *[str(i) for i in blocked])
    task = asyncio.create_task(expiry_loop())
    pay_task = asyncio.create_task(payments.reconcile_loop())
    yield
    task.cancel()
    pay_task.cancel()
    await payments.chapa.aclose()
    await R.aclose()
    await engine.dispose()


app = FastAPI(title="White-Label Lowest Unique Bid Auction", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
payments.hooks["wallet_changed"] = push_wallet
app.include_router(payments.router)  # Chapa: /api/wallet/deposit/initiate, /api/webhooks/chapa, ...
admin.hooks.update(
    redis=lambda: R, finalize=finalize_auction, load_auction=load_auction_into_redis,
    broadcast_auction=broadcast_auction, push_wallet=push_wallet, push_user_statuses=push_user_statuses, kick_user=kick_user,
)
app.include_router(admin.router)  # back office: /api/admin/*, UI at /admin


@app.middleware("http")
async def admin_guard(request: Request, call_next):
    """IP allowlist + hardened headers for everything admin-related."""
    path = request.url.path
    if path.startswith("/api/admin") or path == "/admin":
        if not admin.ip_allowed(request):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        resp = await call_next(request)
        resp.headers.update({"Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                             "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow"})
        return resp
    return await call_next(request)


@app.get("/admin")
async def admin_page():
    nonce = secrets.token_urlsafe(16)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html"), encoding="utf-8") as fh:
        html = fh.read().replace("{{NONCE}}", nonce)
    csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; "
           "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return HTMLResponse(html, headers={"Content-Security-Policy": csp})


@app.get("/")
async def index():
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"))


# ---- auth: phone OTP -> signed session token
async def rate_limit(key: str, limit: int, window: int):
    n = await R.incr(key)
    if n == 1:
        await R.expire(key, window)
    if n > limit:
        raise HTTPException(429, "Too many attempts. Try again later")


@app.post("/api/auth/send-otp")
async def api_send_otp(body: OtpRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    await rate_limit(f"rl:otp-ip:{ip}", 20, 600)
    await rate_limit(f"rl:otp-phone:{body.phone_number}", 5, 600)
    user = (await db.execute(select(User).where(User.phone_number == body.phone_number))).scalar_one_or_none()
    if not user:
        db.add(User(phone_number=body.phone_number, wallet_balance=Decimal("0.00"), is_verified=False))
        await db.commit()
    await R.delete(f"otp_tries:{body.phone_number}")
    dev_code = await send_user_otp(body.phone_number)
    return {"sent": True, "dev_code": dev_code}


@app.post("/api/auth/verify-otp")
async def api_verify_otp(body: OtpVerify, db: AsyncSession = Depends(get_db)):
    phone = body.phone_number
    tries = await R.incr(f"otp_tries:{phone}")
    if tries == 1:
        await R.expire(f"otp_tries:{phone}", OTP_TTL_SECONDS)
    if tries > 5:  # brute-force guard: burn the code
        await R.delete(f"otp:{phone}")
        raise HTTPException(429, "Too many attempts. Try again later")
    user = (await db.execute(select(User).where(User.phone_number == phone))).scalar_one_or_none()
    if not user or not await verify_user_otp(phone, body.code):
        raise HTTPException(400, "Invalid or expired code")
    if await R.sismember("blocked_users", str(user.id)):
        raise HTTPException(403, "Account suspended")
    await R.delete(f"otp_tries:{phone}")
    user.is_verified = True
    await db.commit()
    return {"verified": True, "token": auth.create_token(user.id), "user": user_dict(user)}


@app.get("/api/me")
async def api_me(uid: int = Depends(auth.current_user_id), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, uid)
    if not user:
        raise HTTPException(401, "Session expired")
    return user_dict(user)


# ---- users (dev helper only)
@app.get("/api/users")
async def api_users(db: AsyncSession = Depends(get_db)):
    if not DEV_MODE:
        raise HTTPException(404, "Not found")
    users = (await db.execute(select(User).order_by(User.id))).scalars().all()
    return [user_dict(u) for u in users]


# ---- wallet stubs
@app.post("/api/wallet/deposit")
async def api_deposit(body: DepositRequest, uid: int = Depends(auth.current_user_id),
                      db: AsyncSession = Depends(get_db)):
    if not DEV_MODE:  # the mock deposit credits money without payment: never expose it in production
        raise HTTPException(403, "Use /api/wallet/deposit/initiate")
    user = await db.get(User, uid)
    if not user:
        raise HTTPException(404, "User not found")
    amount = body.amount.quantize(MONEY)
    reference = body.reference or f"DEP-{secrets.token_hex(8)}"
    return await process_wallet_deposit(db, user, amount, body.provider, reference)


@app.post("/api/webhooks/payment/{provider}")
async def api_payment_webhook(provider: str, request: Request, db: AsyncSession = Depends(get_db)):
    """STUB webhook listener: adapt the payload parsing to the partner's callback format."""
    raw = await request.body()
    if not verify_webhook_signature(provider, raw, request.headers.get("x-signature")):
        raise HTTPException(401, "Bad signature")
    data = json.loads(raw or b"{}")
    user = (await db.execute(
        select(User).where(User.phone_number == clean_phone(str(data.get("phone_number", ""))))
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    amount = Decimal(str(data.get("amount", "0"))).quantize(MONEY)
    if amount <= 0 or not data.get("reference"):
        raise HTTPException(400, "amount and reference required")
    return await process_wallet_deposit(db, user, amount, provider, str(data["reference"]))


# ---- auctions
@app.get("/api/auctions")
async def api_auctions():
    return await all_public_auctions()


@app.post("/api/auctions/{auction_id}/bid-batch")
async def bid_batch(auction_id: int, body: BatchBidRequest, uid: int = Depends(auth.current_user_id),
                    db: AsyncSession = Depends(get_db)):
    key, bids_key, user_key = akey(auction_id), bkey(auction_id), ukey(auction_id, uid)
    h = await R.hgetall(key)
    if not h:
        raise HTTPException(404, "Auction not found")

    n = len(body.bid_amounts)
    bid_cost = (Decimal(h["bid_fee"]) * n).quantize(MONEY)
    total = bid_cost + PLATFORM_FEE_FLAT
    members = [member(b) for b in body.bid_amounts]

    # 1) lock wallet row and check funds (nothing committed yet)
    user = (await db.execute(select(User).where(User.id == uid).with_for_update())).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if not user.is_verified:
        raise HTTPException(403, "Phone number not verified")
    if Decimal(user.wallet_balance) < total:
        raise HTTPException(402, f"Insufficient balance. Need {total} ETB")

    # 2) ATOMIC Redis slot reservation (single Lua script: check capacity + ZINCRBY/HINCRBY)
    code, extra = await R.eval(RESERVE_LUA, 3, key, bids_key, user_key, *members)
    if code == -3:
        raise HTTPException(404, "Auction not found")
    if code == -1:
        raise HTTPException(409, "Room is closed")
    if code == -2:
        raise HTTPException(400, f"Not enough slots: only {extra} remaining")
    filled, max_slots = code, extra

    # 3) commit ledger; compensate Redis if Postgres fails
    try:
        user.wallet_balance = Decimal(user.wallet_balance) - total
        db.add_all([
            WalletTransaction(user_id=user.id, kind="bid_purchase", amount=-bid_cost,
                              balance_after=Decimal(user.wallet_balance) + PLATFORM_FEE_FLAT,
                              auction_id=auction_id),
            WalletTransaction(user_id=user.id, kind="platform_fee", amount=-PLATFORM_FEE_FLAT,
                              balance_after=user.wallet_balance, auction_id=auction_id),
            PartnerCommission(auction_id=auction_id, user_id=user.id,
                              amount=(bid_cost * PARTNER_COMMISSION_RATE).quantize(MONEY)),
        ])
        now = utcnow()
        db.add_all([BidLedger(auction_id=auction_id, user_id=user.id, bid_amount=Decimal(b), timestamp=now)
                    for b in body.bid_amounts])
        await db.commit()
    except Exception:
        await db.rollback()
        await R.eval(SETTLE_LUA, 3, key, bids_key, user_key, "rollback", *members)
        log.exception("bid commit failed")
        raise HTTPException(500, "Could not record bids; no charge made")
    await R.eval(SETTLE_LUA, 3, key, bids_key, user_key, "commit")

    # 4) realtime fan-out + async DB sync / finalization
    await broadcast_auction(auction_id)
    await push_wallet(user.id, user.wallet_balance)
    await push_user_statuses(auction_id)
    spawn(post_bid_tasks(auction_id))

    mine = (await compute_user_statuses(auction_id, [user.id])).get(user.id)
    return {
        "accepted": n, "charged": float(total), "balance": float(user.wallet_balance),
        "filled_slots": filled, "max_slots": max_slots,
        "room_status": await R.hget(key, "status"), "my_status": mine,
    }


# ---- websocket
async def build_snapshot(user_id: int) -> dict:
    auctions = await all_public_auctions()
    wallet = None
    if user_id:
        async with SessionLocal() as s:
            u = await s.get(User, user_id)
            wallet = float(u.wallet_balance) if u else None
    statuses = []
    if user_id:
        for a in auctions:
            st = (await compute_user_statuses(a["id"], [user_id])).get(user_id)
            if st:
                statuses.append({"auction_id": a["id"], **st})
    return {"type": "snapshot", "auctions": auctions, "wallet": wallet, "statuses": statuses}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    """Connects as a spectator (public data only). Send {"type":"auth","token":...} to receive personal data."""
    await manager.connect(ws, 0)
    try:
        await ws.send_text(json.dumps(await build_snapshot(0)))
        while True:
            raw = await ws.receive_text()
            if raw == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("type") == "auth":
                uid = auth.decode_token(str(msg.get("token", "")))
                if uid is None:
                    await ws.send_text(json.dumps({"type": "auth_error"}))
                    await ws.close(code=4401)
                    return
                if await R.sismember("blocked_users", str(uid)):
                    await ws.send_text(json.dumps({"type": "auth_error"}))
                    await ws.close(code=4403)
                    return
                manager.active[ws] = uid
                await ws.send_text(json.dumps(await build_snapshot(uid)))
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("websocket error")
    finally:
        manager.disconnect(ws)
