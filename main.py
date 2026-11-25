import os, asyncio, datetime as dt
from contextlib import asynccontextmanager
from decimal import Decimal
from pathlib import Path
import redis.asyncio as aioredis
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update, func
from database import (SessionLocal, init_models, User, Auction, BidLedger, WalletTransaction,
                      PaymentIntent, PartnerCommission, utcnow)
from auth import (make_token, send_user_otp, verify_user_otp, get_current_user, get_optional_user,
                  PHONE_RE, DEV_MODE)
import payments
from payments import process_wallet_deposit, initiate_chapa_deposit

BASE = Path(__file__).parent
r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
PAD = 8
META = lambda a: f"auction:{a}:meta"
CNT = lambda a: f"auction:{a}:counts"

LUA_BID = """
if redis.call('HGET',KEYS[1],'status')~='active' then return -1 end
local n=#ARGV
local filled=tonumber(redis.call('HGET',KEYS[1],'filled'))
local max=tonumber(redis.call('HGET',KEYS[1],'max'))
local room=redis.call('HGET',KEYS[1],'is_room')=='1'
if room and filled+n>max then return -2 end
for i=1,n do redis.call('HINCRBY',KEYS[2],ARGV[i],1) end
filled=filled+n
redis.call('HSET',KEYS[1],'filled',filled)
if room and filled>=max then redis.call('HSET',KEYS[1],'status','frozen') end
return filled
"""
LUA_ROLLBACK = """
for i=1,#ARGV do
  local c=redis.call('HINCRBY',KEYS[2],ARGV[i],-1)
  if c<=0 then redis.call('HDEL',KEYS[2],ARGV[i]) end
end
redis.call('HINCRBY',KEYS[1],'filled',-#ARGV)
if redis.call('HGET',KEYS[1],'status')=='frozen' then redis.call('HSET',KEYS[1],'status','active') end
return 1
"""


class WS:
    def __init__(self): self.conns: set[WebSocket] = set()
    async def connect(self, ws):
        await ws.accept(); self.conns.add(ws)
    def drop(self, ws): self.conns.discard(ws)
    async def broadcast(self, msg: dict):
        for ws in list(self.conns):
            try: await ws.send_json(msg)
            except Exception: self.conns.discard(ws)


ws_mgr = WS()


async def rebuild_redis(session, a: Auction):
    rows = (await session.execute(select(BidLedger.bid_amount, func.count()).where(
        BidLedger.auction_id == a.id).group_by(BidLedger.bid_amount))).all()
    pipe = r.pipeline()
    pipe.delete(META(a.id), CNT(a.id))
    for amt, c in rows:
        pipe.hset(CNT(a.id), str(amt).zfill(PAD), c)
    filled = sum(c for _, c in rows)
    status = "active" if a.status == "active" else "ended"
    if a.status == "active" and a.is_room and filled >= a.max_slots:
        status = "frozen"
    pipe.hset(META(a.id), mapping={"status": status, "filled": filled, "max": a.max_slots,
                                   "is_room": "1" if a.is_room else "0"})
    await pipe.execute()


async def recover():
    async with SessionLocal() as s:
        for a in (await s.execute(select(Auction).where(Auction.status.in_(["active", "calculating"])))).scalars():
            if not await r.exists(META(a.id)):
                await rebuild_redis(s, a)


async def resolve(aid: int):
    """Claim the auction once, compute the lowest unique bid from the Postgres ledger (source of truth)."""
    async with SessionLocal() as s, s.begin():
        claimed = (await s.execute(update(Auction).where(Auction.id == aid, Auction.status == "active")
                                   .values(status="calculating").returning(Auction.id))).first()
        if not claimed:
            return
        await r.hset(META(aid), "status", "frozen")
        low = (await s.execute(select(BidLedger.bid_amount).where(BidLedger.auction_id == aid)
                               .group_by(BidLedger.bid_amount).having(func.count() == 1)
                               .order_by(BidLedger.bid_amount).limit(1))).scalar_one_or_none()
        winner = None
        if low is not None:
            winner = (await s.execute(select(BidLedger.user_id).where(
                BidLedger.auction_id == aid, BidLedger.bid_amount == low))).scalar_one()
        await s.execute(update(Auction).where(Auction.id == aid).values(
            status="ended", lowest_unique_bid=low, winner_id=winner))
    await r.hset(META(aid), "status", "ended")
    await ws_mgr.broadcast({"type": "closed", "auction_id": aid})


async def timer_loop():
    while True:
        try:
            async with SessionLocal() as s:
                ids = (await s.execute(select(Auction.id).where(
                    Auction.status == "active", Auction.ends_at.is_not(None), Auction.ends_at <= utcnow()))).scalars().all()
            for i in ids:
                await resolve(i)
        except Exception as e:
            print("timer_loop error:", e)
        await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(app):
    await init_models()
    await recover()
    task = asyncio.create_task(timer_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)
app.include_router(payments.router)
try:
    from admin import router as admin_router  # optional back-office module
    app.include_router(admin_router)
except ImportError:
    pass


@app.get("/")
async def index(): return FileResponse(BASE / "index.html")


@app.get("/admin")
async def admin_page():
    p = BASE / "admin.html"
    return FileResponse(p) if p.exists() else PlainTextResponse("admin.html not installed", 404)


# ---------- auth ----------
class PhoneIn(BaseModel):
    phone_number: str

class OtpIn(PhoneIn):
    code: str


@app.post("/api/auth/send-otp")
async def send_otp(b: PhoneIn):
    if not PHONE_RE.match(b.phone_number):
        raise HTTPException(400, "Use format +2519XXXXXXXX or +2517XXXXXXXX")
    await send_user_otp(b.phone_number)
    return {"ok": True, "dev_hint": "123456" if DEV_MODE else None}


@app.post("/api/auth/verify-otp")
async def verify_otp(b: OtpIn):
    if not PHONE_RE.match(b.phone_number) or not await verify_user_otp(b.phone_number, b.code):
        raise HTTPException(400, "Invalid or expired code")
    async with SessionLocal() as s, s.begin():
        u = (await s.execute(select(User).where(User.phone_number == b.phone_number))).scalar_one_or_none()
        if not u:
            u = User(phone_number=b.phone_number, wallet_balance=Decimal("0"), is_verified=True)
            s.add(u); await s.flush()
        u.is_verified = True
    return {"token": make_token(u.id)}


def me_out(u: User): return {"id": u.id, "phone_number": u.phone_number, "wallet_balance": float(u.wallet_balance)}


@app.get("/api/me")
async def me(u: User = Depends(get_current_user)):
    async with SessionLocal() as s:
        return me_out(await s.get(User, u.id))


# ---------- wallet ----------
class DepositIn(BaseModel):
    amount: Decimal = Field(gt=0, le=100000)
    provider: str = "chapa"


@app.get("/api/payments/config")
async def pay_config():
    return {"providers": ["chapa", "telebirr", "cbe"], "currency": "ETB", "dev_mode": DEV_MODE,
            "min_deposit": 10, "presets": [50, 100, 200, 500]}


@app.post("/api/wallet/deposit")
async def deposit(b: DepositIn, u: User = Depends(get_current_user)):
    if not DEV_MODE:
        raise HTTPException(403, "Direct deposit disabled; use /api/wallet/deposit/initiate")
    import uuid
    async with SessionLocal() as s, s.begin():
        await process_wallet_deposit(s, u.id, b.amount, f"dev-{uuid.uuid4().hex}")
    async with SessionLocal() as s:
        return me_out(await s.get(User, u.id))


@app.post("/api/wallet/deposit/initiate")
async def deposit_initiate(b: DepositIn, u: User = Depends(get_current_user)):
    if b.provider not in ("chapa", "telebirr", "cbe"):
        raise HTTPException(400, "Unknown provider")
    return await initiate_chapa_deposit(u, b.amount, b.provider)


@app.get("/api/wallet/deposit/status/{ref}")
async def deposit_status(ref: str, u: User = Depends(get_current_user)):
    async with SessionLocal() as s:
        pi = (await s.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == ref, PaymentIntent.user_id == u.id))).scalar_one_or_none()
        if not pi: raise HTTPException(404, "Not found")
        return {"tx_ref": ref, "status": pi.status, "amount": float(pi.amount), "failure_reason": pi.failure_reason}


# ---------- auctions ----------
def iso(d): return d.isoformat() + "Z" if d else None


@app.get("/api/auctions")
async def list_auctions(u: User | None = Depends(get_optional_user)):
    async with SessionLocal() as s:
        auctions = (await s.execute(select(Auction).where(Auction.status != "cancelled")
                                    .order_by(Auction.status, Auction.id.desc()))).scalars().all()
        mine: dict[int, list[int]] = {}
        if u:
            for aid, amt in (await s.execute(select(BidLedger.auction_id, BidLedger.bid_amount)
                                             .where(BidLedger.user_id == u.id))).all():
                mine.setdefault(aid, []).append(amt)
    out = []
    for a in auctions:
        meta = await r.hgetall(META(a.id))
        live = a.status == "active" and meta.get("status", "active") == "active"
        filled = int(meta.get("filled", a.filled_slots))
        item = {"id": a.id, "title": a.title, "description": a.description, "market_value": float(a.market_value),
                "bid_fee": float(a.bid_fee), "max_slots": a.max_slots, "filled_slots": filled,
                "is_room": a.is_room, "status": a.status, "ends_at": iso(a.ends_at),
                "user_status": None, "user_bids": [], "won": bool(u and a.winner_id == u.id)}
        if u and a.id in mine:
            counts = {int(k): int(v) for k, v in (await r.hgetall(CNT(a.id))).items()}
            uniq = sorted(x for x in set(mine[a.id]) if counts.get(x) == 1)
            leader = min((k for k, v in counts.items() if v == 1), default=None)
            item["user_bids"] = [{"amount": x, "unique": counts.get(x) == 1} for x in sorted(mine[a.id])]
            if not live: st = "closed"
            elif leader is not None and leader in uniq: st = "leading"
            elif uniq: st = "unique"
            else: st = "duplicated"
            item["user_status"] = st
        elif not live and u:
            item["user_status"] = None
        if not live: item["status"] = "ended" if a.status == "active" else a.status
        out.append(item)  # NOTE: the global leading number is never exposed
    return out


class BatchIn(BaseModel):
    bid_amounts: list[int] = Field(min_length=1, max_length=100)


@app.post("/api/auctions/{aid}/bid-batch")
async def bid_batch(aid: int, b: BatchIn, user: User = Depends(get_current_user)):
    amounts = b.bid_amounts
    if any(x < 1 or x > 10_000_000 for x in amounts):
        raise HTTPException(400, "Bids must be positive integers up to 10,000,000")
    padded = [str(x).zfill(PAD) for x in amounts]
    reserved, filled, room = False, 0, False
    try:
        async with SessionLocal() as s, s.begin():
            u = (await s.execute(select(User).where(User.id == user.id).with_for_update())).scalar_one()  # 1. lock wallet
            a = await s.get(Auction, aid)
            if not a: raise HTTPException(404, "Auction not found")
            room = a.is_room
            if a.status != "active" or (a.ends_at and a.ends_at <= utcnow()):
                raise HTTPException(409, "Auction closed")
            cost = a.bid_fee * len(amounts)
            if u.wallet_balance < cost:                                                            # 2. verify funds
                raise HTTPException(402, f"Insufficient balance: need {cost} ETB")
            res = await r.eval(LUA_BID, 2, META(aid), CNT(aid), *padded)                         # 3. reserve in Redis
            if res == -2: raise HTTPException(409, "Not enough slots left in this room")
            if res < 0: raise HTTPException(409, "Auction closed")
            reserved, filled = True, int(res)
            u.wallet_balance = u.wallet_balance - cost                                             # 4. ledger + wallet
            rows = [BidLedger(auction_id=aid, user_id=u.id, bid_amount=x, fee_charged=a.bid_fee) for x in amounts]
            s.add_all(rows); await s.flush()
            pf = min(a.bid_fee, payments.PLATFORM_FEE_FLAT)
            ps = ((a.bid_fee - pf) * payments.PARTNER_COMMISSION_RATE).quantize(Decimal("0.01"))
            s.add_all([PartnerCommission(auction_id=aid, bid_ledger_id=x.id, platform_fee=pf, partner_share=ps) for x in rows])
            s.add(WalletTransaction(user_id=u.id, kind="bid_fee", amount=-cost, balance_after=u.wallet_balance))
            await s.execute(update(Auction).where(Auction.id == aid).values(filled_slots=Auction.filled_slots + len(amounts)))
            balance = float(u.wallet_balance)
    except BaseException:
        if reserved:  # Postgres failed -> release Redis slots so nothing leaks
            await r.eval(LUA_ROLLBACK, 2, META(aid), CNT(aid), *padded)
        raise
    await ws_mgr.broadcast({"type": "slots", "auction_id": aid, "filled_slots": filled})
    if room and (await r.hget(META(aid), "status")) == "frozen":
        asyncio.create_task(resolve(aid))
    return {"ok": True, "placed": len(amounts), "wallet_balance": balance, "filled_slots": filled}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws_mgr.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_mgr.drop(ws)
    except Exception:
        ws_mgr.drop(ws)
