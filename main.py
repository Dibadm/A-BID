import os, json, asyncio, logging, datetime as dt
from contextlib import asynccontextmanager
from decimal import Decimal
from pathlib import Path
import redis.asyncio as aioredis
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, update, func, or_, and_
from database import (SessionLocal, init_models, User, UserFlag, Auction, BidLedger, WalletTransaction,
                      PaymentIntent, PartnerCommission, utcnow)
from auth import (make_token, send_user_otp, verify_user_otp, get_current_user, get_optional_user, PHONE_RE, DEV_MODE)
import payments
from payments import initiate_chapa_deposit, process_wallet_deposit, PROVIDERS
from admin import router as admin_router, ip_guard

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("lub")
events = logging.getLogger("lub.events")

BASE = Path(__file__).parent
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
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

_tasks: set = set()


def spawn(coro):
    t = asyncio.create_task(coro)
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return t


class BidError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def mask_phone(phone: str) -> str:
    """+251911000042 -> '+251 9*** *** 42'"""
    return f"+251 {phone[4]}*** *** {phone[-2:]}"


async def send_winner_sms(phone_number: str, auction_title: str, winning_bid: int) -> None:
    """STUB: plug in your SMS gateway. Called once, right after an auction resolves with a winner."""
    events.info(json.dumps({"event": "winner_sms_stub", "to": mask_phone(phone_number), "auction": auction_title,
                            "winning_bid": winning_bid}))


class WSManager:
    """Local sockets + Redis Pub/Sub, so a broadcast from any worker reaches players connected to every worker."""
    CHANNEL = "lub:events"

    def __init__(self):
        self.conns: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.conns.add(ws)

    def drop(self, ws: WebSocket):
        self.conns.discard(ws)

    async def broadcast(self, msg: dict):
        payload = json.dumps(msg)
        try:
            await r.publish(self.CHANNEL, payload)
        except Exception:
            log.exception("pubsub publish failed; delivering to local sockets only")
            await self._fan(payload)

    async def _fan(self, payload: str):
        for ws in list(self.conns):
            try:
                await ws.send_text(payload)
            except Exception:
                self.conns.discard(ws)

    async def listen(self):
        while True:
            ps = None
            try:
                ps = r.pubsub()
                await ps.subscribe(self.CHANNEL)
                async for m in ps.listen():
                    if m.get("type") == "message":
                        await self._fan(m["data"])
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("pubsub listener error; reconnecting")
                await asyncio.sleep(2)
            finally:
                if ps is not None:
                    try:
                        await ps.aclose()
                    except Exception:
                        pass


ws_mgr = WSManager()


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
    """Rebuild missing Redis state from the Postgres ledger; a short lock keeps multiple workers from racing."""
    async with SessionLocal() as s:
        for a in (await s.execute(select(Auction).where(Auction.status.in_(["active", "calculating"])))).scalars():
            if not await r.exists(META(a.id)) and await r.set(f"auction:{a.id}:rebuild", "1", nx=True, ex=30):
                await rebuild_redis(s, a)


async def on_auction_resolved(aid: int):
    """Post-resolution hook: structured event log, winner SMS (STUB) and a live WebSocket broadcast."""
    async with SessionLocal() as s:
        a = await s.get(Auction, aid)
        phone = None
        if a.winner_id:
            phone = (await s.get(User, a.winner_id)).phone_number
    masked = mask_phone(phone) if phone else None
    events.info(json.dumps({"event": "auction_resolved", "auction_id": aid, "title": a.title,
                            "winning_bid": a.lowest_unique_bid, "winner_id": a.winner_id, "winner_masked": masked,
                            "at": dt.datetime.utcnow().isoformat() + "Z"}))
    if phone:
        try:
            await send_winner_sms(phone, a.title, a.lowest_unique_bid)
        except Exception:
            log.exception("send_winner_sms failed for auction %s", aid)
    await ws_mgr.broadcast({"type": "auction_ended", "auction_id": aid, "winning_bid": a.lowest_unique_bid,
                            "winner_masked": masked})


async def resolve(aid: int):
    """Claim the auction exactly once, compute the lowest unique bid from the Postgres ledger (source of truth)."""
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
    await on_auction_resolved(aid)


async def timer_loop():
    while True:
        try:
            async with SessionLocal() as s:
                ids = (await s.execute(select(Auction.id).where(
                    Auction.status == "active",
                    or_(and_(Auction.ends_at.is_not(None), Auction.ends_at <= utcnow()),
                        and_(Auction.is_room.is_(True), Auction.filled_slots >= Auction.max_slots))))).scalars().all()
            for i in ids:
                await resolve(i)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("timer_loop error")
        await asyncio.sleep(2)


# ---------- bid engine (shared by /bid-batch and paid bid-checkout) ----------
def check_amounts(amounts: list[int]):
    if not 1 <= len(amounts) <= 100:
        raise BidError(400, "Place between 1 and 100 bids")
    if any(x < 1 or x > 10_000_000 for x in amounts):
        raise BidError(400, "Bids must be positive integers up to 10,000,000")


async def release_slots(aid: int, padded: list[str]):
    await r.eval(LUA_ROLLBACK, 2, META(aid), CNT(aid), *padded)


async def place_bids_tx(s, user_id: int, aid: int, amounts: list[int], state: dict) -> dict:
    """Runs inside the caller's transaction. Order: lock wallet -> verify funds -> Redis Lua reserve -> Postgres ledger.
    Sets state['reserved'] so the caller can release Redis slots if anything later fails."""
    check_amounts(amounts)
    padded = [str(x).zfill(PAD) for x in amounts]
    state["padded"] = padded
    u = (await s.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()
    fl = await s.get(UserFlag, user_id)
    if fl and fl.blocked:
        raise BidError(403, "Account blocked")
    a = await s.get(Auction, aid)
    if not a:
        raise BidError(404, "Auction not found")
    if a.status != "active" or (a.ends_at and a.ends_at <= utcnow()):
        raise BidError(409, "Auction closed")
    cost = a.bid_fee * len(amounts)
    if u.wallet_balance < cost:
        raise BidError(402, f"Insufficient balance: need {cost} ETB")
    res = await r.eval(LUA_BID, 2, META(aid), CNT(aid), *padded)
    if res == -2:
        raise BidError(409, "Not enough slots left in this room")
    if res < 0:
        raise BidError(409, "Auction closed")
    state["reserved"] = True
    # Fence: only succeeds while the auction is still 'active', so a concurrent close/cancel can never miss this bid.
    upd = await s.execute(update(Auction).where(Auction.id == aid, Auction.status == "active")
                          .values(filled_slots=Auction.filled_slots + len(amounts)))
    if upd.rowcount != 1:
        raise BidError(409, "Auction closed")
    u.wallet_balance = u.wallet_balance - cost
    rows = [BidLedger(auction_id=aid, user_id=user_id, bid_amount=x, fee_charged=a.bid_fee) for x in amounts]
    s.add_all(rows)
    await s.flush()
    pf = min(a.bid_fee, payments.PLATFORM_FEE_FLAT)
    ps = ((a.bid_fee - pf) * payments.PARTNER_COMMISSION_RATE).quantize(Decimal("0.01"))
    s.add_all([PartnerCommission(auction_id=aid, bid_ledger_id=x.id, platform_fee=pf, partner_share=ps) for x in rows])
    s.add(WalletTransaction(user_id=user_id, kind="bid_fee", amount=-cost, balance_after=u.wallet_balance,
                            note=f"{len(amounts)} bid(s) on auction #{aid}"))
    return {"aid": aid, "filled": int(res), "room": a.is_room, "balance": float(u.wallet_balance), "placed": len(amounts)}


async def after_bid(res: dict):
    await ws_mgr.broadcast({"type": "slots", "auction_id": res["aid"], "filled_slots": res["filled"]})
    if res["room"] and (await r.hget(META(res["aid"]), "status")) == "frozen":
        spawn(resolve(res["aid"]))


payments.register_bid_hooks(place_bids_tx, release_slots, after_bid)


@asynccontextmanager
async def lifespan(app):
    payments.webhook_secret()  # fail fast if the secret is missing in production
    await init_models()
    await recover()
    tasks = [asyncio.create_task(timer_loop()), asyncio.create_task(ws_mgr.listen())]
    yield
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    try:
        await r.aclose()
    except Exception:
        pass


app = FastAPI(lifespan=lifespan, docs_url="/docs" if DEV_MODE else None, redoc_url=None,
              openapi_url="/openapi.json" if DEV_MODE else None)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS or (["*"] if DEV_MODE else []),
                   allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


app.include_router(payments.router)
app.include_router(admin_router)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


@app.get("/")
async def index(): return FileResponse(BASE / "index.html")


@app.get("/admin", dependencies=[Depends(ip_guard)])
async def admin_page(): return FileResponse(BASE / "admin.html")


# ---------- auth ----------
class PhoneIn(BaseModel):
    phone_number: str

class OtpIn(PhoneIn):
    code: str = Field(min_length=6, max_length=6)


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
            s.add(u)
            await s.flush()
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
    return {"providers": list(PROVIDERS), "currency": "ETB", "dev_mode": DEV_MODE,
            "min_deposit": 10, "presets": [50, 100, 200, 500]}


if DEV_MODE:  # these routes do not exist at all when DEV_MODE=0
    @app.post("/api/wallet/deposit")
    async def dev_deposit(b: DepositIn, u: User = Depends(get_current_user)):
        import uuid
        async with SessionLocal() as s, s.begin():
            await process_wallet_deposit(s, u.id, b.amount, f"dev-{uuid.uuid4().hex}", note="DEV_MODE credit")
        async with SessionLocal() as s:
            return me_out(await s.get(User, u.id))

    @app.get("/api/users")
    async def dev_users():
        async with SessionLocal() as s:
            rows = (await s.execute(select(User).order_by(User.id).limit(100))).scalars().all()
        return [me_out(x) for x in rows]


@app.post("/api/wallet/deposit/initiate")
async def deposit_initiate(b: DepositIn, u: User = Depends(get_current_user)):
    if b.provider not in PROVIDERS:
        raise HTTPException(400, "Unknown provider")
    return await initiate_chapa_deposit(u, b.amount, b.provider)


@app.get("/api/wallet/deposit/status/{ref}")
async def deposit_status(ref: str, u: User = Depends(get_current_user)):
    async def load():
        async with SessionLocal() as s:
            return (await s.execute(select(PaymentIntent).where(
                PaymentIntent.tx_ref == ref, PaymentIntent.user_id == u.id))).scalar_one_or_none()
    pi = await load()
    if not pi:
        raise HTTPException(404, "Not found")
    if pi.status == "pending":  # webhook may be late: ask the provider directly
        verdict = await payments.verify_with_provider(pi.tx_ref, pi.provider)
        if verdict == "success":
            await payments.confirm_payment(ref)
        elif verdict == "failed":
            await payments.mark_failed(ref, None, "provider reported failure")
        pi = await load()
    return {"tx_ref": ref, "status": pi.status, "amount": float(pi.amount), "auction_id": pi.auction_id,
            "bids_placed": bool(pi.status == "confirmed" and pi.auction_id and not pi.failure_reason),
            "note": pi.failure_reason}


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
        item = {"id": a.id, "title": a.title, "description": a.description, "image_url": a.image_url,
                "market_value": float(a.market_value), "bid_fee": float(a.bid_fee), "max_slots": a.max_slots,
                "filled_slots": int(meta.get("filled", a.filled_slots)), "is_room": a.is_room, "status": a.status,
                "ends_at": iso(a.ends_at), "user_status": None, "user_bids": [],
                "won": bool(u and a.winner_id == u.id),
                "winning_bid": a.lowest_unique_bid if a.status == "ended" else None}  # never exposed while live
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
        if not live:
            item["status"] = "ended" if a.status == "active" else a.status
        out.append(item)
    return out


@app.get("/api/winners")
async def winners(limit: int = Query(20, ge=1, le=100)):
    async with SessionLocal() as s:
        rows = (await s.execute(select(Auction, User.phone_number).join(User, User.id == Auction.winner_id)
                                .where(Auction.status == "ended").order_by(Auction.id.desc()).limit(limit))).all()
    return [{"auction_id": a.id, "title": a.title, "image_url": a.image_url, "market_value": float(a.market_value),
             "bid_fee": float(a.bid_fee), "winning_bid": a.lowest_unique_bid, "winner_masked": mask_phone(ph),
             "winner_city": a.winner_city, "winner_photo_url": a.winner_photo_url,
             "winner_video_url": a.winner_video_url, "winner_quote": a.winner_quote, "is_room": a.is_room,
             "total_bids": a.filled_slots} for a, ph in rows]


class BatchIn(BaseModel):
    bid_amounts: list[int] = Field(min_length=1, max_length=100)


class CheckoutIn(BatchIn):
    provider: str = "chapa"


@app.post("/api/auctions/{aid}/bid-batch")
async def bid_batch(aid: int, b: BatchIn, user: User = Depends(get_current_user)):
    state = {"reserved": False, "padded": []}
    try:
        async with SessionLocal() as s, s.begin():
            res = await place_bids_tx(s, user.id, aid, b.bid_amounts, state)
    except BaseException as e:
        if state["reserved"]:  # Postgres failed or aborted -> release Redis slots so nothing leaks
            await release_slots(aid, state["padded"])
        if isinstance(e, BidError):
            raise HTTPException(e.status, e.msg)
        raise
    await after_bid(res)
    return {"ok": True, "placed": res["placed"], "wallet_balance": res["balance"], "filled_slots": res["filled"]}


@app.post("/api/auctions/{aid}/bid-checkout")
async def bid_checkout(aid: int, b: CheckoutIn, user: User = Depends(get_current_user)):
    """Pay for a bid pack straight from Chapa/Telebirr/CBE. Bids are placed when the payment confirms
    (webhook or status poll); if the room fills first, the ETB stays in the wallet."""
    if b.provider not in PROVIDERS:
        raise HTTPException(400, "Unknown provider")
    try:
        check_amounts(b.bid_amounts)
    except BidError as e:
        raise HTTPException(e.status, e.msg)
    async with SessionLocal() as s:
        a = await s.get(Auction, aid)
    if not a or a.status != "active" or (a.ends_at and a.ends_at <= utcnow()):
        raise HTTPException(409, "Auction closed")
    if a.is_room:
        filled = int((await r.hget(META(aid), "filled")) or a.filled_slots)
        if filled + len(b.bid_amounts) > a.max_slots:
            raise HTTPException(409, "Not enough slots left in this room")
    cost = a.bid_fee * len(b.bid_amounts)
    d = await initiate_chapa_deposit(user, cost, b.provider, auction_id=aid, pending_bids=b.bid_amounts)
    return {**d, "amount": float(cost), "bids": len(b.bid_amounts)}


def origin_ok(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    if not origin:
        return True  # non-browser client
    origin = origin.rstrip("/")
    if ALLOWED_ORIGINS:
        return origin in ALLOWED_ORIGINS
    return DEV_MODE or origin.split("://", 1)[-1] == ws.headers.get("host", "")


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    if not origin_ok(ws):
        await ws.close(code=1008)
        return
    await ws_mgr.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_mgr.drop(ws)
