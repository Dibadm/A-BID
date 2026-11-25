import os, hashlib, secrets, hmac, uuid, asyncio, datetime as dt
from decimal import Decimal
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Header, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy import select, func, update, delete
from database import (SessionLocal, User, UserFlag, Auction, BidLedger, WalletTransaction, PaymentIntent,
                      PartnerCommission, AdminUser, AdminAuditLog, utcnow)
from auth import DEV_MODE, JWT_SECRET, require_secret
import payments

router = APIRouter(prefix="/api/admin")
SECRET = require_secret("ADMIN_JWT_SECRET", "dev-only-admin-secret-never-use-in-production")
if not DEV_MODE and SECRET == JWT_SECRET:
    raise RuntimeError("ADMIN_JWT_SECRET must differ from JWT_SECRET")
ALLOWED_IPS = [x.strip() for x in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if x.strip()]
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"  # set to 1 only when behind exactly one trusted proxy (e.g. Render)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_UPLOAD = 15 * 1024 * 1024
UPLOAD_TYPES = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp",
                ".mp4": "video/mp4", ".webm": "video/webm"}
ROLES = ("superadmin", "operator", "finance", "support")
AREAS = {"read": set(ROLES), "auctions": {"superadmin", "operator"}, "finance": {"superadmin", "finance"},
         "users": {"superadmin", "support"}, "prize": {"superadmin", "operator", "support"},
         "media": {"superadmin", "operator", "support"}}


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def check_password(pw: str, stored: str) -> bool:
    try:
        salt_hex, h_hex = stored.split("$")
        h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def client_ip(req: Request) -> str:
    if TRUST_PROXY:
        xff = req.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[-1].strip()  # the entry appended by our own proxy, not client-supplied
    return req.client.host if req.client else ""


def ip_guard(req: Request):
    if ALLOWED_IPS and client_ip(req) not in ALLOWED_IPS:
        raise HTTPException(403, "IP not allowed")


async def current_admin(req: Request, authorization: str | None = Header(default=None)) -> dict:
    ip_guard(req)
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Admin login required")
    try:
        d = jwt.decode(authorization[7:], SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Session expired")
    async with SessionLocal() as s:
        a = (await s.execute(select(AdminUser).where(AdminUser.username == d["sub"]))).scalar_one_or_none()
    if not a or not a.is_active:
        raise HTTPException(401, "Account disabled")
    return {"username": a.username, "role": a.role, "ip": client_ip(req)}


def need(area: str):
    async def dep(adm: dict = Depends(current_admin)):
        if adm["role"] not in AREAS[area]:
            raise HTTPException(403, f"Role '{adm['role']}' cannot do this")
        return adm
    return dep


def audit(s, adm: dict, action: str, detail: str = ""):
    s.add(AdminAuditLog(admin_username=adm["username"], action=action, detail=detail, ip=adm["ip"]))


def f(x): return float(x or 0)
def iso(d): return d.isoformat() + "Z" if d else None


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(b: LoginIn, req: Request):
    ip_guard(req)
    err, token, role = None, None, None
    async with SessionLocal() as s, s.begin():
        a = (await s.execute(select(AdminUser).where(AdminUser.username == b.username).with_for_update())).scalar_one_or_none()
        if not a or not a.is_active:
            err = (401, "Invalid credentials")
        elif a.locked_until and a.locked_until > utcnow():
            err = (423, "Account temporarily locked. Try again later.")
        elif not check_password(b.password, a.password_hash):
            a.failed_logins += 1
            if a.failed_logins >= 5:
                a.locked_until, a.failed_logins = utcnow() + dt.timedelta(minutes=15), 0
            s.add(AdminAuditLog(admin_username=a.username, action="login_failed", ip=client_ip(req)))
            err = (401, "Invalid credentials")
        else:
            a.failed_logins, a.locked_until = 0, None
            s.add(AdminAuditLog(admin_username=a.username, action="login", ip=client_ip(req)))
            token = jwt.encode({"sub": a.username, "exp": utcnow() + dt.timedelta(hours=8)}, SECRET, algorithm="HS256")
            role = a.role
    if err:
        raise HTTPException(*err)
    return {"token": token, "username": b.username, "role": role}


@router.get("/stats")
async def stats(adm=Depends(need("read"))):
    async with SessionLocal() as s:
        one = lambda q: s.scalar(q)
        return {
            "bid_revenue": f(await one(select(func.sum(BidLedger.fee_charged)))),
            "bids_total": await one(select(func.count(BidLedger.id))) or 0,
            "platform_fees": f(await one(select(func.sum(PartnerCommission.platform_fee)))),
            "partner_share": f(await one(select(func.sum(PartnerCommission.partner_share)))),
            "deposits": f(await one(select(func.sum(WalletTransaction.amount)).where(WalletTransaction.kind == "deposit"))),
            "wallet_liability": f(await one(select(func.sum(User.wallet_balance)))),
            "users": await one(select(func.count(User.id))) or 0,
            "active_rooms": await one(select(func.count(Auction.id)).where(Auction.status == "active", Auction.is_room.is_(True))) or 0,
            "active_items": await one(select(func.count(Auction.id)).where(Auction.status == "active", Auction.is_room.is_(False))) or 0,
            "pending_prizes": await one(select(func.count(Auction.id)).where(Auction.status == "ended", Auction.winner_id.is_not(None), Auction.prize_status != "delivered")) or 0,
            "pending_payments": await one(select(func.count(PaymentIntent.id)).where(PaymentIntent.status == "pending")) or 0}


# ---------- media ----------
def clean_url(v):
    v = (v or "").strip()
    if not v:
        return None
    if len(v) > 500 or ".." in v or not (v.startswith("/uploads/") or v.startswith("https://")):
        raise HTTPException(400, "URLs must start with /uploads/ or https://")
    return v


def sniff(ext: str, head: bytes) -> bool:
    if ext in (".jpg", ".jpeg"): return head[:3] == b"\xff\xd8\xff"
    if ext == ".png": return head[:8] == b"\x89PNG\r\n\x1a\n"
    if ext == ".webp": return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if ext == ".mp4": return head[4:8] == b"ftyp"
    if ext == ".webm": return head[:4] == b"\x1a\x45\xdf\xa3"
    return False


def _write(path: str, data: bytes):
    with open(path, "wb") as fh:
        fh.write(data)


@router.post("/upload")
async def upload(request: Request, file: UploadFile = File(...), adm=Depends(need("media"))):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in UPLOAD_TYPES:
        raise HTTPException(400, "Allowed types: jpg, png, webp, mp4, webm")
    if int(request.headers.get("content-length") or 0) > MAX_UPLOAD + 1024 * 1024:
        raise HTTPException(413, "File too large (max 15 MB)")
    buf = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_UPLOAD:
            raise HTTPException(413, "File too large (max 15 MB)")
    if not buf or not sniff(ext, bytes(buf[:16])):
        raise HTTPException(400, "File content does not match its extension")
    name = f"{uuid.uuid4().hex}{ext}"
    await asyncio.to_thread(_write, os.path.join(UPLOAD_DIR, name), bytes(buf))
    async with SessionLocal() as s, s.begin():
        audit(s, adm, "upload", f"{name} ({len(buf)} bytes)")
    return {"url": "/uploads/" + name, "size": len(buf), "content_type": UPLOAD_TYPES[ext]}


class MediaIn(BaseModel):
    image_url: str | None = None
    winner_photo_url: str | None = None
    winner_video_url: str | None = None
    winner_quote: str | None = Field(default=None, max_length=500)
    winner_city: str | None = Field(default=None, max_length=80)


# ---------- auctions ----------
class AuctionIn(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str = ""
    market_value: Decimal = Field(gt=0)
    bid_fee: Decimal = Field(gt=0)
    max_slots: int = Field(gt=0, le=1_000_000)
    is_room: bool = False
    ends_at: dt.datetime | None = None
    image_url: str | None = None


def naive_utc(d: dt.datetime | None):
    if d and d.tzinfo:
        return d.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return d


def aout(a: Auction):
    return {"id": a.id, "title": a.title, "market_value": f(a.market_value), "bid_fee": f(a.bid_fee),
            "max_slots": a.max_slots, "filled_slots": a.filled_slots, "is_room": a.is_room, "status": a.status,
            "lowest_unique_bid": a.lowest_unique_bid, "winner_id": a.winner_id, "prize_status": a.prize_status,
            "ends_at": iso(a.ends_at), "image_url": a.image_url, "winner_photo_url": a.winner_photo_url,
            "winner_video_url": a.winner_video_url, "winner_quote": a.winner_quote, "winner_city": a.winner_city}


@router.get("/auctions")
async def auctions(adm=Depends(need("read"))):
    async with SessionLocal() as s:
        return [aout(a) for a in (await s.execute(select(Auction).order_by(Auction.id.desc()))).scalars()]


@router.post("/auctions")
async def create_auction(b: AuctionIn, adm=Depends(need("auctions"))):
    import main as m
    if not b.is_room and not b.ends_at:
        raise HTTPException(400, "Open items need an end time")
    async with SessionLocal() as s, s.begin():
        a = Auction(title=b.title, description=b.description, market_value=b.market_value, bid_fee=b.bid_fee,
                    max_slots=b.max_slots, is_room=b.is_room, ends_at=naive_utc(b.ends_at), image_url=clean_url(b.image_url))
        s.add(a)
        await s.flush()
        audit(s, adm, "auction_create", f"#{a.id} {a.title} room={a.is_room}")
    async with SessionLocal() as s:
        await m.rebuild_redis(s, await s.get(Auction, a.id))
    await m.ws_mgr.broadcast({"type": "closed", "auction_id": a.id})
    return aout(a)


@router.post("/prizes/{aid}/media")
async def set_media(aid: int, b: MediaIn, adm=Depends(need("media"))):
    """Attach product photo (image_url) and winner proof (photo, video, quote, city). Only supplied fields change; '' clears."""
    async with SessionLocal() as s, s.begin():
        a = await s.get(Auction, aid)
        if not a:
            raise HTTPException(404, "Not found")
        for k in b.model_fields_set:
            v = getattr(b, k)
            setattr(a, k, clean_url(v) if k.endswith("_url") else ((v or "").strip() or None))
        audit(s, adm, "auction_media", f"#{aid} fields={sorted(b.model_fields_set)}")
        return aout(a)


@router.post("/auctions/{aid}/toggle-room")
async def toggle_room(aid: int, adm=Depends(need("auctions"))):
    import main as m
    async with SessionLocal() as s, s.begin():
        a = await s.get(Auction, aid)
        if not a: raise HTTPException(404, "Not found")
        if a.status != "active": raise HTTPException(409, "Only active auctions can change type")
        new = not a.is_room
        if new and a.filled_slots >= a.max_slots: raise HTTPException(409, "Already at capacity; cannot become a room")
        if not new and not a.ends_at: raise HTTPException(409, "Set an end time before converting to an open item")
        a.is_room = new
        audit(s, adm, "auction_toggle_room", f"#{aid} is_room={new}")
    await m.r.hset(m.META(aid), "is_room", "1" if new else "0")
    await m.ws_mgr.broadcast({"type": "closed", "auction_id": aid})
    return {"id": aid, "is_room": new}


@router.post("/auctions/{aid}/close")
async def close_auction(aid: int, adm=Depends(need("auctions"))):
    import main as m
    async with SessionLocal() as s:
        a = await s.get(Auction, aid)
    if not a or a.status != "active": raise HTTPException(409, "Auction is not active")
    await m.resolve(aid)
    async with SessionLocal() as s, s.begin():
        audit(s, adm, "auction_close", f"#{aid}")
        a = await s.get(Auction, aid)
    return aout(a)


async def refund_all(s, aid: int) -> tuple[int, Decimal]:
    rows = (await s.execute(select(BidLedger.user_id, func.sum(BidLedger.fee_charged)).where(
        BidLedger.auction_id == aid).group_by(BidLedger.user_id))).all()
    n, total = 0, Decimal("0")
    for uid, amt in rows:
        ref = f"refund-{aid}-{uid}"
        if (await s.execute(select(WalletTransaction.id).where(WalletTransaction.reference == ref))).first():
            continue  # already refunded (idempotent)
        u = (await s.execute(select(User).where(User.id == uid).with_for_update())).scalar_one()
        u.wallet_balance = u.wallet_balance + amt
        s.add(WalletTransaction(user_id=uid, kind="refund", amount=amt, balance_after=u.wallet_balance,
                                reference=ref, note=f"Refund for auction #{aid}"))
        n += 1
        total += amt
    return n, total


@router.post("/auctions/{aid}/cancel")
async def cancel_auction(aid: int, adm=Depends(need("auctions"))):
    import main as m
    async with SessionLocal() as s:
        a = await s.get(Auction, aid)
    if not a: raise HTTPException(404, "Not found")
    if a.status != "active": raise HTTPException(409, "Only active auctions can be cancelled")
    await m.r.hset(m.META(aid), "status", "ended")  # stop new reservations first
    try:
        async with SessionLocal() as s, s.begin():
            # Waits for in-flight bids; any bid arriving later fails its status fence, so no bid can be missed.
            claimed = (await s.execute(update(Auction).where(Auction.id == aid, Auction.status == "active")
                                       .values(status="cancelled").returning(Auction.id))).first()
            if not claimed: raise HTTPException(409, "Auction is no longer active")
            n, total = await refund_all(s, aid)
            await s.execute(delete(PartnerCommission).where(PartnerCommission.auction_id == aid))
            audit(s, adm, "auction_cancel", f"#{aid} refunded {n} users, {total} ETB")
    except BaseException:
        try:  # reopen Redis only if the database still says active
            async with SessionLocal() as s2:
                cur = await s2.get(Auction, aid)
            if cur and cur.status == "active":
                await m.r.hset(m.META(aid), "status", "active")
        except Exception:
            pass
        raise
    await m.ws_mgr.broadcast({"type": "closed", "auction_id": aid})
    return {"ok": True, "users_refunded": n, "total_refunded": float(total)}


@router.post("/auctions/{aid}/refund")
async def refund_auction(aid: int, adm=Depends(need("finance"))):
    """Refund every bidder of a cancelled auction, or of an ended auction that had no winner."""
    async with SessionLocal() as s, s.begin():
        a = (await s.execute(select(Auction).where(Auction.id == aid).with_for_update())).scalar_one_or_none()
        if not a: raise HTTPException(404, "Not found")
        if not (a.status == "cancelled" or (a.status == "ended" and a.winner_id is None)):
            raise HTTPException(409, "Refund only for cancelled auctions or ended auctions without a winner")
        n, total = await refund_all(s, aid)
        await s.execute(delete(PartnerCommission).where(PartnerCommission.auction_id == aid))
        audit(s, adm, "auction_refund", f"#{aid} refunded {n} users, {total} ETB")
    return {"ok": True, "users_refunded": n, "total_refunded": float(total)}


# ---------- prizes ----------
class PrizeIn(BaseModel):
    status: str


@router.get("/prizes")
async def prizes(adm=Depends(need("read"))):
    async with SessionLocal() as s:
        rows = (await s.execute(select(Auction, User.phone_number).join(User, User.id == Auction.winner_id)
                                .where(Auction.status == "ended").order_by(Auction.id.desc()))).all()
    return [{**aout(a), "winner_phone": ph} for a, ph in rows]


@router.post("/auctions/{aid}/prize")
async def set_prize(aid: int, b: PrizeIn, adm=Depends(need("prize"))):
    if b.status not in ("pending", "contacted", "delivered"): raise HTTPException(400, "Bad status")
    async with SessionLocal() as s, s.begin():
        a = await s.get(Auction, aid)
        if not a or a.winner_id is None: raise HTTPException(404, "No winner for this auction")
        a.prize_status = b.status
        audit(s, adm, "prize_status", f"#{aid} -> {b.status}")
    return {"ok": True}


# ---------- commissions ----------
@router.get("/commissions")
async def commissions(adm=Depends(need("read"))):
    async with SessionLocal() as s:
        rows = (await s.execute(select(PartnerCommission.auction_id, Auction.title, func.count(PartnerCommission.id),
                                       func.sum(PartnerCommission.platform_fee), func.sum(PartnerCommission.partner_share))
                                .join(Auction, Auction.id == PartnerCommission.auction_id)
                                .group_by(PartnerCommission.auction_id, Auction.title)
                                .order_by(PartnerCommission.auction_id.desc()))).all()
    return [{"auction_id": i, "title": t, "bids": c, "platform_fee": f(p), "partner_share": f(sh)} for i, t, c, p, sh in rows]


# ---------- users ----------
class BlockIn(BaseModel):
    blocked: bool
    reason: str = ""


class AdjustIn(BaseModel):
    amount: Decimal
    reason: str = Field(min_length=3)


@router.get("/users")
async def users(q: str = "", adm=Depends(need("read"))):
    async with SessionLocal() as s:
        qq = select(User, UserFlag.blocked).outerjoin(UserFlag, UserFlag.user_id == User.id).order_by(User.id.desc()).limit(100)
        if q.strip():
            qq = qq.where(User.phone_number.contains(q.strip()))
        rows = (await s.execute(qq)).all()
    return [{"id": u.id, "phone_number": u.phone_number, "wallet_balance": f(u.wallet_balance), "blocked": bool(bl),
             "created_at": iso(u.created_at)} for u, bl in rows]


@router.post("/users/{uid}/block")
async def block_user(uid: int, b: BlockIn, adm=Depends(need("users"))):
    async with SessionLocal() as s, s.begin():
        if not await s.get(User, uid): raise HTTPException(404, "Not found")
        fl = await s.get(UserFlag, uid)
        if not fl:
            fl = UserFlag(user_id=uid)
            s.add(fl)
        fl.blocked, fl.reason, fl.updated_by, fl.updated_at = b.blocked, b.reason, adm["username"], utcnow()
        audit(s, adm, "user_block" if b.blocked else "user_unblock", f"user {uid}: {b.reason}")
    return {"ok": True}


@router.post("/users/{uid}/adjust")
async def adjust_wallet(uid: int, b: AdjustIn, adm=Depends(need("finance"))):
    if b.amount == 0: raise HTTPException(400, "Amount cannot be zero")
    async with SessionLocal() as s, s.begin():
        u = (await s.execute(select(User).where(User.id == uid).with_for_update())).scalar_one_or_none()
        if not u: raise HTTPException(404, "Not found")
        if u.wallet_balance + b.amount < 0: raise HTTPException(409, "Balance cannot go negative")
        u.wallet_balance = u.wallet_balance + b.amount
        s.add(WalletTransaction(user_id=uid, kind="admin_adjust", amount=b.amount, balance_after=u.wallet_balance,
                                reference=f"adj-{secrets.token_hex(8)}", note=b.reason))
        audit(s, adm, "wallet_adjust", f"user {uid}: {b.amount} ETB ({b.reason})")
        bal = f(u.wallet_balance)
    return {"ok": True, "wallet_balance": bal}


# ---------- payments ----------
@router.get("/payments")
async def payments_list(status: str = "", adm=Depends(need("read"))):
    async with SessionLocal() as s:
        qq = select(PaymentIntent, User.phone_number).join(User, User.id == PaymentIntent.user_id).order_by(PaymentIntent.id.desc()).limit(100)
        if status: qq = qq.where(PaymentIntent.status == status)
        rows = (await s.execute(qq)).all()
    return [{"id": p.id, "phone": ph, "provider": p.provider, "tx_ref": p.tx_ref, "amount": f(p.amount),
             "status": p.status, "failure_reason": p.failure_reason, "auction_id": p.auction_id,
             "created_at": iso(p.created_at)} for p, ph in rows]


@router.post("/payments/{pid}/approve")
async def approve_payment(pid: int, adm=Depends(need("finance"))):
    """Credits the wallet and, for a bid-checkout, places the pending bids (same safe-fallback as the webhook)."""
    async with SessionLocal() as s:
        p = await s.get(PaymentIntent, pid)
    if not p: raise HTTPException(404, "Not found")
    if p.status == "confirmed": raise HTTPException(409, "Already confirmed")
    out = await payments.confirm_payment(p.tx_ref, allow_failed=True)
    async with SessionLocal() as s, s.begin():
        audit(s, adm, "payment_approve", f"{p.tx_ref} {p.amount} ETB bids_placed={out['bids_placed']}")
    return {"ok": True, **out}


@router.post("/payments/{pid}/reject")
async def reject_payment(pid: int, adm=Depends(need("finance"))):
    async with SessionLocal() as s, s.begin():
        p = (await s.execute(select(PaymentIntent).where(PaymentIntent.id == pid).with_for_update())).scalar_one_or_none()
        if not p: raise HTTPException(404, "Not found")
        if p.status != "pending": raise HTTPException(409, "Only pending payments can be rejected")
        p.status, p.failure_reason = "failed", f"rejected by {adm['username']}"
        audit(s, adm, "payment_reject", p.tx_ref)
    return {"ok": True}


@router.post("/payments/{pid}/recheck")
async def recheck_payment(pid: int, adm=Depends(need("finance"))):
    async with SessionLocal() as s:
        p = await s.get(PaymentIntent, pid)
    if not p: raise HTTPException(404, "Not found")
    if p.status == "pending":
        verdict = await payments.verify_with_provider(p.tx_ref, p.provider)  # STUB until you implement it
        if verdict == "success":
            await payments.confirm_payment(p.tx_ref)
        elif verdict == "failed":
            await payments.mark_failed(p.tx_ref, None, "provider reported failure")
    async with SessionLocal() as s:
        p = await s.get(PaymentIntent, pid)
    return {"status": p.status, "note": "Provider verification is a STUB until payments.verify_with_provider is implemented."}


@router.get("/audit")
async def audit_log(adm=Depends(need("read"))):
    async with SessionLocal() as s:
        rows = (await s.execute(select(AdminAuditLog).order_by(AdminAuditLog.id.desc()).limit(200))).scalars().all()
    return [{"id": r.id, "admin": r.admin_username, "action": r.action, "detail": r.detail, "ip": r.ip, "at": iso(r.created_at)} for r in rows]
