import os, hashlib, secrets, datetime as dt
from decimal import Decimal
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update, func, desc, text
from database import (SessionLocal, AdminUser, AdminAuditLog, User, UserFlag, Auction, BidLedger,
                      WalletTransaction, PaymentIntent, PartnerCommission, utcnow)
from auth import JWT_SECRET, DEV_MODE
import jwt

router = APIRouter(prefix="/api/admin", tags=["admin"])

ADMIN_JWT_SECRET = os.getenv("ADMIN_JWT_SECRET", JWT_SECRET)
ADMIN_ALLOWED_IPS = [ip.strip() for ip in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if ip.strip()]
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

ROLE_PERMS = {
    "superadmin": ["stats", "auctions", "prizes", "users", "payments", "manage_admins"],
    "operator": ["stats", "auctions", "prizes", "users"],
    "finance": ["stats", "payments", "users"],
    "support": ["stats", "users"],
}

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return salt.hex() + "$" + dk.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def make_admin_token(admin_id: int, username: str, role: str) -> str:
    exp = dt.datetime.utcnow() + dt.timedelta(hours=8)
    return jwt.encode({"sub": str(admin_id), "username": username, "role": role, "exp": exp}, ADMIN_JWT_SECRET, algorithm="HS256")

async def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def log_audit(admin_username: str, action: str, detail: str | None, ip: str):
    async with SessionLocal() as s, s.begin():
        s.add(AdminAuditLog(admin_username=admin_username, action=action, detail=detail, ip=ip))

async def check_admin_perms(admin: AdminUser, required: str) -> bool:
    perms = ROLE_PERMS.get(admin.role, [])
    return required in perms or admin.role == "superadmin"

async def get_current_admin(
    authorization: str | None = Header(default=None),
    request: Request = None
) -> AdminUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Admin authentication required")
    
    if ADMIN_ALLOWED_IPS:
        ip = await get_client_ip(request)
        if ip not in ADMIN_ALLOWED_IPS:
            raise HTTPException(403, "IP not allowed")
    
    try:
        payload = jwt.decode(authorization[7:], ADMIN_JWT_SECRET, algorithms=["HS256"])
        admin_id = int(payload["sub"])
        role = payload.get("role", "support")
    except Exception:
        raise HTTPException(401, "Invalid or expired admin token")
    
    async with SessionLocal() as s:
        admin = await s.get(AdminUser, admin_id)
        if not admin or not admin.is_active:
            raise HTTPException(401, "Admin not found or inactive")
        if admin.locked_until and admin.locked_until > utcnow():
            raise HTTPException(403, "Admin account locked")
    return admin

class AdminLoginIn(BaseModel):
    username: str
    password: str

@router.post("/login")
async def admin_login(body: AdminLoginIn, request: Request):
    ip = await get_client_ip(request)
    async with SessionLocal() as s, s.begin():
        admin = (await s.execute(select(AdminUser).where(AdminUser.username == body.username))).scalar_one_or_none()
        if not admin:
            await log_audit(body.username, "login_failed", "user not found", ip)
            raise HTTPException(401, "Invalid credentials")
        if admin.locked_until and admin.locked_until > utcnow():
            await log_audit(admin.username, "login_failed", "account locked", ip)
            raise HTTPException(403, "Account locked")
        if not verify_password(body.password, admin.password_hash):
            admin.failed_logins += 1
            if admin.failed_logins >= MAX_FAILED_LOGINS:
                admin.locked_until = utcnow() + dt.timedelta(minutes=LOCKOUT_MINUTES)
            await log_audit(admin.username, "login_failed", "bad password", ip)
            raise HTTPException(401, "Invalid credentials")
        admin.failed_logins = 0
        admin.locked_until = None
        await log_audit(admin.username, "login_success", None, ip)
    token = make_admin_token(admin.id, admin.username, admin.role)
    return {"token": token, "role": admin.role, "username": admin.username}

def require_perm(permission: str):
    async def dep(admin: AdminUser = Depends(get_current_admin)):
        if not await check_admin_perms(admin, permission):
            raise HTTPException(403, f"Requires {permission} permission")
        return admin
    return dep

# ---------- Stats ----------
@router.get("/stats")
async def admin_stats(admin: AdminUser = Depends(require_perm("stats"))):
    async with SessionLocal() as s:
        total_bid_revenue = (await s.execute(select(func.coalesce(func.sum(BidLedger.fee_charged), 0)))).scalar() or 0
        total_bids = (await s.execute(select(func.count(BidLedger.id)))).scalar() or 0
        platform_fees = (await s.execute(select(func.coalesce(func.sum(PartnerCommission.platform_fee), 0)))).scalar() or 0
        partner_shares = (await s.execute(select(func.coalesce(func.sum(PartnerCommission.partner_share), 0)))).scalar() or 0
        total_deposits = (await s.execute(select(func.coalesce(func.sum(WalletTransaction.amount), 0)).where(WalletTransaction.kind == "deposit"))).scalar() or 0
        wallet_liability = (await s.execute(select(func.coalesce(func.sum(User.wallet_balance), 0)))).scalar() or 0
        active_rooms = (await s.execute(select(func.count(Auction.id)).where(Auction.status == "active", Auction.is_room == True))).scalar() or 0
        active_items = (await s.execute(select(func.count(Auction.id)).where(Auction.status == "active", Auction.is_room == False))).scalar() or 0
        pending_prizes = (await s.execute(select(func.count(Auction.id)).where(Auction.status == "ended", Auction.winner_id.is_not(None), Auction.prize_status == "pending"))).scalar() or 0
    return {
        "total_bid_revenue": float(total_bid_revenue),
        "total_bids_cast": total_bids,
        "platform_fees_collected": float(platform_fees),
        "partner_shares_accrued": float(partner_shares),
        "total_deposits": float(total_deposits),
        "wallet_liability": float(wallet_liability),
        "active_flash_rooms": active_rooms,
        "active_bidded_items": active_items,
        "pending_prizes": pending_prizes,
    }

# ---------- Auctions ----------
class AuctionCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    market_value: Decimal = Field(gt=0)
    bid_fee: Decimal = Field(gt=0)
    max_slots: int = Field(gt=0)
    is_room: bool = False
    ends_at: dt.datetime | None = None
    image_url: str | None = None

class AuctionToggle(BaseModel):
    is_room: bool

@router.get("/auctions")
async def admin_auctions(
    admin: AdminUser = Depends(require_perm("auctions")),
    status: str | None = Query(None),
    is_room: bool | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0)
):
    async with SessionLocal() as s:
        q = select(Auction).order_by(desc(Auction.id))
        if status:
            q = q.where(Auction.status == status)
        if is_room is not None:
            q = q.where(Auction.is_room == is_room)
        q = q.limit(limit).offset(offset)
        auctions = (await s.execute(q)).scalars().all()
    return [{"id": a.id, "title": a.title, "description": a.description, "market_value": float(a.market_value),
             "bid_fee": float(a.bid_fee), "max_slots": a.max_slots, "filled_slots": a.filled_slots,
             "is_room": a.is_room, "status": a.status, "ends_at": a.ends_at.isoformat() + "Z" if a.ends_at else None,
             "image_url": a.image_url, "lowest_unique_bid": a.lowest_unique_bid, "winner_id": a.winner_id,
             "prize_status": a.prize_status, "created_at": a.created_at.isoformat() + "Z"} for a in auctions]

@router.post("/auctions")
async def admin_create_auction(body: AuctionCreate, admin: AdminUser = Depends(require_perm("auctions")), request: Request = None):
    async with SessionLocal() as s, s.begin():
        a = Auction(**body.model_dump())
        s.add(a)
        await s.flush()
        await log_audit(admin.username, "auction_create", f"id={a.id} title={a.title}", await get_client_ip(request))
    return {"id": a.id, "message": "Auction created"}

@router.post("/auctions/{aid}/toggle-room")
async def admin_toggle_room(aid: int, body: AuctionToggle, admin: AdminUser = Depends(require_perm("auctions")), request: Request = None):
    async with SessionLocal() as s, s.begin():
        a = await s.get(Auction, aid)
        if not a: raise HTTPException(404, "Auction not found")
        a.is_room = body.is_room
        await log_audit(admin.username, "auction_toggle_room", f"id={aid} is_room={body.is_room}", await get_client_ip(request))
    return {"ok": True}

@router.post("/auctions/{aid}/close")
async def admin_close_auction(aid: int, admin: AdminUser = Depends(require_perm("auctions")), request: Request = None):
    from main import resolve
    await resolve(aid)
    await log_audit(admin.username, "auction_close", f"id={aid}", await get_client_ip(request))
    return {"ok": True}

@router.post("/auctions/{aid}/refund")
async def admin_refund_auction(aid: int, admin: AdminUser = Depends(require_perm("auctions")), request: Request = None):
    from main import r, META, CNT, LUA_ROLLBACK
    async with SessionLocal() as s, s.begin():
        a = await s.get(Auction, aid)
        if not a: raise HTTPException(404, "Auction not found")
        if a.status != "active":
            raise HTTPException(409, "Only active auctions can be refunded")
        bids = (await s.execute(select(BidLedger).where(BidLedger.auction_id == aid))).scalars().all()
        if not bids:
            a.status = "cancelled"
            await log_audit(admin.username, "auction_refund", f"id={aid} no bids", await get_client_ip(request))
            return {"ok": True, "refunded": 0}
        user_ids = [b.user_id for b in bids]
        amounts = [b.bid_amount for b in bids]
        fees = [b.fee_charged for b in bids]
        for b in bids:
            await s.delete(b)
        u = (await s.execute(select(User).where(User.id.in_(user_ids)).with_for_update())).scalars().all()
        for user in u:
            user_bids = [b for b in bids if b.user_id == user.id]
            refund = sum(b.fee_charged for b in user_bids)
            user.wallet_balance += refund
            s.add(WalletTransaction(user_id=user.id, kind="refund", amount=refund, balance_after=user.wallet_balance, reference=f"refund-auction-{aid}"))
        await s.execute(update(Auction).where(Auction.id == aid).values(status="cancelled"))
        padded = [str(x).zfill(8) for x in amounts]
        await r.eval(LUA_ROLLBACK, 2, META(aid), CNT(aid), *padded)
        await log_audit(admin.username, "auction_refund", f"id={aid} users={user_ids}", await get_client_ip(request))
    return {"ok": True, "refunded": len(bids)}

# ---------- Prizes ----------
@router.get("/prizes")
async def admin_prizes(admin: AdminUser = Depends(require_perm("prizes")), status: str = Query("pending")):
    async with SessionLocal() as s:
        q = select(Auction).where(Auction.status == "ended", Auction.winner_id.is_not(None))
        if status != "all":
            q = q.where(Auction.prize_status == status)
        q = q.order_by(desc(Auction.id))
        auctions = (await s.execute(q)).scalars().all()
    out = []
    for a in auctions:
        winner = await s.get(User, a.winner_id)
        out.append({"auction_id": a.id, "title": a.title, "market_value": float(a.market_value),
                    "lowest_unique_bid": a.lowest_unique_bid, "winner_id": a.winner_id,
                    "winner_phone": winner.phone_number if winner else "unknown",
                    "prize_status": a.prize_status, "ends_at": a.ends_at.isoformat() + "Z" if a.ends_at else None})
    return out

class PrizeUpdate(BaseModel):
    prize_status: str = Field(pattern="^(pending|contacted|delivered)$")

@router.post("/prizes/{aid}")
async def admin_update_prize(aid: int, body: PrizeUpdate, admin: AdminUser = Depends(require_perm("prizes")), request: Request = None):
    async with SessionLocal() as s, s.begin():
        a = await s.get(Auction, aid)
        if not a: raise HTTPException(404, "Auction not found")
        a.prize_status = body.prize_status
        await log_audit(admin.username, "prize_update", f"id={aid} status={body.prize_status}", await get_client_ip(request))
    return {"ok": True}

# ---------- Users ----------
@router.get("/users")
async def admin_users(
    admin: AdminUser = Depends(require_perm("users")),
    q: str = Query(""),
    blocked: bool | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0)
):
    async with SessionLocal() as s:
        query = select(User).order_by(desc(User.id))
        if q:
            query = query.where(User.phone_number.ilike(f"%{q}%"))
        if blocked is not None:
            query = query.join(UserFlag, User.id == UserFlag.user_id, isouter=True).where(UserFlag.blocked == blocked)
        query = query.limit(limit).offset(offset)
        users = (await s.execute(query)).scalars().all()
    out = []
    for u in users:
        flag = await s.get(UserFlag, u.id)
        out.append({"id": u.id, "phone_number": u.phone_number, "wallet_balance": float(u.wallet_balance),
                    "is_verified": u.is_verified, "blocked": flag.blocked if flag else False,
                    "blocked_reason": flag.reason if flag else None, "created_at": u.created_at.isoformat() + "Z"})
    return out

class BlockUser(BaseModel):
    blocked: bool
    reason: str | None = None

@router.post("/users/{uid}/block")
async def admin_block_user(uid: int, body: BlockUser, admin: AdminUser = Depends(require_perm("users")), request: Request = None):
    async with SessionLocal() as s, s.begin():
        u = await s.get(User, uid)
        if not u: raise HTTPException(404, "User not found")
        flag = await s.get(UserFlag, uid)
        if not flag:
            flag = UserFlag(user_id=uid)
            s.add(flag)
        flag.blocked = body.blocked
        flag.reason = body.reason
        flag.updated_by = admin.username
        flag.updated_at = utcnow()
        await log_audit(admin.username, "user_block", f"id={uid} blocked={body.blocked}", await get_client_ip(request))
    return {"ok": True}

class WalletAdjust(BaseModel):
    amount: Decimal
    note: str = "admin adjustment"

@router.post("/users/{uid}/adjust-wallet")
async def admin_adjust_wallet(uid: int, body: WalletAdjust, admin: AdminUser = Depends(require_perm("users")), request: Request = None):
    async with SessionLocal() as s, s.begin():
        u = await s.get(User, uid)
        if not u: raise HTTPException(404, "User not found")
        u = (await s.execute(select(User).where(User.id == uid).with_for_update())).scalar_one()
        u.wallet_balance = u.wallet_balance + body.amount
        ref = f"adj-{admin.username}-{dt.datetime.utcnow().timestamp()}"
        s.add(WalletTransaction(user_id=uid, kind="admin_adjust", amount=body.amount, balance_after=u.wallet_balance, reference=ref))
        await log_audit(admin.username, "wallet_adjust", f"id={uid} amount={body.amount} note={body.note}", await get_client_ip(request))
    return {"ok": True, "new_balance": float(u.wallet_balance)}

# ---------- Payments ----------
@router.get("/payments")
async def admin_payments(
    admin: AdminUser = Depends(require_perm("payments")),
    status: str = Query("pending"),
    provider: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0)
):
    async with SessionLocal() as s:
        query = select(PaymentIntent).order_by(desc(PaymentIntent.created_at))
        if status != "all":
            query = query.where(PaymentIntent.status == status)
        if provider:
            query = query.where(PaymentIntent.provider == provider)
        query = query.limit(limit).offset(offset)
        payments = (await s.execute(query)).scalars().all()
    out = []
    for p in payments:
        user = await s.get(User, p.user_id)
        out.append({"id": p.id, "tx_ref": p.tx_ref, "provider": p.provider, "amount": float(p.amount),
                    "status": p.status, "failure_reason": p.failure_reason, "user_id": p.user_id,
                    "user_phone": user.phone_number if user else "unknown", "created_at": p.created_at.isoformat() + "Z"})
    return out

class PaymentResolve(BaseModel):
    action: str = Field(pattern="^(approve|reject)$")
    reason: str | None = None

@router.post("/payments/{tx_ref}/resolve")
async def admin_resolve_payment(tx_ref: str, body: PaymentResolve, admin: AdminUser = Depends(require_perm("payments")), request: Request = None):
    async with SessionLocal() as s, s.begin():
        pi = (await s.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref).with_for_update())).scalar_one_or_none()
        if not pi: raise HTTPException(404, "Payment intent not found")
        if pi.status != "pending":
            raise HTTPException(409, "Already resolved")
        if body.action == "approve":
            from payments import process_wallet_deposit
            await process_wallet_deposit(s, pi.user_id, pi.amount, f"pi-{pi.tx_ref}")
            pi.status = "confirmed"
        else:
            pi.status = "failed"
            pi.failure_reason = body.reason or "manually rejected by admin"
        await log_audit(admin.username, "payment_resolve", f"tx_ref={tx_ref} action={body.action}", await get_client_ip(request))
    return {"ok": True}