"""
admin.py - Back-office API for the LowBid platform (mounted by main.py at /api/admin, UI at /admin).

Security model
  * Separate staff accounts (AdminUser); scrypt password hashes; lockout after 5 bad passwords (15 min).
  * Separate token secret (ADMIN_AUTH_SECRET), audience "admin", short lifetime (ADMIN_TOKEN_HOURS, default 8).
    The admin row is re-read on EVERY request, so disabling an account or changing its role takes effect instantly.
  * Role-based permissions (see ROLE_PERMS). Every state-changing action writes an AdminAuditLog row in the SAME
    transaction as the change, so there is never an unaudited money movement.
  * Optional IP allowlist (ADMIN_IP_ALLOWLIST="203.0.113.0/24,198.51.100.7"). Non-allowed IPs get a plain 404.

Money safety
  * Wallet changes lock the user row (SELECT ... FOR UPDATE) and use UNIQUE WalletTransaction.reference keys,
    so refunds / adjustments / payment approvals are idempotent even under double-clicks or retries.
"""
import asyncio
import calendar
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import secrets
from datetime import date, datetime, time as dtime, timedelta, timezone
from decimal import Decimal
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Date, cast, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

import payments
from database import (
    AdminAuditLog, AdminUser, Auction, AuctionOutcome, AuctionStatus, BidLedger, PartnerCommission,
    PaymentIntent, SessionLocal, User, UserFlag, WalletTransaction, engine, get_db, utcnow,
)

log = logging.getLogger("lub.admin")
router = APIRouter(prefix="/api/admin")
hooks: dict = {}  # injected by main.py: redis, finalize, load_auction, broadcast_auction, push_wallet, push_user_statuses, kick_user

DEV_MODE = os.getenv("DEV_MODE", "1") == "1"
ISSUER, AUDIENCE = "lowbid-admin", "admin"
TOKEN_TTL = int(os.getenv("ADMIN_TOKEN_HOURS", "8")) * 3600
TZ_OFFSET = timedelta(hours=int(os.getenv("TZ_OFFSET_HOURS", "3")))  # Addis Ababa = UTC+3 (reports/dashboard days)
MONEY = Decimal("0.01")
MAX_ADJUST = Decimal(os.getenv("ADMIN_MAX_ADJUSTMENT", "100000"))

_secret = os.getenv("ADMIN_AUTH_SECRET", "")
if not _secret:
    if not DEV_MODE:
        raise RuntimeError("ADMIN_AUTH_SECRET must be set when DEV_MODE=0 (and differ from AUTH_SECRET)")
    _secret = "dev-only-admin-secret-do-not-use-in-production"
    log.warning("ADMIN_AUTH_SECRET not set: using an insecure development secret")
elif not DEV_MODE and (len(_secret) < 32 or _secret == os.getenv("AUTH_SECRET", "")):
    raise RuntimeError("ADMIN_AUTH_SECRET must be >= 32 chars and different from AUTH_SECRET")

_nets = []
for part in os.getenv("ADMIN_IP_ALLOWLIST", "").split(","):
    if part.strip():
        _nets.append(ipaddress.ip_network(part.strip(), strict=False))

ALL_PERMS = {
    "dashboard", "auctions:read", "auctions:write", "refunds", "users:read", "users:block", "wallet:adjust",
    "payments:read", "payments:resolve", "ledger:read", "reports:read", "prizes", "audit:read", "admins:manage",
}
ROLE_PERMS = {
    "superadmin": set(ALL_PERMS),
    "operator": {"dashboard", "auctions:read", "auctions:write", "refunds", "users:read", "payments:read", "prizes", "reports:read"},
    "finance": {"dashboard", "auctions:read", "users:read", "payments:read", "payments:resolve", "ledger:read",
                "wallet:adjust", "reports:read", "refunds"},
    "support": {"dashboard", "auctions:read", "users:read", "users:block", "payments:read", "ledger:read"},
}


# ----------------------------------------------------------------------------- helpers
def rds():
    return hooks["redis"]()


def client_ip(request: Optional[Request]) -> Optional[str]:
    return request.client.host if request is not None and request.client else None


def ip_allowed(request: Request) -> bool:
    if not _nets:
        return True
    ip = client_ip(request)
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in n for n in _nets)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        cand = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(cand.hex(), dk)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password("dummy-password-for-timing")


def validate_password(pw: str):
    if len(pw) < 12 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        raise HTTPException(400, "Password must be at least 12 characters and contain letters and digits")


def create_admin_token(admin_id: int) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode({"sub": str(admin_id), "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + TOKEN_TTL},
                      _secret, algorithm="HS256")


def decode_admin_token(token: str):
    try:
        p = jwt.decode(token, _secret, algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE,
                       options={"require": ["exp", "sub", "iat"]})
        return int(p["sub"]), int(p["iat"])
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        return None


async def current_admin(request: Request, authorization: Optional[str] = Header(default=None),
                        db: AsyncSession = Depends(get_db)) -> AdminUser:
    if not ip_allowed(request):
        raise HTTPException(404, "Not found")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Sign in required")
    decoded = decode_admin_token(authorization[7:].strip())
    if not decoded:
        raise HTTPException(401, "Session expired")
    admin = await db.get(AdminUser, decoded[0])
    if not admin or not admin.is_active:
        raise HTTPException(401, "Session expired")
    if admin.password_changed_at and decoded[1] < calendar.timegm(admin.password_changed_at.utctimetuple()):
        raise HTTPException(401, "Session expired")  # password changed after this token was issued
    return admin


def require(perm: str):
    async def dep(admin: AdminUser = Depends(current_admin)) -> AdminUser:
        if perm not in ROLE_PERMS.get(admin.role, set()):
            raise HTTPException(403, "You do not have permission for this action")
        return admin
    return dep


def audit(db: AsyncSession, admin: Optional[AdminUser], action: str, target_type: Optional[str] = None,
          target_id=None, details: Optional[dict] = None, request: Optional[Request] = None, username: str = ""):
    db.add(AdminAuditLog(
        admin_id=admin.id if admin else None, admin_username=admin.username if admin else username,
        action=action, target_type=target_type, target_id=None if target_id is None else str(target_id),
        details=json.dumps(details or {}, default=str)[:4000], ip=client_ip(request), created_at=utcnow(),
    ))


async def rate_limit(key: str, limit: int, window: int):
    r = rds()
    n = await r.incr(key)
    if n == 1:
        await r.expire(key, window)
    if n > limit:
        raise HTTPException(429, "Too many attempts. Try again later")


def pg(page: int = Query(1, ge=1), size: int = Query(25, ge=1, le=100)):
    return page, size


async def paginate(db: AsyncSession, stmt, page: int, size: int):
    total = (await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar_one()
    rows = (await db.execute(stmt.limit(size).offset((page - 1) * size))).all()
    return total, rows


def iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() if d else None


def f(x) -> float:
    return float(x or 0)


def day_expr(col):
    """Local (UTC+offset) calendar day of a UTC timestamp column."""
    if engine.dialect.name == "postgresql":
        return cast(col + TZ_OFFSET, Date)
    return func.date(func.datetime(col, f"+{int(TZ_OFFSET.total_seconds() // 3600)} hours"))


def local_day_start(d: date) -> datetime:
    return datetime.combine(d, dtime.min) - TZ_OFFSET


def parse_day(s: Optional[str], default: date) -> date:
    if not s:
        return default
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise HTTPException(400, "Dates must be YYYY-MM-DD")


def clean_q(q: Optional[str]) -> str:
    return re.sub(r"[^\d+]", "", q or "")


# ----------------------------------------------------------------------------- auth endpoints
class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


def admin_dict(a: AdminUser) -> dict:
    return {"id": a.id, "username": a.username, "role": a.role, "is_active": a.is_active,
            "last_login_at": iso(a.last_login_at), "created_at": iso(a.created_at),
            "perms": sorted(ROLE_PERMS.get(a.role, set()))}


@router.post("/login")
async def login(body: LoginBody, request: Request, db: AsyncSession = Depends(get_db)):
    if not ip_allowed(request):
        raise HTTPException(404, "Not found")
    await rate_limit(f"rl:adm-login-ip:{client_ip(request)}", 20, 900)
    username = body.username.strip().lower()
    admin = (await db.execute(select(AdminUser).where(AdminUser.username == username))).scalar_one_or_none()
    if not admin or not admin.is_active:
        check_password(body.password, _DUMMY_HASH)  # equalize timing
        audit(db, None, "login_failed", "admin", username, {"reason": "unknown or inactive"}, request, username[:32])
        await db.commit()
        raise HTTPException(401, "Invalid credentials")
    if admin.locked_until and admin.locked_until > utcnow():
        raise HTTPException(429, "Account temporarily locked. Try again later")
    if not check_password(body.password, admin.password_hash):
        admin.failed_logins += 1
        if admin.failed_logins >= 5:
            admin.locked_until = utcnow() + timedelta(minutes=15)
            admin.failed_logins = 0
        audit(db, admin, "login_failed", "admin", admin.id, {}, request)
        await db.commit()
        raise HTTPException(401, "Invalid credentials")
    admin.failed_logins, admin.locked_until, admin.last_login_at = 0, None, utcnow()
    audit(db, admin, "login", "admin", admin.id, {}, request)
    await db.commit()
    return {"token": create_admin_token(admin.id), "admin": admin_dict(admin)}


@router.get("/me")
async def me(admin: AdminUser = Depends(current_admin)):
    return admin_dict(admin)


@router.post("/change-password")
async def change_password(body: PasswordBody, request: Request, admin: AdminUser = Depends(current_admin),
                          db: AsyncSession = Depends(get_db)):
    if not check_password(body.current_password, admin.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    validate_password(body.new_password)
    admin.password_hash = hash_password(body.new_password)
    admin.password_changed_at = utcnow()
    audit(db, admin, "password_changed", "admin", admin.id, {}, request)
    await db.commit()
    return {"ok": True, "token": create_admin_token(admin.id)}


# ----------------------------------------------------------------------------- dashboard
async def sum_tx(db, kind: str, since: Optional[datetime] = None) -> Decimal:
    stmt = select(func.coalesce(func.sum(WalletTransaction.amount), 0)).where(WalletTransaction.kind == kind)
    if since:
        stmt = stmt.where(WalletTransaction.created_at >= since)
    return Decimal(str((await db.execute(stmt)).scalar_one()))


@router.get("/dashboard")
async def dashboard(admin: AdminUser = Depends(require("dashboard")), db: AsyncSession = Depends(get_db)):
    today = (utcnow() + TZ_OFFSET).date()
    start = local_day_start(today)
    status_counts = dict((await db.execute(select(Auction.status, func.count()).group_by(Auction.status))).all())
    pay_counts = dict((await db.execute(select(PaymentIntent.status, func.count()).group_by(PaymentIntent.status))).all())
    users_total = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    users_today = (await db.execute(select(func.count()).select_from(User).where(User.created_at >= start))).scalar_one()
    liabilities = (await db.execute(select(func.coalesce(func.sum(User.wallet_balance), 0)))).scalar_one()
    commissions = (await db.execute(select(func.coalesce(func.sum(PartnerCommission.amount), 0)))).scalar_one()

    since = local_day_start(today - timedelta(days=13))
    day = day_expr(WalletTransaction.created_at)
    rows = (await db.execute(
        select(day, WalletTransaction.kind, func.sum(WalletTransaction.amount))
        .where(WalletTransaction.created_at >= since, WalletTransaction.kind.in_(["deposit", "bid_purchase"]))
        .group_by(day, WalletTransaction.kind)
    )).all()
    series = {(today - timedelta(days=i)).isoformat(): {"date": (today - timedelta(days=i)).isoformat(), "deposits": 0.0, "bids": 0.0}
              for i in range(13, -1, -1)}
    for d, kind, total in rows:
        key = d.isoformat() if isinstance(d, date) else str(d)
        if key in series:
            series[key]["deposits" if kind == "deposit" else "bids"] += abs(f(total))

    return {
        "users_total": users_total, "users_today": users_today,
        "deposits_total": f(await sum_tx(db, "deposit")), "deposits_today": f(await sum_tx(db, "deposit", start)),
        "bids_total": -f(await sum_tx(db, "bid_purchase")), "bids_today": -f(await sum_tx(db, "bid_purchase", start)),
        "fees_total": -f(await sum_tx(db, "platform_fee")), "refunds_total": f(await sum_tx(db, "refund")),
        "commissions_total": f(commissions), "wallet_liabilities": f(liabilities),
        "rooms_active": status_counts.get(AuctionStatus.active, 0),
        "rooms_calculating": status_counts.get(AuctionStatus.calculating, 0),
        "rooms_ended": status_counts.get(AuctionStatus.ended, 0),
        "payments_pending": pay_counts.get("pending", 0), "payments_review": pay_counts.get("review", 0),
        "series": list(series.values()), "tz_offset_hours": int(TZ_OFFSET.total_seconds() // 3600),
    }


# ----------------------------------------------------------------------------- rooms
async def live_map(ids: list) -> dict:
    if not ids:
        return {}
    pipe = rds().pipeline()
    for i in ids:
        pipe.hmget(f"auction:{i}", "status", "filled_slots", "pending")
    out = {}
    for i, v in zip(ids, await pipe.execute()):
        out[i] = {"status": v[0], "filled": int(v[1]) if v[1] is not None else None, "pending": int(v[2] or 0)}
    return out


def auction_dict(a: Auction, live: Optional[dict] = None) -> dict:
    live = live or {}
    return {
        "id": a.id, "title": a.title, "description": a.description, "market_value": f(a.market_value),
        "bid_fee": f(a.bid_fee), "max_slots": a.max_slots,
        "filled_slots": live.get("filled") if live.get("filled") is not None else a.filled_slots,
        "status": live.get("status") or a.status.value, "ends_at": iso(a.ends_at),
        "winner_id": a.winner_id, "lowest_unique_bid": None if a.lowest_unique_bid is None else int(a.lowest_unique_bid),
    }


class AuctionCreate(BaseModel):
    title: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)
    market_value: Decimal = Field(gt=0, le=1_000_000_000)
    bid_fee: Decimal = Field(gt=0, le=100_000)
    max_slots: int = Field(ge=2, le=100_000)
    ends_at: datetime

    @field_validator("ends_at")
    @classmethod
    def _ends(cls, v: datetime):
        if v.tzinfo is not None:
            v = v.astimezone(timezone.utc).replace(tzinfo=None)
        if v < utcnow() + timedelta(minutes=5) or v > utcnow() + timedelta(days=90):
            raise ValueError("ends_at must be between 5 minutes and 90 days from now")
        return v


class ReasonBody(BaseModel):
    reason: str = Field(min_length=5, max_length=200)


@router.get("/auctions")
async def list_auctions(admin: AdminUser = Depends(require("auctions:read")), db: AsyncSession = Depends(get_db)):
    auctions = (await db.execute(select(Auction).order_by(Auction.id.desc()).limit(200))).scalars().all()
    live = await live_map([a.id for a in auctions])
    return [auction_dict(a, live.get(a.id)) for a in auctions]


@router.post("/auctions")
async def create_auction(body: AuctionCreate, request: Request, admin: AdminUser = Depends(require("auctions:write")),
                         db: AsyncSession = Depends(get_db)):
    a = Auction(title=body.title.strip(), description=body.description.strip(),
                market_value=body.market_value.quantize(MONEY), bid_fee=body.bid_fee.quantize(MONEY),
                max_slots=body.max_slots, filled_slots=0, status=AuctionStatus.active, ends_at=body.ends_at)
    db.add(a)
    await db.flush()
    audit(db, admin, "auction_created", "auction", a.id,
          {"title": a.title, "max_slots": a.max_slots, "bid_fee": str(a.bid_fee), "ends_at": a.ends_at}, request)
    await db.commit()
    await hooks["load_auction"](a, db)
    await hooks["broadcast_auction"](a.id)
    return auction_dict(a)


@router.get("/auctions/{aid}")
async def auction_detail(aid: int, admin: AdminUser = Depends(require("auctions:read")), db: AsyncSession = Depends(get_db)):
    a = await db.get(Auction, aid)
    if not a:
        raise HTTPException(404, "Room not found")
    live = (await live_map([aid])).get(aid)

    def tx_sum(kind):
        return select(func.coalesce(func.sum(WalletTransaction.amount), 0)).where(
            WalletTransaction.auction_id == aid, WalletTransaction.kind == kind)

    bids = (await db.execute(select(func.count()).select_from(BidLedger).where(BidLedger.auction_id == aid))).scalar_one()
    players = (await db.execute(select(func.count(func.distinct(BidLedger.user_id))).where(BidLedger.auction_id == aid))).scalar_one()
    commissions = (await db.execute(select(func.coalesce(func.sum(PartnerCommission.amount), 0)).where(PartnerCommission.auction_id == aid))).scalar_one()
    outcome = await db.get(AuctionOutcome, aid)
    winner_phone = None
    if a.winner_id:
        winner_phone = (await db.execute(select(User.phone_number).where(User.id == a.winner_id))).scalar_one_or_none()
    return {
        **auction_dict(a, live), "bids": bids, "players": players,
        "bid_revenue": -f((await db.execute(tx_sum("bid_purchase"))).scalar_one()),
        "fees": -f((await db.execute(tx_sum("platform_fee"))).scalar_one()),
        "refunded": f((await db.execute(tx_sum("refund"))).scalar_one()), "commissions": f(commissions),
        "pending_bids": (live or {}).get("pending", 0), "winner_phone": winner_phone,
        "outcome": outcome.outcome if outcome else None, "outcome_note": outcome.note if outcome else "",
        "refunded_at": iso(outcome.refunded_at) if outcome else None,
        "prize_status": (outcome.prize_status or "pending") if (outcome and a.winner_id) else ("pending" if a.winner_id else None),
        "prize_note": outcome.prize_note if outcome else "",
    }


@router.post("/auctions/{aid}/close")
async def close_auction(aid: int, request: Request, admin: AdminUser = Depends(require("auctions:write")),
                        db: AsyncSession = Depends(get_db)):
    a = await db.get(Auction, aid)
    if not a:
        raise HTTPException(404, "Room not found")
    status = ((await live_map([aid])).get(aid) or {}).get("status") or a.status.value
    if status != "active":
        raise HTTPException(409, f"Room is {status}, only active rooms can be closed")
    audit(db, admin, "auction_closed_early", "auction", aid, {}, request)
    await db.commit()
    await hooks["finalize"](aid, force=True)
    return {"ok": True}


async def refund_auction(aid: int, admin: AdminUser, reason: str, cancel: bool, request: Request) -> dict:
    """Refund every player's net payments (bid cost + platform fee) for a room. Idempotent and fully audited."""
    r = rds()
    lock, key = f"auction:{aid}:finalizing", f"auction:{aid}"
    if not await r.set(lock, "1", nx=True, ex=120):
        raise HTTPException(409, "Room is being processed, try again in a moment")
    prior_status = await r.hget(key, "status")
    try:
        if cancel and prior_status == "active":
            await r.hset(key, "status", "calculating")  # freeze: no new bids
        for _ in range(100):
            if int(await r.hget(key, "pending") or 0) <= 0:
                break
            await asyncio.sleep(0.05)
        else:
            if cancel and prior_status == "active":
                await r.hset(key, "status", "active")
            raise HTTPException(409, "Bids are still being processed, try again in a moment")

        affected, total = [], Decimal("0")
        async with SessionLocal() as db:
            a = (await db.execute(select(Auction).where(Auction.id == aid).with_for_update())).scalar_one_or_none()
            if not a:
                raise HTTPException(404, "Room not found")
            outcome = await db.get(AuctionOutcome, aid)
            if outcome and outcome.refunded_at:
                raise HTTPException(409, "This room has already been refunded")
            if cancel and a.status == AuctionStatus.ended:
                raise HTTPException(409, "Room has already ended; use refund if nobody won")
            if not cancel and not (a.status == AuctionStatus.ended and a.winner_id is None):
                raise HTTPException(409, "Refunds are only allowed for ended rooms with no winner")

            rows = (await db.execute(
                select(WalletTransaction.user_id, func.sum(WalletTransaction.amount))
                .where(WalletTransaction.auction_id == aid,
                       WalletTransaction.kind.in_(["bid_purchase", "platform_fee", "refund"]))
                .group_by(WalletTransaction.user_id)
            )).all()
            for uid, s in rows:
                due = -Decimal(str(s))
                if due <= 0:
                    continue
                user = (await db.execute(select(User).where(User.id == uid).with_for_update())).scalar_one()
                user.wallet_balance = Decimal(user.wallet_balance) + due
                db.add(WalletTransaction(user_id=uid, kind="refund", amount=due, balance_after=user.wallet_balance,
                                         reference=f"refund:{aid}:{uid}", auction_id=aid))
                affected.append((uid, user.wallet_balance))
                total += due
            comm = (await db.execute(
                select(PartnerCommission.user_id, func.sum(PartnerCommission.amount))
                .where(PartnerCommission.auction_id == aid).group_by(PartnerCommission.user_id)
            )).all()
            for uid, s in comm:
                if Decimal(str(s)) > 0:
                    db.add(PartnerCommission(auction_id=aid, user_id=uid, amount=-Decimal(str(s))))
            if cancel:
                a.status, a.winner_id, a.lowest_unique_bid = AuctionStatus.ended, None, None
            kind = "cancelled" if cancel else "no_winner_refunded"
            if outcome:
                outcome.outcome, outcome.note, outcome.refunded_at, outcome.updated_at = kind, reason, utcnow(), utcnow()
            else:
                db.add(AuctionOutcome(auction_id=aid, outcome=kind, note=reason, refunded_at=utcnow(), updated_at=utcnow()))
            audit(db, admin, "auction_cancelled" if cancel else "auction_refunded", "auction", aid,
                  {"reason": reason, "players": len(affected), "total": str(total)}, request)
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                raise HTTPException(409, "Refund already processed")
        if cancel:
            await r.hset(key, mapping={"status": "ended", "cancelled": "1", "winner_id": 0, "lowest_unique_bid": 0})
        for uid, bal in affected:
            await hooks["push_wallet"](uid, bal)
        await hooks["broadcast_auction"](aid)
        await hooks["push_user_statuses"](aid)
        return {"ok": True, "players_refunded": len(affected), "total_refunded": float(total)}
    finally:
        await r.delete(lock)


@router.post("/auctions/{aid}/cancel")
async def cancel_auction(aid: int, body: ReasonBody, request: Request, admin: AdminUser = Depends(require("refunds"))):
    return await refund_auction(aid, admin, body.reason.strip(), True, request)


@router.post("/auctions/{aid}/refund")
async def refund_no_winner(aid: int, body: ReasonBody, request: Request, admin: AdminUser = Depends(require("refunds"))):
    return await refund_auction(aid, admin, body.reason.strip(), False, request)


class PrizeBody(BaseModel):
    status: str = Field(pattern="^(pending|delivered)$")
    note: str = Field(default="", max_length=200)


@router.post("/auctions/{aid}/prize")
async def set_prize(aid: int, body: PrizeBody, request: Request, admin: AdminUser = Depends(require("prizes")),
                    db: AsyncSession = Depends(get_db)):
    a = await db.get(Auction, aid)
    if not a or not a.winner_id:
        raise HTTPException(404, "Room has no winner")
    outcome = await db.get(AuctionOutcome, aid)
    if outcome:
        outcome.prize_status, outcome.prize_note, outcome.updated_at = body.status, body.note.strip(), utcnow()
    else:
        db.add(AuctionOutcome(auction_id=aid, prize_status=body.status, prize_note=body.note.strip(), updated_at=utcnow()))
    audit(db, admin, "prize_status", "auction", aid, {"status": body.status, "note": body.note}, request)
    await db.commit()
    return {"ok": True}


@router.get("/prizes")
async def list_prizes(status: Optional[str] = None, admin: AdminUser = Depends(require("prizes")),
                      db: AsyncSession = Depends(get_db), p=Depends(pg)):
    stmt = (select(Auction, User.phone_number, AuctionOutcome)
            .join(User, User.id == Auction.winner_id)
            .outerjoin(AuctionOutcome, AuctionOutcome.auction_id == Auction.id)
            .where(Auction.winner_id.is_not(None)).order_by(Auction.id.desc()))
    if status in ("pending", "delivered"):
        stmt = stmt.where((AuctionOutcome.prize_status == status) if status == "delivered"
                          else (AuctionOutcome.prize_status.is_(None) | (AuctionOutcome.prize_status == "pending")))
    total, rows = await paginate(db, stmt, *p)
    return {"total": total, "items": [{
        "auction_id": a.id, "title": a.title, "market_value": f(a.market_value), "winning_bid": int(a.lowest_unique_bid or 0),
        "winner_id": a.winner_id, "winner_phone": phone, "ended_at": iso(a.ends_at),
        "prize_status": (o.prize_status if o and o.prize_status else "pending"), "prize_note": o.prize_note if o else "",
    } for a, phone, o in rows]}


# ----------------------------------------------------------------------------- players
def user_dict(u: User, blocked: bool = False, reason: str = "") -> dict:
    return {"id": u.id, "phone_number": u.phone_number, "wallet_balance": f(u.wallet_balance),
            "is_verified": u.is_verified, "created_at": iso(u.created_at), "blocked": bool(blocked), "block_reason": reason or ""}


@router.get("/users")
async def list_users(q: Optional[str] = None, admin: AdminUser = Depends(require("users:read")),
                     db: AsyncSession = Depends(get_db), p=Depends(pg)):
    stmt = select(User, UserFlag.blocked, UserFlag.reason).outerjoin(UserFlag, UserFlag.user_id == User.id).order_by(User.id.desc())
    term = clean_q(q)
    if term:
        cond = User.phone_number.contains(term)
        stmt = stmt.where(cond | (User.id == int(term))) if term.isdigit() and len(term) < 9 else stmt.where(cond)
    total, rows = await paginate(db, stmt, *p)
    return {"total": total, "items": [user_dict(u, b, r) for u, b, r in rows]}


@router.get("/users/{uid}")
async def user_detail(uid: int, admin: AdminUser = Depends(require("users:read")), db: AsyncSession = Depends(get_db)):
    u = await db.get(User, uid)
    if not u:
        raise HTTPException(404, "Player not found")
    flag = await db.get(UserFlag, uid)
    txs = (await db.execute(select(WalletTransaction).where(WalletTransaction.user_id == uid)
                            .order_by(WalletTransaction.id.desc()).limit(30))).scalars().all()
    bids = (await db.execute(
        select(BidLedger.auction_id, Auction.title, func.count(), func.min(BidLedger.timestamp))
        .join(Auction, Auction.id == BidLedger.auction_id).where(BidLedger.user_id == uid)
        .group_by(BidLedger.auction_id, Auction.title).order_by(BidLedger.auction_id.desc()).limit(30))).all()
    pays = (await db.execute(select(PaymentIntent).where(PaymentIntent.user_id == uid)
                             .order_by(PaymentIntent.id.desc()).limit(20))).scalars().all()
    return {
        "user": user_dict(u, flag.blocked if flag else False, flag.reason if flag else ""),
        "transactions": [{"id": t.id, "kind": t.kind, "amount": f(t.amount), "balance_after": f(t.balance_after),
                          "reference": t.reference, "auction_id": t.auction_id, "created_at": iso(t.created_at)} for t in txs],
        "bids": [{"auction_id": a, "title": title, "count": c, "first_at": iso(ts)} for a, title, c, ts in bids],
        "payments": [{"tx_ref": p.tx_ref, "amount": f(p.amount), "status": p.status, "created_at": iso(p.created_at)} for p in pays],
    }


async def set_blocked(uid: int, blocked: bool, reason: str, request: Request, admin: AdminUser, db: AsyncSession):
    u = await db.get(User, uid)
    if not u:
        raise HTTPException(404, "Player not found")
    flag = await db.get(UserFlag, uid)
    if flag:
        flag.blocked, flag.reason, flag.updated_by, flag.updated_at = blocked, reason, admin.username, utcnow()
    else:
        db.add(UserFlag(user_id=uid, blocked=blocked, reason=reason, updated_by=admin.username, updated_at=utcnow()))
    audit(db, admin, "user_blocked" if blocked else "user_unblocked", "user", uid, {"reason": reason}, request)
    await db.commit()
    r = rds()
    if blocked:
        await r.sadd("blocked_users", str(uid))
        await hooks["kick_user"](uid)
    else:
        await r.srem("blocked_users", str(uid))
    return {"ok": True}


@router.post("/users/{uid}/block")
async def block_user(uid: int, body: ReasonBody, request: Request, admin: AdminUser = Depends(require("users:block")),
                     db: AsyncSession = Depends(get_db)):
    return await set_blocked(uid, True, body.reason.strip(), request, admin, db)


@router.post("/users/{uid}/unblock")
async def unblock_user(uid: int, body: ReasonBody, request: Request, admin: AdminUser = Depends(require("users:block")),
                       db: AsyncSession = Depends(get_db)):
    return await set_blocked(uid, False, body.reason.strip(), request, admin, db)


class AdjustBody(BaseModel):
    amount: Decimal
    reason: str = Field(min_length=5, max_length=200)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9_-]{8,48}$")

    @field_validator("amount")
    @classmethod
    def _amt(cls, v: Decimal):
        if v == 0 or abs(v) > MAX_ADJUST:
            raise ValueError(f"amount must be non-zero and at most {MAX_ADJUST}")
        return v.quantize(MONEY)


@router.post("/users/{uid}/adjust")
async def adjust_wallet(uid: int, body: AdjustBody, request: Request, admin: AdminUser = Depends(require("wallet:adjust")),
                        db: AsyncSession = Depends(get_db)):
    ref = f"adj:{body.idempotency_key}"
    if (await db.execute(select(WalletTransaction.id).where(WalletTransaction.reference == ref))).first():
        return {"ok": True, "duplicate": True}
    user = (await db.execute(select(User).where(User.id == uid).with_for_update())).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Player not found")
    new_balance = Decimal(user.wallet_balance) + body.amount
    if new_balance < 0:
        raise HTTPException(400, "Adjustment would make the balance negative")
    user.wallet_balance = new_balance
    db.add(WalletTransaction(user_id=uid, kind="admin_adjust", amount=body.amount, balance_after=new_balance, reference=ref))
    audit(db, admin, "wallet_adjusted", "user", uid, {"amount": str(body.amount), "reason": body.reason, "balance_after": str(new_balance)}, request)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return {"ok": True, "duplicate": True}
    await hooks["push_wallet"](uid, new_balance)
    return {"ok": True, "balance": float(new_balance)}


# ----------------------------------------------------------------------------- payments
def payment_dict(p: PaymentIntent, phone: Optional[str] = None) -> dict:
    return {"tx_ref": p.tx_ref, "user_id": p.user_id, "phone": phone, "amount": f(p.amount), "currency": p.currency,
            "status": p.status, "chapa_reference": p.chapa_reference, "failure_reason": p.failure_reason,
            "created_at": iso(p.created_at), "completed_at": iso(p.completed_at)}


@router.get("/payments")
async def list_payments(status: Optional[str] = None, q: Optional[str] = None,
                        admin: AdminUser = Depends(require("payments:read")), db: AsyncSession = Depends(get_db), p=Depends(pg)):
    stmt = select(PaymentIntent, User.phone_number).join(User, User.id == PaymentIntent.user_id).order_by(PaymentIntent.id.desc())
    if status in ("pending", "success", "failed", "expired", "review"):
        stmt = stmt.where(PaymentIntent.status == status)
    if q and q.strip():
        term = q.strip()[:64]
        stmt = stmt.where(PaymentIntent.tx_ref.contains(term) | User.phone_number.contains(clean_q(term) or "~"))
    total, rows = await paginate(db, stmt, *p)
    return {"total": total, "items": [payment_dict(i, phone) for i, phone in rows]}


@router.post("/payments/{tx_ref}/recheck")
async def recheck_payment(tx_ref: str, request: Request, admin: AdminUser = Depends(require("payments:read")),
                          db: AsyncSession = Depends(get_db)):
    intent = (await db.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref))).scalar_one_or_none()
    if not intent:
        raise HTTPException(404, "Payment not found")
    if intent.status == "expired":
        intent.status = "pending"  # Chapa may have completed it after our 24h window
    elif intent.status != "pending":
        raise HTTPException(409, f"Payment is already {intent.status}")
    audit(db, admin, "payment_recheck", "payment", tx_ref, {}, request)
    await db.commit()
    try:
        result = await payments.settle_intent(tx_ref)
    except payments.ChapaError as exc:
        raise HTTPException(502, f"Chapa could not be reached: {exc}")
    return {"status": result.status if result else "unknown"}


class ResolveBody(BaseModel):
    action: str = Field(pattern="^(approve|reject)$")
    note: str = Field(min_length=5, max_length=160)


@router.post("/payments/{tx_ref}/resolve")
async def resolve_payment(tx_ref: str, body: ResolveBody, request: Request,
                          admin: AdminUser = Depends(require("payments:resolve")), db: AsyncSession = Depends(get_db)):
    intent = (await db.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref).with_for_update())).scalar_one_or_none()
    if not intent:
        raise HTTPException(404, "Payment not found")
    if intent.status != "review":
        raise HTTPException(409, "Only payments flagged for review can be resolved")
    credited = None
    if body.action == "approve":
        user = (await db.execute(select(User).where(User.id == intent.user_id).with_for_update())).scalar_one()
        user.wallet_balance = Decimal(user.wallet_balance) + Decimal(intent.amount)
        db.add(WalletTransaction(user_id=user.id, kind="deposit", amount=intent.amount, balance_after=user.wallet_balance,
                                 reference=tx_ref, provider="chapa"))
        intent.status, intent.completed_at = "success", utcnow()
        intent.failure_reason = f"approved by {admin.username}: {body.note}"[:200]
        credited = (user.id, user.wallet_balance)
    else:
        intent.status = "failed"
        intent.failure_reason = f"rejected by {admin.username}: {body.note}"[:200]
    audit(db, admin, f"payment_{body.action}", "payment", tx_ref, {"note": body.note, "amount": str(intent.amount)}, request)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Payment was already credited")
    if credited:
        await hooks["push_wallet"](*credited)
    return {"status": intent.status}


# ----------------------------------------------------------------------------- ledger + reports
def ledger_stmt(kind, user_id, auction_id, date_from, date_to, q):
    stmt = select(WalletTransaction, User.phone_number).join(User, User.id == WalletTransaction.user_id).order_by(WalletTransaction.id.desc())
    if kind:
        stmt = stmt.where(WalletTransaction.kind == kind)
    if user_id:
        stmt = stmt.where(WalletTransaction.user_id == user_id)
    if auction_id:
        stmt = stmt.where(WalletTransaction.auction_id == auction_id)
    if date_from:
        stmt = stmt.where(WalletTransaction.created_at >= local_day_start(parse_day(date_from, date.today())))
    if date_to:
        stmt = stmt.where(WalletTransaction.created_at < local_day_start(parse_day(date_to, date.today())) + timedelta(days=1))
    if q and q.strip():
        stmt = stmt.where(WalletTransaction.reference.contains(q.strip()[:80]))
    return stmt


def tx_dict(t: WalletTransaction, phone: str) -> dict:
    return {"id": t.id, "user_id": t.user_id, "phone": phone, "kind": t.kind, "amount": f(t.amount),
            "balance_after": f(t.balance_after), "reference": t.reference, "provider": t.provider,
            "auction_id": t.auction_id, "created_at": iso(t.created_at)}


@router.get("/ledger")
async def ledger(kind: Optional[str] = None, user_id: Optional[int] = None, auction_id: Optional[int] = None,
                 date_from: Optional[str] = None, date_to: Optional[str] = None, q: Optional[str] = None,
                 admin: AdminUser = Depends(require("ledger:read")), db: AsyncSession = Depends(get_db), p=Depends(pg)):
    total, rows = await paginate(db, ledger_stmt(kind, user_id, auction_id, date_from, date_to, q), *p)
    return {"total": total, "items": [tx_dict(t, phone) for t, phone in rows]}


def csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # block spreadsheet formula injection


@router.get("/ledger/export.csv")
async def ledger_export(request: Request, kind: Optional[str] = None, user_id: Optional[int] = None,
                        auction_id: Optional[int] = None, date_from: Optional[str] = None, date_to: Optional[str] = None,
                        q: Optional[str] = None, admin: AdminUser = Depends(require("ledger:read")),
                        db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(ledger_stmt(kind, user_id, auction_id, date_from, date_to, q).limit(50000))).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_at_utc", "user_id", "phone", "kind", "amount_etb", "balance_after_etb", "reference", "provider", "auction_id"])
    for t, phone in rows:
        d = tx_dict(t, phone)
        w.writerow([csv_safe(d[k]) for k in ("id", "created_at", "user_id", "phone", "kind", "amount", "balance_after", "reference", "provider", "auction_id")])
    audit(db, admin, "ledger_export", "ledger", None, {"rows": len(rows), "kind": kind, "from": date_from, "to": date_to}, request)
    await db.commit()
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="ledger-{utcnow():%Y%m%d-%H%M}.csv"'})


@router.get("/reports/summary")
async def report_summary(date_from: Optional[str] = None, date_to: Optional[str] = None,
                         admin: AdminUser = Depends(require("reports:read")), db: AsyncSession = Depends(get_db)):
    today = (utcnow() + TZ_OFFSET).date()
    d_to = parse_day(date_to, today)
    d_from = parse_day(date_from, d_to - timedelta(days=29))
    if d_from > d_to or (d_to - d_from).days > 366:
        raise HTTPException(400, "Invalid date range (max 366 days)")
    start, end = local_day_start(d_from), local_day_start(d_to) + timedelta(days=1)
    day = day_expr(WalletTransaction.created_at)
    rows = (await db.execute(
        select(day, WalletTransaction.kind, func.sum(WalletTransaction.amount))
        .where(WalletTransaction.created_at >= start, WalletTransaction.created_at < end).group_by(day, WalletTransaction.kind)
    )).all()
    days: dict = {}
    for d, kind, total in rows:
        key = d.isoformat() if isinstance(d, date) else str(d)
        days.setdefault(key, {"date": key, "deposits": 0.0, "bids": 0.0, "fees": 0.0, "refunds": 0.0, "adjustments": 0.0})
        col = {"deposit": "deposits", "bid_purchase": "bids", "platform_fee": "fees", "refund": "refunds", "admin_adjust": "adjustments"}.get(kind)
        if col:
            days[key][col] += f(total) if col in ("deposits", "refunds", "adjustments") else -f(total)
    comm_day = day_expr(PartnerCommission.created_at)
    comm_by_day = dict((str(d), f(s)) for d, s in (await db.execute(
        select(comm_day, func.sum(PartnerCommission.amount))
        .where(PartnerCommission.created_at >= start, PartnerCommission.created_at < end).group_by(comm_day))).all())
    for key, row in days.items():
        row["commissions"] = comm_by_day.get(key, 0.0)
    by_room = (await db.execute(
        select(Auction.id, Auction.title, func.sum(PartnerCommission.amount))
        .join(Auction, Auction.id == PartnerCommission.auction_id)
        .where(PartnerCommission.created_at >= start, PartnerCommission.created_at < end)
        .group_by(Auction.id, Auction.title).order_by(Auction.id.desc()))).all()
    ordered = [days[k] for k in sorted(days)]
    totals = {k: round(sum(r[k] for r in ordered), 2) for k in ("deposits", "bids", "fees", "refunds", "adjustments", "commissions")}
    return {"from": d_from.isoformat(), "to": d_to.isoformat(), "days": ordered, "totals": totals,
            "commissions_by_room": [{"auction_id": i, "title": t, "commission": f(s)} for i, t, s in by_room]}


# ----------------------------------------------------------------------------- audit + admin accounts
@router.get("/audit")
async def audit_log(action: Optional[str] = None, admin_name: Optional[str] = None,
                    admin: AdminUser = Depends(require("audit:read")), db: AsyncSession = Depends(get_db), p=Depends(pg)):
    stmt = select(AdminAuditLog).order_by(AdminAuditLog.id.desc())
    if action:
        stmt = stmt.where(AdminAuditLog.action == action[:48])
    if admin_name:
        stmt = stmt.where(AdminAuditLog.admin_username == admin_name.strip().lower()[:32])
    total, rows = await paginate(db, stmt, *p)
    return {"total": total, "items": [{"id": r.id, "admin": r.admin_username, "action": r.action, "target_type": r.target_type,
                                       "target_id": r.target_id, "details": r.details, "ip": r.ip, "created_at": iso(r.created_at)}
                                      for (r,) in rows]}


class AdminCreate(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9_.-]{3,32}$")
    password: str = Field(max_length=256)
    role: str = Field(pattern="^(superadmin|operator|finance|support)$")


class AdminUpdate(BaseModel):
    role: Optional[str] = Field(default=None, pattern="^(superadmin|operator|finance|support)$")
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, max_length=256)


@router.get("/admins")
async def list_admins(admin: AdminUser = Depends(require("admins:manage")), db: AsyncSession = Depends(get_db)):
    return [admin_dict(a) for a in (await db.execute(select(AdminUser).order_by(AdminUser.id))).scalars().all()]


@router.post("/admins")
async def create_admin(body: AdminCreate, request: Request, admin: AdminUser = Depends(require("admins:manage")),
                       db: AsyncSession = Depends(get_db)):
    validate_password(body.password)
    if (await db.execute(select(AdminUser.id).where(AdminUser.username == body.username))).first():
        raise HTTPException(409, "Username already exists")
    a = AdminUser(username=body.username, password_hash=hash_password(body.password), role=body.role, password_changed_at=utcnow())
    db.add(a)
    await db.flush()
    audit(db, admin, "admin_created", "admin", a.id, {"username": a.username, "role": a.role}, request)
    await db.commit()
    return admin_dict(a)


@router.patch("/admins/{aid}")
async def update_admin(aid: int, body: AdminUpdate, request: Request, admin: AdminUser = Depends(require("admins:manage")),
                       db: AsyncSession = Depends(get_db)):
    a = await db.get(AdminUser, aid)
    if not a:
        raise HTTPException(404, "Admin not found")
    if a.id == admin.id and (body.role not in (None, a.role) or body.is_active is False):
        raise HTTPException(400, "You cannot change your own role or deactivate yourself")
    changes = {}
    if body.role and body.role != a.role:
        changes["role"] = body.role
        a.role = body.role
    if body.is_active is not None and body.is_active != a.is_active:
        changes["is_active"] = body.is_active
        a.is_active = body.is_active
    if body.password:
        validate_password(body.password)
        a.password_hash, a.password_changed_at, a.failed_logins, a.locked_until = hash_password(body.password), utcnow(), 0, None
        changes["password"] = "reset"
    await db.flush()
    active_supers = (await db.execute(select(func.count()).select_from(AdminUser).where(
        AdminUser.role == "superadmin", AdminUser.is_active.is_(True)))).scalar_one()
    if active_supers < 1:
        await db.rollback()
        raise HTTPException(400, "At least one active superadmin is required")
    audit(db, admin, "admin_updated", "admin", a.id, changes, request)
    await db.commit()
    return admin_dict(a)
