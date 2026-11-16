"""
database.py - Asynchronous persistent layer (PostgreSQL via SQLAlchemy 2.0 async + asyncpg).

Holds long-term data only: users, wallet ledger, auction audit records.
Live game state (counters, uniqueness) lives in Redis (see main.py).
"""
import enum
import os
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/lub_auction"
)

_engine_kwargs = {} if DATABASE_URL.startswith("sqlite") else dict(pool_size=20, max_overflow=40, pool_pre_ping=True)
engine = create_async_engine(DATABASE_URL, echo=False, **_engine_kwargs)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def utcnow() -> datetime:
    """Naive UTC timestamp (matches DateTime columns without timezone)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class AuctionStatus(str, enum.Enum):
    active = "active"
    calculating = "calculating"
    ended = "ended"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    phone_number: Mapped[str] = mapped_column(String(20), index=True, unique=True)
    wallet_balance: Mapped[float] = mapped_column(Numeric(10, 2), default=0, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class Auction(Base):
    __tablename__ = "auctions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    market_value: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)
    bid_fee: Mapped[float] = mapped_column(Numeric(10, 2), default=10, nullable=False)  # price per bid
    max_slots: Mapped[int] = mapped_column(Integer, nullable=False)
    filled_slots: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[AuctionStatus] = mapped_column(
        Enum(AuctionStatus, name="auction_status", values_callable=lambda e: [m.value for m in e]),
        default=AuctionStatus.active,
        nullable=False,
    )
    lowest_unique_bid: Mapped[float | None] = mapped_column(Numeric(10, 2), nullable=True)
    winner_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class BidLedger(Base):
    """Immutable audit record: one row per individual bid (one slot each)."""

    __tablename__ = "bid_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    auction_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    bid_amount: Mapped[float] = mapped_column(Numeric(10, 2), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class WalletTransaction(Base):
    """Explicit wallet ledger. amount is signed (+ credit / - debit)."""

    __tablename__ = "wallet_transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # deposit | bid_purchase | platform_fee
    amount: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)
    balance_after: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(80), unique=True, nullable=True)  # idempotency key
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    auction_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class PartnerCommission(Base):
    """Partner cafe commission accrual, rolled up per auction / partner payout cycle."""

    __tablename__ = "partner_commissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    auction_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    amount: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class PaymentIntent(Base):
    """One wallet top-up attempt via a payment provider (Chapa). Status: pending|success|failed|expired|review."""

    __tablename__ = "payment_intents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tx_ref: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    amount: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="ETB", nullable=False)
    provider: Mapped[str] = mapped_column(String(32), default="chapa", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True, nullable=False)
    checkout_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    chapa_reference: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AdminUser(Base):
    """Back-office staff account (separate from players). Roles: superadmin | operator | finance | support."""

    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class AdminAuditLog(Base):
    """Append-only record of every admin action (written in the same transaction as the action)."""

    __tablename__ = "admin_audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    admin_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    admin_username: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    action: Mapped[str] = mapped_column(String(48), index=True, nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(24), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str] = mapped_column(Text, default="", nullable=False)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True, nullable=False)


class UserFlag(Base):
    """Player suspension flag. Mirrored into the Redis set `blocked_users` for fast enforcement."""

    __tablename__ = "user_flags"

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), primary_key=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reason: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    updated_by: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class AuctionOutcome(Base):
    """Operational outcome of a room: cancelled / refunded, plus prize delivery tracking for the winner."""

    __tablename__ = "auction_outcomes"

    auction_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)  # cancelled | no_winner_refunded
    note: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    refunded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    prize_status: Mapped[str | None] = mapped_column(String(12), nullable=True)  # pending (default) | delivered
    prize_note: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


async def init_models() -> None:
    """Create all tables (idempotent)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI dependency: yields one AsyncSession per request and always closes it."""
    async with SessionLocal() as session:
        yield session
