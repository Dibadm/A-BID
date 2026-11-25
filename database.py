import os, datetime as dt
from sqlalchemy import String, Integer, Boolean, Numeric, DateTime, Text, ForeignKey, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _url() -> str:
    u = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/auction")
    for p in ("postgres://", "postgresql://"):
        if u.startswith(p):
            u = "postgresql+asyncpg://" + u[len(p):]
    return u.replace("sslmode=require", "ssl=require")


engine = create_async_engine(_url(), pool_size=20, max_overflow=20, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


def utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    phone_number: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    wallet_balance = mapped_column(Numeric(12, 2), default=0, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class UserFlag(Base):
    __tablename__ = "user_flags"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Auction(Base):
    __tablename__ = "auctions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    image_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    market_value = mapped_column(Numeric(12, 2))
    bid_fee = mapped_column(Numeric(10, 2))
    max_slots: Mapped[int] = mapped_column(Integer)
    filled_slots: Mapped[int] = mapped_column(Integer, default=0)
    is_room: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)  # active|calculating|ended|cancelled
    lowest_unique_bid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    winner_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prize_status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|contacted|delivered
    ends_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class BidLedger(Base):
    __tablename__ = "bid_ledger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    auction_id: Mapped[int] = mapped_column(Integer, index=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    bid_amount: Mapped[int] = mapped_column(Integer, index=True)
    fee_charged = mapped_column(Numeric(10, 2))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class WalletTransaction(Base):
    __tablename__ = "wallet_transactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(20))  # deposit|bid_fee|refund|admin_adjust
    amount = mapped_column(Numeric(12, 2))
    balance_after = mapped_column(Numeric(12, 2))
    reference: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    provider: Mapped[str] = mapped_column(String(20))
    tx_ref: Mapped[str] = mapped_column(String(100), unique=True)
    amount = mapped_column(Numeric(12, 2))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|confirmed|failed
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class PartnerCommission(Base):
    __tablename__ = "partner_commissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    auction_id: Mapped[int] = mapped_column(Integer, index=True)
    bid_ledger_id: Mapped[int] = mapped_column(Integer)
    platform_fee = mapped_column(Numeric(10, 2))
    partner_share = mapped_column(Numeric(10, 2))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))  # hashlib.scrypt, "salt$hash" hex
    role: Mapped[str] = mapped_column(String(20), default="support")  # superadmin|operator|finance|support
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    admin_username: Mapped[str] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


async def init_models():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE auctions ADD COLUMN IF NOT EXISTS is_room BOOLEAN NOT NULL DEFAULT FALSE;"))
