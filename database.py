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


_pool = int(os.getenv("DB_POOL_SIZE", "10"))
engine = create_async_engine(_url(), pool_size=_pool, max_overflow=_pool, pool_pre_ping=True, pool_recycle=300)
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
    image_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    winner_photo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    winner_video_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    winner_quote: Mapped[str | None] = mapped_column(Text, nullable=True)
    winner_city: Mapped[str | None] = mapped_column(String(80), nullable=True)


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
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    provider: Mapped[str] = mapped_column(String(20))
    tx_ref: Mapped[str] = mapped_column(String(100), unique=True)
    amount = mapped_column(Numeric(12, 2))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|confirmed|failed
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)  # also holds the "bids not placed" note
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    auction_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pending_bids_json: Mapped[str | None] = mapped_column(Text, nullable=True)


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


# Every statement is idempotent, so a live database upgrades in place without data loss.
MIGRATIONS = [
    "ALTER TABLE auctions ADD COLUMN IF NOT EXISTS is_room BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE auctions ADD COLUMN IF NOT EXISTS image_url TEXT",
    "ALTER TABLE auctions ADD COLUMN IF NOT EXISTS winner_photo_url TEXT",
    "ALTER TABLE auctions ADD COLUMN IF NOT EXISTS winner_video_url TEXT",
    "ALTER TABLE auctions ADD COLUMN IF NOT EXISTS winner_quote TEXT",
    "ALTER TABLE auctions ADD COLUMN IF NOT EXISTS winner_city VARCHAR(80)",
    "ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS auction_id INTEGER",
    "ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS pending_bids_json TEXT",
    "ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS note TEXT",
    "CREATE INDEX IF NOT EXISTS ix_bid_ledger_auction_amount ON bid_ledger (auction_id, bid_amount)",
    """DO $$ BEGIN
         ALTER TABLE users ADD CONSTRAINT ck_users_wallet_nonneg CHECK (wallet_balance >= 0) NOT VALID;
       EXCEPTION WHEN duplicate_object THEN NULL;
       END $$""",
]


async def init_models():
    async with engine.begin() as conn:
        await conn.execute(text("SELECT pg_advisory_xact_lock(727201)"))  # serialises multi-worker startup
        await conn.run_sync(Base.metadata.create_all)
        for stmt in MIGRATIONS:
            await conn.execute(text(stmt))
