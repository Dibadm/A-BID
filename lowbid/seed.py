"""
seed.py - White-label initializer.

Usage:
    python seed.py            # create tables, add missing users/rooms (safe to re-run)
    python seed.py --reset    # DROP all tables, flush auction keys in Redis, then re-seed
"""
import argparse
import asyncio
import os
from datetime import timedelta
from decimal import Decimal

import redis.asyncio as aioredis
from sqlalchemy import select

from database import Auction, AuctionStatus, Base, SessionLocal, User, engine, init_models, utcnow

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

TEST_USERS = [
    # (phone_number, wallet_balance ETB, is_verified)
    ("+251911000001", "5000.00", True),
    ("+251911000002", "5000.00", True),
    ("+251911000003", "2500.00", True),
    ("+251911000004", "1000.00", True),
    ("+251911000005", "500.00", True),
    ("+251911000006", "0.00", False),  # unverified: exercise the OTP flow
]

ROOMS = [
    dict(title="High-Velocity Tech", description="Smartwatch + earbuds bundle. Small room, fast finish.",
         market_value="12000.00", bid_fee="10.00", max_slots=50),
    dict(title="Premium Electronics", description="Flagship 55-inch smart TV. Medium room.",
         market_value="45000.00", bid_fee="20.00", max_slots=100),
    dict(title="Home Appliances", description="Front-load washing machine. Large mass-volume room.",
         market_value="60000.00", bid_fee="5.00", max_slots=500),
]


async def flush_redis_auction_keys() -> int:
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    count = 0
    try:
        async for k in r.scan_iter(match="auction:*"):
            await r.delete(k)
            count += 1
        await r.delete("auctions:index")
        async for k in r.scan_iter(match="otp:*"):
            await r.delete(k)
    finally:
        await r.aclose()
    return count


async def main(reset: bool):
    if reset:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        print(f"Dropped tables; flushed {await flush_redis_auction_keys()} Redis keys")
    await init_models()
    print("Tables ready")

    async with SessionLocal() as s:
        for phone, balance, verified in TEST_USERS:
            exists = (await s.execute(select(User).where(User.phone_number == phone))).scalar_one_or_none()
            if not exists:
                s.add(User(phone_number=phone, wallet_balance=Decimal(balance), is_verified=verified))
                print(f"  user {phone}  balance={balance} verified={verified}")
        for room in ROOMS:
            exists = (await s.execute(select(Auction).where(Auction.title == room["title"]))).scalar_one_or_none()
            if not exists:
                s.add(Auction(
                    title=room["title"], description=room["description"],
                    market_value=Decimal(room["market_value"]), bid_fee=Decimal(room["bid_fee"]),
                    max_slots=room["max_slots"], filled_slots=0, status=AuctionStatus.active,
                    ends_at=utcnow() + timedelta(days=7),
                ))
                print(f"  room '{room['title']}' ({room['max_slots']} slots)")
        await s.commit()
    await engine.dispose()
    print("Seed complete. Start the API with: uvicorn main:app --port 8000")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="drop all tables and flush Redis first")
    asyncio.run(main(parser.parse_args().reset))
