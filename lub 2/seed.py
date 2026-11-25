import asyncio, sys, datetime as dt
from decimal import Decimal
from sqlalchemy import select
from database import engine, Base, SessionLocal, User, Auction, init_models
import main


async def run(reset: bool):
    if reset:
        async with engine.begin() as c:
            await c.run_sync(Base.metadata.drop_all)
        for k in await main.r.keys("auction:*"):
            await main.r.delete(k)
    await init_models()
    now = dt.datetime.utcnow()
    async with SessionLocal() as s, s.begin():
        for ph, bal in [("+251911000001", 500), ("+251911000002", 1000), ("+251911000003", 250), ("+251711000004", 2000)]:
            if not (await s.execute(select(User).where(User.phone_number == ph))).scalar_one_or_none():
                s.add(User(phone_number=ph, wallet_balance=Decimal(bal), is_verified=True))
        if not (await s.execute(select(Auction.id).limit(1))).first():
            s.add_all([
                Auction(title="iPhone 15 Pro Flash Room", description="50 slots only", market_value=Decimal(95000), bid_fee=Decimal(20), max_slots=50, is_room=True),
                Auction(title="Samsung 55\" Smart TV Room", description="100 slots only", market_value=Decimal(40000), bid_fee=Decimal(10), max_slots=100, is_room=True),
                Auction(title="MacBook Air M2", description="Open auction", market_value=Decimal(120000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=48)),
                Auction(title="PlayStation 5", description="Open auction", market_value=Decimal(60000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=24)),
            ])
    async with SessionLocal() as s:
        for a in (await s.execute(select(Auction).where(Auction.status == "active"))).scalars():
            await main.rebuild_redis(s, a)
    print("Seeded. Login with any seeded phone and code 123456 (DEV_MODE=1).")


if __name__ == "__main__":
    asyncio.run(run("--reset" in sys.argv))
