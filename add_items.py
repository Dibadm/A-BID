import asyncio, datetime as dt
from decimal import Decimal
from sqlalchemy import select
from database import SessionLocal, Auction


async def add_items():
    now = dt.datetime.utcnow()
    async with SessionLocal() as s, s.begin():
        # 10 Room auctions (limited slots)
        rooms = [
            Auction(title="iPhone 16 Pro Max Room", description="25 slots only - flagship phone", market_value=Decimal(120000), bid_fee=Decimal(25), max_slots=25, is_room=True, image_url="https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=400"),
            Auction(title="MacBook Pro M3 Room", description="30 slots only", market_value=Decimal(180000), bid_fee=Decimal(30), max_slots=30, is_room=True, image_url="https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=400"),
            Auction(title="Sony A7IV Camera Room", description="20 slots only", market_value=Decimal(150000), bid_fee=Decimal(25), max_slots=20, is_room=True, image_url="https://images.unsplash.com/photo-1516035069371-29a1b244cc32?w=400"),
            Auction(title="Dyson V15 Vacuum Room", description="40 slots only", market_value=Decimal(45000), bid_fee=Decimal(10), max_slots=40, is_room=True, image_url="https://images.unsplash.com/photo-1558280535-e61a5c44a9a0?w=400"),
            Auction(title="iPad Pro M4 Room", description="35 slots only", market_value=Decimal(80000), bid_fee=Decimal(15), max_slots=35, is_room=True, image_url="https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=400"),
            Auction(title="Samsung Galaxy S24 Ultra Room", description="30 slots only", market_value=Decimal(90000), bid_fee=Decimal(20), max_slots=30, is_room=True, image_url="https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=400"),
            Auction(title="LG OLED 65\" TV Room", description="25 slots only", market_value=Decimal(110000), bid_fee=Decimal(25), max_slots=25, is_room=True, image_url="https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=400"),
            Auction(title="Nintendo Switch OLED Room", description="50 slots only", market_value=Decimal(25000), bid_fee=Decimal(8), max_slots=50, is_room=True, image_url="https://images.unsplash.com/photo-1606813907291-d86efa9b94db?w=400"),
            Auction(title="AirPods Max Room", description="40 slots only", market_value=Decimal(35000), bid_fee=Decimal(10), max_slots=40, is_room=True, image_url="https://images.unsplash.com/photo-1588423771073-b8903fbb85b5?w=400"),
            Auction(title="DJI Mini 4 Pro Drone Room", description="20 slots only", market_value=Decimal(55000), bid_fee=Decimal(15), max_slots=20, is_room=True, image_url="https://images.unsplash.com/photo-1473968512647-3e447244af8f?w=400"),
        ]
        s.add_all(rooms)

        # 10 Open auctions (time-based)
        opens = [
            Auction(title="Apple Watch Ultra 2", description="Open auction - ends in 48h", market_value=Decimal(65000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=48), image_url="https://images.unsplash.com/photo-1434493907772-5b24f2e84237?w=400"),
            Auction(title="Sony WH-1000XM5 Headphones", description="Open auction - ends in 24h", market_value=Decimal(28000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=24), image_url="https://images.unsplash.com/photo-1583394838336-acd977736f90?w=400"),
            Auction(title="Samsung Galaxy Tab S9", description="Open auction - ends in 72h", market_value=Decimal(75000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=72), image_url="https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=400"),
            Auction(title="GoPro Hero 12 Black", description="Open auction - ends in 36h", market_value=Decimal(32000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=36), image_url="https://images.unsplash.com/photo-1526170375885-4d8ecf77b99f?w=400"),
            Auction(title="Kindle Paperwhite Signature", description="Open auction - ends in 48h", market_value=Decimal(15000), bid_fee=Decimal(3), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=48), image_url="https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=400"),
            Auction(title="Bose QuietComfort Earbuds", description="Open auction - ends in 12h", market_value=Decimal(22000), bid_fee=Decimal(5), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=12), image_url="https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=400"),
            Auction(title="Logitech MX Master 3S", description="Open auction - ends in 24h", market_value=Decimal(8500), bid_fee=Decimal(3), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=24), image_url="https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=400"),
            Auction(title="Anker 737 Power Bank", description="Open auction - ends in 18h", market_value=Decimal(12000), bid_fee=Decimal(3), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=18), image_url="https://images.unsplash.com/photo-1609091839311-d5365f9ff1c5?w=400"),
            Auction(title="Razer DeathAdder V3 Pro", description="Open auction - ends in 30h", market_value=Decimal(11000), bid_fee=Decimal(3), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=30), image_url="https://images.unsplash.com/photo-1527814050087-3793815479db?w=400"),
            Auction(title="Elgato Stream Deck MK.2", description="Open auction - ends in 42h", market_value=Decimal(14000), bid_fee=Decimal(4), max_slots=5000, is_room=False, ends_at=now + dt.timedelta(hours=42), image_url="https://images.unsplash.com/photo-1511467687858-23d96c32e4ae?w=400"),
        ]
        s.add_all(opens)

    print("Added 20 items (10 rooms + 10 open auctions)")


if __name__ == "__main__":
    asyncio.run(add_items())