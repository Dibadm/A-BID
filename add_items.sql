-- Run this in Neon SQL Editor to add 20 items (10 rooms + 10 open auctions)

-- 10 Room auctions (limited slots)
INSERT INTO auctions (title, description, market_value, bid_fee, max_slots, is_room, image_url, created_at) VALUES
('iPhone 16 Pro Max Room', '25 slots only - flagship phone', 120000, 25, 25, true, 'https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=400', NOW()),
('MacBook Pro M3 Room', '30 slots only', 180000, 30, 30, true, 'https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=400', NOW()),
('Sony A7IV Camera Room', '20 slots only', 150000, 25, 20, true, 'https://images.unsplash.com/photo-1516035069371-29a1b244cc32?w=400', NOW()),
('Dyson V15 Vacuum Room', '40 slots only', 45000, 10, 40, true, 'https://images.unsplash.com/photo-1558280535-e61a5c44a9a0?w=400', NOW()),
('iPad Pro M4 Room', '35 slots only', 80000, 15, 35, true, 'https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=400', NOW()),
('Samsung Galaxy S24 Ultra Room', '30 slots only', 90000, 20, 30, true, 'https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=400', NOW()),
('LG OLED 65" TV Room', '25 slots only', 110000, 25, 25, true, 'https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=400', NOW()),
('Nintendo Switch OLED Room', '50 slots only', 25000, 8, 50, true, 'https://images.unsplash.com/photo-1606813907291-d86efa9b94db?w=400', NOW()),
('AirPods Max Room', '40 slots only', 35000, 10, 40, true, 'https://images.unsplash.com/photo-1588423771073-b8903fbb85b5?w=400', NOW()),
('DJI Mini 4 Pro Drone Room', '20 slots only', 55000, 15, 20, true, 'https://images.unsplash.com/photo-1473968512647-3e447244af8f?w=400', NOW());

-- 10 Open auctions (time-based, ends_at in future)
INSERT INTO auctions (title, description, market_value, bid_fee, max_slots, is_room, ends_at, image_url, created_at) VALUES
('Apple Watch Ultra 2', 'Open auction - ends in 48h', 65000, 5, 5000, false, NOW() + INTERVAL '48 hours', 'https://images.unsplash.com/photo-1434493907772-5b24f2e84237?w=400', NOW()),
('Sony WH-1000XM5 Headphones', 'Open auction - ends in 24h', 28000, 5, 5000, false, NOW() + INTERVAL '24 hours', 'https://images.unsplash.com/photo-1583394838336-acd977736f90?w=400', NOW()),
('Samsung Galaxy Tab S9', 'Open auction - ends in 72h', 75000, 5, 5000, false, NOW() + INTERVAL '72 hours', 'https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=400', NOW()),
('GoPro Hero 12 Black', 'Open auction - ends in 36h', 32000, 5, 5000, false, NOW() + INTERVAL '36 hours', 'https://images.unsplash.com/photo-1526170375885-4d8ecf77b99f?w=400', NOW()),
('Kindle Paperwhite Signature', 'Open auction - ends in 48h', 15000, 3, 5000, false, NOW() + INTERVAL '48 hours', 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=400', NOW()),
('Bose QuietComfort Earbuds', 'Open auction - ends in 12h', 22000, 5, 5000, false, NOW() + INTERVAL '12 hours', 'https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=400', NOW()),
('Logitech MX Master 3S', 'Open auction - ends in 24h', 8500, 3, 5000, false, NOW() + INTERVAL '24 hours', 'https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=400', NOW()),
('Anker 737 Power Bank', 'Open auction - ends in 18h', 12000, 3, 5000, false, NOW() + INTERVAL '18 hours', 'https://images.unsplash.com/photo-1609091839311-d5365f9ff1c5?w=400', NOW()),
('Razer DeathAdder V3 Pro', 'Open auction - ends in 30h', 11000, 3, 5000, false, NOW() + INTERVAL '30 hours', 'https://images.unsplash.com/photo-1527814050087-3793815479db?w=400', NOW()),
('Elgato Stream Deck MK.2', 'Open auction - ends in 42h', 14000, 4, 5000, false, NOW() + INTERVAL '42 hours', 'https://images.unsplash.com/photo-1511467687858-23d96c32e4ae?w=400', NOW());