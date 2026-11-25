#!/usr/bin/env python3
"""
CLI script to create or reset a superadmin account in PostgreSQL.
Usage: python create_admin.py <username>
"""
import sys, secrets, hashlib, asyncio
from sqlalchemy import select
from database import engine, SessionLocal, AdminUser, Base, init_models

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return salt.hex() + "$" + dk.hex()

async def create_admin(username: str):
    await init_models()
    password = secrets.token_urlsafe(16)
    async with SessionLocal() as s, s.begin():
        existing = (await s.execute(select(AdminUser).where(AdminUser.username == username))).scalar_one_or_none()
        if existing:
            existing.password_hash = hash_password(password)
            existing.role = "superadmin"
            existing.is_active = True
            existing.failed_logins = 0
            existing.locked_until = None
            print(f"Reset password for existing admin: {username}")
        else:
            s.add(AdminUser(username=username, password_hash=hash_password(password), role="superadmin", is_active=True))
            print(f"Created new superadmin: {username}")
        await s.flush()
    print(f"Password: {password}")
    print("SAVE THIS PASSWORD - it won't be shown again!")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python create_admin.py <username>")
        sys.exit(1)
    asyncio.run(create_admin(sys.argv[1]))