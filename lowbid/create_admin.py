"""
create_admin.py - create or reset a back-office account from the command line.

    python create_admin.py <username> [--role superadmin|operator|finance|support]
    python create_admin.py <username> --reset-password

The password is typed at a hidden prompt (never passed on the command line or stored in shell history).
Run this once to create your first superadmin; further staff are managed from the panel (Admins page).
"""
import argparse
import asyncio
import getpass
import re
import sys

from sqlalchemy import select

from admin import ROLE_PERMS, hash_password
from database import AdminUser, SessionLocal, engine, init_models, utcnow


def ask_password() -> str:
    while True:
        pw = getpass.getpass("Password (min 12 chars, letters and digits): ")
        if len(pw) < 12 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
            print("Too weak. Use at least 12 characters with letters and digits.")
            continue
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
            continue
        return pw


async def main(username: str, role: str, reset: bool):
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", username):
        sys.exit("Username must be 3-32 chars: lowercase letters, digits, _ . -")
    await init_models()
    async with SessionLocal() as db:
        admin = (await db.execute(select(AdminUser).where(AdminUser.username == username))).scalar_one_or_none()
        if reset:
            if not admin:
                sys.exit(f"No admin named {username}")
            admin.password_hash, admin.password_changed_at = hash_password(ask_password()), utcnow()
            admin.failed_logins, admin.locked_until, admin.is_active = 0, None, True
            print(f"Password reset for {username}; existing sessions are now invalid.")
        else:
            if admin:
                sys.exit(f"{username} already exists (use --reset-password)")
            db.add(AdminUser(username=username, password_hash=hash_password(ask_password()), role=role, password_changed_at=utcnow()))
            print(f"Created {role} account '{username}'. Sign in at /admin")
        await db.commit()
    await engine.dispose()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("username")
    ap.add_argument("--role", default="superadmin", choices=sorted(ROLE_PERMS))
    ap.add_argument("--reset-password", action="store_true")
    a = ap.parse_args()
    asyncio.run(main(a.username, a.role, a.reset_password))
