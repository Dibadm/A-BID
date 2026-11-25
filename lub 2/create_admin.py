"""Create or reset a back-office admin.
Usage: python create_admin.py --username boss --role superadmin [--password 'secret']
Omit --password to be prompted securely. Re-running with an existing username resets the password, role and lockout."""
import argparse, asyncio, getpass, sys
from sqlalchemy import select
from database import SessionLocal, init_models, AdminUser
from admin import hash_password, ROLES


async def run(username: str, password: str, role: str):
    await init_models()
    async with SessionLocal() as s, s.begin():
        a = (await s.execute(select(AdminUser).where(AdminUser.username == username))).scalar_one_or_none()
        if a:
            a.password_hash, a.role, a.is_active, a.failed_logins, a.locked_until = hash_password(password), role, True, 0, None
            print(f"Reset admin '{username}' ({role}).")
        else:
            s.add(AdminUser(username=username, password_hash=hash_password(password), role=role))
            print(f"Created admin '{username}' ({role}).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True)
    ap.add_argument("--role", default="superadmin", choices=ROLES)
    ap.add_argument("--password")
    a = ap.parse_args()
    pw = a.password or getpass.getpass("Password (min 10 chars): ")
    if len(pw) < 10:
        sys.exit("Password must be at least 10 characters.")
    asyncio.run(run(a.username, pw, a.role))
