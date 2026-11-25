import os, re, time, secrets, datetime as dt
import jwt
from fastapi import Header, HTTPException
from sqlalchemy import select
from database import SessionLocal, User, UserFlag

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
DEV_MODE = os.getenv("DEV_MODE", "0") == "1"
PHONE_RE = re.compile(r"^\+251[79]\d{8}$")
_otps: dict[str, tuple[str, float]] = {}  # STUB store; use Redis with TTL in production


def make_token(user_id: int) -> str:
    exp = dt.datetime.utcnow() + dt.timedelta(days=14)
    return jwt.encode({"sub": str(user_id), "exp": exp}, JWT_SECRET, algorithm="HS256")


async def send_user_otp(phone: str) -> None:
    """STUB: replace the body with your SMS gateway call (e.g. AfroMessage, Ethio Telecom SMS API)."""
    code = "123456" if DEV_MODE else f"{secrets.randbelow(10**6):06d}"
    _otps[phone] = (code, time.time() + 300)
    if not DEV_MODE:
        pass  # TODO: send `code` via SMS provider here


async def verify_user_otp(phone: str, code: str) -> bool:
    """STUB: verifies against the in-memory store. DEV_MODE=1 also accepts 123456."""
    if DEV_MODE and code == "123456":
        return True
    entry = _otps.get(phone)
    if not entry or entry[1] < time.time():
        return False
    ok = secrets.compare_digest(entry[0], code)
    if ok:
        _otps.pop(phone, None)
    return ok


async def _user_from_header(authorization: str | None) -> User | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    try:
        uid = int(jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])["sub"])
    except Exception:
        return None
    async with SessionLocal() as s:
        return (await s.execute(select(User).where(User.id == uid))).scalar_one_or_none()


async def get_current_user(authorization: str | None = Header(default=None)) -> User:
    u = await _user_from_header(authorization)
    if not u:
        raise HTTPException(401, "Please log in")
    async with SessionLocal() as s:
        f = await s.get(UserFlag, u.id)
        if f and f.blocked:
            raise HTTPException(403, "Account blocked")
    return u


async def get_optional_user(authorization: str | None = Header(default=None)) -> User | None:
    return await _user_from_header(authorization)
