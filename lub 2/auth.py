import os, re, secrets, logging, datetime as dt
import jwt
import redis.asyncio as aioredis
from fastapi import Header, HTTPException
from sqlalchemy import select
from database import SessionLocal, User, UserFlag

log = logging.getLogger("lub.auth")
DEV_MODE = os.getenv("DEV_MODE", "0") == "1"


def require_secret(name: str, dev_default: str) -> str:
    """Production (DEV_MODE=0) refuses to start without an explicit, strong secret."""
    v = os.getenv(name, "")
    if v:
        if not DEV_MODE and len(v) < 32:
            raise RuntimeError(f"{name} must be at least 32 characters")
        return v
    if DEV_MODE:
        return dev_default
    raise RuntimeError(f"{name} must be set when DEV_MODE=0")


JWT_SECRET = require_secret("JWT_SECRET", "dev-only-jwt-secret-never-use-in-production")
PHONE_RE = re.compile(r"^\+251[79]\d{8}$")
_r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
OTP_TTL, OTP_RESEND, OTP_MAX_TRIES = 300, 60, 5


def make_token(user_id: int) -> str:
    exp = dt.datetime.utcnow() + dt.timedelta(days=14)
    return jwt.encode({"sub": str(user_id), "exp": exp}, JWT_SECRET, algorithm="HS256")


async def send_otp_sms(phone: str, code: str) -> None:
    """STUB: plug in your SMS gateway (AfroMessage, Ethio Telecom, etc.) here."""
    if DEV_MODE:
        log.info("DEV OTP for %s is %s", phone, code)
    else:
        log.error("SMS gateway not configured: OTP for %s was NOT delivered", phone[:8] + "****")


async def send_user_otp(phone: str) -> None:
    """Stores the code in Redis (works across workers), rate-limited to one send per minute per phone."""
    if not await _r.set(f"otp:rl:{phone}", "1", nx=True, ex=OTP_RESEND):
        raise HTTPException(429, "Please wait a minute before requesting another code")
    code = "123456" if DEV_MODE else f"{secrets.randbelow(10**6):06d}"
    await _r.set(f"otp:{phone}", code, ex=OTP_TTL)
    await _r.delete(f"otp:tries:{phone}")
    await send_otp_sms(phone, code)


async def verify_user_otp(phone: str, code: str) -> bool:
    """The magic code 123456 is accepted ONLY when DEV_MODE=1. Five wrong tries burn the code."""
    if DEV_MODE and code == "123456":
        return True
    tries = await _r.incr(f"otp:tries:{phone}")
    await _r.expire(f"otp:tries:{phone}", OTP_TTL)
    if tries > OTP_MAX_TRIES:
        await _r.delete(f"otp:{phone}")
        return False
    stored = await _r.get(f"otp:{phone}")
    if not stored or not secrets.compare_digest(stored, code):
        return False
    await _r.delete(f"otp:{phone}", f"otp:tries:{phone}")
    return True


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
