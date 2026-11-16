"""
auth.py - Session tokens (JWT, HS256) issued after a successful phone OTP.

  * create_token(user_id)  -> signed token, returned by POST /api/auth/verify-otp
  * decode_token(token)    -> user_id or None (used by the WebSocket "auth" message)
  * current_user_id        -> FastAPI dependency for HTTP routes (Authorization: Bearer <token>)

Routes must take the user from this dependency and never from the request body.

Environment:
  AUTH_SECRET        required when DEV_MODE=0 (>= 32 chars).
                     Generate: python -c "import secrets; print(secrets.token_urlsafe(48))"
  AUTH_TOKEN_HOURS   token lifetime, default 72
"""
import logging
import os
import time
from typing import Optional

import jwt
from fastapi import Header, HTTPException

log = logging.getLogger("lub.auth")

DEV_MODE = os.getenv("DEV_MODE", "1") == "1"
ISSUER = "lowbid"
TOKEN_TTL_SECONDS = int(os.getenv("AUTH_TOKEN_HOURS", "72")) * 3600

_secret = os.getenv("AUTH_SECRET", "")
if not _secret:
    if not DEV_MODE:
        raise RuntimeError("AUTH_SECRET must be set when DEV_MODE=0")
    _secret = "dev-only-insecure-secret-do-not-use-in-production"
    log.warning("AUTH_SECRET not set: using an insecure development secret")
elif len(_secret) < 32 and not DEV_MODE:
    raise RuntimeError("AUTH_SECRET must be at least 32 characters")


_redis = None


def set_redis(client) -> None:
    """main.py injects the Redis client so suspended accounts (Redis set `blocked_users`) are rejected everywhere."""
    global _redis
    _redis = client


def create_token(user_id: int) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": str(user_id), "iat": now, "exp": now + TOKEN_TTL_SECONDS, "iss": ISSUER},
        _secret, algorithm="HS256",
    )


def decode_token(token: str) -> Optional[int]:
    """Return the user id for a valid, unexpired token, otherwise None."""
    try:
        payload = jwt.decode(token, _secret, algorithms=["HS256"], issuer=ISSUER,
                             options={"require": ["exp", "sub", "iss"]})
        return int(payload["sub"])
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        return None


async def current_user_id(authorization: Optional[str] = Header(default=None)) -> int:
    """FastAPI dependency: the authenticated user's id, or HTTP 401."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Sign in required", headers={"WWW-Authenticate": "Bearer"})
    uid = decode_token(authorization[7:].strip())
    if uid is None:
        raise HTTPException(401, "Session expired", headers={"WWW-Authenticate": "Bearer"})
    if _redis is not None and await _redis.sismember("blocked_users", str(uid)):
        raise HTTPException(403, "Account suspended")
    return uid
