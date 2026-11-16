"""
payments.py - Chapa wallet top-ups (hosted checkout) for the LowBid platform.

Flow (every path converges on settle_intent(), which is idempotent and server-verified):
  1. POST /api/wallet/deposit/initiate    -> saves a PaymentIntent, asks Chapa for a checkout_url
  2. Player pays on Chapa's hosted page   -> Chapa redirects to /payment/return/{tx_ref} -> /?deposit={tx_ref}
  3. Money is credited by whichever arrives first, all calling settle_intent():
        a) POST /api/webhooks/chapa             (signed webhook, primary)
        b) GET  /api/webhooks/chapa/callback    (unsigned callback_url ping, trigger only)
        c) GET  /api/wallet/deposit/status/..   (frontend polling after return)
        d) reconcile_loop()                     (safety net for missed webhooks)

Safety rules:
  * Nothing in a webhook/callback body is trusted. We ALWAYS call Chapa's verify API with our own tx_ref.
  * Credit only if verified status == success, currency == ETB and paid amount >= requested amount.
  * The intent row is locked (SELECT ... FOR UPDATE) and WalletTransaction.reference (= tx_ref) is UNIQUE,
    so a deposit can never be credited twice, even with concurrent workers or repeated webhooks.

Environment:
  CHAPA_SECRET_KEY        required (test key starts CHASECK_TEST-, live key CHASECK-)
  CHAPA_WEBHOOK_SECRET    the "secret hash" you set in the Chapa dashboard (falls back to the secret key)
  PUBLIC_BASE_URL         public HTTPS origin of this server, e.g. https://play.example.com (no trailing slash)
  CHAPA_BASE_URL          default https://api.chapa.co/v1
  CHAPA_MIN_AMOUNT / CHAPA_MAX_AMOUNT   default 10 / 50000 (ETB)
  CHAPA_FALLBACK_EMAIL_DOMAIN           default example.com (used only if a real email is required)
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Optional
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

import auth
from database import PaymentIntent, SessionLocal, User, WalletTransaction, get_db, utcnow

log = logging.getLogger("lub.chapa")
router = APIRouter()
hooks: dict = {}  # main.py injects {"wallet_changed": async fn(user_id, balance)}

CHAPA_SECRET_KEY = os.getenv("CHAPA_SECRET_KEY", "").strip()
CHAPA_WEBHOOK_SECRET = os.getenv("CHAPA_WEBHOOK_SECRET", "").strip()
CHAPA_BASE_URL = os.getenv("CHAPA_BASE_URL", "https://api.chapa.co/v1").rstrip("/")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
MIN_AMOUNT = Decimal(os.getenv("CHAPA_MIN_AMOUNT", "10"))
MAX_AMOUNT = Decimal(os.getenv("CHAPA_MAX_AMOUNT", "50000"))
EMAIL_DOMAIN = os.getenv("CHAPA_FALLBACK_EMAIL_DOMAIN", "example.com")
BRAND_TITLE = os.getenv("CHAPA_TITLE", "LowBid")[:16]
MONEY = Decimal("0.01")


def configured() -> bool:
    return bool(CHAPA_SECRET_KEY)


# ----------------------------------------------------------------------------- Chapa HTTP client
class ChapaError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, transient: bool = False):
        super().__init__(message)
        self.status = status
        self.transient = transient


class ChapaClient:
    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=CHAPA_BASE_URL,
                timeout=httpx.Timeout(15.0, connect=8.0),
                headers={"Authorization": f"Bearer {CHAPA_SECRET_KEY}", "Content-Type": "application/json"},
            )
        return self._client

    async def aclose(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def _json(resp: httpx.Response) -> dict:
        try:
            body = resp.json()
            return body if isinstance(body, dict) else {}
        except ValueError:
            return {}

    async def initialize(self, payload: dict) -> str:
        """Create a hosted checkout session and return its checkout_url. Not retried (tx_ref must stay unique)."""
        try:
            resp = await self._http().post("/transaction/initialize", json=payload)
        except httpx.RequestError as exc:
            raise ChapaError(f"Chapa unreachable: {exc.__class__.__name__}", transient=True)
        body = self._json(resp)
        if resp.status_code in (401, 403):
            raise ChapaError("Chapa rejected the API key", resp.status_code)
        url = (body.get("data") or {}).get("checkout_url") if isinstance(body.get("data"), dict) else None
        if resp.status_code != 200 or body.get("status") != "success" or not url:
            raise ChapaError(str(body.get("message") or f"HTTP {resp.status_code}")[:200], resp.status_code)
        return url

    async def verify(self, tx_ref: str) -> Optional[dict]:
        """
        Return Chapa's transaction object (its `status` is the payment status) or None if Chapa has no
        such transaction yet. Retries transient failures; raises ChapaError if Chapa stays unreachable.
        """
        for attempt in range(3):
            try:
                resp = await self._http().get(f"/transaction/verify/{quote(tx_ref, safe='')}")
            except httpx.RequestError:
                await asyncio.sleep(0.5 * 2 ** attempt)
                continue
            if resp.status_code in (401, 403):
                raise ChapaError("Chapa rejected the API key", resp.status_code)
            if resp.status_code in (400, 404):
                return None
            if resp.status_code >= 500:
                await asyncio.sleep(0.5 * 2 ** attempt)
                continue
            body = self._json(resp)
            data = body.get("data")
            return data if body.get("status") == "success" and isinstance(data, dict) else None
        raise ChapaError("Chapa unreachable while verifying", transient=True)


chapa = ChapaClient()


# ----------------------------------------------------------------------------- helpers
def verify_signature(raw: bytes, headers) -> bool:
    """
    x-chapa-signature = HMAC-SHA256(webhook secret, event payload). The 'Chapa-Signature' header is a
    constant (HMAC of the secret by itself), proves nothing about the body, so it is deliberately ignored.
    Raw bytes are tried first, then the compact JSON form some Chapa examples sign.
    """
    given = (headers.get("x-chapa-signature") or "").strip().lower()
    secret = (CHAPA_WEBHOOK_SECRET or CHAPA_SECRET_KEY).encode()
    if not given or not secret:
        return False
    candidates = [raw]
    try:
        candidates.append(json.dumps(json.loads(raw), separators=(",", ":"), ensure_ascii=False).encode())
    except ValueError:
        pass
    return any(hmac.compare_digest(hmac.new(secret, c, hashlib.sha256).hexdigest(), given) for c in candidates)


def local_phone(phone: str) -> Optional[str]:
    """+251911000001 -> 0911000001 (the local format Chapa expects). None if it does not fit."""
    digits = re.sub(r"\D", "", phone or "")
    if digits.startswith("251") and len(digits) == 12:
        return "0" + digits[3:]
    if len(digits) == 10 and digits.startswith(("09", "07")):
        return digits
    return None


def money(value) -> Optional[Decimal]:
    try:
        return Decimal(str(value).replace(",", "")).quantize(MONEY)
    except (InvalidOperation, ValueError):
        return None


async def _fetch_intent(tx_ref: str) -> Optional[PaymentIntent]:
    async with SessionLocal() as db:
        return (await db.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref))).scalar_one_or_none()


# ----------------------------------------------------------------------------- the one place money is credited
async def settle_intent(tx_ref: str) -> Optional[PaymentIntent]:
    """Idempotent. Verifies with Chapa, then credits the wallet exactly once. Raises ChapaError if Chapa is down."""
    credited = None
    async with SessionLocal() as db:
        intent = (await db.execute(
            select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref).with_for_update()
        )).scalar_one_or_none()
        if intent is None or intent.status != "pending":
            return intent

        data = await chapa.verify(tx_ref)  # lock is released automatically if this raises
        if data is None:
            return intent  # Chapa has no record yet; stay pending
        state = str(data.get("status", "")).lower()

        if state == "success":
            paid = money(data.get("amount"))
            ref_ok = (not data.get("tx_ref")) or str(data["tx_ref"]) == tx_ref
            if not ref_ok or str(data.get("currency", "ETB")).upper() != "ETB" or paid is None or paid < intent.amount:
                intent.status = "review"
                intent.failure_reason = f"mismatch paid={paid} currency={data.get('currency')} ref_ok={ref_ok}"[:200]
                await db.commit()
                log.error("payment %s needs manual review: %s", tx_ref, intent.failure_reason)
                return intent
            user = (await db.execute(select(User).where(User.id == intent.user_id).with_for_update())).scalar_one()
            user.wallet_balance = Decimal(user.wallet_balance) + Decimal(intent.amount)
            db.add(WalletTransaction(user_id=user.id, kind="deposit", amount=intent.amount,
                                     balance_after=user.wallet_balance, reference=tx_ref, provider="chapa"))
            intent.status = "success"
            intent.chapa_reference = (str(data.get("reference") or "")[:80]) or None
            intent.completed_at = utcnow()
            try:
                await db.commit()
            except IntegrityError:  # already credited by a concurrent path
                await db.rollback()
                return await _fetch_intent(tx_ref)
            credited = (user.id, user.wallet_balance)
        elif state in ("failed", "cancelled", "canceled", "expired", "reversed"):
            intent.status = "failed"
            intent.failure_reason = f"chapa status {state}"
            await db.commit()
        else:
            return intent  # still pending at Chapa

    if credited and hooks.get("wallet_changed"):
        await hooks["wallet_changed"](*credited)
    return intent


# ----------------------------------------------------------------------------- API
class InitiateRequest(BaseModel):
    user_id: Optional[int] = None  # ignored: identity comes from the token
    amount: Decimal = Field(gt=0)


@router.get("/api/payments/config")
async def payments_config():
    key = CHAPA_SECRET_KEY.upper()
    return {
        "chapa": configured(),
        "mode": None if not configured() else ("test" if "TEST" in key else "live"),
        "min_amount": float(MIN_AMOUNT), "max_amount": float(MAX_AMOUNT),
        "webhook_secret_set": bool(CHAPA_WEBHOOK_SECRET),
        "webhook_url": f"{PUBLIC_BASE_URL}/api/webhooks/chapa",
    }


@router.post("/api/wallet/deposit/initiate")
async def initiate_deposit(body: InitiateRequest, uid: int = Depends(auth.current_user_id),
                           db: AsyncSession = Depends(get_db)):
    if not configured():
        raise HTTPException(503, "Payments are not configured")
    amount = body.amount.quantize(MONEY)
    if amount < MIN_AMOUNT or amount > MAX_AMOUNT:
        raise HTTPException(400, f"Deposit must be between {MIN_AMOUNT} and {MAX_AMOUNT} ETB")
    user = await db.get(User, uid)
    if not user:
        raise HTTPException(404, "User not found")
    if not user.is_verified:
        raise HTTPException(403, "Phone number not verified")

    tx_ref = f"lub-{user.id}-{secrets.token_hex(8)}"
    intent = PaymentIntent(tx_ref=tx_ref, user_id=user.id, amount=amount, currency="ETB", provider="chapa", status="pending")
    db.add(intent)
    await db.commit()  # persisted BEFORE calling Chapa, so a fast webhook always finds it

    payload = {
        "amount": f"{amount:.2f}", "currency": "ETB",
        "email": f"player{user.id}@{EMAIL_DOMAIN}",
        "first_name": "Player", "last_name": str(user.id),
        "tx_ref": tx_ref,
        "callback_url": f"{PUBLIC_BASE_URL}/api/webhooks/chapa/callback",
        "return_url": f"{PUBLIC_BASE_URL}/payment/return/{tx_ref}",
        "customization": {"title": BRAND_TITLE, "description": "Wallet top up"},
    }
    phone = local_phone(user.phone_number)
    if phone:
        payload["phone_number"] = phone
    try:
        intent.checkout_url = await chapa.initialize(payload)
    except ChapaError as exc:
        intent.status = "failed"
        intent.failure_reason = str(exc)[:200]
        await db.commit()
        log.error("chapa initialize failed for %s: %s", tx_ref, exc)
        raise HTTPException(502, "Payment provider is unavailable. Try again shortly")
    await db.commit()
    return {"tx_ref": tx_ref, "checkout_url": intent.checkout_url, "amount": float(amount)}


@router.get("/payment/return/{tx_ref}")
async def payment_return(tx_ref: str):
    """Chapa's return_url. Sends the player back to the app, which then polls the status endpoint."""
    return RedirectResponse(f"/?deposit={quote(tx_ref, safe='')}", status_code=302)


@router.get("/api/wallet/deposit/status/{tx_ref}")
async def deposit_status(tx_ref: str, user_id: int = Depends(auth.current_user_id),
                         db: AsyncSession = Depends(get_db)):
    intent = (await db.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref))).scalar_one_or_none()
    if not intent or intent.user_id != user_id:
        raise HTTPException(404, "Payment not found")
    if intent.status == "pending":
        try:
            await settle_intent(tx_ref)
        except ChapaError as exc:
            log.warning("status check could not verify %s: %s", tx_ref, exc)
        await db.refresh(intent)
    user = await db.get(User, user_id)
    await db.refresh(user)
    return {"tx_ref": tx_ref, "status": intent.status, "amount": float(intent.amount), "balance": float(user.wallet_balance)}


@router.post("/api/webhooks/chapa")
async def chapa_webhook(request: Request):
    raw = await request.body()
    if not verify_signature(raw, request.headers):
        raise HTTPException(401, "Bad signature")
    try:
        event = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(event, dict):
        raise HTTPException(400, "Invalid payload")
    etype = str(event.get("event") or "")
    if etype and not etype.startswith("charge."):
        return {"ignored": etype}  # payout.* events etc. are not handled yet

    refs = [str(event[k]) for k in ("tx_ref", "trx_ref", "reference", "chapa_reference") if event.get(k)]
    async with SessionLocal() as db:
        intent = (await db.execute(
            select(PaymentIntent).where((PaymentIntent.tx_ref.in_(refs)) | (PaymentIntent.chapa_reference.in_(refs)))
        )).scalars().first() if refs else None
    if not intent:
        return {"ignored": "unknown reference"}
    try:
        await settle_intent(intent.tx_ref)
    except ChapaError as exc:
        log.warning("webhook could not verify %s: %s", intent.tx_ref, exc)
        raise HTTPException(503, "Verification unavailable, retry later")  # reconcile_loop is the backstop
    return {"ok": True}


@router.get("/api/webhooks/chapa/callback")
async def chapa_callback(trx_ref: Optional[str] = None, tx_ref: Optional[str] = None, status: Optional[str] = None):
    """Chapa's unsigned callback_url ping. Treated purely as a hint; settle_intent() verifies with Chapa."""
    ref = trx_ref or tx_ref
    if ref:
        try:
            await settle_intent(ref)
        except ChapaError as exc:
            log.warning("callback could not verify %s: %s", ref, exc)
    return {"ok": True}


# ----------------------------------------------------------------------------- safety net
async def reconcile_loop():
    """Every minute: re-verify pending payments older than 90s; expire ones still unpaid after 24h."""
    while True:
        try:
            if configured():
                async with SessionLocal() as db:
                    refs = (await db.execute(
                        select(PaymentIntent.tx_ref).where(
                            PaymentIntent.status == "pending",
                            PaymentIntent.created_at < utcnow() - timedelta(seconds=90))
                    )).scalars().all()
                for ref in refs:
                    try:
                        await settle_intent(ref)
                    except ChapaError as exc:
                        log.warning("reconcile %s: %s", ref, exc)
                async with SessionLocal() as db:
                    await db.execute(update(PaymentIntent).where(
                        PaymentIntent.status == "pending",
                        PaymentIntent.created_at < utcnow() - timedelta(hours=24)
                    ).values(status="expired", failure_reason="unpaid after 24h"))
                    await db.commit()
        except Exception:
            log.exception("reconcile_loop error")
        await asyncio.sleep(60)
