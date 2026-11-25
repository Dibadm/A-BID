import os, hmac, hashlib, uuid
from decimal import Decimal
from fastapi import APIRouter, Request, HTTPException
from sqlalchemy import select
from database import SessionLocal, User, WalletTransaction, PaymentIntent

PLATFORM_FEE_FLAT = Decimal(os.getenv("PLATFORM_FEE_FLAT", "0.50"))          # ETB per bid kept by platform
PARTNER_COMMISSION_RATE = Decimal(os.getenv("PARTNER_COMMISSION_RATE", "0.10"))  # share of the remainder
WEBHOOK_SECRET = os.getenv("PAYMENT_WEBHOOK_SECRET", "dev-secret")
router = APIRouter()


async def process_wallet_deposit(session, user_id: int, amount: Decimal, reference: str) -> bool:
    """Idempotent credit. Call inside an open transaction. Returns False if `reference` already credited.
    STUB-safe: the real provider confirmation must happen BEFORE calling this."""
    dup = (await session.execute(select(WalletTransaction.id).where(WalletTransaction.reference == reference))).first()
    if dup:
        return False
    u = (await session.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()
    u.wallet_balance = u.wallet_balance + amount
    session.add(WalletTransaction(user_id=user_id, kind="deposit", amount=amount,
                                  balance_after=u.wallet_balance, reference=reference))
    return True


async def initiate_chapa_deposit(user: User, amount: Decimal, provider: str = "chapa") -> dict:
    """STUB: call Chapa's /transaction/initialize (or Telebirr/CBE equivalent) with httpx and return its checkout_url."""
    tx_ref = f"{provider}-{user.id}-{uuid.uuid4().hex[:12]}"
    async with SessionLocal() as s, s.begin():
        s.add(PaymentIntent(user_id=user.id, provider=provider, tx_ref=tx_ref, amount=amount))
    return {"tx_ref": tx_ref, "checkout_url": f"https://checkout.example/{tx_ref}", "status": "pending"}


def verify_webhook_signature(raw_body: bytes, signature: str | None) -> bool:
    """STUB: HMAC-SHA256 of the raw body. Adapt header name/algorithm to each provider's docs."""
    if not signature:
        return False
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/api/webhooks/payment/{provider}")
async def payment_webhook(provider: str, request: Request):
    raw = await request.body()
    sig = request.headers.get("x-signature") or request.headers.get("chapa-signature")
    if not verify_webhook_signature(raw, sig):
        raise HTTPException(401, "bad signature")
    data = await request.json()
    tx_ref, ok = data.get("tx_ref"), data.get("status") in ("success", "confirmed")
    async with SessionLocal() as s, s.begin():
        pi = (await s.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref).with_for_update())).scalar_one_or_none()
        if not pi or pi.provider != provider:
            raise HTTPException(404, "unknown intent")
        if pi.status != "pending":
            return {"ok": True, "idempotent": True}
        if ok:
            await process_wallet_deposit(s, pi.user_id, pi.amount, f"pi-{pi.tx_ref}")
            pi.status = "confirmed"
        else:
            pi.status, pi.failure_reason = "failed", str(data.get("reason", "provider reported failure"))
    return {"ok": True}
