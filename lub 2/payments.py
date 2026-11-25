import os, hmac, hashlib, json, uuid, logging
from decimal import Decimal, InvalidOperation
from fastapi import APIRouter, Request, HTTPException
from sqlalchemy import select
from database import SessionLocal, User, WalletTransaction, PaymentIntent
from auth import require_secret

log = logging.getLogger("lub.payments")
PLATFORM_FEE_FLAT = Decimal(os.getenv("PLATFORM_FEE_FLAT", "0.50"))              # ETB per bid kept by platform
PARTNER_COMMISSION_RATE = Decimal(os.getenv("PARTNER_COMMISSION_RATE", "0.10"))  # share of the remainder
PROVIDERS = ("chapa", "telebirr", "cbe")
router = APIRouter()
_secret: str | None = None
_hooks: dict = {}


def webhook_secret() -> str:
    global _secret
    if _secret is None:
        _secret = require_secret("PAYMENT_WEBHOOK_SECRET", "dev-webhook-secret-not-for-production")
    return _secret


def register_bid_hooks(execute, release, after):
    """main.py registers its bid engine here so payments can place pending bids without a circular import."""
    _hooks.update(execute=execute, release=release, after=after)


async def process_wallet_deposit(session, user_id: int, amount: Decimal, reference: str, note: str | None = None):
    """Idempotent credit inside the caller's transaction. Returns the WalletTransaction, or None if `reference` was already credited."""
    dup = (await session.execute(select(WalletTransaction.id).where(WalletTransaction.reference == reference))).first()
    if dup:
        return None
    u = (await session.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()
    u.wallet_balance = u.wallet_balance + amount
    tx = WalletTransaction(user_id=user_id, kind="deposit", amount=amount, balance_after=u.wallet_balance,
                           reference=reference, note=note)
    session.add(tx)
    return tx


async def initiate_chapa_deposit(user: User, amount: Decimal, provider: str = "chapa",
                                 auction_id: int | None = None, pending_bids: list[int] | None = None) -> dict:
    """STUB: call Chapa /transaction/initialize (or Telebirr/CBE) with httpx, passing tx_ref, and return its checkout_url.
    The intent row below is what the webhook/status handler later confirms."""
    tx_ref = f"{provider}-{user.id}-{uuid.uuid4().hex[:12]}"
    async with SessionLocal() as s, s.begin():
        s.add(PaymentIntent(user_id=user.id, provider=provider, tx_ref=tx_ref, amount=amount, auction_id=auction_id,
                            pending_bids_json=json.dumps(pending_bids) if pending_bids else None))
    return {"tx_ref": tx_ref, "checkout_url": f"https://checkout.example/{tx_ref}", "status": "pending"}


async def verify_with_provider(tx_ref: str, provider: str) -> str:
    """STUB: call the provider's verify endpoint (Chapa: GET /transaction/verify/{tx_ref}).
    Return 'success', 'failed' or 'pending'."""
    return "pending"


def verify_webhook_signature(raw_body: bytes, signature: str | None) -> bool:
    """HMAC-SHA256 of the raw body. Adapt header and algorithm to each provider's documentation."""
    if not signature:
        return False
    expected = hmac.new(webhook_secret().encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


async def confirm_payment(tx_ref: str, *, provider: str | None = None, allow_failed: bool = False,
                          reported_amount: Decimal | None = None) -> dict:
    """Atomically: credit the wallet, mark the intent confirmed and, for a bid-checkout, place the pending bids.
    If the bids cannot be placed (room filled, auction closed, ...) the bid step rolls back on its own savepoint and the
    credited ETB stays in the wallet with an explanatory WalletTransaction note. Safe to call repeatedly."""
    out = {"status": "unknown", "bids_placed": False, "note": None}
    placed, state = None, {"reserved": False, "padded": []}
    try:
        async with SessionLocal() as s, s.begin():
            pi = (await s.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref).with_for_update())).scalar_one_or_none()
            if not pi or (provider and pi.provider != provider):
                out["status"] = "not_found"
                return out
            out["status"] = pi.status
            if pi.status == "confirmed" or (pi.status == "failed" and not allow_failed):
                out["note"] = pi.failure_reason
                out["bids_placed"] = bool(pi.status == "confirmed" and pi.auction_id and not pi.failure_reason)
                return out
            if reported_amount is not None and reported_amount != pi.amount:
                pi.status, pi.failure_reason = "failed", "amount mismatch"
                out.update(status="failed", note="amount mismatch")
                return out
            dep = await process_wallet_deposit(s, pi.user_id, pi.amount, f"pi-{pi.tx_ref}")
            await s.flush()
            pi.status, pi.failure_reason = "confirmed", None
            out["status"] = "confirmed"
            if pi.auction_id and pi.pending_bids_json and _hooks:
                try:
                    amounts = json.loads(pi.pending_bids_json)
                    async with s.begin_nested():
                        placed = await _hooks["execute"](s, pi.user_id, pi.auction_id, amounts, state)
                    out["bids_placed"] = True
                except Exception as e:
                    placed = None
                    if state["reserved"]:
                        await _hooks["release"](pi.auction_id, state["padded"])
                        state["reserved"] = False
                    reason = getattr(e, "msg", None) or "bids could not be placed"
                    note = f"Payment {pi.tx_ref} received but bids not placed ({reason}). Funds kept in your wallet."
                    if dep:
                        dep.note = note
                    pi.failure_reason, out["note"] = note, note
                    log.warning("bid-checkout fallback for %s: %s", pi.tx_ref, reason)
    except BaseException:
        if placed is not None and state["reserved"]:
            await _hooks["release"](placed["aid"], state["padded"])
        raise
    if placed:
        await _hooks["after"](placed)
    return out


async def mark_failed(tx_ref: str, provider: str | None, reason: str) -> None:
    async with SessionLocal() as s, s.begin():
        pi = (await s.execute(select(PaymentIntent).where(PaymentIntent.tx_ref == tx_ref).with_for_update())).scalar_one_or_none()
        if pi and pi.status == "pending" and (provider is None or pi.provider == provider):
            pi.status, pi.failure_reason = "failed", reason


@router.post("/api/webhooks/payment/{provider}")
async def payment_webhook(provider: str, request: Request):
    if provider not in PROVIDERS:
        raise HTTPException(404, "unknown provider")
    raw = await request.body()
    if not verify_webhook_signature(raw, request.headers.get("x-signature") or request.headers.get("chapa-signature")):
        raise HTTPException(401, "bad signature")
    try:
        data = json.loads(raw)
        tx_ref = data["tx_ref"]
        assert isinstance(tx_ref, str)
    except Exception:
        raise HTTPException(400, "malformed payload")
    if data.get("status") in ("success", "confirmed"):
        reported = None
        if data.get("amount") is not None:
            try:
                reported = Decimal(str(data["amount"]))
            except InvalidOperation:
                raise HTTPException(400, "bad amount")
        out = await confirm_payment(tx_ref, provider=provider, reported_amount=reported)
        if out["status"] == "not_found":
            raise HTTPException(404, "unknown intent")
        return {"ok": True, **out}
    await mark_failed(tx_ref, provider, str(data.get("reason", "provider reported failure"))[:200])
    return {"ok": True}
