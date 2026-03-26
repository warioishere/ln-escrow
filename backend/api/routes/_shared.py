"""
Shared models, helpers, and utilities used across deal route files.
"""
import hmac
import logging
from typing import Optional
from fastapi import HTTPException, status
from pydantic import BaseModel, Field

from backend.api.routes.websockets import manager as ws_manager
from backend.auth.sig_verify import verify_action_signature
from backend.config import CONFIG

logger = logging.getLogger(__name__)


async def _ws_notify(deal_id: str, event: str, data: dict = None):
    """Send WebSocket + webhook notifications (fire-and-forget, never raises)."""
    try:
        await ws_manager.broadcast(deal_id, event, data)
    except Exception as e:
        logger.debug("WebSocket notification failed: %s", e)
    try:
        from backend.webhooks import deliver_webhook_event
        await deliver_webhook_event(event, deal_id, data)
    except Exception as e:
        logger.debug("Webhook delivery failed: %s", e)


def verify_admin(
    x_admin_key: Optional[str] = None,
    x_admin_pubkey: Optional[str] = None
):
    # SECURITY: X-Admin-Pubkey is replayable — acceptable behind HTTPS+Cloudflare tunnel.
    # For higher security, add session tokens.
    """Verify admin access via LNURL-auth pubkey (primary) or legacy API key. Logs all attempts."""
    pubkey_prefix = x_admin_pubkey[:12] + "..." if x_admin_pubkey else "none"

    # Primary: LNURL-auth pubkey
    if x_admin_pubkey:
        admin_pubkeys = CONFIG.admin_pubkeys or []
        if x_admin_pubkey in admin_pubkeys:
            logger.info("ADMIN AUTH OK: pubkey=%s", pubkey_prefix)
            return True

    # Legacy fallback: API key (for CLI tools like monitor.sh)
    if x_admin_key and CONFIG.admin_api_key and hmac.compare_digest(x_admin_key, CONFIG.admin_api_key):
        key_prefix = x_admin_key[:4] + "..." if len(x_admin_key) > 4 else "***"
        logger.info("ADMIN AUTH OK: key=%s", key_prefix)
        return True

    if not CONFIG.admin_api_key and not CONFIG.admin_pubkeys:
        logger.warning("ADMIN AUTH DENIED: admin not configured (set ADMIN_PUBKEYS in .env)")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin not configured. Set ADMIN_PUBKEYS in .env"
        )

    logger.warning("ADMIN AUTH DENIED: pubkey=%s", pubkey_prefix)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid admin credentials"
    )


def log_admin_action(action: str, detail: str = "", request=None):
    """Log admin action for audit trail (journalctl is the audit log)."""
    ip = "unknown"
    if request and hasattr(request, 'client') and request.client:
        ip = request.client.host
    logger.info("ADMIN ACTION: %s %s ip=%s", action, detail, ip)


def deal_to_response(deal: dict, base_url: str = None):
    """Convert deal dict to response model"""
    if base_url is None:
        base_url = CONFIG.frontend_url or "http://localhost:5173"
    return DealResponse(
        deal_id=deal['deal_id'],
        deal_link_token=deal['deal_link_token'],
        deal_link=f"{base_url}/join/{deal['deal_link_token']}",
        creator_role=deal.get('creator_role', 'seller'),
        status=deal['status'],
        title=deal['title'],
        description=deal.get('description'),
        price_sats=deal['price_sats'],
        timeout_hours=deal['timeout_hours'],
        timeout_action=deal['timeout_action'],
        requires_tracking=deal['requires_tracking'],
        seller_id=deal['seller_id'],
        seller_name=deal.get('seller_name'),
        buyer_id=deal.get('buyer_id'),
        buyer_name=deal.get('buyer_name'),
        seller_linking_pubkey=deal.get('seller_linking_pubkey'),
        buyer_linking_pubkey=deal.get('buyer_linking_pubkey'),
        ln_invoice=deal.get('ln_invoice'),
        ln_payment_hash=deal.get('ln_payment_hash'),
        tracking_carrier=deal.get('tracking_carrier'),
        tracking_number=deal.get('tracking_number'),
        shipping_notes=deal.get('shipping_notes'),
        created_at=deal['created_at'],
        buyer_started_at=deal.get('buyer_started_at'),
        buyer_joined_at=deal.get('buyer_joined_at'),
        funded_at=deal.get('funded_at'),
        shipped_at=deal.get('shipped_at'),
        completed_at=deal.get('completed_at'),
        expires_at=deal.get('expires_at'),
        disputed_at=deal.get('disputed_at'),
        disputed_by=deal.get('disputed_by'),
        dispute_reason=deal.get('dispute_reason'),
        has_seller_payout_invoice=bool(deal.get('seller_payout_invoice')),
        payout_status=deal.get('payout_status'),
        has_buyer_payout_invoice=bool(deal.get('buyer_payout_invoice')),
        buyer_payout_status=deal.get('buyer_payout_status'),
        fedimint_escrow_id=deal.get('fedimint_escrow_id'),
        fedimint_timeout_block=deal.get('fedimint_timeout_block'),
        buyer_escrow_pubkey=deal.get('buyer_escrow_pubkey'),
    )


def _verify_deal_signature(deal: dict, role: str, action: str, timestamp: int, signature: str, deal_id: str):
    """Verify a secp256k1 signature for a deal action."""
    pubkeys_to_try = []
    if role == 'either':
        if deal.get('buyer_pubkey'):
            pubkeys_to_try.append(deal['buyer_pubkey'])
        if deal.get('seller_pubkey'):
            pubkeys_to_try.append(deal['seller_pubkey'])
    elif role == 'buyer':
        if deal.get('buyer_pubkey'):
            pubkeys_to_try.append(deal['buyer_pubkey'])
    elif role == 'seller':
        if deal.get('seller_pubkey'):
            pubkeys_to_try.append(deal['seller_pubkey'])

    if not pubkeys_to_try:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No registered public key found for signature verification"
        )

    for pubkey in pubkeys_to_try:
        try:
            verify_action_signature(deal_id, action, timestamp, signature, pubkey)
            return
        except ValueError:
            continue

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid signature"
    )


# ============================================================================
# Request/Response Models
# ============================================================================

class SignedActionRequest(BaseModel):
    """Generic signed action request (user_id + signature + timestamp)"""
    user_id: str = Field(..., min_length=1, max_length=100)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")


class CreateDealRequest(BaseModel):
    """Request to create a new deal (buyer or seller)"""
    creator_role: str = Field(default='seller', pattern='^(buyer|seller)$')
    seller_id: Optional[str] = Field(None, min_length=1, max_length=100)
    seller_name: Optional[str] = Field(None, max_length=100)
    buyer_id: Optional[str] = Field(None, min_length=1, max_length=100)
    buyer_name: Optional[str] = Field(None, max_length=100)
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    price_sats: int = Field(..., gt=0, description="Amount in satoshis")
    timeout_hours: int = Field(default=72, gt=0, le=8760)
    timeout_action: str = Field(default='refund', pattern='^(refund|release)$')
    requires_tracking: bool = Field(default=False)
    recovery_contact: Optional[str] = Field(None, max_length=200, description="Optional contact (email, nostr, telegram) for recovery if keys lost")

    class Config:
        json_schema_extra = {
            "example": {
                "creator_role": "seller",
                "seller_id": "user_abc123",
                "seller_name": "Alice",
                "title": "MacBook Pro M3",
                "description": "Barely used, original packaging",
                "price_sats": 500000,
                "timeout_hours": 72,
                "timeout_action": "refund",
                "requires_tracking": True
            }
        }


class JoinDealRequest(BaseModel):
    """Request to join a deal (counterparty)"""
    user_id: str = Field(..., min_length=1, max_length=100)
    user_name: Optional[str] = Field(None, max_length=100)


class ShipDealRequest(BaseModel):
    """Request to mark deal as shipped (seller)"""
    seller_id: str = Field(..., min_length=1, max_length=100)
    tracking_carrier: Optional[str] = Field(None, max_length=50)
    tracking_number: Optional[str] = Field(None, max_length=100)
    shipping_notes: Optional[str] = Field(None, max_length=500)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")


class ReleaseDealRequest(BaseModel):
    """Request to release funds (buyer confirms receipt)"""
    buyer_id: str = Field(..., min_length=1, max_length=100)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")
    secret_code: Optional[str] = Field(None, description="Escrow recovery code from buyer's browser")
    buyer_escrow_signature: Optional[str] = Field(None, description="Schnorr sig over SHA256(secret_code) from buyer's ephemeral key (hex)")


class RefundDealRequest(BaseModel):
    """Request to initiate refund"""
    user_id: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=500)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")


class SubmitPayoutInvoiceRequest(BaseModel):
    """Request to submit a payout invoice/address for receiving funds"""
    user_id: str = Field(..., min_length=1, max_length=100)
    invoice: str = Field(..., min_length=3, max_length=1500, description="BOLT11 invoice or Lightning Address (user@domain)")
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")


class DisputeDealRequest(BaseModel):
    """Request to open a dispute"""
    user_id: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=1000)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")
    escrow_signature: Optional[str] = Field(None, description="Schnorr sig over SHA256('dispute') from user's ephemeral key (hex)")


class CancelDisputeRequest(BaseModel):
    """Request to cancel a dispute and return to normal flow"""
    user_id: str = Field(..., min_length=1, max_length=100)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")


class DisputeContactRequest(BaseModel):
    """Request to submit contact info during a dispute"""
    user_id: str = Field(..., min_length=1, max_length=100)
    contact: Optional[str] = Field(None, max_length=200)
    message: Optional[str] = Field(None, max_length=1000)
    signature: str = Field(..., min_length=1, description="DER-encoded ECDSA signature (hex)")
    timestamp: int = Field(..., description="Unix seconds when signature was created")


class RegisterKeyRequest(BaseModel):
    """Request to register a user's ephemeral public key"""
    user_id: str = Field(..., min_length=1, max_length=100)
    public_key: str = Field(..., min_length=66, max_length=66, description="Compressed pubkey (66 hex)")


class SigningStatusResponse(BaseModel):
    """Signing phase status"""
    deal_id: str
    phase: str
    buyer_pubkey_registered: bool
    seller_pubkey_registered: bool
    ready_for_funding: bool
    ready_for_resolution: bool
    funding_txid: Optional[str] = None
    funding_vout: Optional[int] = None
    funding_amount_sats: Optional[int] = None


class DealResponse(BaseModel):
    """Deal details response"""
    deal_id: str
    deal_link_token: str
    deal_link: str
    creator_role: str
    status: str
    title: str
    description: Optional[str]
    price_sats: int
    timeout_hours: int
    timeout_action: str
    requires_tracking: bool
    seller_id: Optional[str]
    seller_name: Optional[str]
    buyer_id: Optional[str]
    buyer_name: Optional[str]
    seller_linking_pubkey: Optional[str]
    buyer_linking_pubkey: Optional[str]
    ln_invoice: Optional[str]
    ln_payment_hash: Optional[str]
    tracking_carrier: Optional[str]
    tracking_number: Optional[str]
    shipping_notes: Optional[str]
    created_at: str
    buyer_started_at: Optional[str]
    buyer_joined_at: Optional[str]
    funded_at: Optional[str]
    shipped_at: Optional[str]
    completed_at: Optional[str]
    expires_at: Optional[str]
    disputed_at: Optional[str]
    disputed_by: Optional[str]
    dispute_reason: Optional[str]
    has_seller_payout_invoice: bool = False
    payout_status: Optional[str] = None
    has_buyer_payout_invoice: bool = False
    buyer_payout_status: Optional[str] = None
    fedimint_escrow_id: Optional[str] = None
    fedimint_timeout_block: Optional[int] = None
    buyer_escrow_pubkey: Optional[str] = None


class DealListResponse(BaseModel):
    """Simplified deal for list view"""
    deal_id: str
    title: str
    status: str
    price_sats: int
    seller_name: Optional[str]
    buyer_name: Optional[str]
    role: str
    created_at: str


class DealStatsResponse(BaseModel):
    """Deal statistics"""
    total_deals: int
    total_value_sats: int
    by_status: dict


class LedgerEntry(BaseModel):
    deal_id: str
    title: str
    status: str
    created_at: str
    ln_in_sats: Optional[int] = None
    ln_out_sats: Optional[int] = None
    ln_out_type: Optional[str] = None
    ln_out_fee_sats: Optional[int] = None
    net_sats: Optional[int] = None


class ResolveDisputeRequest(BaseModel):
    """Request to resolve a dispute"""
    resolution_note: Optional[str] = Field(None, max_length=500, description="Admin note about resolution")


class CreateInvoiceResponse(BaseModel):
    """Lightning invoice response"""
    deal_id: str
    payment_hash: str
    bolt11: str
    amount_sats: int
    description: str
    expires_at: Optional[str] = None
    price_sats: Optional[int] = None
    service_fee_sats: Optional[int] = None
    chain_fee_sats: Optional[int] = None


class InvoiceStatusResponse(BaseModel):
    """Invoice payment status"""
    deal_id: str
    payment_hash: str
    paid: bool
    amount_sats: Optional[int] = None
    paid_at: Optional[str] = None
    invoice_expired: bool = False


class OracleSignRequest(BaseModel):
    """Request to publish a pre-signed oracle attestation (Nostr event).
    Private key never touches the server — signing happens in the browser."""
    signed_event: dict = Field(..., description="Pre-signed Nostr event (id, pubkey, created_at, kind, tags, content, sig)")


class UpdateLimitsRequest(BaseModel):
    """Request to update deal limits"""
    min_sats: Optional[int] = Field(None, gt=0, description="Minimum amount in sats")
    max_sats: Optional[int] = Field(None, gt=0, description="Maximum amount in sats")


class UpdateFeesRequest(BaseModel):
    """Request to update fee settings"""
    service_fee_percent: Optional[float] = Field(None, ge=0, le=10, description="Service fee percentage (0-10%)")
    chain_fee_sats: Optional[int] = Field(None, ge=0, le=10000, description="Chain fee reserve in sats")
