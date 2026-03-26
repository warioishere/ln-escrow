"""
Admin endpoints: config, list-all-deals, disputes, ledger,
resolve-release, resolve-refund, retry-payout, bulk operations,
limits, fees, cancel-deal.
"""
import asyncio
import logging
import os
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, status, Header
from pydantic import BaseModel, Field

from backend.database import deal_storage
from backend.database.models import DealStatus
from backend.database.settings import get_limits, set_limits, get_fees, set_fees

from backend.api.routes._shared import (
    verify_admin, log_admin_action, _ws_notify,
    LedgerEntry, ResolveDisputeRequest,
    OracleSignRequest,
    UpdateLimitsRequest, UpdateFeesRequest,
)
from backend.api.routes._payout import halt_payouts, resume_payouts, payouts_halted, _payout_fields

logger = logging.getLogger(__name__)

router = APIRouter()

# Fields that should never be exposed in admin API responses.
# Auth signatures are ephemeral key seed material; timeout signatures
# are pre-signed authorizations that could be replayed.
_SENSITIVE_DEAL_FIELDS = {
    'buyer_auth_signature', 'seller_auth_signature',
    'buyer_timeout_signature', 'seller_timeout_signature',
    'fedimint_secret_code_hash',
}


def _strip_sensitive(deal: dict) -> dict:
    """Remove sensitive fields from a deal dict before returning to admin."""
    return {k: v for k, v in deal.items() if k not in _SENSITIVE_DEAL_FIELDS}


def _load_oracle_dev_keys() -> list[str]:
    """Load oracle dev private keys from .oracle-dev-keys file.

    Returns list of hex private key strings.
    """
    keys_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '.oracle-dev-keys')
    keys_path = os.path.normpath(keys_path)
    privkeys = []
    try:
        with open(keys_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith('ORACLE_') and '_PRIVKEY=' in line:
                    privkeys.append(line.split('=', 1)[1])
    except FileNotFoundError:
        pass
    return privkeys


def _sign_oracle_attestations(escrow_id: str, outcome: str) -> list[dict]:
    """
    # CUSTODIAL: Sign 2 oracle attestations server-side using dev keys.
    # Violates invariant #4. Temporary bridge for single-admin setup.

    Returns list of SignedAttestation-compatible dicts for resolve_via_oracle.
    """
    from tools.oracle_sign import sign_attestation

    privkeys = _load_oracle_dev_keys()
    if len(privkeys) < 2:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cannot sign oracle attestations — need at least 2 oracle dev keys"
        )

    attestations = []
    for privkey in privkeys[:2]:
        event = sign_attestation(privkey, escrow_id, outcome)
        # Convert Nostr event format → SignedAttestation format for escrow-httpd
        # pubkey: x-only (64 hex) → compressed with correct parity prefix
        import secp256k1 as secp_lib
        pk = secp_lib.PrivateKey(bytes.fromhex(privkey))
        compressed_pubkey = pk.pubkey.serialize(compressed=True).hex()
        attestations.append({
            "pubkey": compressed_pubkey,
            "signature": event["sig"],
            "content": {
                "escrow_id": escrow_id,
                "outcome": outcome.capitalize(),  # Rust Beneficiary enum expects "Buyer"/"Seller"
                "decided_at": event["created_at"],
            },
        })

    logger.info(
        "Signed 2 oracle attestations for escrow %s: outcome=%s (CUSTODIAL: dev keys)",
        escrow_id, outcome,
    )
    return attestations


# ============================================================================
# Kill switch endpoints
# ============================================================================

@router.post("/admin/halt-payouts")
async def admin_halt_payouts(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Emergency halt: block all payouts immediately."""
    verify_admin(x_admin_key, x_admin_pubkey)
    halt_payouts()
    log_admin_action("halt_payouts", "ALL PAYOUTS HALTED")
    return {"success": True, "payouts_halted": True}


@router.post("/admin/resume-payouts")
async def admin_resume_payouts(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Resume payouts after emergency halt."""
    verify_admin(x_admin_key, x_admin_pubkey)
    resume_payouts()
    log_admin_action("resume_payouts", "Payouts resumed")
    return {"success": True, "payouts_halted": False}


@router.get("/admin/config")
async def get_admin_config(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Get current network configuration (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)

    return {
        "network": "mainnet",
        "escrow_backend": "fedimint",
    }


@router.get("/admin/deals")
async def list_all_deals(
    include_finished: bool = False,
    limit: int = 100,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """List all deals (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)

    try:
        deals = deal_storage.get_all_deals(include_finished=include_finished, limit=limit)
        return {
            "deals": [_strip_sensitive(d) for d in deals],
            "count": len(deals),
            "include_finished": include_finished
        }
    except Exception as e:
        logger.error("Failed to list deals: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error. Please try again.")


@router.get("/admin/disputes")
async def list_disputed_deals(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """List all disputed deals (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)

    try:
        deals = deal_storage.get_deals_by_status('disputed')
        return {
            "deals": [_strip_sensitive(d) for d in deals],
            "count": len(deals)
        }
    except Exception as e:
        logger.error("Failed to list disputes: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error. Please try again.")


@router.get("/admin/ledger")
async def get_admin_ledger(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Financial ledger showing actual transaction amounts per deal (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)

    try:
        all_deals = deal_storage.get_all_deals(include_finished=True, limit=10000)
        funded_deals = [d for d in all_deals if d.get('funded_at')]

        entries = []
        totals = {'ln_in': 0, 'ln_out': 0, 'ln_out_fees': 0}

        for deal in funded_deals:
            entry = LedgerEntry(
                deal_id=deal['deal_id'],
                title=deal.get('title', ''),
                status=deal.get('status', ''),
                created_at=deal.get('created_at', ''),
            )

            if deal.get('invoice_amount_sats'):
                entry.ln_in_sats = deal['invoice_amount_sats']
                totals['ln_in'] += entry.ln_in_sats

            if deal.get('payout_status') == 'paid':
                entry.ln_out_sats = deal.get('price_sats')
                entry.ln_out_type = 'release'
                entry.ln_out_fee_sats = deal.get('payout_fee_sat')
            elif deal.get('buyer_payout_status') == 'paid':
                entry.ln_out_sats = deal.get('price_sats')
                entry.ln_out_type = 'refund'
                entry.ln_out_fee_sats = deal.get('buyer_payout_fee_sat')
            if entry.ln_out_sats:
                totals['ln_out'] += entry.ln_out_sats
            if entry.ln_out_fee_sats:
                totals['ln_out_fees'] += entry.ln_out_fee_sats

            total_in = entry.ln_in_sats or 0
            total_out = (entry.ln_out_sats or 0) + (entry.ln_out_fee_sats or 0)
            entry.net_sats = total_in - total_out

            entries.append(entry.model_dump())

        totals['net'] = totals['ln_in'] - totals['ln_out'] - totals['ln_out_fees']
        return {"entries": entries, "totals": totals}

    except Exception as e:
        logger.exception("Failed to build ledger")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error. Please try again.")


async def _admin_resolve_dispute(deal_id: str, payout_type: str, request, body, x_admin_key, x_admin_pubkey):
    """Shared logic for admin resolve-release and resolve-refund."""
    verify_admin(x_admin_key, x_admin_pubkey)
    log_admin_action(f"resolve-{payout_type}", deal_id, request)

    is_release = (payout_type == 'release')

    # Field mapping: release vs refund
    fields = _payout_fields(payout_type)
    invoice_field = fields['invoice_field']
    cross_txid_field = fields['cross_txid_field']
    own_txid_field = fields['txid_field']
    own_status_field = fields['payout_status_field']
    ws_event = 'deal:completed' if is_release else 'deal:admin_refunded'
    recipient = 'seller' if is_release else 'buyer'

    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    if deal['status'] not in [DealStatus.DISPUTED.value, DealStatus.EXPIRED.value]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Deal must be disputed or expired (status: {deal['status']})")

    if not deal.get('fedimint_escrow_id'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No Fedimint escrow associated with deal")

    if not deal.get(invoice_field):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot {payout_type} — {recipient} has not provided a Lightning Address yet"
        )

    # COIN SAFETY: block if the other side already claimed the escrow
    if deal.get(cross_txid_field):
        other = 'refund' if is_release else 'release'
        raise HTTPException(status_code=409, detail=f"Escrow already claimed for {other} — cannot {payout_type}")
    if deal.get(own_txid_field) and deal.get(own_status_field) == 'paid':
        raise HTTPException(status_code=409, detail=f"Escrow already claimed and payment sent to {recipient}")

    try:
        from backend.api.routes._payout import execute_fedimint_payout

        if deal['status'] == DealStatus.DISPUTED.value:
            # CUSTODIAL: Admin signs oracle attestations server-side using dev keys.
            # This violates invariant #4 (oracle keys should be held by 3 independent
            # parties). Temporary bridge while there is only one admin. Must be replaced
            # with independent oracle signing before real money is at stake.
            from backend.fedimint.fedimint_service import FedimintEscrowService
            fedimint = FedimintEscrowService()
            escrow_id = deal['fedimint_escrow_id']

            try:
                escrow_info = await fedimint.get_escrow_info(escrow_id)
                escrow_state = escrow_info.state
            except Exception as e:
                logger.error("Could not check escrow state for deal %s: %s", deal_id, e)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Could not check escrow state. Please try again."
                )

            if escrow_state not in ('DisputedByBuyer', 'DisputedBySeller'):
                if escrow_state == 'ResolvedByOracle':
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Oracle already resolved. If LN payment failed, "
                               "e-cash is in wallet — use fedimint-cli to pay out."
                    )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unexpected escrow state for disputed deal: {escrow_state}"
                )

            # Sign 2-of-3 oracle attestations using dev keys
            oracle_outcome = 'seller' if is_release else 'buyer'
            attestations = _sign_oracle_attestations(escrow_id, oracle_outcome)

            from backend.api.routes._payout import execute_oracle_payout
            result = await execute_oracle_payout(
                deal=deal,
                payout_type=payout_type,
                attestations=attestations,
                ws_complete_event=ws_event,
            )
        else:
            # Expired deals use timeout claim path (no secret_code needed).
            # SAFETY: payout_type must match timeout_action to prevent paying the wrong party.
            # The Fedimint signature is selected by timeout_action, but the invoice is selected
            # by payout_type — a mismatch would pay the wrong recipient.
            timeout_action = deal.get('timeout_action', 'refund')
            expected_payout = 'release' if timeout_action == 'release' else 'refund'
            if payout_type != expected_payout:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot {payout_type} — deal timeout_action is '{timeout_action}', "
                           f"so only resolve-{expected_payout} is allowed"
                )
            result = await execute_fedimint_payout(
                deal=deal,
                payout_type=payout_type,
                ws_complete_event=ws_event,
                timeout_claim=True,
            )

        resolution = 'released' if is_release else 'refunded'
        logger.info("Admin resolved dispute %s: %s. Note: %s", deal_id, resolution.upper(), body.resolution_note if body else 'None')

        response = {
            "success": True,
            "resolution": resolution,
            "txid": result.get('txid'),
            "message": f"Funds {resolution} to {recipient}",
        }

        # Release path includes payout details in response
        if is_release:
            payout_result = result.get('payout_result', {})
            if payout_result.get('success'):
                response.update({"payout": "paid", "payout_fee_sat": payout_result.get('fee_sat', 0)})
            else:
                response.update({"payout": "failed", "payout_error": payout_result.get('error')})

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Admin resolve-%s failed for %s: %s", payout_type, deal_id, e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error. Please try again.")


@router.post("/admin/{deal_id}/resolve-release")
async def admin_resolve_release(
    request: Request,
    deal_id: str,
    body: ResolveDisputeRequest = None,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Admin resolves dispute by releasing funds to seller via Fedimint."""
    return await _admin_resolve_dispute(deal_id, "release", request, body, x_admin_key, x_admin_pubkey)


@router.post("/admin/{deal_id}/resolve-refund")
async def admin_resolve_refund(
    request: Request,
    deal_id: str,
    body: ResolveDisputeRequest = None,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Admin resolves dispute by refunding to buyer via Fedimint."""
    return await _admin_resolve_dispute(deal_id, "refund", request, body, x_admin_key, x_admin_pubkey)



@router.post("/admin/{deal_id}/oracle-sign")
async def admin_oracle_sign(
    request: Request,
    deal_id: str,
    body: OracleSignRequest,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Verify and publish a pre-signed oracle attestation to Nostr relays.
    The private key NEVER reaches the server — signing happens in the browser."""
    verify_admin(x_admin_key, x_admin_pubkey)
    log_admin_action("oracle-sign", deal_id, request)

    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")
    if deal['status'] != DealStatus.DISPUTED.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Deal must be disputed (status: {deal['status']})")
    if not deal.get('fedimint_escrow_id'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No Fedimint escrow associated with deal")

    event = body.signed_event

    # Validate event structure
    required = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    missing = required - set(event.keys())
    if missing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Signed event missing fields: {missing}")

    # Verify the pubkey is a registered oracle (x-only = 64 hex chars)
    oracle_pubkeys_raw = os.environ.get("ORACLE_PUBKEYS", "")
    # Oracle pubkeys in .env are compressed (66 hex) — strip 02/03 prefix to get x-only
    oracle_xonly = {pk[2:] for pk in oracle_pubkeys_raw.split(",") if len(pk) == 66}
    if event["pubkey"] not in oracle_xonly:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Pubkey {event['pubkey'][:16]}... is not a registered oracle"
        )

    # Verify escrow_id in tags matches this deal
    d_tags = [t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "d"]
    if deal['fedimint_escrow_id'] not in d_tags:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Event escrow_id does not match deal"
        )

    # Verify BIP-340 Schnorr signature
    try:
        import secp256k1 as secp_lib
        compressed_hex = "02" + event["pubkey"]
        pub = secp_lib.PublicKey(bytes.fromhex(compressed_hex), raw=True)
        event_id_bytes = bytes.fromhex(event["id"])
        sig_bytes = bytes.fromhex(event["sig"])
        valid = pub.schnorr_verify(event_id_bytes, sig_bytes, bip340tag="", raw=True)
        if not valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid BIP-340 signature")
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Oracle signature verification failed for deal %s: %s", deal_id, e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Signature verification failed")

    # Publish verified event to Nostr relays
    try:
        from tools.oracle_publish import publish_event, DEFAULT_RELAYS
        results = await publish_event(event, DEFAULT_RELAYS)

        relay_results = [{"url": url, "ok": ok, "message": msg} for url, ok, msg in results]
        ok_count = sum(1 for r in relay_results if r["ok"])

        # Extract outcome from content
        content = event.get("content", "")
        try:
            import json as _json
            parsed = _json.loads(content)
            outcome = parsed.get("outcome", content)
        except (ValueError, AttributeError):
            outcome = content

        logger.info(
            "Oracle attestation published for deal %s: outcome=%s pubkey=%s...%s published=%d/%d",
            deal_id, outcome, event["pubkey"][:8], event["pubkey"][-4:],
            ok_count, len(relay_results),
        )

        return {
            "event_id": event["id"],
            "pubkey": event["pubkey"],
            "outcome": outcome,
            "relays": relay_results,
            "published": ok_count,
            "total": len(relay_results),
        }

    except Exception as e:
        logger.error("Oracle publish failed for deal %s: %s", deal_id, e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Relay publishing failed")



# ============================================================================
# Limits & Fees (public + admin)
# ============================================================================

@router.get("/settings/limits")
async def get_deal_limits():
    """Get current deal amount limits (public endpoint)."""
    limits = get_limits()
    fees = get_fees()
    limits["service_fee_percent"] = fees["service_fee_percent"]
    limits["chain_fee_sats"] = 0  # No chain fees in Fedimint mode
    return limits


@router.put("/admin/settings/limits")
async def update_deal_limits(
    body: UpdateLimitsRequest,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Update deal amount limits (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)

    try:
        new_limits = set_limits(min_sats=body.min_sats, max_sats=body.max_sats)
        return {
            "success": True,
            "limits": new_limits,
            "message": "Limits updated successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/admin/settings/fees")
async def update_deal_fees(
    body: UpdateFeesRequest,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None)
):
    """Update fee settings (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)

    try:
        new_fees = set_fees(
            service_fee_percent=body.service_fee_percent,
        )
        return {
            "success": True,
            "fees": new_fees,
            "message": "Fees updated successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# Recovery tools
# ============================================================================

@router.get("/admin/wallet-balance")
async def admin_wallet_balance(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Get the federation wallet e-cash balance."""
    verify_admin(x_admin_key, x_admin_pubkey)
    from backend.fedimint.fedimint_service import FedimintEscrowService
    fedimint = FedimintEscrowService()
    balance_sats = await fedimint.get_wallet_balance_sats()
    return {"balance_sats": balance_sats, "balance_btc": balance_sats / 100_000_000}


@router.get("/admin/failed-payouts")
async def admin_failed_payouts(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """List all deals with failed or stuck payouts."""
    verify_admin(x_admin_key, x_admin_pubkey)
    deals = deal_storage.get_deals_with_failed_payouts()
    # Also include payout_stuck
    from backend.database.connection import get_db_session
    from backend.database.models import DealModel
    from sqlalchemy import or_
    with get_db_session() as db:
        stuck = db.query(DealModel).filter(
            or_(
                DealModel.payout_status == 'payout_stuck',
                DealModel.buyer_payout_status == 'payout_stuck',
            )
        ).all()
        stuck_deals = [d.to_dict() for d in stuck]

    all_deals = {d['deal_id']: d for d in deals + stuck_deals}
    result = []
    for d in all_deals.values():
        result.append({
            "deal_id": d["deal_id"],
            "title": d.get("title"),
            "price_sats": d.get("price_sats"),
            "status": d["status"],
            "payout_status": d.get("payout_status"),
            "buyer_payout_status": d.get("buyer_payout_status"),
            "release_txid": d.get("release_txid"),
            "refund_txid": d.get("refund_txid"),
            "created_at": d.get("created_at"),
        })
    return {"count": len(result), "deals": result}


@router.get("/admin/{deal_id}/escrow-status")
async def admin_escrow_status(
    deal_id: str,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Query Fedimint escrow state directly for a deal."""
    verify_admin(x_admin_key, x_admin_pubkey)
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=404, detail="Deal not found")
    escrow_id = deal.get('fedimint_escrow_id')
    if not escrow_id:
        return {"deal_id": deal_id, "escrow_id": None, "state": "no_escrow"}

    from backend.fedimint.fedimint_service import FedimintEscrowService
    fedimint = FedimintEscrowService()
    try:
        info = await fedimint.get_escrow_info(escrow_id)
        return {
            "deal_id": deal_id,
            "escrow_id": escrow_id,
            "state": info.state,
            "amount_msats": getattr(info, 'amount', None),
            "timeout_block": getattr(info, 'timeout_block', None),
            "timeout_action": getattr(info, 'timeout_action', None),
            "deal_status": deal['status'],
            "payout_status": deal.get('payout_status'),
            "buyer_payout_status": deal.get('buyer_payout_status'),
        }
    except Exception as e:
        logger.error("Failed to query escrow %s for deal %s: %s", escrow_id, deal_id, e)
        return {"deal_id": deal_id, "escrow_id": escrow_id, "error": "Failed to query escrow state"}


# ============================================================================
# Bulk Operations
# ============================================================================

# ============================================================================
# Webhooks
# ============================================================================

class RegisterWebhookRequest(BaseModel):
    """Request to register a webhook endpoint."""
    url: str = Field(..., min_length=10, max_length=500, description="Target URL for webhook delivery")
    secret: Optional[str] = Field(None, max_length=200, description="Shared secret for HMAC-SHA256 signature")
    events: Optional[list[str]] = Field(None, description="Event filter (e.g. ['deal:funded', 'deal:completed']). Omit for all events.")


@router.post("/admin/webhooks")
async def admin_register_webhook(
    body: RegisterWebhookRequest,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Register a webhook endpoint for deal event notifications."""
    verify_admin(x_admin_key, x_admin_pubkey)

    if not body.url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")

    from backend.webhooks import register_webhook
    webhook = register_webhook(url=body.url, secret=body.secret, events=body.events)
    log_admin_action("register_webhook", f"url={body.url}")
    return {"success": True, "webhook": webhook}


@router.get("/admin/webhooks")
async def admin_list_webhooks(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """List all registered webhooks (secrets redacted)."""
    verify_admin(x_admin_key, x_admin_pubkey)
    from backend.webhooks import list_webhooks
    webhooks = list_webhooks()
    return {"webhooks": webhooks, "count": len(webhooks)}


@router.delete("/admin/webhooks/{webhook_id}")
async def admin_delete_webhook(
    webhook_id: str,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Remove a registered webhook."""
    verify_admin(x_admin_key, x_admin_pubkey)
    from backend.webhooks import unregister_webhook
    removed = unregister_webhook(webhook_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Webhook not found")
    log_admin_action("delete_webhook", f"id={webhook_id}")
    return {"success": True}


class BulkResolveRequest(BaseModel):
    """Request to resolve multiple disputed deals at once."""
    deal_ids: list[str] = Field(..., min_length=1, max_length=50, description="List of deal IDs to resolve")
    resolution: str = Field(..., pattern='^(release|refund)$', description="Resolution type")
    resolution_note: Optional[str] = Field(None, max_length=500)


class BulkRetryPayoutsRequest(BaseModel):
    """Request to retry failed payouts for multiple deals."""
    deal_ids: list[str] = Field(default=None, max_length=50, description="Specific deal IDs, or omit to retry all failed")


@router.post("/admin/bulk/resolve")
async def admin_bulk_resolve(
    request: Request,
    body: BulkResolveRequest,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """
    Resolve multiple disputed deals in one call.

    Each deal is resolved independently — failures in one don't affect others.
    Returns per-deal results.
    """
    verify_admin(x_admin_key, x_admin_pubkey)
    log_admin_action("bulk_resolve", f"{len(body.deal_ids)} deals → {body.resolution}", request)

    results = []
    for deal_id in body.deal_ids:
        try:
            resolve_body = ResolveDisputeRequest(resolution_note=body.resolution_note)
            result = await _admin_resolve_dispute(
                deal_id, body.resolution, request, resolve_body,
                x_admin_key, x_admin_pubkey,
            )
            results.append({"deal_id": deal_id, "success": True, "result": result})
        except HTTPException as e:
            results.append({"deal_id": deal_id, "success": False, "error": e.detail})
        except Exception as e:
            results.append({"deal_id": deal_id, "success": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["success"])
    return {
        "total": len(body.deal_ids),
        "succeeded": succeeded,
        "failed": len(body.deal_ids) - succeeded,
        "results": results,
    }


@router.post("/admin/bulk/retry-payouts")
async def admin_bulk_retry_payouts(
    request: Request,
    body: BulkRetryPayoutsRequest = None,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """
    Retry failed payouts for multiple deals.

    If deal_ids is omitted, retries all deals with failed payouts.
    Each retry is independent — failures don't affect others.
    """
    verify_admin(x_admin_key, x_admin_pubkey)

    if body and body.deal_ids:
        deal_ids = body.deal_ids
    else:
        failed_deals = deal_storage.get_deals_with_failed_payouts()
        deal_ids = [d['deal_id'] for d in failed_deals]

    if not deal_ids:
        return {"total": 0, "succeeded": 0, "failed": 0, "results": [], "message": "No failed payouts found"}

    log_admin_action("bulk_retry_payouts", f"{len(deal_ids)} deals", request)

    from backend.api.routes._payout import execute_fedimint_payout

    results = []
    for deal_id in deal_ids:
        try:
            deal = deal_storage.get_deal_by_id(deal_id)
            if not deal:
                results.append({"deal_id": deal_id, "success": False, "error": "Deal not found"})
                continue

            # Determine payout type from deal state
            if deal.get('payout_status') == 'failed' and deal.get('seller_payout_invoice'):
                payout_type = "release"
            elif deal.get('buyer_payout_status') == 'failed' and deal.get('buyer_payout_invoice'):
                payout_type = "refund"
            else:
                results.append({"deal_id": deal_id, "success": False, "error": "No failed payout to retry"})
                continue

            await execute_fedimint_payout(
                deal=deal,
                payout_type=payout_type,
                timeout_claim=True,
            )
            results.append({"deal_id": deal_id, "success": True, "payout_type": payout_type})
        except Exception as e:
            results.append({"deal_id": deal_id, "success": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["success"])
    return {
        "total": len(deal_ids),
        "succeeded": succeeded,
        "failed": len(deal_ids) - succeeded,
        "results": results,
    }


