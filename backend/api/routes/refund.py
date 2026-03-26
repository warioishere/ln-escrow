"""
Refund endpoints: submit-refund-invoice, refund (Fedimint escrow claim + LN payout),
dispute, cancel-dispute, dispute-contact.
"""
import asyncio
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, status

from backend.database import deal_storage
from backend.database.models import DealStatus

from backend.api.routes._shared import (
    _ws_notify, deal_to_response, _verify_deal_signature,
    SubmitPayoutInvoiceRequest,
    DisputeDealRequest, CancelDisputeRequest, DisputeContactRequest,
    RefundDealRequest,
    DealResponse,
)
from backend.api.security import strip_html_tags
from backend.api.routes._payout import validate_lightning_address, execute_fedimint_payout, execute_oracle_payout

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/{deal_id}/submit-refund-invoice")
async def submit_refund_invoice(deal_id: str, body: SubmitPayoutInvoiceRequest):
    """Buyer submits a Lightning Address for receiving refund payout."""
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    if deal['buyer_id'] != body.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the buyer can submit a refund invoice")

    _verify_deal_signature(deal, 'buyer', 'submit-refund-invoice', body.timestamp, body.signature, deal_id)

    if deal['status'] in ['completed', 'released', 'cancelled']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot submit refund invoice for deal in status: {deal['status']}")

    # Block update if refund payout already succeeded or is currently in-flight.
    if deal.get('refund_txid') and deal.get('buyer_payout_status') == 'paid':
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot change refund invoice — funds have already been sent."
        )
    if deal.get('buyer_payout_status') == 'pending' or deal['status'] in ['refunding']:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot change refund invoice while payment is in progress."
        )

    invoice = body.invoice.strip()
    await validate_lightning_address(invoice, deal['price_sats'])

    deal_storage.update_deal(deal_id, buyer_payout_invoice=invoice)
    await _ws_notify(deal_id, 'deal:refund_invoice')
    logger.info("Buyer refund Lightning Address saved for deal %s", deal_id)

    # FUND-LOCK FIX: If deal expired with timeout_action='refund' but had no buyer invoice,
    # the timeout handler marked it 'expired' with buyer_payout_status=NULL and no refund_txid.
    # Now that the buyer submitted an invoice, trigger a full timeout claim+pay.
    if (deal.get('status') == 'expired'
          and deal.get('timeout_action') == 'refund'
          and deal.get('fedimint_escrow_id')
          and not deal.get('refund_txid')
          and not deal.get('buyer_payout_status')):
        deal_storage.update_deal(deal_id, buyer_payout_status='failed')
        logger.info("Expired deal %s: buyer submitted invoice, triggering timeout refund", deal_id[:8])
        try:
            deal_fresh = deal_storage.get_deal_by_id(deal_id)
            await execute_fedimint_payout(
                deal=deal_fresh,
                payout_type="refund",
                ws_complete_event='deal:timeout_refunded',
                timeout_claim=True,
            )
        except Exception as e:
            logger.warning("Auto timeout refund after invoice submit failed for deal %s: %s", deal_id, e)

    return {
        "success": True,
        "deal_id": deal_id,
        "type": "lightning_address",
        "message": "Refund destination saved",
    }


@router.post("/{deal_id}/refund", response_model=DealResponse)
async def refund_deal(deal_id: str, body: RefundDealRequest):
    """Refund funds to buyer. Claims Fedimint escrow for refund, pays buyer via LN."""
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    if body.user_id not in [deal['seller_id'], deal['buyer_id']]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only deal participants can request refund")

    role = 'buyer' if body.user_id == deal['buyer_id'] else 'seller'
    _verify_deal_signature(deal, role, 'refund', body.timestamp, body.signature, deal_id)

    # Already refunded — return success (idempotency)
    if deal.get('buyer_payout_status') == 'paid':
        logger.info("Deal %s refund: already paid, returning success", deal_id)
        return deal_to_response(deal)

    refund_allowed = [DealStatus.FUNDED.value, DealStatus.SHIPPED.value, DealStatus.REFUNDING.value]
    if deal['status'] == DealStatus.EXPIRED.value and not deal.get('release_txid') and not deal.get('refund_txid'):
        refund_allowed.append(DealStatus.EXPIRED.value)
    if deal['status'] not in refund_allowed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot refund deal in status: {deal['status']}")

    if not deal.get('fedimint_escrow_id'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Deal has no Fedimint escrow yet")

    if not deal.get('buyer_payout_invoice'):
        raise HTTPException(status_code=400, detail="Buyer has not submitted a refund invoice yet")

    # COIN SAFETY: block if a release already claimed the escrow
    if deal.get('release_txid'):
        raise HTTPException(status_code=409, detail="Escrow already claimed for release — cannot refund")

    # Kick off the payout in the background so the HTTP response returns immediately.
    # The frontend shows "Refunding Funds..." and waits for a WebSocket notification.
    async def _bg_refund():
        try:
            await execute_fedimint_payout(
                deal=deal,
                payout_type="refund",
                raise_on_ln_fail=False,
                ws_complete_event='deal:refunded',
            )
        except Exception as e:
            logger.error("Background refund failed for deal %s: %s", deal_id, e, exc_info=True)

    asyncio.create_task(_bg_refund())

    # Return immediately with 'refunding' status — the frontend will poll/WS for completion.
    await asyncio.sleep(0.1)
    updated_deal = deal_storage.get_deal_by_id(deal_id)
    return deal_to_response(updated_deal)


# ============================================================================
# Dispute Endpoints
# ============================================================================

@router.post("/{deal_id}/dispute", response_model=DealResponse)
async def open_dispute(deal_id: str, body: DisputeDealRequest, request: Request = None):
    """Open a dispute for admin resolution."""
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    if body.user_id not in [deal['seller_id'], deal['buyer_id']]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only deal participants can open a dispute")

    _verify_deal_signature(deal, 'either', 'dispute', body.timestamp, body.signature, deal_id)

    if deal['status'] == DealStatus.DISPUTED.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Deal is already disputed")
    if deal['status'] not in [DealStatus.FUNDED.value, DealStatus.SHIPPED.value]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot open dispute on deal in status: {deal['status']}")

    # Remember previous status for rollback if Fedimint call fails
    previous_status = DealStatus.SHIPPED.value if deal.get('shipped_at') else DealStatus.FUNDED.value

    try:
        transitioned = deal_storage.atomic_status_transition(
            deal_id,
            [DealStatus.FUNDED.value, DealStatus.SHIPPED.value],
            DealStatus.DISPUTED.value,
            disputed_at=datetime.now(timezone.utc),
            disputed_by=body.user_id,
            dispute_reason=strip_html_tags(body.reason)[:1000] if body.reason else None,
        )
        if not transitioned:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Deal state changed concurrently. Please refresh and try again."
            )
        updated_deal = deal_storage.get_deal_by_id(deal_id)
        logger.info("Dispute opened for deal %s by %s: %s...", deal_id, body.user_id, body.reason[:50])
        await _ws_notify(deal_id, 'deal:disputed')

        # Fedimint: initiate dispute in the escrow module and start oracle listener
        if deal.get('fedimint_escrow_id'):
            try:
                from backend.fedimint.fedimint_service import FedimintEscrowService
                from backend.fedimint.oracle_listener import OracleListener
                from backend.api.routes._payout import execute_fedimint_payout

                fedimint = FedimintEscrowService()
                # Non-custodial: use buyer/seller's ephemeral key signature if provided
                escrow_pubkey = deal.get('buyer_escrow_pubkey') if body.user_id == deal['buyer_id'] else deal.get('seller_pubkey')
                if body.escrow_signature and escrow_pubkey:
                    await fedimint.dispute_deal_delegated(
                        deal['fedimint_escrow_id'], escrow_pubkey, body.escrow_signature,
                    )
                else:
                    await fedimint.dispute_deal_escrow(deal['fedimint_escrow_id'])
                logger.info("Fedimint dispute initiated for deal %s", deal_id)

                # Start oracle listener in background
                oracle_listener: OracleListener = getattr(
                    request.app.state,
                    'oracle_listener', None
                )
                if oracle_listener:
                    async def _on_oracle_resolved(escrow_id, attestations):
                        fresh_deal = deal_storage.get_deal_by_id(deal_id)
                        if not fresh_deal:
                            logger.error("Oracle resolved escrow %s but deal %s not found", escrow_id, deal_id)
                            return
                        # Determine winner from oracle attestation outcome
                        outcome = attestations[0].content.get('outcome', '') if attestations else ''
                        payout_type = 'release' if outcome == 'seller' else 'refund'
                        ws_event = 'deal:completed' if payout_type == 'release' else 'deal:refunded'
                        logger.info(
                            "Oracle resolved deal %s (escrow %s): outcome=%s → %s",
                            deal_id, escrow_id, outcome, payout_type,
                        )
                        try:
                            await execute_oracle_payout(
                                deal=fresh_deal,
                                payout_type=payout_type,
                                attestations=attestations,
                                ws_complete_event=ws_event,
                            )
                        except Exception as e:
                            logger.error("Oracle payout failed for deal %s: %s", deal_id, e, exc_info=True)

                    await oracle_listener.watch_escrow(
                        deal['fedimint_escrow_id'],
                        oracle_pubkeys=None,
                        on_resolved=_on_oracle_resolved,
                    )
                    logger.info("Oracle listener started for dispute in deal %s", deal_id)
                else:
                    # Fedimint dispute SUCCEEDED — escrow is disputed on the federation.
                    # Do NOT rollback DB: that would desync DB (funded) vs federation (disputed),
                    # blocking all resolution paths. Keep DB as 'disputed' so admin can resolve manually.
                    logger.error(
                        "No oracle_listener on app.state — cannot watch for oracle resolution on deal %s. "
                        "Fedimint escrow IS disputed; admin must resolve manually.",
                        deal_id,
                    )
            except HTTPException:
                raise
            except Exception as fm_err:
                logger.error("Fedimint dispute setup failed for deal %s: %s", deal_id, fm_err)
                # Rollback DB: Fedimint call failed, deal should not stay in 'disputed'.
                # Use atomic transition to avoid overwriting a concurrent state change.
                deal_storage.atomic_status_transition(
                    deal_id, ['disputed'], previous_status,
                    disputed_at=None, disputed_by=None, dispute_reason=None,
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Dispute could not be filed. Please try again.",
                )

        return deal_to_response(updated_deal)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to open dispute for deal %s: %s", deal_id, e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error. Please try again.")


@router.post("/{deal_id}/cancel-dispute", response_model=DealResponse)
async def cancel_dispute(deal_id: str, body: CancelDisputeRequest):
    """Cancel a dispute and return deal to previous state."""
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    if deal['status'] != DealStatus.DISPUTED.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Deal is not disputed (status: {deal['status']})")

    if body.user_id != deal.get('disputed_by'):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the party who opened the dispute can cancel it")

    _verify_deal_signature(deal, 'either', 'cancel-dispute', body.timestamp, body.signature, deal_id)

    # COIN SAFETY: if the Fedimint escrow is already disputed, we cannot cancel it
    # (Fedimint has no cancel-dispute command — only oracle resolution).
    # Allowing DB-only cancel while escrow stays disputed creates a dangerous desync:
    # the oracle listener could still resolve and pay out after the UI shows "not disputed".
    if deal.get('fedimint_escrow_id'):
        try:
            from backend.fedimint.fedimint_service import FedimintEscrowService
            fedimint = FedimintEscrowService()
            escrow_info = await fedimint.get_escrow_info(deal['fedimint_escrow_id'])
            if escrow_info.state in ('DisputedByBuyer', 'DisputedBySeller'):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot cancel dispute — the Fedimint escrow is already in disputed state. "
                           "Only oracle resolution can proceed from here."
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Could not check escrow state for cancel-dispute on deal %s: %s", deal_id, e)
            # If we can't verify, block the cancel to be safe
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not verify escrow state. Please try again."
            )

    previous_status = DealStatus.SHIPPED.value if deal.get('shipped_at') else DealStatus.FUNDED.value

    try:
        transitioned = deal_storage.atomic_status_transition(
            deal_id,
            [DealStatus.DISPUTED.value],
            previous_status,
            disputed_at=None,
            disputed_by=None,
            dispute_reason=None,
        )
        if not transitioned:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Deal state changed concurrently. Please refresh and try again."
            )
        updated_deal = deal_storage.get_deal_by_id(deal_id)
        logger.info("Dispute cancelled for deal %s by %s, returning to %s", deal_id, body.user_id, previous_status)
        await _ws_notify(deal_id, 'deal:dispute-cancelled')
        return deal_to_response(updated_deal)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to cancel dispute for deal %s: %s", deal_id, e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error. Please try again.")


@router.post("/{deal_id}/dispute-contact")
async def submit_dispute_contact(deal_id: str, body: DisputeContactRequest):
    """Participant submits contact info during a dispute."""
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    if deal['status'] != DealStatus.DISPUTED.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Deal is not disputed")

    if body.user_id == deal['seller_id']:
        role = 'seller'
    elif body.user_id == deal['buyer_id']:
        role = 'buyer'
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only deal participants can submit contact info")

    _verify_deal_signature(deal, role, 'dispute-contact', body.timestamp, body.signature, deal_id)

    contact = strip_html_tags(body.contact or '')[:200]
    message = strip_html_tags(body.message or '')[:1000]

    update_data = {}
    if contact:
        update_data[f'{role}_recovery_contact'] = contact
    if message:
        existing = deal.get('dispute_reason', '') or ''
        separator = '\n---\n' if existing else ''
        role_label = 'Seller' if role == 'seller' else 'Buyer'
        update_data['dispute_reason'] = existing + separator + f"[{role_label}]: {message}"

    if update_data:
        deal_storage.update_deal(deal_id, **update_data)
        await _ws_notify(deal_id, 'deal:dispute_update')

    return {"success": True}
